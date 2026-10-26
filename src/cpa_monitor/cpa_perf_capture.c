// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/* name_to_handle_at() */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "gunwinder/unwinder.h"
#include "cpa_runtime.h"
#include "cpa_capture_stats.h"
#include "cli_common.h"
#include "cpa_env.h"
#include <offcpu_capture.h>
#include <cpa_bpf/perf_stack_capture.h>
#include "cli_single_queue.h"
#include "cpa_drop_policy.h"
#include "cpa_unwinder.h"
#include <stdatomic.h>
#include "uthash.h"
#include <asm/ptrace.h>
#include "cpa_nobpf_unwinder_event.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__CPA_BPF_ARCH_arm64)
#define pt_regs user_pt_regs
#endif

struct perf_capture_config {
	unsigned int freq;
	/* pid/tid in the pid namespace of cpa; 0 captures every task */
	unsigned int pid;
	/* weight of one on-CPU sample: 1 sample, or 1e6/freq us with off-CPU */
	unsigned long oncpu_count;
	/* one off-CPU stack per this many context switches; 0 disables */
	unsigned int offcpu_period;
	unsigned int offcpu_stack_size;
	int cgroup_fd;
	/* id of the scoped cgroup, reported as the cgroup of every sample */
	unsigned long cgid;
	bool kernel_only;
	/* thread comm to keep, truncated like the kernel comm; empty keeps all */
	char comm[TASK_COMM_LEN];
	/* --probe resolved to a perf event; probe_type 0 means no probe */
	unsigned int probe_type;
	unsigned long long probe_config;
	char probe_func[256];
};

enum cpa_capture_state { STACK_PROCESS_STATE_INIT = 0, STACK_PROCESS_STATE_PAUSE, STACK_PROCESS_STATE_RUNNING, STACK_PROCESS_STATE_EXIT };
static atomic_int capture_state;

static struct perf_capture_config perf_capture_config = { .cgroup_fd = -1 };

struct perf_stack_capture_ctx *perf_ctx = NULL;

static struct stack_sample *perf_stack_sample_build(struct perf_stack_event *event, bool drop_dwarf)
{
	struct stack_sample *sample = (struct stack_sample *)malloc(sizeof(struct gu_stack_info) + event->ustack_raw_sz + sizeof(struct pt_regs) + sizeof(struct stack_sample));
	if (!sample) {
		CLI_ERROR("malloc stack failed!");
		return sample;
	}

	sample->timestamp = event->time;
	sample->cgid = perf_capture_config.cgid ? perf_capture_config.cgid : event->cgid;
	sample->cpu = event->cpu;
	sample->type = 0;
	sample->user_mode = true;
	sample->pid = event->pid;
	sample->stack_count = perf_capture_config.oncpu_count;
	sample->state = 0;
	if (perf_capture_config.kernel_only)
		sample->type |= STACK_EVENT_KERNEL_ONLY;

	memset(sample->group_comm, 0, sizeof(sample->group_comm));
	memset(sample->comm, 0, sizeof(sample->comm));

	get_pid_comm_auto_retire(event->pid, sample->group_comm);
	get_pid_comm_direct(event->tid, sample->comm);

	if (event->pid == 0 || sample->comm[0] == '[')
		sample->type |= STACK_EVENT_KTHREAD;
	if (sample->type & STACK_EVENT_KTHREAD)
		sample->user_mode = false;

	sample->kstack_fp_level = event->kstack_sz;
	memcpy(sample->kstack_fp, event->kstack, event->kstack_sz * sizeof(uint64_t));

	struct gu_stack_info *stack = (struct gu_stack_info *)(sample + 1);
	sample->info = stack;

	stack->pid = sample->pid;
	stack->unique_id = 0;
	stack->flags = 0;
	stack->stack_data = (uint8_t *)(stack + 1);

	if (drop_dwarf) {
		sample->info->ustack_fp_level = 0;
		sample->info->stack_size = 0;
		if (!(sample->type & STACK_EVENT_KTHREAD))
			sample->type |= STACK_EVENT_DROP_BY_PRESSURE;
		return sample;
	}

	sample->info->ustack_fp_level = event->ustack_sz;
	memcpy(sample->info->ustack_fp, event->ustack, event->ustack_sz * sizeof(uint64_t));

	sample->info->stack_size = event->ustack_raw_sz;
	memcpy(sample->info->stack_data, event->ustack_raw, event->ustack_raw_sz);

	struct pt_regs *regs = (struct pt_regs *)&(sample->info->stack_data[sample->info->stack_size]);
	memset(regs, 0, sizeof(struct pt_regs));

#if defined(__CPA_BPF_ARCH_arm64)
	regs->regs[29] = event->rbp;
	regs->regs[30] = event->lr;
	regs->pc = event->rip;
	regs->sp = event->rsp;
#else
	regs->rsp = event->rsp;
	regs->rip = event->rip;
	regs->rbp = event->rbp;
#endif

	sample->info->regs = regs;
	sample->info->regs_size = sizeof(struct pt_regs);

	return sample;
}

/*
 * Comm match results per thread. Switch records arrive far too often to read
 * /proc/<tid>/comm each time, so results are cached and rechecked
 * periodically because threads may rename themselves.
 */
struct comm_match_entry {
	unsigned int tid;
	bool matched;
	uint64_t checked_ts;
	UT_hash_handle hh;
};

#define COMM_MATCH_RECHECK_NS (10ULL * 1000 * 1000 * 1000)
#define COMM_MATCH_CACHE_MAX 65536

static struct comm_match_entry *comm_match_cache;

static void comm_match_cache_destroy(void)
{
	struct comm_match_entry *e, *tmp;

	HASH_ITER (hh, comm_match_cache, e, tmp) {
		HASH_DEL(comm_match_cache, e);
		free(e);
	}
}

/* Same rule as the bpf backend: the thread comm must equal --comm. */
static bool perf_capture_comm_match(unsigned int tid, uint64_t now)
{
	struct comm_match_entry *e = NULL;
	char comm[TASK_COMM_LEN] = { 0 };

	if (!perf_capture_config.comm[0])
		return true;

	HASH_FIND_INT(comm_match_cache, &tid, e);
	if (e && now - e->checked_ts < COMM_MATCH_RECHECK_NS)
		return e->matched;

	if (!e) {
		/* Host-wide sampling sees short-lived tids; keep the cache bounded. */
		if (HASH_COUNT(comm_match_cache) >= COMM_MATCH_CACHE_MAX)
			comm_match_cache_destroy();
		e = calloc(1, sizeof(*e));
		if (!e)
			return false;
		e->tid = tid;
		HASH_ADD_INT(comm_match_cache, tid, e);
	}
	e->matched = get_pid_comm_direct(tid, comm) == 0 && strcmp(comm, perf_capture_config.comm) == 0;
	e->checked_ts = now;

	return e->matched;
}

static bool perf_capture_pid_match(unsigned int pid, unsigned int tid)
{
	return !perf_capture_config.pid || pid == perf_capture_config.pid || tid == perf_capture_config.pid;
}

static bool perf_capture_task_match(unsigned int pid, unsigned int tid, uint64_t now)
{
	return perf_capture_pid_match(pid, tid) && perf_capture_comm_match(tid, now);
}

/*
 * Per-thread off-CPU pairing state, only touched by the perf poll thread.
 * A sampled stack waits in @pending until its switch-out record arrives and
 * in @armed until the matching switch-in closes the interval. Switch records
 * of one thread can sit in different per-cpu buffers after a migration, so a
 * switch-in may be read before its switch-out; @early_in_ts keeps it.
 */
struct offcpu_thread {
	unsigned int tid;
	uint64_t out_ts;
	uint64_t early_in_ts;
	uint64_t last_seen;
	bool preempt;
	struct stack_sample *pending;
	struct stack_sample *armed;
	UT_hash_handle hh;
};

#define OFFCPU_SAMPLE_MATCH_NS (1000ULL * 1000)
#define OFFCPU_EARLY_IN_MAX_NS (10ULL * 1000 * 1000 * 1000)
#define OFFCPU_PURGE_INTERVAL_NS (10ULL * 1000 * 1000 * 1000)
#define OFFCPU_STALE_NS (30ULL * 1000 * 1000 * 1000)

static struct offcpu_thread *offcpu_threads;
static uint64_t offcpu_last_purge;

static void offcpu_thread_release(struct offcpu_thread *t)
{
	free(t->pending);
	free(t->armed);
	t->pending = NULL;
	t->armed = NULL;
}

static void offcpu_threads_destroy(void)
{
	struct offcpu_thread *t, *tmp;

	HASH_ITER (hh, offcpu_threads, t, tmp) {
		HASH_DEL(offcpu_threads, t);
		offcpu_thread_release(t);
		free(t);
	}
	offcpu_last_purge = 0;
}

/* Drop threads that stopped switching, typically because they exited. */
static void offcpu_threads_purge(uint64_t now)
{
	struct offcpu_thread *t, *tmp;

	if (now - offcpu_last_purge < OFFCPU_PURGE_INTERVAL_NS)
		return;
	offcpu_last_purge = now;

	HASH_ITER (hh, offcpu_threads, t, tmp) {
		if (now - t->last_seen < OFFCPU_STALE_NS)
			continue;
		HASH_DEL(offcpu_threads, t);
		offcpu_thread_release(t);
		free(t);
	}
}

static struct offcpu_thread *offcpu_thread_get(unsigned int tid, uint64_t now)
{
	struct offcpu_thread *t = NULL;

	HASH_FIND_INT(offcpu_threads, &tid, t);
	if (!t) {
		t = calloc(1, sizeof(*t));
		if (!t)
			return NULL;
		t->tid = tid;
		HASH_ADD_INT(offcpu_threads, tid, t);
	}
	t->last_seen = now;

	return t;
}

/* Weight the sampled interval by its duration times the sampling period. */
static void offcpu_thread_close(struct offcpu_thread *t, uint64_t in_ts)
{
	struct stack_sample *sample = t->armed;
	uint64_t off_us = (in_ts - t->out_ts) / 1000;

	t->armed = NULL;
	t->out_ts = 0;

	sample->type |= STACK_EVENT_OFFCPU;
	sample->state = t->preempt ? 'R' : 'S';
	sample->stack_count = (off_us ? off_us : 1) * perf_capture_config.offcpu_period;

	if (cpa_add_stack_event(sample))
		free(sample);
}

static void perf_offcpu_handler(struct perf_stack_event *event, void *data)
{
	if (atomic_load_explicit(&capture_state, memory_order_acquire) != STACK_PROCESS_STATE_RUNNING)
		return;
	if (event->pid == 0 || !perf_capture_task_match(event->pid, event->tid, event->time))
		return;

	struct offcpu_thread *t = offcpu_thread_get(event->tid, event->time);
	if (!t)
		return;

	enum drop_sample_result drop_state = should_drop_sample();

	free(t->pending);
	t->pending = perf_stack_sample_build(event, drop_state != DROP_SAMPLE_RESULT_PASS);
}

static void perf_switch_handler(const struct perf_switch_event *event, void *data)
{
	if (atomic_load_explicit(&capture_state, memory_order_acquire) != STACK_PROCESS_STATE_RUNNING)
		return;

	offcpu_threads_purge(event->time);

	if (event->pid == 0 || !perf_capture_task_match(event->pid, event->tid, event->time))
		return;

	struct offcpu_thread *t = offcpu_thread_get(event->tid, event->time);
	if (!t)
		return;

	if (!event->out) {
		if (t->armed && event->time >= t->out_ts)
			offcpu_thread_close(t, event->time);
		else
			t->early_in_ts = event->time;
		return;
	}

	/* Only intervals that start with a sampled stack are measured. */
	free(t->armed);
	t->armed = NULL;
	if (t->pending && event->time >= t->pending->timestamp && event->time - t->pending->timestamp < OFFCPU_SAMPLE_MATCH_NS)
		t->armed = t->pending;
	else
		free(t->pending);
	t->pending = NULL;

	if (!t->armed)
		return;

	t->out_ts = event->time;
	t->preempt = event->preempt;
	if (t->early_in_ts > t->out_ts && t->early_in_ts - t->out_ts < OFFCPU_EARLY_IN_MAX_NS)
		offcpu_thread_close(t, t->early_in_ts);
	t->early_in_ts = 0;
}

/*
 * Resolve the perf_event cgroup directory to scope events to. "auto" maps
 * the cgroup of the target pid (cpa itself when pid is 0) through the cgroup
 * mount, which inside a container is usually the container cgroup
 * bind-mounted as the root.
 */
static int perf_cgroup_resolve_auto(int pid, char *dir, size_t dir_sz)
{
	char line[4096], cg_path[PATH_MAX] = { 0 }, cg_file[64];
	char mnt_root[PATH_MAX] = { 0 }, mnt_point[PATH_MAX] = { 0 };
	bool v1 = false;
	FILE *fp;

	fp = fopen("/proc/self/mountinfo", "r");
	if (!fp)
		return -errno;
	while (fgets(line, sizeof(line), fp)) {
		char root[PATH_MAX], point[PATH_MAX], fstype[64], super_opts[1024];
		char *sep = strstr(line, " - ");

		if (!sep || sscanf(line, "%*s %*s %*s %4095s %4095s", root, point) != 2)
			continue;
		if (sscanf(sep + 3, "%63s %*s %1023s", fstype, super_opts) != 2)
			continue;
		if (strcmp(fstype, "cgroup") == 0 && strstr(super_opts, "perf_event")) {
			snprintf(mnt_root, sizeof(mnt_root), "%s", root);
			snprintf(mnt_point, sizeof(mnt_point), "%s", point);
			v1 = true;
			break;
		}
		if (strcmp(fstype, "cgroup2") == 0 && !mnt_point[0]) {
			snprintf(mnt_root, sizeof(mnt_root), "%s", root);
			snprintf(mnt_point, sizeof(mnt_point), "%s", point);
		}
	}
	fclose(fp);
	if (!mnt_point[0])
		return -ENOENT;

	if (pid > 0)
		snprintf(cg_file, sizeof(cg_file), "/proc/%d/cgroup", pid);
	else
		snprintf(cg_file, sizeof(cg_file), "/proc/self/cgroup");
	fp = fopen(cg_file, "r");
	if (!fp)
		return -errno;
	while (fgets(line, sizeof(line), fp)) {
		char *controllers = strchr(line, ':');
		char *path = controllers ? strchr(controllers + 1, ':') : NULL;

		if (!path)
			continue;
		*path++ = '\0';
		controllers++;
		if ((v1 && strstr(controllers, "perf_event")) || (!v1 && controllers[0] == '\0')) {
			path[strcspn(path, "\n")] = '\0';
			snprintf(cg_path, sizeof(cg_path), "%s", path);
			break;
		}
	}
	fclose(fp);
	if (!cg_path[0])
		return -ENOENT;

	const char *rel = cg_path;
	size_t root_len = strlen(mnt_root);
	if (strcmp(mnt_root, "/") != 0 && strncmp(cg_path, mnt_root, root_len) == 0)
		rel = cg_path + root_len;
	if (strcmp(rel, "/") == 0)
		rel = "";

	snprintf(dir, dir_sz, "%s%s", mnt_point, rel);
	return 0;
}

static int perf_cgroup_open(const char *spec, int pid)
{
	char dir[PATH_MAX];
	int fd;

	if (strcmp(spec, "auto") == 0) {
		int ret = perf_cgroup_resolve_auto(pid, dir, sizeof(dir));

		if (ret) {
			CLI_ERROR("Failed to resolve perf_event cgroup of %s: %s", pid > 0 ? "pid" : "cpa", strerror(-ret));
			return -1;
		}
	} else {
		snprintf(dir, sizeof(dir), "%s", spec);
	}

	fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0) {
		CLI_ERROR("Failed to open perf_event cgroup %s: %s", dir, strerror(errno));
		return -1;
	}
	CLI_OUTPUT("perf backend scoped to cgroup %s", dir);

	return fd;
}

static int perf_read_sysfs_line(const char *path, char *buf, size_t buf_sz)
{
	FILE *fp = fopen(path, "r");

	if (!fp)
		return -errno;
	if (!fgets(buf, buf_sz, fp)) {
		fclose(fp);
		return -EIO;
	}
	fclose(fp);
	buf[strcspn(buf, "\n")] = '\0';

	return 0;
}

static int perf_probe_resolve_tracepoint(const char *group, const char *name)
{
	const char *bases[] = { "/sys/kernel/tracing/events", "/sys/kernel/debug/tracing/events" };
	char path[PATH_MAX], buf[64];

	for (size_t i = 0; i < sizeof(bases) / sizeof(bases[0]); i++) {
		snprintf(path, sizeof(path), "%s/%s/%s/id", bases[i], group, name);
		if (perf_read_sysfs_line(path, buf, sizeof(buf)) == 0) {
			perf_capture_config.probe_type = PERF_TYPE_TRACEPOINT;
			perf_capture_config.probe_config = strtoull(buf, NULL, 10);
			return 0;
		}
	}

	CLI_ERROR("Failed to find tracepoint %s:%s; is tracefs mounted at /sys/kernel/tracing?", group, name);
	return -ENOENT;
}

/* kprobe PMU (4.17+): type and retprobe bit come from sysfs. */
static int perf_probe_resolve_kprobe(const char *func, bool retprobe)
{
	char buf[64];
	int bit = 0;

	if (perf_read_sysfs_line("/sys/bus/event_source/devices/kprobe/type", buf, sizeof(buf))) {
		CLI_ERROR("kprobe PMU is not available, cannot attach perf kprobe %s", func);
		return -ENOENT;
	}
	perf_capture_config.probe_type = strtoul(buf, NULL, 10);
	perf_capture_config.probe_config = 0;

	if (retprobe) {
		if (perf_read_sysfs_line("/sys/bus/event_source/devices/kprobe/format/retprobe", buf, sizeof(buf)) || sscanf(buf, "config:%d", &bit) != 1) {
			CLI_ERROR("kprobe PMU does not support kretprobe");
			return -ENOENT;
		}
		perf_capture_config.probe_config = 1ULL << bit;
	}
	snprintf(perf_capture_config.probe_func, sizeof(perf_capture_config.probe_func), "%s", func);

	return 0;
}

/* Same syntax as the bpf backend: kprobe:F, kretprobe:F, tracepoint:G:N. */
static int perf_probe_resolve(const char *spec)
{
	char copy[256];
	char *saveptr = NULL;
	char *type, *target, *subtype;

	perf_capture_config.probe_type = 0;
	perf_capture_config.probe_config = 0;
	perf_capture_config.probe_func[0] = '\0';

	if (snprintf(copy, sizeof(copy), "%s", spec) >= (int)sizeof(copy)) {
		CLI_ERROR("probe specification is too long");
		return -ENAMETOOLONG;
	}

	type = strtok_r(copy, ":", &saveptr);
	target = strtok_r(NULL, ":", &saveptr);
	subtype = strtok_r(NULL, ":", &saveptr);

	if (type && target && (strcmp(type, "kprobe") == 0 || strcmp(type, "kretprobe") == 0))
		return perf_probe_resolve_kprobe(target, strcmp(type, "kretprobe") == 0);
	if (type && target && subtype && strcmp(type, "tracepoint") == 0)
		return perf_probe_resolve_tracepoint(target, subtype);

	CLI_ERROR("Invalid probe %s; use kprobe:<func>, kretprobe:<func> or tracepoint:<group>:<name>", spec);
	return -EINVAL;
}

/* The kernfs file handle of a cgroup directory is its cgroup id. */
static unsigned long perf_cgroup_id(int cgroup_fd)
{
	struct file_handle *handle = calloc(1, sizeof(*handle) + sizeof(unsigned long));
	unsigned long id = 0;
	int mount_id;

	if (!handle)
		return 0;

	handle->handle_bytes = sizeof(unsigned long);
	if (name_to_handle_at(cgroup_fd, "", handle, &mount_id, AT_EMPTY_PATH) == 0)
		memcpy(&id, handle->f_handle, sizeof(id));
	else
		CLI_ERROR("Failed to read perf_event cgroup id: %s", strerror(errno));

	free(handle);
	return id;
}

void perf_capture_handler(struct perf_stack_event *event, void *data)
{
	if (atomic_load_explicit(&capture_state, memory_order_acquire) != STACK_PROCESS_STATE_RUNNING)
		return;

	/*
	 * The kernel reports perf sample pid/tid in the pid namespace of the
	 * event opener, and as 0 for tasks outside it, so this filter works
	 * inside containers where BPF-side pid filtering would see host pids.
	 */
	if (!perf_capture_task_match(event->pid, event->tid, event->time))
		return;

	enum drop_sample_result drop_state = should_drop_sample();

	struct stack_sample *sample = perf_stack_sample_build(event, drop_state != DROP_SAMPLE_RESULT_PASS);

	if (!sample)
		return;

	int ret = cpa_add_stack_event(sample);

	if (ret)
		free(sample);
}

static enum cpa_worker_init_result cpa_perf_capture_init_fn(void *ctx, void *worker_ctx)
{
	const char *backend = get_arg_by_name(ctx, "backend");
	if (strncmp(backend, "perf", strlen("perf")) != 0)
		return CPA_INIT_SKIP;

	atomic_init(&capture_state, STACK_PROCESS_STATE_INIT);

	const char *probe = get_arg_by_name(ctx, "probe");
	bool probe_enabled = !cli_arg_is_null_default(probe);

	if (probe_enabled && atoi(get_arg_by_name(ctx, "offcpu"))) {
		CLI_ERROR("--probe cannot be combined with --offcpu");
		return CPA_INIT_FAILED;
	}
	if (probe_enabled && perf_probe_resolve(probe) < 0)
		return CPA_INIT_FAILED;
	if (!probe_enabled)
		perf_capture_config.probe_type = 0;

	perf_capture_config.freq = atoi(get_arg_by_name(ctx, "freq"));
	if (perf_capture_config.freq > 99 || perf_capture_config.freq < 9) {
		CLI_ERROR("Please use frequency in range [9, 99]");
		return CPA_INIT_FAILED;
	}

	int pid = atoi(get_arg_by_name(ctx, "pid"));
	if (pid < 0) {
		CLI_ERROR("Please use pid >= 0");
		return CPA_INIT_FAILED;
	}
	perf_capture_config.pid = pid;

	/* Same rule as the bpf backend, clamped to the perf dump limit. */
	int stack_size = atoi(get_arg_by_name(ctx, "stack_size"));
	if (stack_size < 4096 || stack_size > 65536 || stack_size % 4096 != 0) {
		CLI_ERROR("Please use stack_size >= 4096 && <= 65536 && align to 4096");
		return CPA_INIT_FAILED;
	}
	if (stack_size > MAX_USER_STACK_DUMP_SIZE)
		stack_size = MAX_USER_STACK_DUMP_SIZE;

	perf_capture_config.kernel_only = atoi(get_arg_by_name(ctx, "kernel_stack")) != 0;

	const char *comm = get_arg_by_name(ctx, "comm");
	memset(perf_capture_config.comm, 0, sizeof(perf_capture_config.comm));
	if (!cli_arg_is_null_default(comm))
		snprintf(perf_capture_config.comm, sizeof(perf_capture_config.comm), "%s", comm);
	comm_match_cache_destroy();

	/* --offcpu alone collects off-CPU only; with --oncpu both go into one store. */
	bool offcpu = atoi(get_arg_by_name(ctx, "offcpu")) != 0;
	bool oncpu = !offcpu || atoi(get_arg_by_name(ctx, "oncpu")) != 0;
	int offcpu_period = atoi(get_arg_by_name(ctx, "offcpu_period"));
	int offcpu_stack_size = atoi(get_arg_by_name(ctx, "offcpu_stack_size"));
	if (offcpu && offcpu_period <= 0) {
		CLI_ERROR("Please use offcpu_period > 0");
		return CPA_INIT_FAILED;
	}
	/* The kernel needs a u64-aligned dump size below 64KiB. */
	if (offcpu && (offcpu_stack_size <= 0 || offcpu_stack_size % 8 || offcpu_stack_size > MAX_USER_STACK_DUMP_SIZE)) {
		CLI_ERROR("Please use offcpu_stack_size as a multiple of 8 in (0, %d]", MAX_USER_STACK_DUMP_SIZE);
		return CPA_INIT_FAILED;
	}
	perf_capture_config.offcpu_period = offcpu ? offcpu_period : 0;
	perf_capture_config.offcpu_stack_size = offcpu_stack_size;
	/* Off-CPU stores count microseconds so on- and off-CPU weights add up. */
	perf_capture_config.oncpu_count = offcpu ? 1000000UL / perf_capture_config.freq : 1;

	/*
	 * Off-CPU needs cgroup scoping: host-wide switch records are too many.
	 * With --pid, scoping to the target's cgroup keeps the kernel from
	 * sampling (and copying stacks of) tasks we would drop anyway; on-CPU
	 * falls back to host-wide sampling if that cgroup cannot be used.
	 */
	const char *cgroup_spec = get_arg_by_name(ctx, "perf_cgroup");
	bool cgroup_implicit = cli_arg_is_null_default(cgroup_spec);
	if (cgroup_implicit)
		cgroup_spec = (offcpu || pid > 0) ? "auto" : NULL;
	bool cgroup_optional = cgroup_implicit && !offcpu;

	if (perf_capture_config.cgroup_fd >= 0) {
		close(perf_capture_config.cgroup_fd);
		perf_capture_config.cgroup_fd = -1;
	}
	perf_capture_config.cgid = 0;
	if (cgroup_spec) {
		perf_capture_config.cgroup_fd = perf_cgroup_open(cgroup_spec, pid);
		if (perf_capture_config.cgroup_fd >= 0)
			perf_capture_config.cgid = perf_cgroup_id(perf_capture_config.cgroup_fd);
		else if (cgroup_optional)
			CLI_OUTPUT("perf backend falls back to host-wide sampling");
		else
			return CPA_INIT_FAILED;
	}

	if (perf_ctx) {
		perf_stack_capture_cleanup(perf_ctx);
		perf_ctx = NULL;
	}
	offcpu_threads_destroy();

	struct perf_stack_capture_opts opts = {
		.sample_freq = perf_capture_config.freq,
		.cgroup_fd = perf_capture_config.cgroup_fd,
		.oncpu = oncpu,
		.stack_size = stack_size,
		.kernel_only = perf_capture_config.kernel_only,
		.probe_type = perf_capture_config.probe_type,
		.probe_config = perf_capture_config.probe_config,
		.probe_func = perf_capture_config.probe_func[0] ? perf_capture_config.probe_func : NULL,
		.handler = perf_capture_handler,
		.offcpu_period = perf_capture_config.offcpu_period,
		.offcpu_stack_size = perf_capture_config.offcpu_stack_size,
		.offcpu_handler = perf_offcpu_handler,
		.switch_handler = perf_switch_handler,
	};

	perf_ctx = perf_setup_stack_capture(&opts);
	if (!perf_ctx && cgroup_optional && perf_capture_config.cgroup_fd >= 0) {
		CLI_OUTPUT("perf backend falls back to host-wide sampling");
		close(perf_capture_config.cgroup_fd);
		perf_capture_config.cgroup_fd = -1;
		perf_capture_config.cgid = 0;
		opts.cgroup_fd = -1;
		perf_ctx = perf_setup_stack_capture(&opts);
	}
	if (!perf_ctx) {
		CLI_ERROR("Failed to setup stack capture event");
		return CPA_INIT_FAILED;
	}

	atomic_store_explicit(&capture_state, STACK_PROCESS_STATE_RUNNING, memory_order_release);

	return CPA_INIT_SUCCESS;
}

static void cpa_perf_capture_destroy_fn(void *worker_ctx)
{
	atomic_store_explicit(&capture_state, STACK_PROCESS_STATE_EXIT, memory_order_release);

	if (perf_ctx) {
		perf_stack_capture_cleanup(perf_ctx);
		perf_ctx = NULL;
	}
	offcpu_threads_destroy();
	comm_match_cache_destroy();
	if (perf_capture_config.cgroup_fd >= 0) {
		close(perf_capture_config.cgroup_fd);
		perf_capture_config.cgroup_fd = -1;
	}
}

static void cpa_perf_capture_pause_fn(void *worker_ctx)
{
	atomic_store_explicit(&capture_state, STACK_PROCESS_STATE_PAUSE, memory_order_release);
}

static void cpa_perf_capture_restore_fn(void *worker_ctx)
{
	atomic_store_explicit(&capture_state, STACK_PROCESS_STATE_RUNNING, memory_order_release);
}

struct cpa_worker perf_capture_worker = {
	.worker_name = "perf_capture_worker",
	.worker_ctx = NULL,
	.worker_index = 10,

	.init_fn = cpa_perf_capture_init_fn,
	.destroy_fn = cpa_perf_capture_destroy_fn,
	.pause_fn = cpa_perf_capture_pause_fn,
	.restore_fn = cpa_perf_capture_restore_fn,
	.timer_fn = NULL,
	.main_worker_fn = NULL,
};

void cpa_perf_capture_get_stats(struct cpa_capture_stats *stat)
{
	struct perf_stack_capture_stats perf_stat = { 0 };

	if (!stat)
		return;

	memset(stat, 0, sizeof(*stat));
	perf_stack_capture_get_stats(perf_ctx, &perf_stat);
	stat->lost_events = perf_stat.lost_events;
}
