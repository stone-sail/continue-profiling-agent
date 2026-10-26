// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/*
 * perf_stat worker: perf stat style counters next to the sampled stacks.
 *
 * Every event is opened as a counting (non-sampling) event on each CPU,
 * scoped to the same perf_event cgroup as perf sampling. Each timer tick
 * reads the per-CPU deltas, scales them by time_enabled / time_running when
 * the PMU multiplexes, and appends one line to <store>/perf_stat:
 *
 *   # record_ms <event> <event> ...
 *   <record_ms> <count> <count> ...
 *
 * record_ms uses the stack.bin record clock, so cpa show can select the same
 * time range for both. One-shot runs print a summary on exit instead.
 */

#include "cpa_runtime.h"
#include "cpa_perf_event.h"
#include "cpa_stackmap_continuous.h"
#include "cli.h"
#include <errno.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#define PERF_STAT_MAX_EVENTS 16
#define PERF_STAT_DEFAULT_EVENTS "cycles,instructions,branches,branch-misses,LLC-loads,LLC-load-misses"

struct perf_stat_read {
	uint64_t value;
	uint64_t enabled;
	uint64_t running;
};

struct perf_stat_event {
	char name[64];
	struct cpa_perf_event ev;
	int *fds;
	struct perf_stat_read *prev;
	double total;
};

static struct {
	struct perf_stat_event events[PERF_STAT_MAX_EVENTS];
	int nr_events;
	int nr_cpus;
	int cgroup_fd;
	bool oneshot;
	uint64_t start_ms;
	FILE *fp;
	char *path;
} perf_stat = { .cgroup_fd = -1 };

static int perf_stat_open_counter(const struct cpa_perf_event *ev, int cpu, int cgroup_fd)
{
	struct perf_event_attr attr = {
		.type = ev->type,
		.size = sizeof(struct perf_event_attr),
		.config = ev->config,
		.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING,
		/* Only cpu-clock counts the idle task; other PMUs may reject the bit. */
		.exclude_idle = ev->type == PERF_TYPE_SOFTWARE,
	};
	unsigned long flags = cgroup_fd >= 0 ? PERF_FLAG_PID_CGROUP : 0;

	return syscall(__NR_perf_event_open, &attr, cgroup_fd >= 0 ? cgroup_fd : -1, cpu, -1, flags);
}

static void perf_stat_close_event(struct perf_stat_event *e)
{
	if (e->fds) {
		for (int cpu = 0; cpu < perf_stat.nr_cpus; cpu++) {
			if (e->fds[cpu] >= 0)
				close(e->fds[cpu]);
		}
	}
	free(e->fds);
	free(e->prev);
	e->fds = NULL;
	e->prev = NULL;
}

static int perf_stat_open_event(struct perf_stat_event *e)
{
	e->fds = malloc(perf_stat.nr_cpus * sizeof(int));
	e->prev = calloc(perf_stat.nr_cpus, sizeof(struct perf_stat_read));
	if (!e->fds || !e->prev) {
		perf_stat_close_event(e);
		return -ENOMEM;
	}
	for (int cpu = 0; cpu < perf_stat.nr_cpus; cpu++)
		e->fds[cpu] = -1;

	for (int cpu = 0; cpu < perf_stat.nr_cpus; cpu++) {
		e->fds[cpu] = perf_stat_open_counter(&e->ev, cpu, perf_stat.cgroup_fd);
		if (e->fds[cpu] < 0) {
			int err = -errno;

			perf_stat_close_event(e);
			return err;
		}
	}

	return 0;
}

/* A cpu-clock counter tells whether the cgroup scope itself is usable. */
static bool perf_stat_cgroup_usable(int cgroup_fd)
{
	struct cpa_perf_event clock = { PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK };
	int fd = perf_stat_open_counter(&clock, 0, cgroup_fd);

	if (fd < 0)
		return false;
	close(fd);
	return true;
}

static int perf_stat_setup_cgroup(void *ctx, int pid)
{
	const char *spec = get_arg_by_name(ctx, "perf_cgroup");
	bool implicit = cli_arg_is_null_default(spec);

	/* Same scope as perf sampling: the --pid cgroup unless told otherwise. */
	if (implicit)
		spec = pid > 0 ? "auto" : NULL;
	if (!spec)
		return 0;

	perf_stat.cgroup_fd = cpa_perf_cgroup_open(spec, pid);
	if (perf_stat.cgroup_fd >= 0 && !perf_stat_cgroup_usable(perf_stat.cgroup_fd)) {
		CLI_ERROR("perf_stat: perf_event cgroup scoping is not supported: %s", strerror(errno));
		close(perf_stat.cgroup_fd);
		perf_stat.cgroup_fd = -1;
	}
	if (perf_stat.cgroup_fd >= 0)
		return 0;
	if (!implicit)
		return -1;

	CLI_OUTPUT("perf_stat falls back to host-wide counting");
	return 0;
}

static int perf_stat_parse_events(const char *spec)
{
	char copy[1024];
	char *saveptr = NULL;

	if (strcmp(spec, "default") == 0)
		spec = PERF_STAT_DEFAULT_EVENTS;
	if (snprintf(copy, sizeof(copy), "%s", spec) >= (int)sizeof(copy)) {
		CLI_ERROR("perf_stat event list is too long");
		return -1;
	}

	for (char *name = strtok_r(copy, ",", &saveptr); name; name = strtok_r(NULL, ",", &saveptr)) {
		struct perf_stat_event *e;

		if (!name[0])
			continue;
		if (perf_stat.nr_events >= PERF_STAT_MAX_EVENTS) {
			CLI_ERROR("perf_stat supports at most %d events", PERF_STAT_MAX_EVENTS);
			return -1;
		}
		e = &perf_stat.events[perf_stat.nr_events];
		memset(e, 0, sizeof(*e));
		if (cpa_perf_event_parse(name, &e->ev) < 0) {
			CLI_ERROR("Unknown perf_stat event %s; use perf list names such as cycles, instructions, LLC-load-misses, or r<hex>", name);
			return -1;
		}
		snprintf(e->name, sizeof(e->name), "%s", name);
		perf_stat.nr_events++;
	}

	if (!perf_stat.nr_events) {
		CLI_ERROR("perf_stat needs at least one event");
		return -1;
	}
	return 0;
}

/* Unsupported events are dropped with a warning, like perf stat's <not supported>. */
static int perf_stat_open_events(void)
{
	int kept = 0;

	for (int i = 0; i < perf_stat.nr_events; i++) {
		struct perf_stat_event *e = &perf_stat.events[i];
		int ret = perf_stat_open_event(e);

		if (ret < 0) {
			CLI_ERROR("perf_stat: event %s is not supported here: %s", e->name, strerror(-ret));
			continue;
		}
		if (kept != i)
			perf_stat.events[kept] = *e;
		kept++;
	}
	perf_stat.nr_events = kept;

	if (!kept) {
		CLI_ERROR("perf_stat: none of the events could be opened");
		return -1;
	}
	return 0;
}

static void perf_stat_cleanup(void)
{
	for (int i = 0; i < perf_stat.nr_events; i++)
		perf_stat_close_event(&perf_stat.events[i]);
	perf_stat.nr_events = 0;
	if (perf_stat.cgroup_fd >= 0)
		close(perf_stat.cgroup_fd);
	perf_stat.cgroup_fd = -1;
	if (perf_stat.fp)
		fclose(perf_stat.fp);
	perf_stat.fp = NULL;
	free(perf_stat.path);
	perf_stat.path = NULL;
}

static enum cpa_worker_init_result cpa_perf_stat_init_fn(void *ctx, void *worker_ctx)
{
	const char *spec = get_arg_by_name(ctx, "perf_stat");

	if (cli_arg_is_null_default(spec))
		return CPA_INIT_SKIP;

	perf_stat_cleanup();
	perf_stat.nr_cpus = get_nprocs();
	perf_stat.oneshot = atoi(get_arg_by_name(ctx, "oneshot")) != 0;
	perf_stat.start_ms = get_current_ms();

	if (perf_stat_parse_events(spec) < 0)
		goto fail;
	if (perf_stat_setup_cgroup(ctx, atoi(get_arg_by_name(ctx, "pid"))) < 0)
		goto fail;
	if (perf_stat_open_events() < 0)
		goto fail;

	CLI_OUTPUT("perf_stat counting %d events on %d cpus%s", perf_stat.nr_events, perf_stat.nr_cpus, perf_stat.cgroup_fd >= 0 ? " in cgroup" : "");
	return CPA_INIT_SUCCESS;
fail:
	perf_stat_cleanup();
	return CPA_INIT_FAILED;
}

/* Scaled count of one event since the previous call, summed over CPUs. */
static double perf_stat_read_delta(struct perf_stat_event *e)
{
	double sum = 0;

	for (int cpu = 0; cpu < perf_stat.nr_cpus; cpu++) {
		struct perf_stat_read cur, *prev = &e->prev[cpu];
		uint64_t value, enabled, running;

		if (read(e->fds[cpu], &cur, sizeof(cur)) != sizeof(cur))
			continue;
		value = cur.value - prev->value;
		enabled = cur.enabled - prev->enabled;
		running = cur.running - prev->running;
		*prev = cur;

		if (running && running < enabled)
			sum += (double)value * enabled / running;
		else
			sum += value;
	}

	return sum;
}

/* Follow the continuous store across rotations; reopen when the directory moves. */
static FILE *perf_stat_output(void)
{
	struct dir_info *dir = cpa_get_stackmap_save_dir();
	char *path;

	if (!dir || !dir->store_dir)
		return NULL;
	path = path_join(dir->store_dir, "perf_stat");
	if (!path)
		return NULL;
	if (perf_stat.path && strcmp(path, perf_stat.path) == 0) {
		free(path);
		return perf_stat.fp;
	}

	if (perf_stat.fp)
		fclose(perf_stat.fp);
	free(perf_stat.path);
	perf_stat.path = path;
	perf_stat.fp = fopen(path, "a");
	if (!perf_stat.fp) {
		CLI_ERROR("perf_stat: failed to open %s: %s", path, strerror(errno));
		return NULL;
	}
	/* A restarted cpa appends to the same store; write the header once. */
	if (fseek(perf_stat.fp, 0, SEEK_END) == 0 && ftell(perf_stat.fp) == 0) {
		fprintf(perf_stat.fp, "# record_ms");
		for (int i = 0; i < perf_stat.nr_events; i++)
			fprintf(perf_stat.fp, " %s", perf_stat.events[i].name);
		fprintf(perf_stat.fp, "\n");
	}
	return perf_stat.fp;
}

static void perf_stat_tick(void)
{
	double delta[PERF_STAT_MAX_EVENTS];
	struct cli_stackmap *map;
	uint64_t record_ms;
	FILE *fp;

	for (int i = 0; i < perf_stat.nr_events; i++) {
		delta[i] = perf_stat_read_delta(&perf_stat.events[i]);
		perf_stat.events[i].total += delta[i];
	}

	if (perf_stat.oneshot)
		return;
	fp = perf_stat_output();
	if (!fp)
		return;

	map = cpa_main_tracemap_get_and_lock();
	record_ms = cli_stackmap_now_record_ms(map);
	cpa_main_tracemap_unlock();

	fprintf(fp, "%lu", (unsigned long)record_ms);
	for (int i = 0; i < perf_stat.nr_events; i++)
		fprintf(fp, " %.0f", delta[i]);
	fprintf(fp, "\n");
	fflush(fp);
}

static void cpa_perf_stat_timer_fn(void *worker_ctx)
{
	perf_stat_tick();
}

static void cpa_perf_stat_destroy_fn(void *worker_ctx)
{
	if (!perf_stat.nr_events)
		return;

	perf_stat_tick();
	if (perf_stat.oneshot) {
		const char *names[PERF_STAT_MAX_EVENTS];
		double totals[PERF_STAT_MAX_EVENTS];

		for (int i = 0; i < perf_stat.nr_events; i++) {
			names[i] = perf_stat.events[i].name;
			totals[i] = perf_stat.events[i].total;
		}
		cpa_perf_stat_print(names, totals, perf_stat.nr_events, (get_current_ms() - perf_stat.start_ms) / 1000.0);
	}
	perf_stat_cleanup();
}

struct cpa_worker perf_stat_worker = {
	.worker_name = "perf_stat_worker",
	.worker_ctx = NULL,
	.worker_index = 11,

	.init_fn = cpa_perf_stat_init_fn,
	.destroy_fn = cpa_perf_stat_destroy_fn,
	.pause_fn = NULL,
	.restore_fn = NULL,
	.timer_fn = cpa_perf_stat_timer_fn,
	.main_worker_fn = NULL,
};
