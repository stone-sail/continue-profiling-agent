// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include <cpa_bpf/perf_stack_capture.h>

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <linux/perf_event.h>

#ifndef hweight64
#define hweight64(w) __builtin_popcountll(w)
#endif

#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <syscall.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <asm/perf_regs.h>
#include <sys/epoll.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <linux/ring_buffer.h>

#include "core.h"

struct perf_stack_capture_ctx {
	int mmap_page_cnt;
	size_t mmap_size;
	int perf_cpu_num;
	perf_event_handler_fn handler;
	perf_event_handler_fn offcpu_handler;
	perf_switch_handler_fn switch_handler;
	void *handler_data;
	int *pmu_fds;
	void **mmap_bufs;
	/* off-CPU context switch events; NULL when off-CPU is disabled */
	int *off_fds;
	void **off_mmap_bufs;
	atomic_bool stop_thread;
	pthread_t poll_thread;
	int epoll_fd;
	struct epoll_event *epoll_events;
	int sleep_us;
	atomic_ullong lost_events;
};

static void hexdump_u64(const void *ptr, size_t size)
{
	const unsigned char *u8_ptr = (const unsigned char *)ptr;
	size_t i, j;

	for (i = 0; i < size; i += 16) {
		BPF_INFOE("%p:  ", u8_ptr + i);

		if (i + 8 <= size)
			fprintf(stderr, "%016lx ", *(unsigned long *)(u8_ptr + i));
		else
			fprintf(stderr, "%-17s", "");

		if (i + 16 <= size)
			fprintf(stderr, "%016lx", *(unsigned long *)(u8_ptr + i + 8));
		else
			fprintf(stderr, "%-16s", "");

		fprintf(stderr, "   ");
		for (j = 0; j < 16; j++) {
			if (i + j < size) {
				unsigned char c = u8_ptr[i + j];
				if (c >= 32 && c <= 126)
					fprintf(stderr, "%c", c);
				else
					fprintf(stderr, ".");
			}
		}
		fprintf(stderr, "\n");
	}
}

static unsigned long sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_REGS_USER | PERF_SAMPLE_STACK_USER;

struct perf_stack_event global_sample;

static unsigned long event_count = 1;
static __attribute__((unused)) void print_perf_stack_event(struct perf_stack_event *event)
{
	BPF_INFOE("[%10lu]: TID pid=%u, tid=%u, cpu=%u, time=%lu\n", event_count++, event->pid, event->tid, event->cpu, event->time);
	BPF_INFOE("print: REGS_USER rsp=0x%lx, rip=0x%lx\n", event->rsp, event->rip);

	BPF_INFOE("print: CALLCHAIN kstack_sz=%lu\n", event->kstack_sz);
	hexdump_u64(event->kstack, 64);
	BPF_INFOE("print: CALLCHAIN ustack_sz=%lu\n", event->ustack_sz);
	hexdump_u64(event->ustack, 64);

	BPF_INFOE("print: STACK_USER ustack_raw_sz=%lu\n", event->ustack_raw_sz);
	hexdump_u64(event->ustack_raw, event->ustack_raw_sz >= 32 ? 32 : event->ustack_raw_sz);
}

#define READ_U32(dst)                                                                                                                                                                                                                                          \
	do {                                                                                                                                                                                                                                                   \
		if (remaining < sizeof(unsigned int))                                                                                                                                                                                                          \
			goto out;                                                                                                                                                                                                                              \
		memcpy(&(dst), ptr, sizeof(unsigned int));                                                                                                                                                                                                     \
		ptr += sizeof(unsigned int);                                                                                                                                                                                                                   \
		remaining -= sizeof(unsigned int);                                                                                                                                                                                                             \
	} while (0)
#define READ_U64(dst)                                                                                                                                                                                                                                          \
	do {                                                                                                                                                                                                                                                   \
		if (remaining < sizeof(unsigned long))                                                                                                                                                                                                         \
			goto out;                                                                                                                                                                                                                              \
		memcpy(&(dst), ptr, sizeof(unsigned long));                                                                                                                                                                                                    \
		ptr += sizeof(unsigned long);                                                                                                                                                                                                                  \
		remaining -= sizeof(unsigned long);                                                                                                                                                                                                            \
	} while (0)

#define KERNEL_STACK_START (0xffffffffffffff80)
#define USER_STACK_START (0xfffffffffffffe00)

static void parse_perf_stack_event(void *data, unsigned long type, struct perf_stack_event *out, size_t data_size)
{
	unsigned char *ptr = data;
	size_t remaining = data_size;
	unsigned long nr = 0;

	memset(out, 0, sizeof(*out));
	if (!data || data_size == 0)
		goto out;

	if (type & PERF_SAMPLE_TID) {
		READ_U32(out->pid);
		READ_U32(out->tid);
	}

	if (type & PERF_SAMPLE_TIME)
		READ_U64(out->time);

	if (type & PERF_SAMPLE_CPU) {
		READ_U32(out->cpu);
		// reserved field
		if (remaining < sizeof(unsigned int))
			goto out;
		ptr += sizeof(unsigned int);
		remaining -= sizeof(unsigned int);
	}

	if (type & PERF_SAMPLE_CALLCHAIN) {
		READ_U64(nr);

		out->kstack_sz = 0;
		out->ustack_sz = 0;

		enum {
			SEARCHING,
			IN_KSTACK,
			IN_USTACK,
		} state = SEARCHING;

		if (nr > remaining / sizeof(unsigned long))
			nr = remaining / sizeof(unsigned long);

		for (unsigned long i = 0; i < nr; i++) {
			unsigned long ip = 0;
			READ_U64(ip);

			if (ip == KERNEL_STACK_START) {
				state = IN_KSTACK;
			} else if (ip == USER_STACK_START) {
				state = IN_USTACK;
			} else if (state == IN_KSTACK && out->kstack_sz < MAX_STACK_DEPTH) {
				out->kstack[out->kstack_sz++] = ip;
			} else if (state == IN_USTACK && out->ustack_sz < MAX_STACK_DEPTH) {
				out->ustack[out->ustack_sz++] = ip;
			}
		}
	}

	if (type & PERF_SAMPLE_REGS_USER) {
		unsigned long abi = 0;
		READ_U64(abi);
		if (abi != PERF_SAMPLE_REGS_ABI_NONE) {
			if (abi == PERF_SAMPLE_REGS_ABI_64) {
				READ_U64(out->rbp);
#if defined(__CPA_BPF_ARCH_arm64)
				READ_U64(out->lr);
#endif
				READ_U64(out->rsp);
				READ_U64(out->rip);
			} else if (abi == PERF_SAMPLE_REGS_ABI_32) {
				READ_U32(out->rbp);
#if defined(__CPA_BPF_ARCH_arm64)
				READ_U64(out->lr);
#endif
				READ_U32(out->rsp);
				READ_U32(out->rip);
			} else {
				goto out;
			}
		}
	}

	if (type & PERF_SAMPLE_STACK_USER) {
		READ_U64(out->ustack_raw_sz);
		if (!out->ustack_raw_sz) {
			goto out;
		}

		unsigned long raw_size = out->ustack_raw_sz;
		if (raw_size > remaining) {
			goto out;
		}
		if (remaining < raw_size + sizeof(unsigned long))
			goto out;

		const unsigned char *raw = ptr;
		ptr += raw_size;
		remaining -= raw_size;

		unsigned long dyn_size = 0;
		READ_U64(dyn_size);
		if (dyn_size > sizeof(out->ustack_raw))
			dyn_size = sizeof(out->ustack_raw);

		size_t copy_size = raw_size;
		if (copy_size > MAX_USER_STACK_DUMP_SIZE)
			copy_size = MAX_USER_STACK_DUMP_SIZE;
		if (copy_size > dyn_size)
			copy_size = dyn_size;

		size_t offset = out->rsp % 4096;
		size_t copy_limit = sizeof(out->ustack_raw) - offset;
		if (copy_size > copy_limit)
			copy_size = copy_limit;

		if (copy_size) {
			memcpy(out->ustack_raw + offset, raw, copy_size);
			out->ustack_raw_sz = copy_size + offset;
		} else {
			out->ustack_raw_sz = offset;
		}
	}

	// print_perf_stack_event(out);
out:

	return;
}

static char copy_buf[64 * 1024 + 4 * 1024];

#ifndef PERF_RECORD_MISC_SWITCH_OUT_PREEMPT
#define PERF_RECORD_MISC_SWITCH_OUT_PREEMPT (1 << 14)
#endif

/*
 * Switch records carry no payload of their own except next/prev pid on the
 * cpu-wide variant; the switching task comes from the sample_id trailer,
 * which for our sample_type is { u32 pid, tid; u64 time; u32 cpu, res; }.
 */
static bool parse_perf_switch_event(const struct perf_event_header *event_header, struct perf_switch_event *out)
{
	const size_t trailer_size = 2 * sizeof(unsigned int) + sizeof(unsigned long) + 2 * sizeof(unsigned int);
	const unsigned char *trailer;

	if (event_header->size < sizeof(*event_header) + trailer_size)
		return false;

	trailer = (const unsigned char *)event_header + event_header->size - trailer_size;
	memcpy(&out->pid, trailer, sizeof(unsigned int));
	memcpy(&out->tid, trailer + sizeof(unsigned int), sizeof(unsigned int));
	memcpy(&out->time, trailer + 2 * sizeof(unsigned int), sizeof(unsigned long));
	memcpy(&out->cpu, trailer + 2 * sizeof(unsigned int) + sizeof(unsigned long), sizeof(unsigned int));
	out->out = event_header->misc & PERF_RECORD_MISC_SWITCH_OUT;
	out->preempt = event_header->misc & PERF_RECORD_MISC_SWITCH_OUT_PREEMPT;

	return true;
}

static void process_perf_data(struct perf_stack_capture_ctx *ctx, struct perf_event_mmap_page *header, perf_event_handler_fn handler)
{
	unsigned long data_tail;
	unsigned long data_head;
	long page_sz = sysconf(_SC_PAGESIZE);
	void *base = (char *)header + page_sz;

	for (;;) {
		data_head = ring_buffer_read_head(header);
		data_tail = header->data_tail;

		if (data_head == data_tail)
			break;

		bool error = false;

		while (data_tail < data_head) {
			struct perf_event_header *event_header = base + (data_tail % ctx->mmap_size);

			if ((void *)event_header + event_header->size > base + ctx->mmap_size) {
				void *copy_start = event_header;
				size_t len_first = base + ctx->mmap_size - copy_start;
				size_t len_second = event_header->size - len_first;

				memcpy(copy_buf, copy_start, len_first);
				memcpy(copy_buf + len_first, base, len_second);
				event_header = (struct perf_event_header *)copy_buf;
			}

			if (event_header->type == PERF_RECORD_SAMPLE) {
				size_t payload_size = 0;
				if (event_header->size > sizeof(struct perf_event_header))
					payload_size = event_header->size - sizeof(struct perf_event_header);
				parse_perf_stack_event((void *)((unsigned char *)event_header + sizeof(struct perf_event_header)), sample_type, &global_sample, payload_size);
				if (handler)
					handler(&global_sample, ctx->handler_data);
			} else if (event_header->type == PERF_RECORD_SWITCH || event_header->type == PERF_RECORD_SWITCH_CPU_WIDE) {
				struct perf_switch_event switch_event;

				if (ctx->switch_handler && parse_perf_switch_event(event_header, &switch_event))
					ctx->switch_handler(&switch_event, ctx->handler_data);
			} else if (event_header->type == PERF_RECORD_LOST) {
				struct {
					uint64_t id;
					uint64_t lost_events;
				} lost_record = { 0 };
				size_t payload_size = 0;

				if (event_header->size > sizeof(struct perf_event_header))
					payload_size = event_header->size - sizeof(struct perf_event_header);

				if (payload_size >= sizeof(lost_record)) {
					memcpy(&lost_record, (unsigned char *)event_header + sizeof(struct perf_event_header), sizeof(lost_record));
					atomic_fetch_add_explicit(&ctx->lost_events, lost_record.lost_events, memory_order_relaxed);
				}
			}

			data_tail += event_header->size;
		}

		ring_buffer_write_tail(header, data_tail);

		if (error)
			break;
	}
}

static void *poll_event_thread(void *arg)
{
	struct perf_stack_capture_ctx *ctx = arg;
	int i;

	while (!atomic_load(&ctx->stop_thread)) {
		usleep(ctx->sleep_us);
		for (i = 0; i < ctx->perf_cpu_num; i++) {
			process_perf_data(ctx, ctx->mmap_bufs[i], ctx->handler);
			if (ctx->off_mmap_bufs)
				process_perf_data(ctx, ctx->off_mmap_bufs[i], ctx->offcpu_handler);
		}
	}
	return NULL;
}

#if defined(__CPA_BPF_ARCH_arm64)
#define PERF_STACK_CAPTURE_REGS_USER ((1UL << PERF_REG_ARM64_SP) | (1UL << PERF_REG_ARM64_PC) | (1UL << PERF_REG_ARM64_X29) | (1UL << PERF_REG_ARM64_LR))
#else
#define PERF_STACK_CAPTURE_REGS_USER ((1UL << PERF_REG_X86_SP) | (1UL << PERF_REG_X86_IP) | (1UL << PERF_REG_X86_BP))
#endif

/*
 * Open one event per cpu, map its ring buffer and register it for polling.
 * With a cgroup fd the kernel only counts tasks of that cgroup, so sampling
 * inside a container does not pay for other workloads on the host.
 */
static int perf_open_cpu_events(struct perf_stack_capture_ctx *ctx, struct perf_event_attr *attr, int cgroup_fd, int **fds_out, void ***bufs_out)
{
	int *fds = calloc(ctx->perf_cpu_num, sizeof(int));
	void **bufs = calloc(ctx->perf_cpu_num, sizeof(void *));
	unsigned long flags = cgroup_fd >= 0 ? PERF_FLAG_PID_CGROUP : 0;
	int pid = cgroup_fd >= 0 ? cgroup_fd : -1;
	int cpu;

	*fds_out = fds;
	*bufs_out = bufs;
	if (!fds || !bufs) {
		BPF_ERR("failed to alloc perf event arrays\n");
		return -1;
	}

	for (cpu = 0; cpu < ctx->perf_cpu_num; cpu++)
		fds[cpu] = -1;

	for (cpu = 0; cpu < ctx->perf_cpu_num; cpu++) {
		fds[cpu] = syscall(__NR_perf_event_open, attr, pid, cpu, -1, flags);
		if (fds[cpu] < 0) {
			BPF_ERR("failed to open perf event type=%u config=%llu cpu=%d cgroup=%d: %s\n", attr->type, (unsigned long long)attr->config, cpu, cgroup_fd, strerror(errno));
			return -1;
		}

		bufs[cpu] = mmap(NULL, ctx->mmap_size + sysconf(_SC_PAGESIZE), PROT_READ | PROT_WRITE, MAP_SHARED, fds[cpu], 0);
		if (bufs[cpu] == MAP_FAILED) {
			BPF_ERR("failed to mmap perf buffer cpu=%d: %s\n", cpu, strerror(errno));
			bufs[cpu] = NULL;
			return -1;
		}

		struct epoll_event ev;
		ev.events = EPOLLIN;
		ev.data.u32 = cpu;
		if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fds[cpu], &ev) < 0) {
			BPF_ERR("failed to add perf fd to epoll cpu=%d: %s\n", cpu, strerror(errno));
			return -1;
		}
	}

	return 0;
}

static int perf_enable_cpu_events(struct perf_stack_capture_ctx *ctx, int *fds)
{
	for (int cpu = 0; cpu < ctx->perf_cpu_num; cpu++) {
		if (fds[cpu] < 0)
			continue;
		if (ioctl(fds[cpu], PERF_EVENT_IOC_RESET, 0) < 0 || ioctl(fds[cpu], PERF_EVENT_IOC_ENABLE, 0) < 0) {
			BPF_ERR("failed to enable perf event cpu=%d: %s\n", cpu, strerror(errno));
			return -1;
		}
	}

	return 0;
}

static void perf_close_cpu_events(struct perf_stack_capture_ctx *ctx, int *fds, void **bufs)
{
	for (int i = 0; fds && i < ctx->perf_cpu_num; i++) {
		if (fds[i] >= 0)
			close(fds[i]);
	}
	for (int i = 0; bufs && i < ctx->perf_cpu_num; i++) {
		if (bufs[i])
			munmap(bufs[i], ctx->mmap_size + sysconf(_SC_PAGESIZE));
	}
	free(fds);
	free(bufs);
}

struct perf_stack_capture_ctx *perf_setup_stack_capture(const struct perf_stack_capture_opts *opts)
{
	struct perf_stack_capture_ctx *ctx;
	const int page_cnt = PERF_STACK_CAPTURE_PAGE_CNT;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->epoll_fd = -1;
	ctx->perf_cpu_num = get_nprocs();
	ctx->mmap_page_cnt = page_cnt;
	ctx->mmap_size = ctx->mmap_page_cnt * sysconf(_SC_PAGESIZE);
	ctx->handler = opts->handler;
	ctx->offcpu_handler = opts->offcpu_handler;
	ctx->switch_handler = opts->switch_handler;
	ctx->handler_data = opts->handler_data;

	ctx->sleep_us = 1000 * 1000 / opts->sample_freq;
	atomic_init(&ctx->lost_events, 0);

	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.size = sizeof(struct perf_event_attr),
		.config = PERF_COUNT_SW_CPU_CLOCK,
		.sample_freq = opts->sample_freq,
		.freq = 1,
		.sample_type = sample_type,
		.sample_stack_user = MAX_USER_STACK_DUMP_SIZE,
		.sample_regs_user = PERF_STACK_CAPTURE_REGS_USER,
		.disabled = 1,
		.exclude_kernel = 0,
		.exclude_user = 0,
		.exclude_hv = 0,
		.exclude_idle = 1,
	};

	ctx->epoll_events = calloc(ctx->perf_cpu_num, sizeof(struct epoll_event));
	if (!ctx->epoll_events) {
		BPF_ERR("failed to alloc epoll_events\n");
		goto error;
	}

	ctx->epoll_fd = epoll_create1(0);
	if (ctx->epoll_fd < 0) {
		BPF_ERR("failed to create epoll fd: %s\n", strerror(errno));
		goto error;
	}

	if (perf_open_cpu_events(ctx, &attr, opts->cgroup_fd, &ctx->pmu_fds, &ctx->mmap_bufs) < 0)
		goto error;

	if (opts->offcpu_period) {
		/*
		 * Sample a stack every offcpu_period switches and record every
		 * switch in/out; userspace pairs the records to weight samples
		 * by the time the task stayed off-CPU.
		 */
		struct perf_event_attr off_attr = {
			.type = PERF_TYPE_SOFTWARE,
			.size = sizeof(struct perf_event_attr),
			.config = PERF_COUNT_SW_CONTEXT_SWITCHES,
			.sample_period = opts->offcpu_period,
			.sample_type = sample_type,
			.sample_stack_user = opts->offcpu_stack_size,
			.sample_regs_user = PERF_STACK_CAPTURE_REGS_USER,
			.disabled = 1,
			.context_switch = 1,
			.sample_id_all = 1,
		};

		if (perf_open_cpu_events(ctx, &off_attr, opts->cgroup_fd, &ctx->off_fds, &ctx->off_mmap_bufs) < 0)
			goto error;
	}

	atomic_init(&ctx->stop_thread, false);

	if (pthread_create(&ctx->poll_thread, NULL, poll_event_thread, ctx)) {
		BPF_ERR("failed to create poll thread\n");
		goto error;
	}

	if (perf_enable_cpu_events(ctx, ctx->pmu_fds) < 0)
		goto error;
	if (ctx->off_fds && perf_enable_cpu_events(ctx, ctx->off_fds) < 0)
		goto error;

	return ctx;
error:
	perf_stack_capture_cleanup(ctx);
	return NULL;
}

struct perf_stack_capture_ctx *perf_setup_stack_capture_event(int sample_period, perf_event_handler_fn handler, void *handler_data)
{
	struct perf_stack_capture_opts opts = {
		.sample_freq = sample_period,
		.cgroup_fd = -1,
		.handler = handler,
		.handler_data = handler_data,
	};

	return perf_setup_stack_capture(&opts);
}

void perf_stack_capture_cleanup(struct perf_stack_capture_ctx *ctx)
{
	if (!ctx)
		return;

	atomic_store(&ctx->stop_thread, true);
	if (ctx->poll_thread)
		pthread_join(ctx->poll_thread, NULL);

	if (ctx->epoll_fd >= 0)
		close(ctx->epoll_fd);

	if (ctx->epoll_events)
		free(ctx->epoll_events);

	perf_close_cpu_events(ctx, ctx->pmu_fds, ctx->mmap_bufs);
	perf_close_cpu_events(ctx, ctx->off_fds, ctx->off_mmap_bufs);
	free(ctx);
}

void perf_stack_capture_get_stats(struct perf_stack_capture_ctx *ctx, struct perf_stack_capture_stats *stats)
{
	if (!stats)
		return;

	stats->lost_events = 0;
	if (!ctx)
		return;

	stats->lost_events = atomic_load_explicit(&ctx->lost_events, memory_order_relaxed);
}
