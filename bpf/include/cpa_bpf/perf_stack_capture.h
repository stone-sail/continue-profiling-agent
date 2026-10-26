// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/**
 * @file perf_stack_capture.h
 * @brief User space perf-based stack capture utilities.
 *
 * This API provides a low-overhead user space stack capture implementation based
 * on Linux perf events. It is used by CPA in "perf" backend mode.
 */
#ifndef CPA_BPF_PERF_STACK_CAPTURE_H
#define CPA_BPF_PERF_STACK_CAPTURE_H

#include <cpa_bpf/bpf_event.h>
#include <stdbool.h>
#include <stdint.h>

#define MAX_STACK_DEPTH 127
#define MAX_USER_STACK_DUMP_SIZE (60 * 1024)
#define PERF_STACK_CAPTURE_PAGE_CNT 512

/**
 * PERF stack capture event payload.
 */
struct perf_stack_event {
	unsigned long time;
	unsigned int pid;
	unsigned int tid;
	unsigned int cpu;
	unsigned long cgid;
	char comm[TASK_COMM_LEN];
	unsigned long rsp;
	unsigned long rip;
	unsigned long rbp;
#if defined(__CPA_BPF_ARCH_arm64)
	unsigned long lr;
#endif
	unsigned long kstack_sz;
	unsigned long kstack[MAX_STACK_DEPTH];
	unsigned long ustack_sz;
	unsigned long ustack[MAX_STACK_DEPTH];
	unsigned long ustack_raw_sz;
	char ustack_raw[MAX_USER_STACK_DUMP_SIZE + 4096];
};

typedef void (*perf_event_handler_fn)(struct perf_stack_event *event, void *data);

/**
 * struct perf_switch_event - one context switch record of a sampled task
 * @time: switch timestamp in nanoseconds (perf clock)
 * @pid: TGID in the pid namespace of the event opener
 * @tid: TID in the pid namespace of the event opener
 * @cpu: cpu the switch happened on
 * @out: true for switch-out, false for switch-in
 * @preempt: switch-out was a preemption (task still runnable)
 */
struct perf_switch_event {
	unsigned long time;
	unsigned int pid;
	unsigned int tid;
	unsigned int cpu;
	bool out;
	bool preempt;
};

typedef void (*perf_switch_handler_fn)(const struct perf_switch_event *event, void *data);

/**
 * struct perf_stack_capture_opts - perf backend capture configuration
 * @sample_freq: on-CPU sampling frequency in Hz, also the buffer poll rate
 * @cgroup_fd: perf_event cgroup directory fd to scope events to, or -1
 * @oncpu: open the on-CPU sampling events
 * @stack_size: user stack bytes dumped per on-CPU sample
 * @kernel_only: capture kernel call chains only, without user stacks
 * @probe_type: perf event type of a probe (tracepoint or kprobe PMU); when
 *              nonzero the probe replaces on-CPU sampling and every hit is
 *              sampled
 * @probe_config: perf event config of the probe
 * @probe_func: kprobe function name, NULL for tracepoints
 * @handler: on-CPU (or probe) sample callback
 * @offcpu_period: sample one stack every N context switches; 0 disables off-CPU
 * @offcpu_stack_size: user stack bytes dumped per off-CPU sample
 * @offcpu_handler: off-CPU (context switch) sample callback
 * @switch_handler: context switch record callback
 * @handler_data: opaque pointer passed to every callback
 *
 * All callbacks run on the single capture poll thread.
 */
struct perf_stack_capture_opts {
	int sample_freq;
	int cgroup_fd;
	bool oncpu;
	unsigned int stack_size;
	bool kernel_only;
	unsigned int probe_type;
	unsigned long long probe_config;
	const char *probe_func;
	perf_event_handler_fn handler;
	unsigned int offcpu_period;
	unsigned int offcpu_stack_size;
	perf_event_handler_fn offcpu_handler;
	perf_switch_handler_fn switch_handler;
	void *handler_data;
};

/**
 * Opaque capture context.
 */
struct perf_stack_capture_ctx;

/**
 * struct perf_stack_capture_stats - perf mmap transport counters
 * @lost_events: lost records observed in the perf mmap stream
 */
struct perf_stack_capture_stats {
	uint64_t lost_events;
};

/**
 * Register perf backend capture callbacks and return context.
 */
struct perf_stack_capture_ctx *perf_setup_stack_capture_event(int sample_period, perf_event_handler_fn handler, void *handler_data);

/**
 * Start perf capture with on-CPU sampling and optional off-CPU sampling.
 */
struct perf_stack_capture_ctx *perf_setup_stack_capture(const struct perf_stack_capture_opts *opts);

/**
 * Tear down perf capture context.
 */
void perf_stack_capture_cleanup(struct perf_stack_capture_ctx *ctx);

/**
 * perf_stack_capture_get_stats - snapshot perf mmap transport counters
 * @ctx: capture context
 * @stats: destination statistics object
 */
void perf_stack_capture_get_stats(struct perf_stack_capture_ctx *ctx, struct perf_stack_capture_stats *stats);

#endif
