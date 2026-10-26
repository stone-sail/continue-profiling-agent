// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#ifndef CPA_PERF_EVENT_H
#define CPA_PERF_EVENT_H

#include <stdbool.h>

/**
 * @file cpa_perf_event.h
 * @brief perf event names and cgroup scoping shared by perf sampling and counting.
 */

/**
 * struct cpa_perf_event - a perf_event_open() type/config pair
 * @type: PERF_TYPE_* of the event
 * @config: event config within @type
 */
struct cpa_perf_event {
	unsigned int type;
	unsigned long long config;
};

/**
 * cpa_perf_event_parse - resolve a perf list event name
 * @name: hardware, generic cache or software event name, or r<hex> for raw
 * @out: resolved event
 *
 * Return: 0 on success, -EINVAL for an unknown name (nothing is printed).
 */
int cpa_perf_event_parse(const char *name, struct cpa_perf_event *out);

/**
 * cpa_perf_event_is_cpu_clock - whether @event is the default cpu-clock
 */
bool cpa_perf_event_is_cpu_clock(const struct cpa_perf_event *event);

/**
 * cpa_perf_cgroup_open - open a perf_event cgroup directory for PERF_FLAG_PID_CGROUP
 * @spec: cgroup directory, or "auto" for the cgroup of @pid
 * @pid: pid whose cgroup "auto" resolves to; 0 means cpa itself
 *
 * Return: directory fd, or -1 after printing why.
 */
int cpa_perf_cgroup_open(const char *spec, int pid);

/**
 * cpa_perf_cgroup_id - cgroup id of an open cgroup directory, 0 on failure
 */
unsigned long cpa_perf_cgroup_id(int cgroup_fd);

/**
 * cpa_perf_stat_print - print perf_stat totals with per-second rates and the
 * ratios (IPC, miss rates) that the recorded events allow
 * @names: event names
 * @totals: event counts over @seconds, in the same order as @names
 * @n: number of events
 * @seconds: covered wall-clock time
 */
void cpa_perf_stat_print(const char *const *names, const double *totals, int n, double seconds);

#endif /* CPA_PERF_EVENT_H */
