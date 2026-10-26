// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/* name_to_handle_at() */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "cpa_perf_event.h"
#include "cli.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Resolve the perf_event cgroup directory to scope events to. "auto" maps
 * the cgroup of the target pid (cpa itself when pid is 0) through the cgroup
 * mount, which inside a container is usually the container cgroup
 * bind-mounted as the root.
 */
static int cpa_perf_cgroup_resolve_auto(int pid, char *dir, size_t dir_sz)
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

int cpa_perf_cgroup_open(const char *spec, int pid)
{
	char dir[PATH_MAX];
	int fd;

	if (strcmp(spec, "auto") == 0) {
		int ret = cpa_perf_cgroup_resolve_auto(pid, dir, sizeof(dir));

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

struct perf_event_name {
	const char *name;
	unsigned int type;
	unsigned long long config;
};

static const struct perf_event_name perf_event_names[] = {
	{ "cpu-clock", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK },
	{ "task-clock", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_TASK_CLOCK },
	{ "page-faults", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS },
	{ "faults", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS },
	{ "minor-faults", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS_MIN },
	{ "major-faults", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS_MAJ },
	{ "context-switches", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CONTEXT_SWITCHES },
	{ "cs", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CONTEXT_SWITCHES },
	{ "cpu-migrations", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_MIGRATIONS },
	{ "migrations", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_MIGRATIONS },
	{ "alignment-faults", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_ALIGNMENT_FAULTS },
	{ "emulation-faults", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_EMULATION_FAULTS },
	{ "cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES },
	{ "cpu-cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES },
	{ "instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS },
	{ "cache-references", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES },
	{ "cache-misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES },
	{ "branches", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS },
	{ "branch-instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS },
	{ "branch-misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES },
	{ "bus-cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BUS_CYCLES },
	{ "stalled-cycles-frontend", PERF_TYPE_HARDWARE, PERF_COUNT_HW_STALLED_CYCLES_FRONTEND },
	{ "stalled-cycles-backend", PERF_TYPE_HARDWARE, PERF_COUNT_HW_STALLED_CYCLES_BACKEND },
	{ "ref-cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_REF_CPU_CYCLES },
};

static const struct perf_event_name perf_cache_names[] = {
	{ "L1-dcache", 0, PERF_COUNT_HW_CACHE_L1D }, { "L1-icache", 0, PERF_COUNT_HW_CACHE_L1I }, { "LLC", 0, PERF_COUNT_HW_CACHE_LL },
	{ "dTLB", 0, PERF_COUNT_HW_CACHE_DTLB },     { "iTLB", 0, PERF_COUNT_HW_CACHE_ITLB },     { "branch", 0, PERF_COUNT_HW_CACHE_BPU },
	{ "node", 0, PERF_COUNT_HW_CACHE_NODE },
};

static const struct perf_event_name perf_cache_ops[] = {
	{ "loads", 0, PERF_COUNT_HW_CACHE_OP_READ },
	{ "stores", 0, PERF_COUNT_HW_CACHE_OP_WRITE },
	{ "prefetches", 0, PERF_COUNT_HW_CACHE_OP_PREFETCH },
};

/* perf's cache event names: <cache>-<loads|stores|prefetches>[-misses]. */
static bool perf_event_resolve_cache(const char *spec, unsigned long long *config)
{
	for (size_t i = 0; i < sizeof(perf_cache_names) / sizeof(perf_cache_names[0]); i++) {
		size_t len = strlen(perf_cache_names[i].name);

		if (strncmp(spec, perf_cache_names[i].name, len) != 0 || spec[len] != '-')
			continue;
		for (size_t j = 0; j < sizeof(perf_cache_ops) / sizeof(perf_cache_ops[0]); j++) {
			const char *op = spec + len + 1;
			size_t op_len = strlen(perf_cache_ops[j].name);
			unsigned long long result;

			if (strncmp(op, perf_cache_ops[j].name, op_len) != 0)
				continue;
			if (op[op_len] == '\0')
				result = PERF_COUNT_HW_CACHE_RESULT_ACCESS;
			else if (strcmp(op + op_len, "-misses") == 0)
				result = PERF_COUNT_HW_CACHE_RESULT_MISS;
			else
				continue;
			*config = perf_cache_names[i].config | (perf_cache_ops[j].config << 8) | (result << 16);
			return true;
		}
	}

	return false;
}

/* Same names as perf list, plus r<hex> for raw PMU events. */
int cpa_perf_event_parse(const char *name, struct cpa_perf_event *out)
{
	for (size_t i = 0; i < sizeof(perf_event_names) / sizeof(perf_event_names[0]); i++) {
		if (strcmp(name, perf_event_names[i].name) == 0) {
			out->type = perf_event_names[i].type;
			out->config = perf_event_names[i].config;
			return 0;
		}
	}

	if (perf_event_resolve_cache(name, &out->config)) {
		out->type = PERF_TYPE_HW_CACHE;
		return 0;
	}

	if (name[0] == 'r' && name[1]) {
		char *end = NULL;

		errno = 0;
		out->config = strtoull(name + 1, &end, 16);
		if (errno == 0 && end && *end == '\0') {
			out->type = PERF_TYPE_RAW;
			return 0;
		}
	}

	return -EINVAL;
}

bool cpa_perf_event_is_cpu_clock(const struct cpa_perf_event *event)
{
	return event->type == PERF_TYPE_SOFTWARE && event->config == PERF_COUNT_SW_CPU_CLOCK;
}

/* The kernfs file handle of a cgroup directory is its cgroup id. */
unsigned long cpa_perf_cgroup_id(int cgroup_fd)
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

static int perf_stat_find(const char *const *names, int n, const char *name)
{
	for (int i = 0; i < n; i++) {
		if (strcmp(names[i], name) == 0)
			return i;
	}
	return -1;
}

static const char *perf_stat_fmt_count(double v, char *buf, size_t sz)
{
	char digits[32];
	int len, out = 0;

	snprintf(digits, sizeof(digits), "%.0f", v);
	len = strlen(digits);
	for (int i = 0; i < len && out + 2 < (int)sz; i++) {
		if (i && (len - i) % 3 == 0 && digits[i - 1] != '-')
			buf[out++] = ',';
		buf[out++] = digits[i];
	}
	buf[out] = '\0';
	return buf;
}

static void perf_stat_print_ratio(const char *const *names, const double *totals, int n, const char *num, const char *den, const char *label, bool percent)
{
	int i = perf_stat_find(names, n, num);
	int j = perf_stat_find(names, n, den);

	if (i < 0 || j < 0 || totals[j] <= 0)
		return;
	if (percent)
		CLI_OUTPUT("  %-28s %10.2f%%   %s / %s", label, 100.0 * totals[i] / totals[j], num, den);
	else
		CLI_OUTPUT("  %-28s %10.2f    %s / %s", label, totals[i] / totals[j], num, den);
}

void cpa_perf_stat_print(const char *const *names, const double *totals, int n, double seconds)
{
	static const char *const cache_ops[][2] = { { "-load-misses", "-loads" }, { "-store-misses", "-stores" }, { "-prefetch-misses", "-prefetches" } };
	char a[64], b[64];

	CLI_OUTPUT("perf_stat over %.1fs:", seconds);
	for (int i = 0; i < n; i++)
		CLI_OUTPUT("  %24s  %-28s %16s/s", perf_stat_fmt_count(totals[i], a, sizeof(a)), names[i], perf_stat_fmt_count(seconds > 0 ? totals[i] / seconds : 0, b, sizeof(b)));

	CLI_OUTPUT("derived:");
	perf_stat_print_ratio(names, totals, n, "instructions", "cycles", "IPC", false);
	perf_stat_print_ratio(names, totals, n, "instructions", "cpu-cycles", "IPC", false);
	perf_stat_print_ratio(names, totals, n, "branch-misses", "branches", "branch miss rate", true);
	perf_stat_print_ratio(names, totals, n, "branch-misses", "branch-instructions", "branch miss rate", true);
	perf_stat_print_ratio(names, totals, n, "cache-misses", "cache-references", "cache miss rate", true);

	/* <cache>-load-misses over <cache>-loads, and the same for stores/prefetches. */
	for (int i = 0; i < n; i++) {
		size_t len = strlen(names[i]);

		for (size_t k = 0; k < sizeof(cache_ops) / sizeof(cache_ops[0]); k++) {
			size_t suffix = strlen(cache_ops[k][0]);
			char den[128], label[128];

			if (len <= suffix || strcmp(names[i] + len - suffix, cache_ops[k][0]) != 0)
				continue;
			snprintf(den, sizeof(den), "%.*s%s", (int)(len - suffix), names[i], cache_ops[k][1]);
			snprintf(label, sizeof(label), "%.*s miss rate", (int)(len - strlen("-misses")), names[i]);
			perf_stat_print_ratio(names, totals, n, names[i], den, label, true);
		}
	}
}
