// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

/*
 * jemalloc_heap worker: record jemalloc heap profiles in the CPA store format.
 *
 * The target process runs with MALLOC_CONF=prof:true,prof_prefix:<prefix> and
 * dumps <prefix>.<pid>.<seq>.<i|m|u|f>[vseq].heap files (lg_prof_interval, prof.dump,
 * prof_gdump or an application endpoint). Every timer tick this worker picks
 * up the new dumps of --pid in sequence order, symbolizes the backtraces with
 * the shared unwinder context and writes them to <store>/jemalloc as a normal
 * stackmap: strmap/idsmap/stack.bin plus conf with count_unit bytes.
 *
 * Counts are unsampled the way jeprof does it: a backtrace with n sampled
 * objects of s bytes on average stands for n/(1-exp(-s/period)) objects.
 *
 * --jemalloc_mode inuse stores each dump as one snapshot record of live bytes;
 * cpa show exports the last snapshot of the selected range. alloc stores the
 * bytes allocated between two dumps (needs prof_accum:true), which adds up
 * over time like sampled CPU stacks.
 */

#include "cpa_runtime.h"
#include "cpa_env.h"
#include "cpa_stackmap_continuous.h"
#include "cpa_unwinder.h"
#include "cli.h"
#include "cli_config.h"
#include "cli_profile_metadata.h"
#include "cli_stackmap.h"
#include "uthash.h"
#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define JEHEAP_MAX_FRAMES 128
#define JEHEAP_MAX_FILES_PER_TICK 16
/* jemalloc writes a dump in one go; leave files younger than this alone. */
#define JEHEAP_SETTLE_MS 1000

enum jeheap_mode {
	JEHEAP_INUSE,
	JEHEAP_ALLOC,
};

/* Unsampled cumulative allocation per backtrace, kept between dumps for alloc mode. */
struct jeheap_accum {
	char *key;
	double bytes;
	UT_hash_handle hh;
};

static struct {
	void *ctx;
	int pid;
	enum jeheap_mode mode;
	bool remove_dump;
	char dir[PATH_MAX];
	char name_prefix[NAME_MAX + 1];
	long last_seq;
	struct cli_stackmap *map;
	char *store_dir;
	struct jeheap_accum *prev;
	struct jeheap_accum *cur;
	bool have_baseline;
	char base_info[CPA_BASE_INFO_LEN];
	uint64_t dumps;
	uint64_t stacks;
	bool warned_no_accum;
	/* Frames of the backtrace being symbolized, innermost first. */
	char *frames[JEHEAP_MAX_FRAMES];
	int nr_frames;
} jeheap = { .last_seq = -1 };

static void jeheap_accum_free(struct jeheap_accum **table)
{
	struct jeheap_accum *e, *tmp;

	HASH_ITER (hh, *table, e, tmp) {
		HASH_DEL(*table, e);
		free(e->key);
		free(e);
	}
}

/* <prefix>.<pid>.<seq>.<type>[vseq].heap -> seq, or -1 for other files. */
static long jeheap_file_seq(const char *name)
{
	size_t plen = strlen(jeheap.name_prefix);
	const char *p;
	char *end;
	long pid, seq;

	if (strncmp(name, jeheap.name_prefix, plen) != 0 || name[plen] != '.')
		return -1;
	p = name + plen + 1;
	pid = strtol(p, &end, 10);
	if (end == p || *end != '.' || pid != jeheap.pid)
		return -1;
	p = end + 1;
	seq = strtol(p, &end, 10);
	if (end == p || *end != '.' || !end[1] || !strchr("imuf", end[1]))
		return -1;
	p = end + 2;
	while (*p >= '0' && *p <= '9')
		p++;
	if (strcmp(p, ".heap") != 0)
		return -1;
	return seq;
}

/* Allocator and jemalloc frames sit above the call site; jeprof drops them too. */
static bool jeheap_allocator_frame(const char *frame)
{
	static const char *const prefixes[] = {
		"je_", "prof_", "imalloc", "ialloc", "iralloc", "irealloc", "malloc", "calloc", "realloc", "posix_memalign", "aligned_alloc", "memalign", "valloc",
		"mallocx", "rallocx", "xallocx", "do_rallocx", "newImpl", "fallback_impl", "arena_", "tcache_", "large_", "operator new", "_Znwm", "_Znam", "_ZnwmRKSt9nothrow_t",
		"_ZnamRKSt9nothrow_t", "_ZnwmSt11align_val_t", "_ZnamSt11align_val_t", "strdup", "strndup",
	};

	for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
		if (strncmp(frame, prefixes[i], strlen(prefixes[i])) == 0)
			return true;
	}
	return false;
}

static void jeheap_collect_frame(const char *frame, void *ctx)
{
	(void)ctx;
	if (jeheap.nr_frames < JEHEAP_MAX_FRAMES)
		jeheap.frames[jeheap.nr_frames++] = strdup(frame);
}

static void jeheap_free_frames(void)
{
	for (int i = 0; i < jeheap.nr_frames; i++)
		free(jeheap.frames[i]);
	jeheap.nr_frames = 0;
}

/* Emit metadata + root..leaf frames of one backtrace with @bytes as its count. */
static void jeheap_emit(const uint64_t *pcs, int nr, uint64_t bytes)
{
	char hex[32];
	int first = 0;

	if (!bytes)
		return;

	jeheap.nr_frames = 0;
	if (cpa_unwinder_symbolize(jeheap.pid, pcs, nr, jeheap_collect_frame, NULL) < 0 || jeheap.nr_frames == 0) {
		jeheap_free_frames();
		for (int i = 0; i < nr && i < JEHEAP_MAX_FRAMES; i++) {
			snprintf(hex, sizeof(hex), "0x%lx", (unsigned long)pcs[i]);
			jeheap.frames[jeheap.nr_frames++] = strdup(hex);
		}
	}

	while (first < jeheap.nr_frames - 1 && (!jeheap.frames[first] || jeheap_allocator_frame(jeheap.frames[first])))
		first++;

	cli_stackmap_append(jeheap.map, jeheap.base_info);
	cli_stackmap_entry_reverse_ids(jeheap.map);
	for (int i = first; i < jeheap.nr_frames; i++) {
		if (jeheap.frames[i])
			cli_stackmap_append(jeheap.map, jeheap.frames[i]);
	}
	cli_stackmap_entry_reverse_ids(jeheap.map);
	cli_stackmap_done(jeheap.map, bytes);
	jeheap.stacks++;

	jeheap_free_frames();
}

static double jeheap_unsample(double objs, double bytes, double period)
{
	if (objs <= 0 || period <= 0)
		return bytes;
	return bytes / (1 - exp(-(bytes / objs) / period));
}

/* alloc mode: bytes allocated since the previous dump for this backtrace. */
static uint64_t jeheap_alloc_delta(const char *key, double accum_bytes)
{
	struct jeheap_accum *e = calloc(1, sizeof(*e)), *prev = NULL;
	double delta;

	if (!e)
		return 0;
	e->key = strdup(key);
	e->bytes = accum_bytes;
	if (!e->key) {
		free(e);
		return 0;
	}
	HASH_ADD_KEYPTR(hh, jeheap.cur, e->key, strlen(e->key), e);

	if (!jeheap.have_baseline)
		return 0;
	HASH_FIND_STR(jeheap.prev, key, prev);
	delta = accum_bytes - (prev ? prev->bytes : 0);
	return delta > 0 ? (uint64_t)delta : 0;
}

static int jeheap_parse_pcs(char *line, uint64_t *pcs)
{
	char *saveptr = NULL;
	int nr = 0;

	for (char *tok = strtok_r(line + 1, " \t\n", &saveptr); tok && nr < JEHEAP_MAX_FRAMES; tok = strtok_r(NULL, " \t\n", &saveptr))
		pcs[nr++] = strtoull(tok, NULL, 16);
	return nr;
}

/*
 * heap_v2/<period>
 *   t*: <objs>: <bytes> [<accum objs>: <accum bytes>]
 *   t<tid>: ...
 * @ 0x... 0x...
 *   t*: <objs>: <bytes> [<accum objs>: <accum bytes>]
 *   ...
 * MAPPED_LIBRARIES:
 */
static int jeheap_ingest(const char *path)
{
	uint64_t pcs[JEHEAP_MAX_FRAMES];
	char key[JEHEAP_MAX_FRAMES * 19 + 1];
	unsigned long period = 0;
	double accum_total = 0;
	char *line = NULL;
	size_t cap = 0;
	int nr = 0;
	FILE *fp = fopen(path, "r");

	if (!fp) {
		CLI_ERROR("jemalloc_heap: failed to open %s: %s", path, strerror(errno));
		return -1;
	}
	if (getline(&line, &cap, fp) < 0 || sscanf(line, "heap_v2/%lu", &period) != 1) {
		CLI_ERROR("jemalloc_heap: %s is not a jemalloc heap_v2 profile", path);
		free(line);
		fclose(fp);
		return -1;
	}

	while (getline(&line, &cap, fp) >= 0) {
		double objs, bytes, accum_objs, accum_bytes;
		uint64_t count;

		if (strncmp(line, "MAPPED_LIBRARIES:", 17) == 0)
			break;
		if (line[0] == '@') {
			size_t n = 0;

			nr = jeheap_parse_pcs(line, pcs);
			for (int i = 0; i < nr && n < sizeof(key) - 19; i++)
				n += snprintf(key + n, sizeof(key) - n, "%lx;", (unsigned long)pcs[i]);
			key[n] = '\0';
			continue;
		}
		/* Only the per-backtrace total line; per-thread lines repeat it. */
		if (nr == 0 || sscanf(line, " t*: %lf: %lf [%lf: %lf]", &objs, &bytes, &accum_objs, &accum_bytes) != 4)
			continue;

		if (jeheap.mode == JEHEAP_INUSE) {
			count = (uint64_t)jeheap_unsample(objs, bytes, period);
		} else {
			accum_total += accum_bytes;
			count = jeheap_alloc_delta(key, jeheap_unsample(accum_objs, accum_bytes, period));
		}
		jeheap_emit(pcs, nr, count);
		nr = 0;
	}

	free(line);
	fclose(fp);

	if (jeheap.mode == JEHEAP_ALLOC && accum_total == 0 && !jeheap.warned_no_accum) {
		CLI_ERROR("jemalloc_heap: %s has no cumulative counts; alloc mode needs MALLOC_CONF prof_accum:true", path);
		jeheap.warned_no_accum = true;
	}
	if (jeheap.mode == JEHEAP_ALLOC) {
		jeheap_accum_free(&jeheap.prev);
		jeheap.prev = jeheap.cur;
		jeheap.cur = NULL;
		jeheap.have_baseline = true;
	}
	return 0;
}

static void jeheap_save_conf(void *ctx)
{
	char *path = path_join(jeheap.store_dir, "conf");
	struct cli_config *config;

	if (!path)
		return;
	config = cli_config_init(path);
	free(path);
	if (!config)
		return;

	add_config_item(config, "version", CLI_VERSION);
	add_config_item(config, "record_interval", get_arg_by_name(ctx, "record_interval"));
	add_config_item(config, "count_unit", "bytes");
	add_config_item(config, "count_mode", jeheap.mode == JEHEAP_INUSE ? "snapshot" : "delta");
	add_config_item(config, "jemalloc_heap", get_arg_by_name(ctx, "jemalloc_heap"));
	add_config_item(config, "jemalloc_mode", get_arg_by_name(ctx, "jemalloc_mode"));
	add_config_item(config, "pid", get_arg_by_name(ctx, "pid"));
	dump_config(config);
	cli_config_destroy(config);
}

/* Follow the continuous store; a rotation starts a fresh stackmap in the new directory. */
static bool jeheap_open_store(void *ctx)
{
	struct dir_info *dir = cpa_get_stackmap_save_dir();
	char *store_dir;

	if (!dir || !dir->store_dir)
		return false;
	store_dir = path_join(dir->store_dir, "jemalloc");
	if (!store_dir)
		return false;
	if (jeheap.store_dir && strcmp(store_dir, jeheap.store_dir) == 0) {
		free(store_dir);
		return true;
	}

	if (mkdir(store_dir, 0755) != 0 && errno != EEXIST) {
		CLI_ERROR("jemalloc_heap: failed to create %s: %s", store_dir, strerror(errno));
		free(store_dir);
		return false;
	}
	if (jeheap.map)
		cli_stackmap_destroy(jeheap.map);
	jeheap.map = cli_stackmap_init();
	free(jeheap.store_dir);
	jeheap.store_dir = store_dir;
	if (!jeheap.map)
		return false;
	/* The first record covers the time since the store was opened. */
	jeheap.map->record_start_time = cli_stackmap_now_record_ms(jeheap.map);
	jeheap_save_conf(ctx);
	CLI_OUTPUT("jemalloc_heap records to %s", store_dir);
	return true;
}

static void jeheap_read_comm(char *comm, size_t len)
{
	char path[64];
	FILE *fp;

	snprintf(comm, len, "%d", jeheap.pid);
	snprintf(path, sizeof(path), "/proc/%d/comm", jeheap.pid);
	fp = fopen(path, "r");
	if (!fp)
		return;
	if (fgets(comm, len, fp))
		comm[strcspn(comm, "\n")] = '\0';
	fclose(fp);
}

static void jeheap_build_base_info(void)
{
	static char default_env[] = "SYSTEM";
	char comm[TASK_COMM_LEN] = { 0 };
	char *env = NULL;
	char **names;
	int nr_names = 0;

	jeheap_read_comm(comm, sizeof(comm));
	names = cpa_get_record_env(&nr_names);
	if (names)
		env = get_env_var_by_pid(jeheap.pid, names, nr_names);
	/* Not a CPU sample: cgroup and cpu stay 0 (the metadata uses '-' as separator). */
	generate_metadata(jeheap.base_info, sizeof(jeheap.base_info), comm, comm, 0, 0, jeheap.pid, env ? env : default_env);
	free(env);
}

/*
 * Without @seqs: return the highest dump sequence present (or @after), so old
 * dumps are not re-imported. With @seqs: fill the @max lowest new dumps in order.
 */
static long jeheap_scan(long after, long *seqs, char names[][NAME_MAX + 1], int max)
{
	struct dirent *ent;
	long highest = after;
	int n = 0;
	DIR *dir = opendir(jeheap.dir);

	if (!dir)
		return -1;
	while ((ent = readdir(dir))) {
		long seq = jeheap_file_seq(ent->d_name);

		if (seq < 0 || seq <= after)
			continue;
		if (seq > highest)
			highest = seq;
		if (!seqs)
			continue;
		/* Keep the @max lowest sequences, in order. */
		int pos = n;
		while (pos > 0 && seqs[pos - 1] > seq)
			pos--;
		if (pos >= max)
			continue;
		if (n < max)
			n++;
		memmove(&seqs[pos + 1], &seqs[pos], (n - 1 - pos) * sizeof(long));
		memmove(names[pos + 1], names[pos], (n - 1 - pos) * sizeof(names[0]));
		seqs[pos] = seq;
		snprintf(names[pos], sizeof(names[0]), "%s", ent->d_name);
	}
	closedir(dir);
	return seqs ? n : highest;
}

static void jeheap_tick(void *ctx)
{
	long seqs[JEHEAP_MAX_FILES_PER_TICK];
	char names[JEHEAP_MAX_FILES_PER_TICK][NAME_MAX + 1];
	char path[PATH_MAX];
	int n;

	if (!jeheap_open_store(ctx))
		return;

	n = jeheap_scan(jeheap.last_seq, seqs, names, JEHEAP_MAX_FILES_PER_TICK);
	for (int i = 0; i < n; i++) {
		struct stat st;

		snprintf(path, sizeof(path), "%s/%s", jeheap.dir, names[i]);
		if (stat(path, &st) != 0)
			continue;
		if ((uint64_t)st.st_mtime * 1000 + JEHEAP_SETTLE_MS > get_current_ms())
			break;

		jeheap.last_seq = seqs[i];
		if (jeheap_ingest(path) == 0) {
			/* One record per dump keeps snapshots apart in stack.bin. */
			cli_stackmap_dump_delta_stack(jeheap.map, jeheap.store_dir);
			jeheap.dumps++;
		}
		if (jeheap.remove_dump && unlink(path) != 0)
			CLI_ERROR("jemalloc_heap: failed to remove %s: %s", path, strerror(errno));
	}
}

static void jeheap_cleanup(void)
{
	jeheap_accum_free(&jeheap.prev);
	jeheap_accum_free(&jeheap.cur);
	if (jeheap.map)
		cli_stackmap_destroy(jeheap.map);
	jeheap.map = NULL;
	free(jeheap.store_dir);
	jeheap.store_dir = NULL;
	jeheap.have_baseline = false;
	jeheap.warned_no_accum = false;
}

static enum cpa_worker_init_result cpa_jemalloc_heap_init_fn(void *ctx, void *worker_ctx)
{
	const char *prefix = get_arg_by_name(ctx, "jemalloc_heap");
	const char *mode = get_arg_by_name(ctx, "jemalloc_mode");
	char copy[PATH_MAX];

	(void)worker_ctx;
	if (cli_arg_is_null_default(prefix))
		return CPA_INIT_SKIP;

	jeheap_cleanup();
	jeheap.pid = atoi(get_arg_by_name(ctx, "pid"));
	jeheap.remove_dump = atoi(get_arg_by_name(ctx, "jemalloc_remove_dump")) != 0;
	if (jeheap.pid <= 0) {
		CLI_ERROR("--jemalloc_heap needs --pid of the process that writes the dumps");
		return CPA_INIT_FAILED;
	}
	if (strcmp(mode, "inuse") == 0) {
		jeheap.mode = JEHEAP_INUSE;
	} else if (strcmp(mode, "alloc") == 0) {
		jeheap.mode = JEHEAP_ALLOC;
	} else {
		CLI_ERROR("--jemalloc_mode must be inuse or alloc, got %s", mode);
		return CPA_INIT_FAILED;
	}
	if (atoi(get_arg_by_name(ctx, "oneshot"))) {
		CLI_ERROR("--jemalloc_heap records into a store; drop --oneshot");
		return CPA_INIT_FAILED;
	}

	snprintf(copy, sizeof(copy), "%s", prefix);
	snprintf(jeheap.dir, sizeof(jeheap.dir), "%s", dirname(copy));
	snprintf(copy, sizeof(copy), "%s", prefix);
	snprintf(jeheap.name_prefix, sizeof(jeheap.name_prefix), "%s", basename(copy));

	if (access(jeheap.dir, R_OK | X_OK) != 0) {
		CLI_ERROR("jemalloc_heap: cannot read dump directory %s: %s", jeheap.dir, strerror(errno));
		return CPA_INIT_FAILED;
	}
	jeheap.last_seq = jeheap_scan(-1, NULL, NULL, 0);
	jeheap.ctx = ctx;
	jeheap_build_base_info();

	CLI_OUTPUT("jemalloc_heap watching %s/%s.%d.*.heap (%s), skipping existing dumps up to seq %ld", jeheap.dir, jeheap.name_prefix, jeheap.pid, mode, jeheap.last_seq);
	return CPA_INIT_SUCCESS;
}

static void cpa_jemalloc_heap_timer_fn(void *worker_ctx)
{
	(void)worker_ctx;
	jeheap_tick(jeheap.ctx);
}

static void cpa_jemalloc_heap_destroy_fn(void *worker_ctx)
{
	(void)worker_ctx;
	if (jeheap.pid <= 0)
		return;
	CLI_OUTPUT("jemalloc_heap recorded %lu dumps, %lu stacks", (unsigned long)jeheap.dumps, (unsigned long)jeheap.stacks);
	jeheap_cleanup();
	jeheap.pid = 0;
}

struct cpa_worker jemalloc_heap_worker = {
	.worker_name = "jemalloc_heap",
	.worker_ctx = NULL,
	.worker_index = 12,

	.init_fn = cpa_jemalloc_heap_init_fn,
	.destroy_fn = cpa_jemalloc_heap_destroy_fn,
	.pause_fn = NULL,
	.restore_fn = NULL,
	.timer_fn = cpa_jemalloc_heap_timer_fn,
	.main_worker_fn = NULL,
};
