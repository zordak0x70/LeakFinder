#include <git2/errors.h>
#include <git2/types.h>
#include <stdio.h>
#include <hs/hs.h>
#include <hs/hs_common.h>
#include "default_regex.h"
#include <stdlib.h>
#include <immintrin.h>
#include <inttypes.h>
#include <stddef.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <git2.h>
#include <stdbool.h>

#include <hs/hs.h>

#define STB_DS_IMPLEMENTATION
#include "stb_ds.h"

#define NUM_WORKERS 8

#define MAX_OFFSETS_TO_PRINT 32
#define MAX_GLOBAL_MATCHES 5000

#define TARGET_BATCH_MB 350
#define TARGET_BATCH_BYTES (TARGET_BATCH_MB * 1024 * 1024)
#define MAX_BLOBS_PER_BATCH 50000
#define QUEUE_DEPTH 20

#define MAX_CUSTOM_RULES 256

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define DEBUG true

static atomic_long total_blobs_processed = 0;
static atomic_long total_bytes_processed = 0;

static const char *custom_patterns[MAX_CUSTOM_RULES];
static unsigned int custom_ids[MAX_CUSTOM_RULES];
static int custom_rule_count = 0;

static const char *custom_rule_names[MAX_CUSTOM_RULES];
static unsigned int custom_ids[MAX_CUSTOM_RULES];

static inline bool should_scan_blob(const char *content, const size_t size) {
    if (size == 0) {
        return false;
    }

    const size_t check_limit = (size > 8192) ? 8192 : size;

    if (memchr(content, '\0', check_limit) != NULL) {
        return false;
    }

    return true;
}

typedef struct {
    git_oid blob_id;
    uint64_t offset;
} SecretMatch;

typedef struct {
    SecretMatch *items;
    _Atomic size_t count;
    size_t capacity;
} MatchList;

MatchList global_matches;

static hs_database_t *g_hs_db = NULL;

static hs_scratch_t *g_hs_scratch[NUM_WORKERS];

static bool g_hs_initialized = false;

typedef struct {
    uint64_t *offsets;
    size_t   *found_count;
    size_t    capacity;
} ScanContext;

static int hs_event_handler(unsigned int id, 
                            unsigned long long from,
                            unsigned long long to, 
                            unsigned int flags, 
                            void *ctx) {
    (void)id;
    (void)from;
    (void)flags;

    ScanContext *sctx = (ScanContext *)ctx;

    if (sctx->found_count[0] < sctx->capacity) {
        sctx->offsets[sctx->found_count[0]] = (uint64_t)to;
        sctx->found_count[0]++;
    }

    return 0;
}

static char *str_trim(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    if (*s == '\0') return s;
    char *end = s + strlen(s) - 1;
    while (end > s && (*end == ' ' || *end == '\t')) end--;
    *(end + 1) = '\0';
    return s;
}

static char *extract_quoted_value(const char *line) {
    const char *start = strchr(line, '"');
    if (!start) return NULL;
    start++;

    const char *end = start;
    size_t len = 0;
    char *result;

    while (*end) {
        if (*end == '\\' && *(end + 1) == '"') {
            len++;
            end += 2;
        } else if (*end == '"') {
            break;
        } else {
            len++;
            end++;
        }
    }

    result = malloc(len + 1);
    if (!result) return NULL;

    const char *p = start;
    char *r = result;
    while (p < end) {
        if (*p == '\\' && *(p + 1) == '"') {
            *r++ = '"';
            p += 2;
        } else {
            *r++ = *p++;
        }
    }
    *r = '\0';

    return result;
}

int load_custom_rules(const char *filepath) {
    FILE *f = fopen(filepath, "r");
    if (!f) {
        fprintf(stderr, "[CONFIG ERROR] Cannot open config file: %s\n", filepath);
        return -1;
    }

    char line[8192];
    custom_rule_count = 0;

    char *current_id = NULL;
    char *current_regex = NULL;
    int in_rule = 0;

    int line_num = 0;

    while (fgets(line, sizeof(line), f) != NULL && custom_rule_count < MAX_CUSTOM_RULES) {
        line_num++;
        char *trimmed = str_trim(line);

        if (trimmed[0] == '\0' || trimmed[0] == '#' || trimmed[0] == ';') {
            continue;
        }

        if (trimmed[0] == '[' && strstr(trimmed, "[[rules]]") == trimmed) {
            if (in_rule && current_regex != NULL) {
                if (current_id == NULL) {
                    char auto_id[64];
                    snprintf(auto_id, sizeof(auto_id), "custom-rule-%d", custom_rule_count);
                    current_id = strdup(auto_id);
                }

                custom_patterns[custom_rule_count] = current_regex;
                custom_rule_names[custom_rule_count] = current_id;
                custom_ids[custom_rule_count] = DEFAULT_REGEX_COUNT + custom_rule_count;
                custom_rule_count++;

                printf("[CONFIG]   Added rule [%d]: id=\"%s\"\n", 
                       custom_rule_count - 1, current_id);
            }

            in_rule = 1;
            current_id = NULL;
            current_regex = NULL;
            continue;
        }

        char *eq = strchr(trimmed, '=');
        if (eq && in_rule) {
            *eq = '\0';
            char *key = str_trim(trimmed);
            char *value_str = str_trim(eq + 1);

            if (strcmp(key, "id") == 0) {
                free(current_id);  /* free previous if any */
                current_id = extract_quoted_value(value_str);
            } else if (strcmp(key, "regex") == 0) {
                free(current_regex);  /* free previous if any */
                current_regex = extract_quoted_value(value_str);
            }
        }
    }

    if (in_rule && current_regex != NULL && custom_rule_count < MAX_CUSTOM_RULES) {
        if (current_id == NULL) {
            char auto_id[64];
            snprintf(auto_id, sizeof(auto_id), "custom-rule-%d", custom_rule_count);
            current_id = strdup(auto_id);
        }

        custom_patterns[custom_rule_count] = current_regex;
        custom_rule_names[custom_rule_count] = current_id;
        custom_ids[custom_rule_count] = DEFAULT_REGEX_COUNT + custom_rule_count;
        custom_rule_count++;

        printf("[CONFIG]   Added rule [%d]: id=\"%s\"\n", 
               custom_rule_count - 1, current_id);
    }

    fclose(f);

    printf("[CONFIG] Loaded %d custom rules from %s\n", custom_rule_count, filepath);
    return 0;
}

int hyperscan_init(void) {
    if (g_hs_initialized) {
        fprintf(stderr, "[HS] Already initialized\n");
        return 0;
    }

    int total_rules = DEFAULT_REGEX_COUNT + custom_rule_count;

    const char *patterns[DEFAULT_REGEX_COUNT + MAX_CUSTOM_RULES];
    unsigned int flags[DEFAULT_REGEX_COUNT + MAX_CUSTOM_RULES];
    unsigned int ids[DEFAULT_REGEX_COUNT + MAX_CUSTOM_RULES];
    hs_compile_error_t *compile_err = NULL;
    int rc;

    for (int i = 0; i < DEFAULT_REGEX_COUNT; i++) {
        patterns[i] = LEAK_RULE_REGEX(i);
        flags[i] = HS_FLAG_DOTALL | HS_FLAG_ALLOWEMPTY | HS_FLAG_UTF8;
        ids[i] = (unsigned int)i;
    }

    for (int i = 0; i < custom_rule_count; i++) {
        patterns[DEFAULT_REGEX_COUNT + i] = custom_patterns[i];
        flags[DEFAULT_REGEX_COUNT + i] = HS_FLAG_DOTALL | HS_FLAG_ALLOWEMPTY | HS_FLAG_UTF8;
        ids[DEFAULT_REGEX_COUNT + i] = custom_ids[i];
    }

    printf("[HS] Compiling %d regex patterns (%d default + %d custom)...\n", 
           total_rules, DEFAULT_REGEX_COUNT, custom_rule_count);

    rc = hs_compile_multi(
        patterns,
        flags,
        ids,
        total_rules,
        HS_MODE_BLOCK,
        NULL,
        &g_hs_db,
        &compile_err
    );

    if (rc != HS_SUCCESS) {
        fprintf(stderr, "[HS FATAL] Compilation failed with code %d\n", rc);
        if (compile_err != NULL) {
            fprintf(stderr, "[HS FATAL] Error: %s\n", compile_err->message);
            if (compile_err->expression >= 0) {
                int expr_idx = compile_err->expression;
                fprintf(stderr, "[HS FATAL] Failed expression #%d", expr_idx);
                if (expr_idx < DEFAULT_REGEX_COUNT) {
                    fprintf(stderr, " (%s): %s\n",
                            LEAK_RULE_ID(expr_idx),
                            LEAK_RULE_REGEX(expr_idx));
                } else {
                    fprintf(stderr, " [CUSTOM]: %s\n", 
                            custom_patterns[expr_idx - DEFAULT_REGEX_COUNT]);
                }
            }
            hs_free_compile_error(compile_err);
        }
        return -1;
    }

    printf("[HS] Database compiled successfully (%d rules)\n", total_rules);

    for (int i = 0; i < NUM_WORKERS; i++) {
        rc = hs_alloc_scratch(g_hs_db, &g_hs_scratch[i]);
        if (rc != HS_SUCCESS) {
            fprintf(stderr, "[HS FATAL] Failed to allocate scratch for worker %d: %d\n", i, rc);

            for (int j = 0; j < i; j++) {
                hs_free_scratch(g_hs_scratch[j]);
                g_hs_scratch[j] = NULL;
            }
            hs_free_database(g_hs_db);
            g_hs_db = NULL;
            return -1;
        }
    }

    printf("[HS] Allocated %d scratch spaces (one per worker)\n", NUM_WORKERS);

    g_hs_initialized = true;
    return 0;
}

void hyperscan_free(void) {
    if (!g_hs_initialized) return;

    printf("[HS] Freeing resources...\n");

    if (g_hs_db != NULL) {
        hs_free_database(g_hs_db);
        g_hs_db = NULL;
    }

    for (int i = 0; i < NUM_WORKERS; i++) {
        if (g_hs_scratch[i] != NULL) {
            hs_free_scratch(g_hs_scratch[i]);
            g_hs_scratch[i] = NULL;
        }
    }

    for (int i = 0; i < custom_rule_count; i++) {
        free((void*)custom_patterns[i]);
        custom_patterns[i] = NULL;
    }
    custom_rule_count = 0;

    g_hs_initialized = false;
    printf("[HS] Cleanup complete.\n");
}

uint64_t *find_all_secrets(const char *raw_content,
                           size_t raw_size,
                           size_t *found,
                           int worker_id) {
    const size_t INITIAL_CAPACITY = 32;
    *found = 0;

    if (raw_content == NULL || raw_size == 0 || found == NULL) {
        return NULL;
    }

    if (worker_id < 0 || worker_id >= NUM_WORKERS) {
        fprintf(stderr, "[HS ERROR] Invalid worker_id: %d\n", worker_id);
        return NULL;
    }

    if (g_hs_db == NULL || g_hs_scratch[worker_id] == NULL) {
        fprintf(stderr, "[HS ERROR] Hyperscan not initialized or invalid scratch[%d]\n", 
                worker_id);
        return NULL;
    }

    uint64_t *offsets = malloc(sizeof(uint64_t) * INITIAL_CAPACITY);
    if (offsets == NULL) {
        fprintf(stderr, "[HS ERROR] malloc failed for offsets\n");
        return NULL;
    }

    ScanContext ctx = {
        .offsets      = offsets,
        .found_count  = found,
        .capacity     = INITIAL_CAPACITY
    };

    hs_error_t err = hs_scan(
        g_hs_db,
        raw_content,
        raw_size,
        0,
        g_hs_scratch[worker_id],
        hs_event_handler,
        &ctx
    );

    if (err != HS_SUCCESS && err != HS_SCAN_TERMINATED) {
        fprintf(stderr, "[HS SCAN ERROR] Code %d on worker %d\n", err, worker_id);
        free(offsets);
        *found = 0;
        return NULL;
    }

    if (*found == 0) {
        free(offsets);
        return NULL;
    }

    return offsets;
}

void hyperscan_print_info(void) {
    if (!g_hs_initialized) {
        printf("[HS] Status: NOT INITIALIZED\n");
        return;
    }

    printf("[HS] Status: ACTIVE\n");
    printf("[HS] Rules loaded: %d (%d default + %d custom)\n", 
           DEFAULT_REGEX_COUNT + custom_rule_count, DEFAULT_REGEX_COUNT, custom_rule_count);
    printf("[HS] Workers supported: %d\n", NUM_WORKERS);

    for (int i = 0; i < DEFAULT_REGEX_COUNT; i++) {
        printf("     - [%d] %s\n", i, LEAK_RULE_ID(i));
    }

    /* NEW: Print custom rule info */
    for (int i = 0; i < custom_rule_count; i++) {
        printf("     - [%d] [CUSTOM] %s\n", DEFAULT_REGEX_COUNT + i, custom_patterns[i]);
    }
}

void matchlist_init(MatchList *list) {
    list->capacity = MAX_GLOBAL_MATCHES;
    list->items = malloc(sizeof(SecretMatch) * list->capacity);

    atomic_init(&list->count, 0);
}

static inline int matchlist_add(MatchList *list, const git_oid *oid, uint64_t offset) {
    while (1) {
        size_t current_index = atomic_load_explicit(&list->count, memory_order_relaxed);

        if (unlikely(current_index >= list->capacity)) {
            return 0;
        }

        size_t expected = current_index;
        if (atomic_compare_exchange_strong_explicit(
                &list->count, &expected, current_index + 1,
                memory_order_acq_rel, memory_order_relaxed)) {

            list->items[current_index].blob_id = *oid;
            list->items[current_index].offset = offset;
            return 1;
        }
    }
}

void matchlist_free(MatchList *list) {
    free(list->items);
}

typedef struct {
    git_oid *blobs;
    int count;
    size_t total_bytes;
    int batch_id;
} WorkBatch;

typedef struct {
    WorkBatch items[QUEUE_DEPTH];

    _Atomic size_t head;
    _Atomic size_t tail;

    _Atomic int done_producing;
} WorkQueue;

typedef struct {
    git_repository *repo;
    git_odb *odb;
    WorkQueue *queue;
    int worker_id;
} WorkerArgs;

void queue_init(WorkQueue *q) {
    memset(q, 0, sizeof(*q));
    atomic_init(&q->head, 0);
    atomic_init(&q->tail, 0);
    atomic_init(&q->done_producing, 0);
}

static inline void cpu_relax(void) {
    #if defined(__x86_64__) || defined(_M_X64) || defined(__i386__)
        _mm_pause();
    #elif defined(__aarch64__) || defined(_M_ARM)
        __asm__ volatile("yield" ::: "memory");
    #elif defined(__riscv)
        __asm__ volatile("nop" ::: "memory");
    #else
        // Nothing, just the while loop is fine
    #endif
}

void queue_push(WorkQueue *q, WorkBatch batch) {
    size_t current_tail = atomic_load_explicit(&q->tail, memory_order_relaxed);
    size_t next_tail = (current_tail + 1) % QUEUE_DEPTH;

    while (next_tail == atomic_load_explicit(&q->head, memory_order_acquire)) {
        cpu_relax();
        if (atomic_load(&q->done_producing)) return;
    }

    q->items[current_tail] = batch;

    atomic_store_explicit(&q->tail, next_tail, memory_order_release);
}

int queue_pop(WorkQueue *q, WorkBatch *out) {
    while (1) {
        size_t current_head = atomic_load_explicit(&q->head, memory_order_relaxed);
        size_t current_tail = atomic_load_explicit(&q->tail, memory_order_acquire);

        if (current_head == current_tail) {
            if (atomic_load_explicit(&q->done_producing, memory_order_acquire)) {
                return 0;
            }
            cpu_relax();
            continue;
        }

        size_t next_head = (current_head + 1) % QUEUE_DEPTH;

        if (atomic_compare_exchange_weak_explicit(
                &q->head, 
                &current_head,
                next_head,
                memory_order_acq_rel, 
                memory_order_relaxed)) {

            *out = q->items[current_head];
            return 1;
        }
    }
}

void queue_finish(WorkQueue *q) {
    atomic_store_explicit(&q->done_producing, 1, memory_order_release);
}

void *worker_routine(void *arg) {
    WorkerArgs *warg = (WorkerArgs *)arg;
    git_odb *odb = warg->odb;
    WorkQueue *queue = warg->queue;
    [[maybe_unused]] int wid = warg->worker_id;

    WorkBatch batch;

    while (queue_pop(queue, &batch)) {
#if DEBUG == true
        printf("[W%d] Processing batch %d (%d blobs, %.2f MB)\n", 
               wid, batch.batch_id, batch.count, batch.total_bytes / (1024.0 * 1024.0));
#endif

        for (int i = 0; i < batch.count; i++) {
            git_odb_object *obj = NULL;

            if (git_odb_read(&obj, odb, &batch.blobs[i]) != 0) {
                continue; 
            }

            const char *raw_content = (const char *)git_odb_object_data(obj);
            size_t raw_size = git_odb_object_size(obj);

            bool should_scan = should_scan_blob(raw_content, raw_size);

            if (should_scan) {
                size_t found = 0;
                uint64_t *results = find_all_secrets(raw_content, raw_size, &found, wid);

                if (found > 0 && results != NULL) {
                    for (size_t f = 0; f < found; f++) {
                        if (!matchlist_add(&global_matches, &batch.blobs[i], results[f])) {
                            break;
                        }
                    }
                    free(results);
                }
            }

            git_odb_object_free(obj);
        }

        atomic_fetch_add(&total_blobs_processed, batch.count);
        atomic_fetch_add(&total_bytes_processed, batch.total_bytes);
        free(batch.blobs);
    }

#if DEBUG
    printf("[W%d] Worker finished.\n", wid);
#endif
    return NULL;
}

typedef struct {
    WorkQueue *queue;
    git_odb *odb;
    git_oid *current_blobs;
    int blob_count;
    size_t current_bytes;
    int batch_id;
} OdbState;

int odb_iterator_cb(const git_oid *id, void *payload) {
    OdbState *state = (OdbState *)payload;
    size_t len;
    git_otype type;

    if (git_odb_read_header(&len, &type, state->odb, id) != 0) return 0;

    if (type != GIT_OBJ_BLOB) return 0;

    state->current_blobs[state->blob_count++] = *id;
    state->current_bytes += len;

    if (state->current_bytes >= TARGET_BATCH_BYTES) {
        WorkBatch batch = {
            .blobs = state->current_blobs,
            .count = state->blob_count,
            .total_bytes = state->current_bytes,
            .batch_id = state->batch_id++
        };
        queue_push(state->queue, batch);

        state->current_blobs = malloc(sizeof(git_oid) * MAX_BLOBS_PER_BATCH);
        state->blob_count = 0;
        state->current_bytes = 0;
    }

    return 0;
}

typedef struct {
    git_oid key;
    char *path;
    char *commit_msg;
} MatchDict;

typedef struct {
    MatchDict *dict;
    const char *current_commit_msg;
    size_t resolved;
    size_t target;
} GlobalWalkState;

int dict_tree_walk_cb(const char *root, const git_tree_entry *entry, void *payload) {
    GlobalWalkState *state = (GlobalWalkState *)payload;

    if (git_tree_entry_type(entry) != GIT_OBJ_BLOB) return 0;

    const git_oid *oid = git_tree_entry_id(entry);

    ptrdiff_t idx = hmgeti(state->dict, *oid);

    if (idx >= 0 && state->dict[idx].path == NULL) {

        size_t path_len = strlen(root) + strlen(git_tree_entry_name(entry)) + 1;
        state->dict[idx].path = malloc(path_len);
        snprintf(state->dict[idx].path, path_len, "%s%s", root, git_tree_entry_name(entry));

        char clean_msg[51] = {0};
        if (state->current_commit_msg) {
            strncpy(clean_msg, state->current_commit_msg, 50);
            for(int c = 0; c < 50 && clean_msg[c]; c++) {
                if(clean_msg[c] == '\n') clean_msg[c] = ' ';
            }
        } else {
            strcpy(clean_msg, "(null)");
        }
        state->dict[idx].commit_msg = strdup(clean_msg);

        state->resolved++;

        if (state->resolved >= state->target) {
            return GIT_EUSER; 
        }
    }
    return 0;
}

void resolve_and_print_matches(git_repository *repo, FILE *out) {
    if (repo == NULL || out == NULL) return;

    size_t safe_count = atomic_load_explicit(&global_matches.count, memory_order_acquire);

    if (safe_count > global_matches.capacity) {
        safe_count = global_matches.capacity;
        fprintf(stderr, "[WARN] Iterating with clamped count: %zu\n", safe_count);
    }

    if (safe_count == 0) {
        fprintf(out, "\n[INFO] No secrets found.\n");
        return;
    }

    MatchDict *dict = NULL;

    for (size_t i = 0; i < global_matches.capacity; i++) {
        git_oid current_oid = global_matches.items[i].blob_id;

        if (hmgeti(dict, current_oid) < 0) {
            MatchDict new_entry;
            new_entry.key = current_oid;
            new_entry.path = NULL;
            new_entry.commit_msg = NULL;
            hmputs(dict, new_entry);
        }
    }

    size_t total_unique_blobs = hmlen(dict);
    fprintf(out, "\n[REVERSE LOOKUP] Resolving %zu unique blobs across all refs...\n", total_unique_blobs);
    fflush(out);

    git_revwalk *walker = NULL;
    if (git_revwalk_new(&walker, repo) == 0) {
        git_strarray ref_list;
        if (git_reference_list(&ref_list, repo) == 0) {
            for (size_t i = 0; i < ref_list.count; i++) {
                git_reference *ref = NULL;
                if (git_reference_lookup(&ref, repo, ref_list.strings[i]) == 0) {
                    git_revwalk_push_ref(walker, ref_list.strings[i]);
                    git_reference_free(ref);
                }
            }
            git_strarray_free(&ref_list);
        }

        git_revwalk_push_glob(walker, "refs/stash");

        git_revwalk_sorting(walker, GIT_SORT_TOPOLOGICAL | GIT_SORT_REVERSE);

        git_oid commit_id;
        GlobalWalkState walk_state = { dict, NULL, 0, total_unique_blobs };
        int commits_checked = 0;

        while (git_revwalk_next(&commit_id, walker) == 0) {
            commits_checked++;

            if (walk_state.resolved >= walk_state.target) {
                break;
            }

            git_commit *commit = NULL;
            git_tree *tree = NULL;

            if (git_commit_lookup(&commit, repo, &commit_id) == 0) {
                walk_state.current_commit_msg = git_commit_message(commit);

                if (git_commit_tree(&tree, commit) == 0) {
                    int rc = git_tree_walk(tree, GIT_TREEWALK_PRE, dict_tree_walk_cb, &walk_state);
                    git_tree_free(tree);

                    if (rc == GIT_EUSER) {
                        git_commit_free(commit);
                        break; 
                    }
                }
                git_commit_free(commit);
            }
        }

        fprintf(out, "[REVERSE LOOKUP] Completed. Checked %d commits total.\n", commits_checked);
        git_revwalk_free(walker);
    }

    size_t i = 0;
    size_t orphans_count = 0;
    size_t resolved_count = 0;

    while (i < safe_count) {
        size_t j = i + 1;
        while (j < safe_count &&
               git_oid_equal(&global_matches.items[i].blob_id,
                             &global_matches.items[j].blob_id)) {
            j++;
        }

        git_oid current_oid = global_matches.items[i].blob_id;
        char oid_str[41] = {0};
        git_oid_fmt(oid_str, &current_oid);

        fprintf(out, "\n[!] Secret hits in Blob %s (%zu matches)\n", oid_str, j - i);
        fprintf(out, "      -> Offsets:");

        size_t to_print = (j - i < MAX_OFFSETS_TO_PRINT) ? (j - i) : MAX_OFFSETS_TO_PRINT;
        for (size_t k = 0; k < to_print; k++) {
            fprintf(out, " %" PRIu64, global_matches.items[i + k].offset);
        }
        if ((j - i) > to_print) {
            fprintf(out, " ... (+%zu more)", (j - i) - to_print);
        }
        fprintf(out, "\n");

        ptrdiff_t idx = hmgeti(dict, current_oid);
        if (idx >= 0 && dict[idx].path != NULL) {
            fprintf(out, "      -> File path: %s\n", dict[idx].path);
            fprintf(out, "      -> Commit: %s...\n", dict[idx].commit_msg);
            resolved_count++;
        } else {
            fprintf(out, "      -> File path: [ORPHAN/DANGLING] Not reachable from any ref (run 'git fsck' to verify)\n");
            orphans_count++;
        }

        i = j;
    }

    fprintf(out, "\n[SUMMARY] Resolved: %zu | True Orphans/Dangling: %zu\n", 
            resolved_count, orphans_count);

    for (ptrdiff_t k = 0; k < hmlen(dict); k++) {
        if (dict[k].path) free(dict[k].path);
        if (dict[k].commit_msg) free(dict[k].commit_msg);
    }
    hmfree(dict); 
}

/* MODIFIED: Added -c option handling */
int main(int argc, char *argv[]) {
    const char *repo_path = NULL;
    const char *config_file = NULL;

    /* Parse arguments: either "./prog repo" or "./prog -c config repo" */
    if (argc == 2) {
        repo_path = argv[1];
    } else if (argc == 4 && strcmp(argv[1], "-c") == 0) {
        config_file = argv[2];
        repo_path = argv[3];
    } else {
        fprintf(stderr, "Usage: %s [-c /path/to/config] <path/to/repo>\n", argv[0]);
        return EXIT_FAILURE;
    }

    git_libgit2_init();
    matchlist_init(&global_matches);

    if (config_file != NULL) {
        if (load_custom_rules(config_file) != 0) {
            fprintf(stderr, "[FATAL] Failed to load config file\n");
            return EXIT_FAILURE;
        }
    }

    if (hyperscan_init() != 0) {
        fprintf(stderr, "[FATAL] Hyperscan initialization failed\n");
        return EXIT_FAILURE;
    }

#if DEBUG
    hyperscan_print_info();
#endif

    git_repository *repo = NULL;
    if (git_repository_open(&repo, repo_path) < 0) {
        fprintf(stderr, "[ERROR] Cannot open repository\n");
        return EXIT_FAILURE;
    }

    git_odb *odb = NULL;
    if (git_repository_odb(&odb, repo) < 0) {
        fprintf(stderr, "[ERROR] Cannot open ODB\n");
        return EXIT_FAILURE; 
    }

    printf("[INFO] Blob Scanner starting (Target Batch: %dMB, Workers: %d)\n", TARGET_BATCH_MB, NUM_WORKERS);

    WorkQueue queue;
    queue_init(&queue);

    pthread_t workers[NUM_WORKERS];
    WorkerArgs args[NUM_WORKERS];

    for (int i = 0; i < NUM_WORKERS; i++) {
        args[i].repo = repo;
        args[i].odb = odb;
        args[i].queue = &queue;
        args[i].worker_id = i;
        pthread_create(&workers[i], NULL, worker_routine, &args[i]);
    }

    time_t start_time = time(NULL);

    OdbState state = {
        .queue = &queue,
        .odb = odb,
        .current_blobs = malloc(sizeof(git_oid) * MAX_BLOBS_PER_BATCH),
        .blob_count = 0,
        .current_bytes = 0,
        .batch_id = 0
    };

    printf("[PROD] Iterating Object Database for files...\n");

    git_odb_foreach(odb, odb_iterator_cb, &state);

    if (state.blob_count > 0) {
        WorkBatch batch = {
            .blobs = state.current_blobs,
            .count = state.blob_count,
            .total_bytes = state.current_bytes,
            .batch_id = state.batch_id++
        };
        queue_push(&queue, batch);
    } else {
        free(state.current_blobs);
    }

    printf("[PROD] Production complete. %d batches queued.\n", state.batch_id);
    queue_finish(&queue);

    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(workers[i], NULL);
    }

    size_t actual_count = atomic_load(&global_matches.count);
    if (actual_count > global_matches.capacity) {
        atomic_store(&global_matches.count, global_matches.capacity);
        fprintf(stderr, "[WARN] Truncated matches from %zu to %zu\n", 
                actual_count, global_matches.capacity);
    }

    FILE* file = fopen("output_leak.txt", "w");
    if (!file) {
        fprintf(stderr, "[ERROR] Cannot open output_leak.txt for writing.\n");
        goto clean;
    }

    resolve_and_print_matches(repo, file);

    time_t end_time = time(NULL);
    double elapsed = difftime(end_time, start_time);

    printf("\n========== RESULTS ==========\n");
    printf("Total Blobs Scanned     : %ld\n", (long)total_blobs_processed);
    printf("Total Data Scanned      : %.2f GB\n", total_bytes_processed / (1024.0 * 1024.0 * 1024.0));
    printf("Total Secrets Found     : %zu %s\n", global_matches.count, global_matches.count == MAX_GLOBAL_MATCHES ? "(Maximum)" : "");
    printf("Elapsed time            : %.1f seconds\n", elapsed);
    if (elapsed > 0) {
        printf("Throughput              : %.2f MB/sec\n", (total_bytes_processed / (1024.0*1024.0)) / elapsed);
    }
    printf("==============================\n");

clean:
    hyperscan_free();
    git_odb_free(odb);
    if(file) fclose(file);
    git_repository_free(repo);
    matchlist_free(&global_matches);
    git_libgit2_shutdown();

    return EXIT_SUCCESS;
}
