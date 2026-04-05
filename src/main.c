#include <git2/errors.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stddef.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <git2.h>
#include <stdbool.h>

#define STB_DS_IMPLEMENTATION
#include "stb_ds.h"

#include "secrets.h"

#define NUM_WORKERS 8

#define MAX_OFFSETS_TO_PRINT 32
#define MAX_GLOBAL_MATCHES 5000

#define TARGET_BATCH_BYTES (500 * 1024 * 1024)
#define MAX_BLOBS_PER_BATCH 50000
#define QUEUE_DEPTH 16

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

typedef struct {
    git_oid blob_id;
    uint64_t offset;
} SecretMatch;

typedef struct {
    SecretMatch *items;
    size_t count;
    size_t capacity;
    pthread_mutex_t mutex;
} MatchList;

MatchList global_matches;

typedef struct {
    git_oid *blobs;
    int count;
    size_t total_bytes;
    int batch_id;
} WorkBatch;

typedef struct {
    WorkBatch items[QUEUE_DEPTH];
    int head, tail, count;
    int done_producing;
    pthread_mutex_t mutex;
    pthread_cond_t not_full, not_empty;
} WorkQueue;

typedef struct { git_repository *repo;
    WorkQueue *queue;
    int worker_id;
} WorkerArgs;

static atomic_long total_blobs_processed = 0;
static atomic_long total_bytes_processed = 0;

static inline int should_scan_blob(git_blob *blob) {
    size_t raw_size = git_blob_rawsize(blob);
    const void *raw_content = git_blob_rawcontent(blob);

    if (raw_size == 0 || raw_content == NULL) {
        return 0;
    }

    if (git_blob_is_binary(blob)) {
        return 0;
    }

    return 1;
}

void matchlist_init(MatchList *list) {
    list->count = 0;
    list->capacity = 128;
    list->items = malloc(sizeof(SecretMatch) * list->capacity);
    pthread_mutex_init(&list->mutex, NULL);
}

int matchlist_add(MatchList *list, const git_oid *oid, uint64_t offset) {
    pthread_mutex_lock(&list->mutex);

    if (unlikely(list->count >= MAX_GLOBAL_MATCHES)) {
        pthread_mutex_unlock(&list->mutex);
        return 0;
    }

    if (unlikely(list->count >= list->capacity)) {
        list->capacity *= 2;
        list->items = realloc(list->items, sizeof(SecretMatch) * list->capacity);
    }

    list->items[list->count].blob_id = *oid;
    list->items[list->count].offset = offset;
    list->count++;

    pthread_mutex_unlock(&list->mutex);
    return 1;
}

void matchlist_free(MatchList *list) {
    free(list->items);
    pthread_mutex_destroy(&list->mutex);
}

void queue_init(WorkQueue *q) {
    memset(q, 0, sizeof(*q));
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->not_full, NULL);
    pthread_cond_init(&q->not_empty, NULL);
}

void queue_push(WorkQueue *q, WorkBatch batch) {
    pthread_mutex_lock(&q->mutex);
    while (q->count >= QUEUE_DEPTH) pthread_cond_wait(&q->not_full, &q->mutex);
    q->items[q->tail] = batch;
    q->tail = (q->tail + 1) % QUEUE_DEPTH;
    q->count++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->mutex);
}

int queue_pop(WorkQueue *q, WorkBatch *out) {
    pthread_mutex_lock(&q->mutex);
    while (q->count == 0 && !q->done_producing) pthread_cond_wait(&q->not_empty, &q->mutex);
    if (q->count == 0 && q->done_producing) {
        pthread_mutex_unlock(&q->mutex);
        return 0;
    }
    *out = q->items[q->head];
    q->head = (q->head + 1) % QUEUE_DEPTH;
    q->count--;
    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->mutex);
    return 1;
}

void queue_finish(WorkQueue *q) {
    pthread_mutex_lock(&q->mutex);
    q->done_producing = 1;
    pthread_cond_broadcast(&q->not_empty);
    pthread_mutex_unlock(&q->mutex);
}

void *worker_routine(void *arg) {
    WorkerArgs *warg = (WorkerArgs *)arg;
    git_repository *repo = warg->repo;
    WorkQueue *queue = warg->queue;
    int wid = warg->worker_id;

    WorkBatch batch;

    while (queue_pop(queue, &batch)) {
        printf("[W%d] Processing batch %d (%d blobs, %.2f MB)\n", 
               wid, batch.batch_id, batch.count, batch.total_bytes / (1024.0 * 1024.0));

        for (int i = 0; i < batch.count; i++) {
            git_blob *blob = NULL;

            if (git_blob_lookup(&blob, repo, &batch.blobs[i]) == 0) {
                if (!should_scan_blob(blob)) {
                    git_blob_free(blob);
                    continue;
                }

                const void *raw_content = git_blob_rawcontent(blob);
                size_t raw_size = git_blob_rawsize(blob);

                size_t found = 0;
                uint64_t *results = find_all_secrets((const char *)raw_content, raw_size, &found);

                if (found > 0 && results != NULL) {
                    for (size_t f = 0; f < found; f++) {
                        if (!matchlist_add(&global_matches, &batch.blobs[i], results[f])) {
                            break;
                        }
                    }

                    free(results);
                }

                git_blob_free(blob);
            }
        }

        total_blobs_processed += batch.count;
        total_bytes_processed += batch.total_bytes;
        free(batch.blobs);
    }

    printf("[W%d] Worker finished.\n", wid);
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

    if (state->current_bytes >= TARGET_BATCH_BYTES || state->blob_count >= MAX_BLOBS_PER_BATCH) {
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

static int secretmatch_cmp(const void *a, const void *b) {
    const SecretMatch *ma = (const SecretMatch *)a;
    const SecretMatch *mb = (const SecretMatch *)b;

    int rc = git_oid_cmp(&ma->blob_id, &mb->blob_id);
    if (rc != 0) return rc;

    if (ma->offset < mb->offset) return -1;
    if (ma->offset > mb->offset) return 1;
    return 0;
}

static void matchlist_sort_and_dedup(MatchList *list) {
    if (list->count < 2) return;

    qsort(list->items, list->count, sizeof(list->items[0]), secretmatch_cmp);

    size_t w = 1;
    for (size_t r = 1; r < list->count; r++) {
        if (!git_oid_equal(&list->items[w - 1].blob_id, &list->items[r].blob_id) ||
            list->items[w - 1].offset != list->items[r].offset) {
            list->items[w++] = list->items[r];
        }
    }

    list->count = w;
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
    if (repo == NULL || out == NULL || global_matches.count == 0) {
        return;
    }

    matchlist_sort_and_dedup(&global_matches);

    MatchDict *dict = NULL;

    for (size_t i = 0; i < global_matches.count; i++) {
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
        // Push TUTTI i refs (heads, tags, remotes, notes, etc.)
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

    while (i < global_matches.count) {
        size_t j = i + 1;
        while (j < global_matches.count &&
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

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <path/repo>\n", argv[0]);
        return EXIT_FAILURE;
    }

    git_libgit2_init();
    matchlist_init(&global_matches);

    git_repository *repo = NULL;
    if (git_repository_open(&repo, argv[1]) < 0) {
        fprintf(stderr, "[ERROR] Cannot open repository\n");
        return EXIT_FAILURE;
    }

    printf("[INFO] Blob Scanner starting (Target Batch: 500MB, Workers: %d)\n", NUM_WORKERS);

    WorkQueue queue;
    queue_init(&queue);

    pthread_t workers[NUM_WORKERS];
    WorkerArgs args[NUM_WORKERS];

    for (int i = 0; i < NUM_WORKERS; i++) {
        args[i].repo = repo;
        args[i].queue = &queue;
        args[i].worker_id = i;
        pthread_create(&workers[i], NULL, worker_routine, &args[i]);
    }

    time_t start_time = time(NULL);

    git_odb *odb = NULL;
    git_repository_odb(&odb, repo);

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
    printf("Total Secrets Found     : %zu\n", global_matches.count);
    printf("Elapsed time            : %.1f seconds\n", elapsed);
    if (elapsed > 0) {
        printf("Throughput              : %.2f MB/sec\n", (total_bytes_processed / (1024.0*1024.0)) / elapsed);
    }
    printf("==============================\n");

clean:
    git_odb_free(odb);
    if(file) fclose(file);
    git_repository_free(repo);
    matchlist_free(&global_matches);
    git_libgit2_shutdown();

    return EXIT_SUCCESS;
}
