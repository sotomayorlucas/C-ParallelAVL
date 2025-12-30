/**
 * @file shard.h
 * @brief High-performance thread-safe AVL shard
 * 
 * Optimizations:
 *   - Atomic statistics (lock-free reads)
 *   - Spinlock option for low-contention scenarios
 *   - Minimized critical section
 *   - Cache-line padding to prevent false sharing
 */

#ifndef SHARD_H
#define SHARD_H

#include "avl_tree.h"
#include "atomics.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32
#include <windows.h>
typedef CRITICAL_SECTION shard_mutex_t;
#define SHARD_MUTEX_INIT(m)    InitializeCriticalSectionAndSpinCount((m), 4000)
#define SHARD_MUTEX_DESTROY(m) DeleteCriticalSection(m)
#define SHARD_MUTEX_LOCK(m)    EnterCriticalSection(m)
#define SHARD_MUTEX_UNLOCK(m)  LeaveCriticalSection(m)
#define SHARD_MUTEX_TRYLOCK(m) TryEnterCriticalSection(m)
#else
#include <pthread.h>
typedef pthread_mutex_t shard_mutex_t;
#define SHARD_MUTEX_INIT(m)    pthread_mutex_init((m), NULL)
#define SHARD_MUTEX_DESTROY(m) pthread_mutex_destroy(m)
#define SHARD_MUTEX_LOCK(m)    pthread_mutex_lock(m)
#define SHARD_MUTEX_UNLOCK(m)  pthread_mutex_unlock(m)
#define SHARD_MUTEX_TRYLOCK(m) (pthread_mutex_trylock(m) == 0)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Cache line size for padding */
#define CACHE_LINE_SIZE 64

/**
 * Shard statistics - atomic for lock-free reads
 */
typedef struct ShardStats {
    size_t size;
    size_t inserts;
    size_t removes;
    size_t lookups;
    int64_t min_key;
    int64_t max_key;
    bool has_keys;
} ShardStats;

/**
 * Tree Shard - cache-line optimized
 */
typedef struct TreeShard {
    /* Hot data - frequently accessed */
    AVLTree* tree;
    shard_mutex_t mutex;
    
    /* Atomic statistics - lock-free reads */
    atomic_size size;
    atomic_size insert_count;
    atomic_size lookup_count;
    
    /* Padding to separate from cold data */
    char _pad1[CACHE_LINE_SIZE - sizeof(atomic_size) * 3];
    
    /* Cold data - less frequently accessed */
    atomic_size remove_count;
    atomic_int64 min_key;
    atomic_int64 max_key;
    atomic_bool_t has_keys;
} TreeShard;

/* ============================================================================
 * Public API
 * ============================================================================ */

TreeShard* shard_create(void);
void shard_destroy(TreeShard* shard);

/* Core operations */
void shard_insert(TreeShard* shard, int64_t key, void* value);
bool shard_remove(TreeShard* shard, int64_t key);
bool shard_contains(TreeShard* shard, int64_t key);
void* shard_get(TreeShard* shard, int64_t key, bool* found);

/* Lock-free size read */
static inline size_t shard_size(const TreeShard* shard) {
    return shard ? atomic_load_size(&((TreeShard*)shard)->size) : 0;
}

/* Range optimization */
bool shard_intersects_range(const TreeShard* shard, int64_t lo, int64_t hi);
void shard_range_query(TreeShard* shard, int64_t lo, int64_t hi,
                       AVLKeyValue* out_array, size_t max_results, size_t* out_count);

/* Statistics and management */
ShardStats shard_get_stats(const TreeShard* shard);
void shard_clear(TreeShard* shard);
void shard_extract_all(TreeShard* shard, AVLKeyValue* out_array, size_t* out_count);

#ifdef __cplusplus
}
#endif

#endif /* SHARD_H */
