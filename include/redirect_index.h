/**
 * @file redirect_index.h
 * @brief High-performance redirect index with RW lock
 * 
 * Optimizations:
 *   - Read-write lock for concurrent reads
 *   - Atomic statistics
 *   - Inline hot paths
 */

#ifndef REDIRECT_INDEX_H
#define REDIRECT_INDEX_H

#include "hash_table.h"
#include "atomics.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32
#include <windows.h>
typedef SRWLOCK redirect_rwlock_t;
#define RWLOCK_INIT(l)         InitializeSRWLock(l)
#define RWLOCK_DESTROY(l)      ((void)0)
#define RWLOCK_READ_LOCK(l)    AcquireSRWLockShared(l)
#define RWLOCK_READ_UNLOCK(l)  ReleaseSRWLockShared(l)
#define RWLOCK_WRITE_LOCK(l)   AcquireSRWLockExclusive(l)
#define RWLOCK_WRITE_UNLOCK(l) ReleaseSRWLockExclusive(l)
#else
#include <pthread.h>
typedef pthread_rwlock_t redirect_rwlock_t;
#define RWLOCK_INIT(l)         pthread_rwlock_init((l), NULL)
#define RWLOCK_DESTROY(l)      pthread_rwlock_destroy(l)
#define RWLOCK_READ_LOCK(l)    pthread_rwlock_rdlock(l)
#define RWLOCK_READ_UNLOCK(l)  pthread_rwlock_unlock(l)
#define RWLOCK_WRITE_LOCK(l)   pthread_rwlock_wrlock(l)
#define RWLOCK_WRITE_UNLOCK(l) pthread_rwlock_unlock(l)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Redirect index statistics
 */
typedef struct RedirectIndexStats {
    size_t total_redirects;
    size_t lookups;
    size_t hits;
    double hit_rate;
    size_t index_size;
} RedirectIndexStats;

/**
 * Redirect index structure
 */
typedef struct RedirectIndex {
    HashTable* redirects;
    redirect_rwlock_t rwlock;
    
    /* Atomic statistics */
    atomic_size total_redirects;
    atomic_size lookups;
    atomic_size hits;
} RedirectIndex;

/* ============================================================================
 * Public API
 * ============================================================================ */

RedirectIndex* redirect_index_create(void);
void redirect_index_destroy(RedirectIndex* index);

void redirect_index_record(RedirectIndex* index, int64_t key, 
                           size_t natural_shard, size_t actual_shard);
bool redirect_index_lookup(RedirectIndex* index, int64_t key, size_t* out_shard);
void redirect_index_remove(RedirectIndex* index, int64_t key);
void redirect_index_clear(RedirectIndex* index);

RedirectIndexStats redirect_index_get_stats(const RedirectIndex* index);
size_t redirect_index_memory_bytes(const RedirectIndex* index);

/* GC callback type */
typedef size_t (*GetCurrentShardFunc)(int64_t key, void* ctx);
size_t redirect_index_gc(RedirectIndex* index, GetCurrentShardFunc get_current_shard, void* ctx);

#ifdef __cplusplus
}
#endif

#endif /* REDIRECT_INDEX_H */
