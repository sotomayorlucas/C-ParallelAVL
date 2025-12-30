/**
 * @file redirect_index.c
 * @brief High-performance redirect index with RW lock
 */

#include "../include/redirect_index.h"
#include <stdlib.h>

/* ============================================================================
 * Public API
 * ============================================================================ */

RedirectIndex* redirect_index_create(void) {
    RedirectIndex* index = (RedirectIndex*)malloc(sizeof(RedirectIndex));
    if (!index) return NULL;
    
    index->redirects = hash_table_create(64);
    if (!index->redirects) {
        free(index);
        return NULL;
    }
    
    RWLOCK_INIT(&index->rwlock);
    
    atomic_store_size(&index->total_redirects, 0);
    atomic_store_size(&index->lookups, 0);
    atomic_store_size(&index->hits, 0);
    
    return index;
}

void redirect_index_destroy(RedirectIndex* index) {
    if (!index) return;
    
    RWLOCK_DESTROY(&index->rwlock);
    hash_table_destroy(index->redirects);
    free(index);
}

void redirect_index_record(RedirectIndex* index, int64_t key, 
                           size_t natural_shard, size_t actual_shard) {
    if (!index) return;
    
    /* Only record if there was actual redirection */
    if (natural_shard == actual_shard) return;
    
    RWLOCK_WRITE_LOCK(&index->rwlock);
    hash_table_insert(index->redirects, key, actual_shard);
    atomic_increment_size(&index->total_redirects);
    RWLOCK_WRITE_UNLOCK(&index->rwlock);
}

bool redirect_index_lookup(RedirectIndex* index, int64_t key, size_t* out_shard) {
    if (!index) return false;
    
    atomic_increment_size(&index->lookups);
    
    RWLOCK_READ_LOCK(&index->rwlock);
    bool found = hash_table_lookup(index->redirects, key, out_shard);
    RWLOCK_READ_UNLOCK(&index->rwlock);
    
    if (found) {
        atomic_increment_size(&index->hits);
    }
    
    return found;
}

void redirect_index_remove(RedirectIndex* index, int64_t key) {
    if (!index) return;
    
    RWLOCK_WRITE_LOCK(&index->rwlock);
    hash_table_remove(index->redirects, key);
    RWLOCK_WRITE_UNLOCK(&index->rwlock);
}

void redirect_index_clear(RedirectIndex* index) {
    if (!index) return;
    
    RWLOCK_WRITE_LOCK(&index->rwlock);
    hash_table_clear(index->redirects);
    atomic_store_size(&index->total_redirects, 0);
    atomic_store_size(&index->lookups, 0);
    atomic_store_size(&index->hits, 0);
    RWLOCK_WRITE_UNLOCK(&index->rwlock);
}

RedirectIndexStats redirect_index_get_stats(const RedirectIndex* index) {
    RedirectIndexStats stats = {0};
    
    if (!index) return stats;
    
    /* Lock-free reads of atomic statistics */
    stats.total_redirects = atomic_load_size(&((RedirectIndex*)index)->total_redirects);
    stats.lookups = atomic_load_size(&((RedirectIndex*)index)->lookups);
    stats.hits = atomic_load_size(&((RedirectIndex*)index)->hits);
    stats.hit_rate = stats.lookups > 0 ? 
                     (stats.hits * 100.0 / stats.lookups) : 0.0;
    stats.index_size = hash_table_size(index->redirects);
    
    return stats;
}

size_t redirect_index_memory_bytes(const RedirectIndex* index) {
    if (!index) return 0;
    
    /* Approximate: each entry = sizeof(int64_t) + sizeof(size_t) + overhead */
    return hash_table_size(index->redirects) * (sizeof(int64_t) + sizeof(size_t) + 16);
}

size_t redirect_index_gc(RedirectIndex* index, GetCurrentShardFunc get_current_shard, void* ctx) {
    if (!index || !get_current_shard) return 0;
    
    RWLOCK_WRITE_LOCK(&index->rwlock);
    
    size_t removed = 0;
    
    /* Collect keys to remove */
    size_t capacity = hash_table_size(index->redirects);
    if (capacity == 0) {
        RWLOCK_WRITE_UNLOCK(&index->rwlock);
        return 0;
    }
    
    int64_t* keys_to_remove = (int64_t*)malloc(capacity * sizeof(int64_t));
    size_t remove_count = 0;
    
    if (keys_to_remove) {
        HashTableIterator iter = hash_table_iterator(index->redirects);
        int64_t key;
        size_t actual_shard;
        
        while (hash_table_next(&iter, &key, &actual_shard)) {
            size_t current_shard = get_current_shard(key, ctx);
            if (current_shard == actual_shard) {
                keys_to_remove[remove_count++] = key;
            }
        }
        
        /* Remove collected keys */
        for (size_t i = 0; i < remove_count; i++) {
            hash_table_remove(index->redirects, keys_to_remove[i]);
            removed++;
        }
        
        free(keys_to_remove);
    }
    
    RWLOCK_WRITE_UNLOCK(&index->rwlock);
    
    return removed;
}
