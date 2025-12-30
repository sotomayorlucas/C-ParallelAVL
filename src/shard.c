/**
 * @file shard.c
 * @brief High-performance thread-safe AVL shard
 */

#include "../include/shard.h"
#include <stdlib.h>
#include <limits.h>

/* ============================================================================
 * Internal Helpers
 * ============================================================================ */

static void update_bounds(TreeShard* shard, int64_t key) {
    if (!atomic_load_bool(&shard->has_keys)) {
        atomic_store_int64(&shard->min_key, key);
        atomic_store_int64(&shard->max_key, key);
        atomic_store_bool(&shard->has_keys, true);
    } else {
        int64_t current_min = atomic_load_int64(&shard->min_key);
        int64_t current_max = atomic_load_int64(&shard->max_key);
        
        if (key < current_min) {
            atomic_store_int64(&shard->min_key, key);
        }
        if (key > current_max) {
            atomic_store_int64(&shard->max_key, key);
        }
    }
}

static void recompute_bounds(TreeShard* shard) {
    if (avl_tree_size(shard->tree) == 0) {
        atomic_store_bool(&shard->has_keys, false);
        atomic_store_int64(&shard->min_key, INT64_MAX);
        atomic_store_int64(&shard->max_key, INT64_MIN);
    } else {
        bool found;
        int64_t min = avl_tree_min_key(shard->tree, &found);
        int64_t max = avl_tree_max_key(shard->tree, &found);
        atomic_store_int64(&shard->min_key, min);
        atomic_store_int64(&shard->max_key, max);
    }
}

/* Range query callback context */
typedef struct {
    AVLKeyValue* out_array;
    size_t max_results;
    size_t count;
} RangeQueryCtx;

static bool range_query_callback(int64_t key, void* value, void* ctx) {
    RangeQueryCtx* rq = (RangeQueryCtx*)ctx;
    if (rq->count >= rq->max_results) {
        return false;  /* Stop iteration */
    }
    rq->out_array[rq->count].key = key;
    rq->out_array[rq->count].value = value;
    rq->count++;
    return true;
}

/* ============================================================================
 * Public API
 * ============================================================================ */

TreeShard* shard_create(void) {
    TreeShard* shard = (TreeShard*)calloc(1, sizeof(TreeShard));
    if (!shard) return NULL;
    
    shard->tree = avl_tree_create(NULL);
    if (!shard->tree) {
        free(shard);
        return NULL;
    }
    
    SHARD_MUTEX_INIT(&shard->mutex);
    
    atomic_store_size(&shard->size, 0);
    atomic_store_size(&shard->insert_count, 0);
    atomic_store_size(&shard->lookup_count, 0);
    atomic_store_size(&shard->remove_count, 0);
    atomic_store_int64(&shard->min_key, INT64_MAX);
    atomic_store_int64(&shard->max_key, INT64_MIN);
    atomic_store_bool(&shard->has_keys, false);
    
    return shard;
}

void shard_destroy(TreeShard* shard) {
    if (!shard) return;
    
    SHARD_MUTEX_DESTROY(&shard->mutex);
    avl_tree_destroy(shard->tree);
    free(shard);
}

void shard_insert(TreeShard* shard, int64_t key, void* value) {
    if (!shard) return;
    
    SHARD_MUTEX_LOCK(&shard->mutex);
    
    size_t old_size = avl_tree_size(shard->tree);
    avl_tree_insert(shard->tree, key, value);
    size_t new_size = avl_tree_size(shard->tree);
    
    if (new_size > old_size) {
        atomic_increment_size(&shard->size);
        update_bounds(shard, key);
    }
    
    atomic_increment_size(&shard->insert_count);
    
    SHARD_MUTEX_UNLOCK(&shard->mutex);
}

bool shard_remove(TreeShard* shard, int64_t key) {
    if (!shard) return false;
    
    SHARD_MUTEX_LOCK(&shard->mutex);
    
    bool removed = avl_tree_remove(shard->tree, key);
    
    if (removed) {
        atomic_decrement_size(&shard->size);
        atomic_increment_size(&shard->remove_count);
        
        /* Recompute bounds if removed key was min or max */
        int64_t min = atomic_load_int64(&shard->min_key);
        int64_t max = atomic_load_int64(&shard->max_key);
        if (key == min || key == max) {
            recompute_bounds(shard);
        }
    }
    
    SHARD_MUTEX_UNLOCK(&shard->mutex);
    
    return removed;
}

bool shard_contains(TreeShard* shard, int64_t key) {
    if (!shard) return false;
    
    SHARD_MUTEX_LOCK(&shard->mutex);
    bool result = avl_tree_contains(shard->tree, key);
    atomic_increment_size(&shard->lookup_count);
    SHARD_MUTEX_UNLOCK(&shard->mutex);
    
    return result;
}

void* shard_get(TreeShard* shard, int64_t key, bool* found) {
    if (found) *found = false;
    if (!shard) return NULL;
    
    SHARD_MUTEX_LOCK(&shard->mutex);
    void* result = avl_tree_get(shard->tree, key, found);
    atomic_increment_size(&shard->lookup_count);
    SHARD_MUTEX_UNLOCK(&shard->mutex);
    
    return result;
}

bool shard_intersects_range(const TreeShard* shard, int64_t lo, int64_t hi) {
    if (!shard) return false;
    if (!atomic_load_bool(&((TreeShard*)shard)->has_keys)) return false;
    
    int64_t shard_min = atomic_load_int64(&((TreeShard*)shard)->min_key);
    int64_t shard_max = atomic_load_int64(&((TreeShard*)shard)->max_key);
    
    /* Intersection: [shard_min, shard_max] ∩ [lo, hi] ≠ ∅ */
    return !(shard_max < lo || shard_min > hi);
}

void shard_range_query(TreeShard* shard, int64_t lo, int64_t hi,
                       AVLKeyValue* out_array, size_t max_results, size_t* out_count) {
    if (!shard || !out_array || !out_count) return;
    
    *out_count = 0;
    
    SHARD_MUTEX_LOCK(&shard->mutex);
    
    RangeQueryCtx ctx = {out_array, max_results, 0};
    avl_tree_range_foreach(shard->tree, lo, hi, range_query_callback, &ctx);
    *out_count = ctx.count;
    
    SHARD_MUTEX_UNLOCK(&shard->mutex);
}

ShardStats shard_get_stats(const TreeShard* shard) {
    ShardStats stats = {0};
    
    if (!shard) return stats;
    
    /* Lock-free reads of atomic statistics */
    stats.size = atomic_load_size(&((TreeShard*)shard)->size);
    stats.inserts = atomic_load_size(&((TreeShard*)shard)->insert_count);
    stats.removes = atomic_load_size(&((TreeShard*)shard)->remove_count);
    stats.lookups = atomic_load_size(&((TreeShard*)shard)->lookup_count);
    stats.has_keys = atomic_load_bool(&((TreeShard*)shard)->has_keys);
    
    if (stats.has_keys) {
        stats.min_key = atomic_load_int64(&((TreeShard*)shard)->min_key);
        stats.max_key = atomic_load_int64(&((TreeShard*)shard)->max_key);
    }
    
    return stats;
}

void shard_clear(TreeShard* shard) {
    if (!shard) return;
    
    SHARD_MUTEX_LOCK(&shard->mutex);
    
    avl_tree_clear(shard->tree);
    
    atomic_store_size(&shard->size, 0);
    atomic_store_size(&shard->insert_count, 0);
    atomic_store_size(&shard->remove_count, 0);
    atomic_store_size(&shard->lookup_count, 0);
    atomic_store_bool(&shard->has_keys, false);
    atomic_store_int64(&shard->min_key, INT64_MAX);
    atomic_store_int64(&shard->max_key, INT64_MIN);
    
    SHARD_MUTEX_UNLOCK(&shard->mutex);
}

void shard_extract_all(TreeShard* shard, AVLKeyValue* out_array, size_t* out_count) {
    if (!shard || !out_array || !out_count) return;
    
    SHARD_MUTEX_LOCK(&shard->mutex);
    avl_tree_extract_all(shard->tree, out_array, out_count);
    SHARD_MUTEX_UNLOCK(&shard->mutex);
}
