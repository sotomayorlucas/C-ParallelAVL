/**
 * @file parallel_avl.c
 * @brief High-Performance Parallel AVL Tree implementation
 */

#include "../include/parallel_avl.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* ============================================================================
 * Internal Helpers
 * ============================================================================ */

/* Compare function for qsort on AVLKeyValue */
static int kv_compare(const void* a, const void* b) {
    const AVLKeyValue* ka = (const AVLKeyValue*)a;
    const AVLKeyValue* kb = (const AVLKeyValue*)b;
    if (ka->key < kb->key) return -1;
    if (ka->key > kb->key) return 1;
    return 0;
}

/* ============================================================================
 * Public API
 * ============================================================================ */

ParallelAVL* parallel_avl_create(size_t num_shards, RouterStrategy strategy) {
    if (num_shards == 0) num_shards = 8;
    
    ParallelAVL* tree = (ParallelAVL*)calloc(1, sizeof(ParallelAVL));
    if (PAVL_UNLIKELY(!tree)) return NULL;
    
    tree->num_shards = num_shards;
    atomic_store_size(&tree->total_ops, 0);
    atomic_store_size(&tree->redirect_hits, 0);
    atomic_store_bool(&tree->topology_changed, false);
    atomic_store_bool(&tree->has_redirects, false);
    
    /* Allocate shard array */
    tree->shards = (TreeShard**)malloc(num_shards * sizeof(TreeShard*));
    if (PAVL_UNLIKELY(!tree->shards)) {
        free(tree);
        return NULL;
    }
    
    /* Create shards */
    for (size_t i = 0; i < num_shards; i++) {
        tree->shards[i] = shard_create();
        if (PAVL_UNLIKELY(!tree->shards[i])) {
            for (size_t j = 0; j < i; j++) {
                shard_destroy(tree->shards[j]);
            }
            free(tree->shards);
            free(tree);
            return NULL;
        }
    }
    
    /* Create router */
    tree->router = router_create(num_shards, strategy);
    if (PAVL_UNLIKELY(!tree->router)) {
        for (size_t i = 0; i < num_shards; i++) {
            shard_destroy(tree->shards[i]);
        }
        free(tree->shards);
        free(tree);
        return NULL;
    }
    
    /* Create redirect index */
    tree->redirect_index = redirect_index_create();
    if (PAVL_UNLIKELY(!tree->redirect_index)) {
        router_destroy(tree->router);
        for (size_t i = 0; i < num_shards; i++) {
            shard_destroy(tree->shards[i]);
        }
        free(tree->shards);
        free(tree);
        return NULL;
    }
    
    return tree;
}

void parallel_avl_destroy(ParallelAVL* tree) {
    if (!tree) return;
    
    redirect_index_destroy(tree->redirect_index);
    router_destroy(tree->router);
    
    for (size_t i = 0; i < tree->num_shards; i++) {
        shard_destroy(tree->shards[i]);
    }
    free(tree->shards);
    free(tree);
}

void PAVL_HOT parallel_avl_insert(ParallelAVL* tree, int64_t key, void* value) {
    if (PAVL_UNLIKELY(!tree)) return;
    
    atomic_increment_size(&tree->total_ops);
    
    /* Calculate natural and target shards */
    uint64_t hash = pavl_hash(key);
    size_t natural_shard = (size_t)(hash % tree->num_shards);
    size_t target_shard = router_route(tree->router, key);
    
    /* Capture size before insert */
    size_t old_size = shard_size(tree->shards[target_shard]);
    
    /* Insert in target shard */
    shard_insert(tree->shards[target_shard], key, value);
    
    /* Only notify router if we actually inserted a new key */
    size_t new_size = shard_size(tree->shards[target_shard]);
    if (new_size > old_size) {
        router_record_insertion(tree->router, target_shard);
        
        /* If there was redirection, record in index */
        if (PAVL_UNLIKELY(target_shard != natural_shard)) {
            redirect_index_record(tree->redirect_index, key, natural_shard, target_shard);
            atomic_store_bool(&tree->has_redirects, true);
        }
    }
}

bool PAVL_HOT parallel_avl_contains(ParallelAVL* tree, int64_t key) {
    if (PAVL_UNLIKELY(!tree)) return false;
    
    /* Fast path: search in natural shard (common case) */
    uint64_t hash = pavl_hash(key);
    size_t natural_shard = (size_t)(hash % tree->num_shards);
    
    if (PAVL_LIKELY(shard_contains(tree->shards[natural_shard], key))) {
        return true;
    }
    
    /* Quick exit if no redirects and no topology changes */
    bool has_redirects = atomic_load_bool(&tree->has_redirects);
    bool topology_changed = atomic_load_bool(&tree->topology_changed);
    
    if (PAVL_LIKELY(!has_redirects && !topology_changed)) {
        return false;
    }
    
    atomic_increment_size(&tree->total_ops);
    
    /* Check redirect index */
    if (has_redirects) {
        size_t redirected_shard;
        if (redirect_index_lookup(tree->redirect_index, key, &redirected_shard)) {
            atomic_increment_size(&tree->redirect_hits);
            return shard_contains(tree->shards[redirected_shard], key);
        }
    }
    
    /* Exhaustive search only if topology changed */
    if (topology_changed) {
        for (size_t i = 0; i < tree->num_shards; i++) {
            if (i == natural_shard) continue;
            if (shard_contains(tree->shards[i], key)) {
                return true;
            }
        }
    }
    
    return false;
}

void* PAVL_HOT parallel_avl_get(ParallelAVL* tree, int64_t key, bool* found) {
    if (found) *found = false;
    if (PAVL_UNLIKELY(!tree)) return NULL;
    
    /* Fast path: search in natural shard */
    uint64_t hash = pavl_hash(key);
    size_t natural_shard = (size_t)(hash % tree->num_shards);
    
    bool shard_found = false;
    void* result = shard_get(tree->shards[natural_shard], key, &shard_found);
    
    if (PAVL_LIKELY(shard_found)) {
        if (found) *found = true;
        return result;
    }
    
    /* Quick exit if no redirects and no topology changes */
    bool has_redirects = atomic_load_bool(&tree->has_redirects);
    bool topology_changed = atomic_load_bool(&tree->topology_changed);
    
    if (PAVL_LIKELY(!has_redirects && !topology_changed)) {
        return NULL;
    }
    
    atomic_increment_size(&tree->total_ops);
    
    /* Check redirect index */
    if (has_redirects) {
        size_t redirected_shard;
        if (redirect_index_lookup(tree->redirect_index, key, &redirected_shard)) {
            atomic_increment_size(&tree->redirect_hits);
            return shard_get(tree->shards[redirected_shard], key, found);
        }
    }
    
    /* Exhaustive search only if topology changed */
    if (topology_changed) {
        for (size_t i = 0; i < tree->num_shards; i++) {
            if (i == natural_shard) continue;
            result = shard_get(tree->shards[i], key, &shard_found);
            if (shard_found) {
                if (found) *found = true;
                return result;
            }
        }
    }
    
    return NULL;
}

bool parallel_avl_remove(ParallelAVL* tree, int64_t key) {
    if (PAVL_UNLIKELY(!tree)) return false;
    
    atomic_increment_size(&tree->total_ops);
    
    /* Try natural shard first */
    uint64_t hash = pavl_hash(key);
    size_t natural_shard = (size_t)(hash % tree->num_shards);
    
    if (shard_remove(tree->shards[natural_shard], key)) {
        router_record_removal(tree->router, natural_shard);
        redirect_index_remove(tree->redirect_index, key);
        return true;
    }
    
    /* Check redirected shard */
    size_t redirected_shard;
    if (redirect_index_lookup(tree->redirect_index, key, &redirected_shard)) {
        if (shard_remove(tree->shards[redirected_shard], key)) {
            router_record_removal(tree->router, redirected_shard);
            redirect_index_remove(tree->redirect_index, key);
            return true;
        }
    }
    
    /* If topology changed, search all shards */
    if (atomic_load_bool(&tree->topology_changed)) {
        for (size_t i = 0; i < tree->num_shards; i++) {
            if (i == natural_shard) continue;
            if (shard_remove(tree->shards[i], key)) {
                router_record_removal(tree->router, i);
                return true;
            }
        }
    }
    
    return false;
}

void parallel_avl_range_query(ParallelAVL* tree, int64_t lo, int64_t hi,
                               AVLKeyValue* out_array, size_t max_results,
                               size_t* out_count) {
    if (!tree || !out_array || !out_count) return;
    
    *out_count = 0;
    atomic_increment_size(&tree->total_ops);
    
    /* Temporary buffer to collect results */
    size_t buffer_size = max_results * 2;
    AVLKeyValue* buffer = (AVLKeyValue*)malloc(buffer_size * sizeof(AVLKeyValue));
    if (!buffer) return;
    
    size_t total_collected = 0;
    
    /* Query all shards that intersect the range */
    for (size_t i = 0; i < tree->num_shards; i++) {
        if (shard_intersects_range(tree->shards[i], lo, hi)) {
            size_t shard_count = 0;
            size_t remaining = buffer_size - total_collected;
            
            shard_range_query(tree->shards[i], lo, hi,
                              buffer + total_collected, remaining, &shard_count);
            total_collected += shard_count;
            
            if (total_collected >= buffer_size) break;
        }
    }
    
    /* Sort results */
    if (total_collected > 0) {
        qsort(buffer, total_collected, sizeof(AVLKeyValue), kv_compare);
    }
    
    /* Copy to output (limited by max_results) */
    size_t copy_count = total_collected < max_results ? total_collected : max_results;
    memcpy(out_array, buffer, copy_count * sizeof(AVLKeyValue));
    *out_count = copy_count;
    
    free(buffer);
}

double parallel_avl_balance_score(const ParallelAVL* tree) {
    if (!tree) return 0.0;
    return router_get_stats(tree->router).balance_score;
}

void parallel_avl_clear(ParallelAVL* tree) {
    if (!tree) return;
    
    for (size_t i = 0; i < tree->num_shards; i++) {
        shard_clear(tree->shards[i]);
    }
    redirect_index_clear(tree->redirect_index);
    atomic_store_size(&tree->total_ops, 0);
    atomic_store_size(&tree->redirect_hits, 0);
}

/* =========================================================================
 * Dynamic Scaling
 * ========================================================================= */

bool parallel_avl_add_shard(ParallelAVL* tree) {
    if (!tree) return false;
    
    /* Create new shard */
    TreeShard* new_shard = shard_create();
    if (!new_shard) return false;
    
    /* Expand shards array */
    TreeShard** new_shards = (TreeShard**)realloc(tree->shards, 
                                                   (tree->num_shards + 1) * sizeof(TreeShard*));
    if (!new_shards) {
        shard_destroy(new_shard);
        return false;
    }
    
    tree->shards = new_shards;
    tree->shards[tree->num_shards] = new_shard;
    tree->num_shards++;
    
    /* Recreate router with new shard count */
    RouterStats old_stats = router_get_stats(tree->router);
    RouterStrategy strategy = old_stats.balance_score > 0.9 ? 
                              ROUTER_INTELLIGENT : ROUTER_LOAD_AWARE;
    
    router_destroy(tree->router);
    tree->router = router_create(tree->num_shards, strategy);
    
    /* Mark topology changed */
    atomic_store_bool(&tree->topology_changed, true);
    
    return true;
}

bool parallel_avl_remove_shard(ParallelAVL* tree) {
    if (!tree || tree->num_shards <= 1) return false;
    
    size_t removing_id = tree->num_shards - 1;
    
    /* Extract all elements from shard to remove */
    size_t shard_sz = shard_size(tree->shards[removing_id]);
    AVLKeyValue* to_redistribute = NULL;
    size_t redistribute_count = 0;
    
    if (shard_sz > 0) {
        to_redistribute = (AVLKeyValue*)malloc(shard_sz * sizeof(AVLKeyValue));
        if (to_redistribute) {
            shard_extract_all(tree->shards[removing_id], to_redistribute, &redistribute_count);
        }
    }
    
    /* Destroy the shard */
    shard_destroy(tree->shards[removing_id]);
    tree->num_shards--;
    
    /* Recreate router */
    router_destroy(tree->router);
    tree->router = router_create(tree->num_shards, ROUTER_INTELLIGENT);
    
    /* Mark topology changed */
    atomic_store_bool(&tree->topology_changed, true);
    
    /* Re-insert data from removed shard */
    if (to_redistribute) {
        for (size_t i = 0; i < redistribute_count; i++) {
            size_t target = router_route(tree->router, to_redistribute[i].key);
            shard_insert(tree->shards[target], to_redistribute[i].key, to_redistribute[i].value);
            router_record_insertion(tree->router, target);
        }
        free(to_redistribute);
    }
    
    return true;
}

void parallel_avl_force_rebalance(ParallelAVL* tree) {
    if (!tree) return;
    
    /* Step 1: Extract all data */
    size_t total_size = parallel_avl_size(tree);
    if (total_size == 0) return;
    
    AVLKeyValue* all_data = (AVLKeyValue*)malloc(total_size * sizeof(AVLKeyValue));
    if (!all_data) return;
    
    size_t total_extracted = 0;
    for (size_t i = 0; i < tree->num_shards; i++) {
        size_t count = 0;
        shard_extract_all(tree->shards[i], all_data + total_extracted, &count);
        total_extracted += count;
    }
    
    /* Step 2: Clear all shards and redirect index */
    for (size_t i = 0; i < tree->num_shards; i++) {
        shard_clear(tree->shards[i]);
    }
    redirect_index_clear(tree->redirect_index);
    
    /* Step 3: Recreate router with STATIC_HASH for consistent routing */
    router_destroy(tree->router);
    tree->router = router_create(tree->num_shards, ROUTER_STATIC_HASH);
    
    /* Step 4: Re-insert everything using simple hash (no redirections) */
    for (size_t i = 0; i < total_extracted; i++) {
        uint64_t hash = pavl_hash(all_data[i].key);
        size_t target = (size_t)(hash % tree->num_shards);
        shard_insert(tree->shards[target], all_data[i].key, all_data[i].value);
        router_record_insertion(tree->router, target);
    }
    
    free(all_data);
    
    /* Reset stats and flags */
    atomic_store_size(&tree->total_ops, total_extracted);
    atomic_store_size(&tree->redirect_hits, 0);
    atomic_store_bool(&tree->topology_changed, false);
    atomic_store_bool(&tree->has_redirects, false);
}

/* =========================================================================
 * Statistics
 * ========================================================================= */

ParallelAVLStats parallel_avl_get_stats(const ParallelAVL* tree) {
    ParallelAVLStats stats = {0};
    
    if (!tree) return stats;
    
    stats.num_shards = tree->num_shards;
    stats.total_ops = atomic_load_size(&((ParallelAVL*)tree)->total_ops);
    
    /* Allocate per-shard arrays */
    stats.shard_sizes = (size_t*)malloc(tree->num_shards * sizeof(size_t));
    stats.shard_inserts = (size_t*)malloc(tree->num_shards * sizeof(size_t));
    stats.shard_lookups = (size_t*)malloc(tree->num_shards * sizeof(size_t));
    
    if (!stats.shard_sizes || !stats.shard_inserts || !stats.shard_lookups) {
        free(stats.shard_sizes);
        free(stats.shard_inserts);
        free(stats.shard_lookups);
        stats.shard_sizes = NULL;
        stats.shard_inserts = NULL;
        stats.shard_lookups = NULL;
        return stats;
    }
    
    /* Collect per-shard stats */
    for (size_t i = 0; i < tree->num_shards; i++) {
        ShardStats shard_stats = shard_get_stats(tree->shards[i]);
        stats.total_size += shard_stats.size;
        stats.shard_sizes[i] = shard_stats.size;
        stats.shard_inserts[i] = shard_stats.inserts;
        stats.shard_lookups[i] = shard_stats.lookups;
    }
    
    /* Router stats */
    RouterStats router_stats = router_get_stats(tree->router);
    stats.balance_score = router_stats.balance_score;
    stats.has_hotspot = router_stats.has_hotspot;
    stats.suspicious_patterns = router_stats.suspicious_patterns;
    stats.blocked_redirects = router_stats.blocked_redirects;
    
    /* Redirect index stats */
    RedirectIndexStats index_stats = redirect_index_get_stats(tree->redirect_index);
    stats.redirect_index_size = index_stats.index_size;
    stats.redirect_index_hits = atomic_load_size(&((ParallelAVL*)tree)->redirect_hits);
    stats.redirect_hit_rate = stats.total_ops > 0 ?
                              (stats.redirect_index_hits * 100.0 / stats.total_ops) : 0.0;
    stats.redirect_index_memory_bytes = redirect_index_memory_bytes(tree->redirect_index);
    
    return stats;
}

void parallel_avl_free_stats(ParallelAVLStats* stats) {
    if (!stats) return;
    free(stats->shard_sizes);
    free(stats->shard_inserts);
    free(stats->shard_lookups);
    stats->shard_sizes = NULL;
    stats->shard_inserts = NULL;
    stats->shard_lookups = NULL;
}

void parallel_avl_print_stats(const ParallelAVL* tree) {
    if (!tree) return;
    
    ParallelAVLStats stats = parallel_avl_get_stats(tree);
    
    printf("\n+============================================+\n");
    printf("|  Parallel AVL Statistics                   |\n");
    printf("+============================================+\n\n");
    
    printf("Shards: %zu\n", stats.num_shards);
    printf("Total elements: %zu\n", stats.total_size);
    printf("Total operations: %zu\n", stats.total_ops);
    printf("Balance score: %.2f%%\n", stats.balance_score * 100);
    
    if (stats.has_hotspot) {
        printf("WARNING: Hotspot detected!\n");
    }
    
    if (stats.suspicious_patterns > 0) {
        printf("ALERT: Suspicious patterns: %zu\n", stats.suspicious_patterns);
        printf("Blocked redirects: %zu\n", stats.blocked_redirects);
    }
    
    printf("\nRedirect Index:\n");
    printf("  Size: %zu entries\n", stats.redirect_index_size);
    printf("  Hits: %zu\n", stats.redirect_index_hits);
    printf("  Hit rate: %.2f%%\n", stats.redirect_hit_rate);
    printf("  Memory: %.2f KB\n", stats.redirect_index_memory_bytes / 1024.0);
    
    printf("\nShard Distribution:\n");
    if (stats.shard_sizes) {
        for (size_t i = 0; i < stats.num_shards; i++) {
            double pct = stats.total_size > 0 ?
                        (stats.shard_sizes[i] * 100.0 / stats.total_size) : 0;
            printf("  Shard %zu: %6zu elements (%5.1f%%) | %zu inserts | %zu lookups\n",
                   i, stats.shard_sizes[i], pct,
                   stats.shard_inserts[i], stats.shard_lookups[i]);
        }
    }
    
    printf("\n");
    
    parallel_avl_free_stats(&stats);
}
