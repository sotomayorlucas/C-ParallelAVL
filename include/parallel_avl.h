/**
 * @file parallel_avl.h
 * @brief High-Performance Parallel AVL Tree in Pure C
 * 
 * Features:
 *   - N independent AVL trees for true parallelism
 *   - Adversary-resistant routing with hotspot detection
 *   - Dynamic scaling: add_shard(), remove_shard(), force_rebalance()
 *   - Linearizability guarantee via RedirectIndex
 *   - Optimized range queries
 * 
 * Optimizations:
 *   - Inline hot paths for minimal overhead
 *   - Lock-free statistics reads
 *   - Cache-friendly data layout
 *   - Reduced indirection in common paths
 */

#ifndef PARALLEL_AVL_H
#define PARALLEL_AVL_H

#include "shard.h"
#include "router.h"
#include "redirect_index.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Compiler hints */
#ifdef __GNUC__
#define PAVL_LIKELY(x)   __builtin_expect(!!(x), 1)
#define PAVL_UNLIKELY(x) __builtin_expect(!!(x), 0)
#define PAVL_INLINE      static inline __attribute__((always_inline))
#define PAVL_HOT         __attribute__((hot))
#else
#define PAVL_LIKELY(x)   (x)
#define PAVL_UNLIKELY(x) (x)
#define PAVL_INLINE      static inline
#define PAVL_HOT
#endif

/**
 * Statistics structure
 */
typedef struct ParallelAVLStats {
    size_t num_shards;
    size_t total_size;
    size_t total_ops;
    
    /* Per-shard stats (dynamically allocated) */
    size_t* shard_sizes;
    size_t* shard_inserts;
    size_t* shard_lookups;
    
    /* Router stats */
    double balance_score;
    bool has_hotspot;
    size_t suspicious_patterns;
    size_t blocked_redirects;
    
    /* Redirect index stats */
    size_t redirect_index_size;
    size_t redirect_index_hits;
    double redirect_hit_rate;
    size_t redirect_index_memory_bytes;
} ParallelAVLStats;

/**
 * Parallel AVL Tree structure - optimized layout
 */
typedef struct ParallelAVL {
    /* Hot path data - first cache line */
    size_t num_shards;
    TreeShard** shards;             /* Array of shard pointers */
    Router* router;
    
    /* Optimization flags (atomic for lock-free reads) */
    atomic_bool_t topology_changed;
    atomic_bool_t has_redirects;
    
    /* Statistics */
    atomic_size total_ops;
    atomic_size redirect_hits;
    
    /* Cold data */
    RedirectIndex* redirect_index;
} ParallelAVL;

/* ============================================================================
 * Inline Hash (for fast natural shard calculation)
 * ============================================================================ */

PAVL_INLINE uint64_t pavl_hash(int64_t key) {
    uint64_t h = (uint64_t)key;
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;
    return h;
}

/* ============================================================================
 * Public API
 * ============================================================================ */

ParallelAVL* parallel_avl_create(size_t num_shards, RouterStrategy strategy);
void parallel_avl_destroy(ParallelAVL* tree);

/* Core operations */
void parallel_avl_insert(ParallelAVL* tree, int64_t key, void* value) PAVL_HOT;
bool parallel_avl_contains(ParallelAVL* tree, int64_t key) PAVL_HOT;
void* parallel_avl_get(ParallelAVL* tree, int64_t key, bool* found) PAVL_HOT;
bool parallel_avl_remove(ParallelAVL* tree, int64_t key);

/* Range queries */
void parallel_avl_range_query(ParallelAVL* tree, int64_t lo, int64_t hi,
                               AVLKeyValue* out_array, size_t max_results,
                               size_t* out_count);

/* Inline size (lock-free) */
PAVL_INLINE size_t parallel_avl_size(const ParallelAVL* tree) {
    if (PAVL_UNLIKELY(!tree)) return 0;
    size_t total = 0;
    for (size_t i = 0; i < tree->num_shards; i++) {
        total += shard_size(tree->shards[i]);
    }
    return total;
}

PAVL_INLINE size_t parallel_avl_num_shards(const ParallelAVL* tree) {
    return tree ? tree->num_shards : 0;
}

double parallel_avl_balance_score(const ParallelAVL* tree);
void parallel_avl_clear(ParallelAVL* tree);

/* Dynamic scaling */
bool parallel_avl_add_shard(ParallelAVL* tree);
bool parallel_avl_remove_shard(ParallelAVL* tree);
void parallel_avl_force_rebalance(ParallelAVL* tree);

/* Statistics */
ParallelAVLStats parallel_avl_get_stats(const ParallelAVL* tree);
void parallel_avl_free_stats(ParallelAVLStats* stats);
void parallel_avl_print_stats(const ParallelAVL* tree);

#ifdef __cplusplus
}
#endif

#endif /* PARALLEL_AVL_H */
