/**
 * @file router.h
 * @brief High-performance adversary-resistant router
 * 
 * Optimizations:
 *   - Inline hot paths
 *   - Cache-friendly data layout
 *   - Minimal branching in common case
 *   - Lock-free statistics reads
 */

#ifndef ROUTER_H
#define ROUTER_H

#include "atomics.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32
#include <windows.h>
typedef CRITICAL_SECTION router_mutex_t;
#define ROUTER_MUTEX_INIT(m)    InitializeCriticalSection(m)
#define ROUTER_MUTEX_DESTROY(m) DeleteCriticalSection(m)
#define ROUTER_MUTEX_LOCK(m)    EnterCriticalSection(m)
#define ROUTER_MUTEX_UNLOCK(m)  LeaveCriticalSection(m)
#else
#include <pthread.h>
typedef pthread_mutex_t router_mutex_t;
#define ROUTER_MUTEX_INIT(m)    pthread_mutex_init((m), NULL)
#define ROUTER_MUTEX_DESTROY(m) pthread_mutex_destroy(m)
#define ROUTER_MUTEX_LOCK(m)    pthread_mutex_lock(m)
#define ROUTER_MUTEX_UNLOCK(m)  pthread_mutex_unlock(m)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Compiler hints */
#ifdef __GNUC__
#define ROUTER_LIKELY(x)   __builtin_expect(!!(x), 1)
#define ROUTER_UNLIKELY(x) __builtin_expect(!!(x), 0)
#define ROUTER_INLINE      static inline __attribute__((always_inline))
#define ROUTER_HOT         __attribute__((hot))
#else
#define ROUTER_LIKELY(x)   (x)
#define ROUTER_UNLIKELY(x) (x)
#define ROUTER_INLINE      static inline
#define ROUTER_HOT
#endif

/**
 * Routing strategy
 */
typedef enum RouterStrategy {
    ROUTER_STATIC_HASH,      /* Simple hash - max performance */
    ROUTER_LOAD_AWARE,       /* Detects and redistributes hotspots */
    ROUTER_CONSISTENT_HASH,  /* Virtual nodes for consistency */
    ROUTER_INTELLIGENT       /* Adaptive hybrid (default) */
} RouterStrategy;

/**
 * Router statistics
 */
typedef struct RouterStats {
    size_t total_load;
    size_t min_load;
    size_t max_load;
    double avg_load;
    double balance_score;
    bool has_hotspot;
    size_t suspicious_patterns;
    size_t blocked_redirects;
} RouterStats;

/* Configuration constants */
#define VNODES_PER_SHARD     16
#define HOTSPOT_THRESHOLD    1.5
#define MIN_CACHE_INTERVAL   10
#define MAX_CACHE_INTERVAL   500

/**
 * Virtual node for consistent hashing
 */
typedef struct VirtualNode {
    size_t shard_id;
    uint64_t hash_value;
} VirtualNode;

/**
 * Router structure - optimized layout
 */
typedef struct Router {
    /* Hot path data - first cache line */
    size_t num_shards;
    size_t mask;                    /* num_shards - 1 if power of 2, else 0 */
    RouterStrategy strategy;
    atomic_size* shard_loads;       /* Array of atomic loads */
    
    /* Virtual nodes for consistent hashing */
    VirtualNode* virtual_nodes;
    size_t num_virtual_nodes;
    
    /* Cache for intelligent strategy */
    atomic_size ops_since_cache;
    atomic_bool_t cached_has_hotspot;
    atomic_size adaptive_interval;
    double cached_balance_score;    /* Not atomic - approximate is fine */
    
    /* Cold data */
    atomic_size suspicious_patterns;
    atomic_size blocked_redirects;
    
    /* RNG for load balancing */
    uint64_t rng_state;
    router_mutex_t rng_mutex;
} Router;

/* ============================================================================
 * Inline Hash Function (hot path)
 * ============================================================================ */

/* Murmur3 finalizer - consistent across compilers */
ROUTER_INLINE uint64_t router_hash(int64_t key) {
    uint64_t h = (uint64_t)key;
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;
    return h;
}

/* Fast shard calculation for power-of-2 shards */
ROUTER_INLINE size_t router_fast_shard(uint64_t hash, size_t num_shards, size_t mask) {
    if (ROUTER_LIKELY(mask != 0)) {
        return (size_t)(hash & mask);
    }
    return (size_t)(hash % num_shards);
}

/* ============================================================================
 * Public API
 * ============================================================================ */

Router* router_create(size_t num_shards, RouterStrategy strategy);
void router_destroy(Router* router);
size_t router_route(Router* router, int64_t key) ROUTER_HOT;
void router_record_insertion(Router* router, size_t shard_idx);
void router_record_removal(Router* router, size_t shard_idx);
RouterStats router_get_stats(const Router* router);

/* Inline natural shard calculation */
ROUTER_INLINE size_t router_natural_shard(const Router* router, int64_t key) {
    uint64_t h = router_hash(key);
    return router_fast_shard(h, router->num_shards, router->mask);
}

#ifdef __cplusplus
}
#endif

#endif /* ROUTER_H */
