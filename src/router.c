/**
 * @file router.c
 * @brief High-performance adversary-resistant router
 */

#include "../include/router.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>

/* ============================================================================
 * Internal Helpers
 * ============================================================================ */

/* Simple xorshift64 RNG */
static uint64_t xorshift64(uint64_t* state) {
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

static int vnode_compare(const void* a, const void* b) {
    const VirtualNode* va = (const VirtualNode*)a;
    const VirtualNode* vb = (const VirtualNode*)b;
    if (va->hash_value < vb->hash_value) return -1;
    if (va->hash_value > vb->hash_value) return 1;
    return 0;
}

static void init_virtual_nodes(Router* router) {
    size_t total_vnodes = router->num_shards * VNODES_PER_SHARD;
    router->virtual_nodes = (VirtualNode*)malloc(total_vnodes * sizeof(VirtualNode));
    if (!router->virtual_nodes) {
        router->num_virtual_nodes = 0;
        return;
    }
    
    router->num_virtual_nodes = total_vnodes;
    
    size_t idx = 0;
    for (size_t shard = 0; shard < router->num_shards; shard++) {
        for (size_t vnode = 0; vnode < VNODES_PER_SHARD; vnode++) {
            router->virtual_nodes[idx].shard_id = shard;
            /* Use different hash for virtual nodes */
            uint64_t seed = (uint64_t)(shard * VNODES_PER_SHARD + vnode);
            router->virtual_nodes[idx].hash_value = router_hash((int64_t)seed);
            idx++;
        }
    }
    
    qsort(router->virtual_nodes, total_vnodes, sizeof(VirtualNode), vnode_compare);
}

static size_t route_load_aware(Router* router, size_t natural_shard) {
    size_t primary_load = atomic_load_size(&router->shard_loads[natural_shard]);
    
    /* Calculate average load */
    size_t total_load = 0;
    for (size_t i = 0; i < router->num_shards; i++) {
        total_load += atomic_load_size(&router->shard_loads[i]);
    }
    double avg_load = (double)total_load / router->num_shards;
    
    /* If not overloaded, use natural shard */
    if (ROUTER_LIKELY(primary_load <= HOTSPOT_THRESHOLD * avg_load)) {
        return natural_shard;
    }
    
    /* Find least loaded shard */
    size_t best_shard = 0;
    size_t min_load = atomic_load_size(&router->shard_loads[0]);
    
    for (size_t i = 1; i < router->num_shards; i++) {
        size_t load = atomic_load_size(&router->shard_loads[i]);
        if (load < min_load) {
            best_shard = i;
            min_load = load;
        }
    }
    
    if (min_load < avg_load) {
        return best_shard;
    }
    
    /* Fallback: random shard */
    ROUTER_MUTEX_LOCK(&router->rng_mutex);
    size_t result = xorshift64(&router->rng_state) % router->num_shards;
    ROUTER_MUTEX_UNLOCK(&router->rng_mutex);
    return result;
}

static size_t route_consistent_hash(const Router* router, int64_t key) {
    if (ROUTER_UNLIKELY(!router->virtual_nodes || router->num_virtual_nodes == 0)) {
        return router_natural_shard(router, key);
    }
    
    uint64_t key_hash = router_hash(key);
    
    /* Binary search for first vnode >= key_hash */
    size_t lo = 0, hi = router->num_virtual_nodes;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (router->virtual_nodes[mid].hash_value < key_hash) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    
    /* Wrap around if needed */
    if (lo >= router->num_virtual_nodes) {
        lo = 0;
    }
    
    return router->virtual_nodes[lo].shard_id;
}

static void update_stats_cache(Router* router) {
    size_t total = 0, min_load = SIZE_MAX, max_load = 0;
    
    for (size_t i = 0; i < router->num_shards; i++) {
        size_t load = atomic_load_size(&router->shard_loads[i]);
        total += load;
        if (load < min_load) min_load = load;
        if (load > max_load) max_load = load;
    }
    
    double avg = (double)total / router->num_shards;
    
    /* Simplified balance score */
    double balance;
    if (avg > 0) {
        balance = 1.0 - (double)(max_load - min_load) / (2.0 * avg);
        if (balance < 0) balance = 0;
    } else {
        balance = 1.0;
    }
    
    bool hotspot = (max_load > HOTSPOT_THRESHOLD * avg);
    
    router->cached_balance_score = balance;
    atomic_store_bool(&router->cached_has_hotspot, hotspot);
    
    /* Adapt interval based on system state */
    size_t new_interval;
    if (hotspot || balance < 0.8) {
        new_interval = MIN_CACHE_INTERVAL;  /* Reactive under attack */
    } else if (balance > 0.95) {
        new_interval = MAX_CACHE_INTERVAL;  /* Efficient when stable */
    } else {
        new_interval = MIN_CACHE_INTERVAL + 
            (size_t)((balance - 0.8) * (MAX_CACHE_INTERVAL - MIN_CACHE_INTERVAL) / 0.15);
    }
    atomic_store_size(&router->adaptive_interval, new_interval);
}

static size_t route_intelligent(Router* router, size_t natural_shard) {
    /* Fast path: if stable, use natural shard directly */
    size_t interval = atomic_load_size(&router->adaptive_interval);
    if (ROUTER_LIKELY(interval >= MAX_CACHE_INTERVAL)) {
        return natural_shard;
    }
    
    /* Update cache periodically */
    size_t ops = atomic_fetch_add_size(&router->ops_since_cache, 1);
    if (ops >= interval) {
        atomic_store_size(&router->ops_since_cache, 0);
        update_stats_cache(router);
    }
    
    /* Use cached values */
    if (atomic_load_bool(&router->cached_has_hotspot) || 
        router->cached_balance_score < 0.9) {
        return route_load_aware(router, natural_shard);
    }
    
    return natural_shard;
}

/* ============================================================================
 * Public API
 * ============================================================================ */

Router* router_create(size_t num_shards, RouterStrategy strategy) {
    Router* router = (Router*)calloc(1, sizeof(Router));
    if (!router) return NULL;
    
    router->num_shards = num_shards;
    router->strategy = strategy;
    
    /* Check if num_shards is power of 2 for fast modulo */
    if (num_shards && !(num_shards & (num_shards - 1))) {
        router->mask = num_shards - 1;
    } else {
        router->mask = 0;
    }
    
    /* Allocate atomic load array */
    router->shard_loads = (atomic_size*)calloc(num_shards, sizeof(atomic_size));
    if (!router->shard_loads) {
        free(router);
        return NULL;
    }
    
    router->virtual_nodes = NULL;
    router->num_virtual_nodes = 0;
    
    if (strategy == ROUTER_CONSISTENT_HASH || strategy == ROUTER_INTELLIGENT) {
        init_virtual_nodes(router);
    }
    
    atomic_store_size(&router->ops_since_cache, 0);
    atomic_store_bool(&router->cached_has_hotspot, false);
    atomic_store_size(&router->adaptive_interval, MIN_CACHE_INTERVAL);
    router->cached_balance_score = 1.0;
    
    atomic_store_size(&router->suspicious_patterns, 0);
    atomic_store_size(&router->blocked_redirects, 0);
    
    /* Initialize RNG */
    router->rng_state = (uint64_t)(size_t)router ^ 0xdeadbeefcafebabeULL;
    ROUTER_MUTEX_INIT(&router->rng_mutex);
    
    return router;
}

void router_destroy(Router* router) {
    if (!router) return;
    
    ROUTER_MUTEX_DESTROY(&router->rng_mutex);
    free(router->shard_loads);
    free(router->virtual_nodes);
    free(router);
}

size_t ROUTER_HOT router_route(Router* router, int64_t key) {
    if (ROUTER_UNLIKELY(!router)) return 0;
    
    size_t natural_shard = router_natural_shard(router, key);
    
    switch (router->strategy) {
        case ROUTER_STATIC_HASH:
            return natural_shard;
            
        case ROUTER_LOAD_AWARE:
            return route_load_aware(router, natural_shard);
            
        case ROUTER_CONSISTENT_HASH:
            return route_consistent_hash(router, key);
            
        case ROUTER_INTELLIGENT:
            return route_intelligent(router, natural_shard);
            
        default:
            return natural_shard;
    }
}

void router_record_insertion(Router* router, size_t shard_idx) {
    if (!router || shard_idx >= router->num_shards) return;
    atomic_increment_size(&router->shard_loads[shard_idx]);
}

void router_record_removal(Router* router, size_t shard_idx) {
    if (!router || shard_idx >= router->num_shards) return;
    
    size_t current = atomic_load_size(&router->shard_loads[shard_idx]);
    if (current > 0) {
        atomic_decrement_size(&router->shard_loads[shard_idx]);
    }
}

RouterStats router_get_stats(const Router* router) {
    RouterStats stats = {0};
    
    if (!router) return stats;
    
    stats.min_load = SIZE_MAX;
    
    for (size_t i = 0; i < router->num_shards; i++) {
        size_t load = atomic_load_size(&((Router*)router)->shard_loads[i]);
        stats.total_load += load;
        if (load < stats.min_load) stats.min_load = load;
        if (load > stats.max_load) stats.max_load = load;
    }
    
    stats.avg_load = (double)stats.total_load / router->num_shards;
    
    /* Balance score */
    if (stats.avg_load > 0) {
        double variance = 0;
        for (size_t i = 0; i < router->num_shards; i++) {
            double diff = (double)atomic_load_size(&((Router*)router)->shard_loads[i]) - stats.avg_load;
            variance += diff * diff;
        }
        variance /= router->num_shards;
        double std_dev = sqrt(variance);
        stats.balance_score = 1.0 - (std_dev / stats.avg_load);
        if (stats.balance_score < 0) stats.balance_score = 0;
    } else {
        stats.balance_score = 1.0;
    }
    
    stats.has_hotspot = (stats.max_load > HOTSPOT_THRESHOLD * stats.avg_load);
    stats.suspicious_patterns = atomic_load_size(&((Router*)router)->suspicious_patterns);
    stats.blocked_redirects = atomic_load_size(&((Router*)router)->blocked_redirects);
    
    return stats;
}
