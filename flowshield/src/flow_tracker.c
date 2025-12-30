/**
 * FlowShield - Flow Tracker Implementation
 *
 * Concurrent flow tracking using ParallelAVL.
 */

#include "../include/flow_tracker.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

/* ============================================================================
 * Internal Structures
 * ============================================================================ */

/* Flow entry stored in AVL tree */
typedef struct {
    FlowKey   key;
    FlowStats stats;
} FlowEntry;

/* Flow Tracker state */
struct FlowTracker {
    ParallelAVL*  avl;              /* Underlying parallel AVL tree */
    RouterStrategy routing;          /* Routing strategy used */

    /* Atomic counters for lock-free statistics */
    _Atomic size_t total_packets;
    _Atomic size_t total_bytes;
    _Atomic size_t flagged_count;
    _Atomic size_t new_flows_count;

    /* Metrics snapshot */
    _Atomic uint64_t last_metrics_time;
    _Atomic uint64_t peak_pps;

    /* Pool for flow entries */
    pthread_mutex_t pool_lock;
    FlowEntry* entry_pool;
    size_t pool_size;
    size_t pool_used;
};

/* ============================================================================
 * Internal Helpers
 * ============================================================================ */

static FlowEntry* alloc_entry(FlowTracker* tracker) {
    pthread_mutex_lock(&tracker->pool_lock);

    /* Grow pool if needed */
    if (tracker->pool_used >= tracker->pool_size) {
        size_t new_size = tracker->pool_size == 0 ? 1024 : tracker->pool_size * 2;
        FlowEntry* new_pool = realloc(tracker->entry_pool, new_size * sizeof(FlowEntry));
        if (!new_pool) {
            pthread_mutex_unlock(&tracker->pool_lock);
            return NULL;
        }
        tracker->entry_pool = new_pool;
        tracker->pool_size = new_size;
    }

    FlowEntry* entry = &tracker->entry_pool[tracker->pool_used++];
    pthread_mutex_unlock(&tracker->pool_lock);

    memset(entry, 0, sizeof(FlowEntry));
    return entry;
}

/* Update rate history */
static void update_rate_history(FlowStats* stats, uint32_t pps, uint32_t bps_kb) {
    stats->pps_history[stats->history_idx] = pps;
    stats->bps_history[stats->history_idx] = bps_kb;
    stats->history_idx = (stats->history_idx + 1) % FLOW_HISTORY_SIZE;
    if (stats->history_count < FLOW_HISTORY_SIZE) {
        stats->history_count++;
    }
}

/* Calculate average from history */
static double calc_avg_pps(const FlowStats* stats) {
    if (stats->history_count == 0) return 0.0;
    uint64_t sum = 0;
    for (uint8_t i = 0; i < stats->history_count; i++) {
        sum += stats->pps_history[i];
    }
    return (double)sum / stats->history_count;
}

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

FlowTracker* flow_tracker_create(size_t num_shards, RouterStrategy routing) {
    FlowTracker* tracker = calloc(1, sizeof(FlowTracker));
    if (!tracker) return NULL;

    tracker->avl = parallel_avl_create(num_shards, routing);
    if (!tracker->avl) {
        free(tracker);
        return NULL;
    }

    tracker->routing = routing;
    pthread_mutex_init(&tracker->pool_lock, NULL);

    /* Pre-allocate initial pool */
    tracker->pool_size = 4096;
    tracker->entry_pool = malloc(tracker->pool_size * sizeof(FlowEntry));
    if (!tracker->entry_pool) {
        parallel_avl_destroy(tracker->avl);
        pthread_mutex_destroy(&tracker->pool_lock);
        free(tracker);
        return NULL;
    }

    return tracker;
}

void flow_tracker_destroy(FlowTracker* tracker) {
    if (!tracker) return;

    parallel_avl_destroy(tracker->avl);
    pthread_mutex_destroy(&tracker->pool_lock);
    free(tracker->entry_pool);
    free(tracker);
}

/* ============================================================================
 * Flow Operations
 * ============================================================================ */

FlowStats* flow_tracker_record_packet(
    FlowTracker* tracker,
    const FlowKey* key,
    uint32_t packet_size,
    uint8_t tcp_flags
) {
    if (!tracker || !key) return NULL;

    int64_t hash = flow_key_hash(key);
    uint64_t now = time_now_ns();

    /* Try to get existing flow */
    bool found = false;
    FlowEntry* entry = parallel_avl_get(tracker->avl, hash, &found);

    if (found && entry) {
        /* Update existing flow */
        entry->stats.packet_count++;
        entry->stats.byte_count += packet_size;
        entry->stats.last_seen_ns = now;

        /* Track TCP flags */
        if (tcp_flags & 0x02) entry->stats.syn_count++;  /* SYN */
        if (tcp_flags & 0x10) entry->stats.ack_count++;  /* ACK */
        if (tcp_flags & 0x01) entry->stats.fin_count++;  /* FIN */
        if (tcp_flags & 0x04) entry->stats.rst_count++;  /* RST */

        /* Update rate (simple approximation) */
        uint64_t elapsed_ns = now - entry->stats.first_seen_ns;
        if (elapsed_ns > 1000000000ULL) {  /* More than 1 second */
            uint32_t pps = (uint32_t)(entry->stats.packet_count * 1000000000ULL / elapsed_ns);
            uint32_t bps_kb = (uint32_t)(entry->stats.byte_count * 1000000ULL / elapsed_ns);
            update_rate_history(&entry->stats, pps, bps_kb);
        }
    } else {
        /* Create new flow */
        entry = alloc_entry(tracker);
        if (!entry) return NULL;

        memcpy(&entry->key, key, sizeof(FlowKey));
        entry->stats.packet_count = 1;
        entry->stats.byte_count = packet_size;
        entry->stats.first_seen_ns = now;
        entry->stats.last_seen_ns = now;

        if (tcp_flags & 0x02) entry->stats.syn_count = 1;
        if (tcp_flags & 0x10) entry->stats.ack_count = 1;
        if (tcp_flags & 0x01) entry->stats.fin_count = 1;
        if (tcp_flags & 0x04) entry->stats.rst_count = 1;

        parallel_avl_insert(tracker->avl, hash, entry);
        atomic_fetch_add(&tracker->new_flows_count, 1);
    }

    /* Update global counters (lock-free) */
    atomic_fetch_add(&tracker->total_packets, 1);
    atomic_fetch_add(&tracker->total_bytes, packet_size);

    return &entry->stats;
}

bool flow_tracker_get_flow(
    FlowTracker* tracker,
    const FlowKey* key,
    FlowStats* out_stats
) {
    if (!tracker || !key || !out_stats) return false;

    int64_t hash = flow_key_hash(key);
    bool found = false;
    FlowEntry* entry = parallel_avl_get(tracker->avl, hash, &found);

    if (found && entry) {
        memcpy(out_stats, &entry->stats, sizeof(FlowStats));
        return true;
    }
    return false;
}

bool flow_tracker_remove_flow(FlowTracker* tracker, const FlowKey* key) {
    if (!tracker || !key) return false;

    int64_t hash = flow_key_hash(key);
    return parallel_avl_remove(tracker->avl, hash);
}

void flow_tracker_flag_flow(
    FlowTracker* tracker,
    const FlowKey* key,
    AttackType attack_type
) {
    if (!tracker || !key) return;

    int64_t hash = flow_key_hash(key);
    bool found = false;
    FlowEntry* entry = parallel_avl_get(tracker->avl, hash, &found);

    if (found && entry) {
        if (!entry->stats.is_flagged) {
            entry->stats.is_flagged = 1;
            atomic_fetch_add(&tracker->flagged_count, 1);
        }
        entry->stats.attack_types |= attack_type;
    }
}

/* ============================================================================
 * Bulk Operations
 * ============================================================================ */

/* Iterator context for get_flows_by_dst */
typedef struct {
    uint32_t dst_ip;
    FlowKey* out_keys;
    FlowStats* out_stats;
    size_t max_results;
    size_t count;
} DstQueryContext;

static bool dst_query_iterator(const FlowKey* key, const FlowStats* stats, void* user_data) {
    DstQueryContext* ctx = user_data;

    if (key->dst_ip == ctx->dst_ip && ctx->count < ctx->max_results) {
        memcpy(&ctx->out_keys[ctx->count], key, sizeof(FlowKey));
        memcpy(&ctx->out_stats[ctx->count], stats, sizeof(FlowStats));
        ctx->count++;
    }

    return ctx->count < ctx->max_results;
}

size_t flow_tracker_get_flows_by_dst(
    FlowTracker* tracker,
    uint32_t dst_ip,
    FlowKey* out_keys,
    FlowStats* out_stats,
    size_t max_results
) {
    if (!tracker || !out_keys || !out_stats || max_results == 0) return 0;

    DstQueryContext ctx = {
        .dst_ip = dst_ip,
        .out_keys = out_keys,
        .out_stats = out_stats,
        .max_results = max_results,
        .count = 0
    };

    flow_tracker_iterate(tracker, dst_query_iterator, &ctx);
    return ctx.count;
}

/* Iterator context for expiration */
typedef struct {
    FlowTracker* tracker;
    uint64_t cutoff_time;
    size_t expired_count;
    int64_t* keys_to_remove;
    size_t remove_capacity;
    size_t remove_count;
} ExpireContext;

static bool expire_iterator(const FlowKey* key, const FlowStats* stats, void* user_data) {
    ExpireContext* ctx = user_data;

    if (stats->last_seen_ns < ctx->cutoff_time) {
        if (ctx->remove_count < ctx->remove_capacity) {
            ctx->keys_to_remove[ctx->remove_count++] = flow_key_hash(key);
        }
    }

    return true;  /* Continue iteration */
}

size_t flow_tracker_expire_old_flows(FlowTracker* tracker, uint64_t timeout_ns) {
    if (!tracker) return 0;

    uint64_t cutoff = time_now_ns() - timeout_ns;

    /* First pass: collect keys to remove */
    size_t capacity = 1024;
    int64_t* keys_to_remove = malloc(capacity * sizeof(int64_t));
    if (!keys_to_remove) return 0;

    ExpireContext ctx = {
        .tracker = tracker,
        .cutoff_time = cutoff,
        .expired_count = 0,
        .keys_to_remove = keys_to_remove,
        .remove_capacity = capacity,
        .remove_count = 0
    };

    flow_tracker_iterate(tracker, expire_iterator, &ctx);

    /* Second pass: remove collected keys */
    for (size_t i = 0; i < ctx.remove_count; i++) {
        if (parallel_avl_remove(tracker->avl, keys_to_remove[i])) {
            ctx.expired_count++;
        }
    }

    free(keys_to_remove);
    return ctx.expired_count;
}

void flow_tracker_clear(FlowTracker* tracker) {
    if (!tracker) return;

    parallel_avl_clear(tracker->avl);

    atomic_store(&tracker->total_packets, 0);
    atomic_store(&tracker->total_bytes, 0);
    atomic_store(&tracker->flagged_count, 0);
    atomic_store(&tracker->new_flows_count, 0);

    pthread_mutex_lock(&tracker->pool_lock);
    tracker->pool_used = 0;
    pthread_mutex_unlock(&tracker->pool_lock);
}

/* ============================================================================
 * Statistics
 * ============================================================================ */

void flow_tracker_get_metrics(const FlowTracker* tracker, FlowMetrics* out_metrics) {
    if (!tracker || !out_metrics) return;

    memset(out_metrics, 0, sizeof(FlowMetrics));

    out_metrics->timestamp_ns = time_now_ns();
    out_metrics->total_packets = atomic_load(&tracker->total_packets);
    out_metrics->total_bytes = atomic_load(&tracker->total_bytes);
    out_metrics->unique_flows = parallel_avl_size(tracker->avl);
    out_metrics->new_flows = atomic_load(&tracker->new_flows_count);
    out_metrics->suspicious_flows = atomic_load(&tracker->flagged_count);
    out_metrics->shard_balance = parallel_avl_balance_score(tracker->avl);
}

size_t flow_tracker_flow_count(const FlowTracker* tracker) {
    if (!tracker) return 0;
    return parallel_avl_size(tracker->avl);
}

double flow_tracker_balance_score(const FlowTracker* tracker) {
    if (!tracker) return 0.0;
    return parallel_avl_balance_score(tracker->avl);
}

size_t flow_tracker_flagged_count(const FlowTracker* tracker) {
    if (!tracker) return 0;
    return atomic_load(&tracker->flagged_count);
}

/* ============================================================================
 * Dynamic Scaling
 * ============================================================================ */

bool flow_tracker_add_shard(FlowTracker* tracker) {
    if (!tracker) return false;
    return parallel_avl_add_shard(tracker->avl);
}

bool flow_tracker_remove_shard(FlowTracker* tracker) {
    if (!tracker) return false;
    return parallel_avl_remove_shard(tracker->avl);
}

size_t flow_tracker_num_shards(const FlowTracker* tracker) {
    if (!tracker) return 0;
    return parallel_avl_num_shards(tracker->avl);
}

/* ============================================================================
 * Iteration
 * ============================================================================ */

/* We need to iterate through all entries in the AVL tree.
 * Since ParallelAVL doesn't have a native iteration method,
 * we'll use a range query approach or iterate through shards.
 *
 * For now, we use a simplified approach by tracking entries ourselves. */

typedef struct {
    FlowIteratorFn callback;
    void* user_data;
    size_t count;
} IteratorContext;

size_t flow_tracker_iterate(
    FlowTracker* tracker,
    FlowIteratorFn callback,
    void* user_data
) {
    if (!tracker || !callback) return 0;

    size_t count = 0;

    /* Iterate through our pool entries (only used ones) */
    pthread_mutex_lock(&tracker->pool_lock);

    for (size_t i = 0; i < tracker->pool_used; i++) {
        FlowEntry* entry = &tracker->entry_pool[i];

        /* Check if entry is still valid in AVL */
        int64_t hash = flow_key_hash(&entry->key);
        bool found = false;
        FlowEntry* check = parallel_avl_get(tracker->avl, hash, &found);

        if (found && check == entry) {
            if (!callback(&entry->key, &entry->stats, user_data)) {
                break;
            }
            count++;
        }
    }

    pthread_mutex_unlock(&tracker->pool_lock);
    return count;
}
