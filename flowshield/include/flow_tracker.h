/**
 * FlowShield - Flow Tracker
 *
 * High-performance concurrent flow tracking using ParallelAVL.
 * Supports millions of concurrent flows with lock-free statistics.
 */

#ifndef FLOWSHIELD_FLOW_TRACKER_H
#define FLOWSHIELD_FLOW_TRACKER_H

#include "flow_types.h"
#include "../../include/parallel_avl.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Flow Tracker Handle
 * ============================================================================ */

typedef struct FlowTracker FlowTracker;

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

/**
 * Create a new flow tracker.
 *
 * @param num_shards    Number of ParallelAVL shards (recommend: CPU cores)
 * @param routing       Routing strategy (ROUTER_LOAD_AWARE recommended)
 * @return              New tracker or NULL on error
 */
FlowTracker* flow_tracker_create(size_t num_shards, RouterStrategy routing);

/**
 * Destroy flow tracker and free all resources.
 */
void flow_tracker_destroy(FlowTracker* tracker);

/* ============================================================================
 * Flow Operations
 * ============================================================================ */

/**
 * Record a packet for a flow (upsert operation).
 * If flow exists, updates counters. If new, creates flow entry.
 *
 * @param tracker       Flow tracker instance
 * @param key           5-tuple flow key
 * @param packet_size   Size of packet in bytes
 * @param tcp_flags     TCP flags (SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04)
 * @return              Pointer to updated flow stats (valid until next op)
 */
FlowStats* flow_tracker_record_packet(
    FlowTracker* tracker,
    const FlowKey* key,
    uint32_t packet_size,
    uint8_t tcp_flags
);

/**
 * Get statistics for a specific flow.
 *
 * @param tracker       Flow tracker instance
 * @param key           5-tuple flow key
 * @param out_stats     Output buffer for stats
 * @return              true if flow exists, false otherwise
 */
bool flow_tracker_get_flow(
    FlowTracker* tracker,
    const FlowKey* key,
    FlowStats* out_stats
);

/**
 * Remove a flow from tracking.
 *
 * @param tracker       Flow tracker instance
 * @param key           5-tuple flow key
 * @return              true if flow was removed, false if not found
 */
bool flow_tracker_remove_flow(FlowTracker* tracker, const FlowKey* key);

/**
 * Mark a flow as suspicious.
 *
 * @param tracker       Flow tracker instance
 * @param key           5-tuple flow key
 * @param attack_type   Type of attack detected
 */
void flow_tracker_flag_flow(
    FlowTracker* tracker,
    const FlowKey* key,
    AttackType attack_type
);

/* ============================================================================
 * Bulk Operations
 * ============================================================================ */

/**
 * Get all flows for a destination IP (for target analysis).
 * Uses range query optimization when possible.
 *
 * @param tracker       Flow tracker instance
 * @param dst_ip        Destination IP to query
 * @param out_keys      Output array for flow keys
 * @param out_stats     Output array for flow stats
 * @param max_results   Maximum flows to return
 * @return              Number of flows found
 */
size_t flow_tracker_get_flows_by_dst(
    FlowTracker* tracker,
    uint32_t dst_ip,
    FlowKey* out_keys,
    FlowStats* out_stats,
    size_t max_results
);

/**
 * Expire old flows that haven't been seen recently.
 *
 * @param tracker       Flow tracker instance
 * @param timeout_ns    Timeout in nanoseconds
 * @return              Number of flows expired
 */
size_t flow_tracker_expire_old_flows(
    FlowTracker* tracker,
    uint64_t timeout_ns
);

/**
 * Clear all flows (reset tracker).
 */
void flow_tracker_clear(FlowTracker* tracker);

/* ============================================================================
 * Statistics
 * ============================================================================ */

/**
 * Get current tracker metrics.
 *
 * @param tracker       Flow tracker instance
 * @param out_metrics   Output buffer for metrics
 */
void flow_tracker_get_metrics(
    const FlowTracker* tracker,
    FlowMetrics* out_metrics
);

/**
 * Get total number of active flows.
 */
size_t flow_tracker_flow_count(const FlowTracker* tracker);

/**
 * Get load balance score (0.0 = completely unbalanced, 1.0 = perfect).
 */
double flow_tracker_balance_score(const FlowTracker* tracker);

/**
 * Get number of flagged (suspicious) flows.
 */
size_t flow_tracker_flagged_count(const FlowTracker* tracker);

/* ============================================================================
 * Dynamic Scaling
 * ============================================================================ */

/**
 * Add a new shard to handle increased load.
 * Triggers automatic rebalancing.
 *
 * @return              true if shard added successfully
 */
bool flow_tracker_add_shard(FlowTracker* tracker);

/**
 * Remove a shard (scale down).
 *
 * @return              true if shard removed successfully
 */
bool flow_tracker_remove_shard(FlowTracker* tracker);

/**
 * Get current number of shards.
 */
size_t flow_tracker_num_shards(const FlowTracker* tracker);

/* ============================================================================
 * Iteration (for batch analysis)
 * ============================================================================ */

/**
 * Callback function type for flow iteration.
 *
 * @param key           Flow key
 * @param stats         Flow statistics
 * @param user_data     User-provided context
 * @return              true to continue iteration, false to stop
 */
typedef bool (*FlowIteratorFn)(
    const FlowKey* key,
    const FlowStats* stats,
    void* user_data
);

/**
 * Iterate over all flows (calls callback for each).
 * Note: Iteration is not atomic across shards.
 *
 * @param tracker       Flow tracker instance
 * @param callback      Function to call for each flow
 * @param user_data     User context passed to callback
 * @return              Number of flows iterated
 */
size_t flow_tracker_iterate(
    FlowTracker* tracker,
    FlowIteratorFn callback,
    void* user_data
);

#ifdef __cplusplus
}
#endif

#endif /* FLOWSHIELD_FLOW_TRACKER_H */
