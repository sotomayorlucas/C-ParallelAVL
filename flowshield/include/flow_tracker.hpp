/**
 * FlowShield - Flow Tracker (C++23)
 *
 * High-performance concurrent flow tracking using ParallelAVL.
 */

#pragma once

#include "flow_types.hpp"

#include "parallel_avl.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

namespace flowshield {

// Flow entry stored in the AVL tree. Pointers to elements of the entry pool
// are inserted as values; the pool owns the storage.
struct flow_entry {
    flow_key   key{};
    flow_stats stats{};
};

class flow_tracker {
public:
    using avl_type = pavl::parallel_avl<std::int64_t, flow_entry*>;

    // Callback type for flow iteration. Returns true to continue.
    using iterator_fn = std::function<bool(const flow_key&, const flow_stats&)>;

    explicit flow_tracker(std::size_t num_shards = 8,
                          pavl::router_strategy routing = pavl::router_strategy::load_aware);

    flow_tracker(const flow_tracker&)            = delete;
    flow_tracker& operator=(const flow_tracker&) = delete;
    flow_tracker(flow_tracker&&)                 = delete;
    flow_tracker& operator=(flow_tracker&&)      = delete;
    ~flow_tracker()                              = default;

    // ----- Flow operations -----

    // Returns a pointer to the (updated) stats for the flow. The pointer is
    // valid until clear() / destruction; entries are never moved within the
    // pool of std::unique_ptr-owned blocks.
    flow_stats* record_packet(const flow_key& key,
                              std::uint32_t   packet_size,
                              std::uint8_t    tcp_flags);

    [[nodiscard]] std::optional<flow_stats> get_flow(const flow_key& key);
    bool                                    remove_flow(const flow_key& key);
    void                                    flag_flow(const flow_key& key, attack_type type);

    // ----- Bulk operations -----

    [[nodiscard]] std::vector<std::pair<flow_key, flow_stats>>
        get_flows_by_dst(std::uint32_t dst_ip, std::size_t max_results);

    std::size_t expire_old_flows(std::uint64_t timeout_ns);

    void clear();

    // ----- Statistics -----

    [[nodiscard]] flow_metrics get_metrics() const;
    [[nodiscard]] std::size_t  flow_count() const;
    [[nodiscard]] double       balance_score() const;
    [[nodiscard]] std::size_t  flagged_count() const noexcept {
        return flagged_count_.load(std::memory_order_relaxed);
    }

    // ----- Dynamic scaling -----

    bool                      add_shard();
    bool                      remove_shard();
    [[nodiscard]] std::size_t num_shards() const;

    // ----- Iteration -----

    // Iterate over all flows. Iteration is not atomic across shards.
    // Returns the number of flows visited.
    std::size_t iterate(const iterator_fn& callback);

    // Access for internal cooperation (e.g. anomaly_detector wants to flag).
    [[nodiscard]] avl_type& tree() noexcept { return *avl_; }

private:
    // Pool of allocated entries. We append unique_ptr<flow_entry> blocks so
    // existing pointers stay stable across growth (unlike a flat realloc'd
    // array of by-value entries — the C version relied on that being safe
    // until the next realloc, which happened to work for small workloads).
    flow_entry* alloc_entry();

    std::unique_ptr<avl_type> avl_;
    pavl::router_strategy     routing_;

    std::atomic<std::size_t>  total_packets_{0};
    std::atomic<std::size_t>  total_bytes_{0};
    std::atomic<std::size_t>  flagged_count_{0};
    std::atomic<std::size_t>  new_flows_count_{0};

    std::atomic<std::uint64_t> last_metrics_time_{0};
    std::atomic<std::uint64_t> peak_pps_{0};

    // Entry pool with stable pointers.
    mutable std::mutex                       pool_lock_;
    std::vector<std::unique_ptr<flow_entry>> entry_pool_;
};

}  // namespace flowshield
