#pragma once

#include "common.hpp"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <random>
#include <vector>

namespace pavl {

enum class router_strategy : std::uint8_t {
    static_hash,       // Plain hash → shard (fastest)
    load_aware,        // Detect hotspots, redirect to least loaded
    consistent_hash,   // Virtual nodes
    intelligent,       // Adaptive hybrid
};

struct router_stats {
    std::size_t total_load{};
    std::size_t min_load{};
    std::size_t max_load{};
    double avg_load{};
    double balance_score{};
    bool has_hotspot{};
    std::size_t suspicious_patterns{};
    std::size_t blocked_redirects{};
};

class router {
public:
    static constexpr std::size_t vnodes_per_shard = 16;
    static constexpr double hotspot_threshold = 1.5;
    static constexpr std::size_t min_cache_interval = 10;
    static constexpr std::size_t max_cache_interval = 500;

    router(std::size_t num_shards, router_strategy strategy)
        : num_shards_{num_shards},
          mask_{is_power_of_two(num_shards) ? num_shards - 1 : std::size_t{0}},
          strategy_{strategy},
          shard_loads_{std::make_unique<std::atomic<std::size_t>[]>(num_shards)},
          rng_state_{static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(this))
                     ^ 0xdeadbeefcafebabeULL}
    {
        if (strategy == router_strategy::consistent_hash || strategy == router_strategy::intelligent) {
            init_virtual_nodes();
        }
    }

    router(const router&) = delete;
    router& operator=(const router&) = delete;
    router(router&&) = delete;
    router& operator=(router&&) = delete;
    ~router() = default;

    [[nodiscard]] std::size_t num_shards() const noexcept { return num_shards_; }

    [[nodiscard]] PAVL_ALWAYS_INLINE std::size_t natural_shard(std::uint64_t hash) const noexcept {
        if (mask_) [[likely]] return static_cast<std::size_t>(hash) & mask_;
        return static_cast<std::size_t>(hash) % num_shards_;
    }

    [[nodiscard]] PAVL_HOT std::size_t route(std::uint64_t hash) {
        const auto natural = natural_shard(hash);
        switch (strategy_) {
        case router_strategy::static_hash:
            return natural;
        case router_strategy::load_aware:
            return route_load_aware(natural);
        case router_strategy::consistent_hash:
            return route_consistent_hash(hash);
        case router_strategy::intelligent:
            return route_intelligent(natural);
        }
        return natural;
    }

    void record_insertion(std::size_t shard_idx) noexcept {
        if (shard_idx >= num_shards_) return;
        shard_loads_[shard_idx].fetch_add(1, std::memory_order_relaxed);
    }

    void record_removal(std::size_t shard_idx) noexcept {
        if (shard_idx >= num_shards_) return;
        auto cur = shard_loads_[shard_idx].load(std::memory_order_relaxed);
        if (cur > 0) shard_loads_[shard_idx].fetch_sub(1, std::memory_order_relaxed);
    }

    [[nodiscard]] router_stats snapshot() const {
        router_stats s{};
        s.min_load = (std::numeric_limits<std::size_t>::max)();
        for (std::size_t i = 0; i < num_shards_; ++i) {
            const auto load = shard_loads_[i].load(std::memory_order_relaxed);
            s.total_load += load;
            s.min_load = std::min(s.min_load, load);
            s.max_load = std::max(s.max_load, load);
        }
        s.avg_load = static_cast<double>(s.total_load) / static_cast<double>(num_shards_);
        if (s.avg_load > 0) {
            double variance = 0;
            for (std::size_t i = 0; i < num_shards_; ++i) {
                const auto load = static_cast<double>(shard_loads_[i].load(std::memory_order_relaxed));
                const double diff = load - s.avg_load;
                variance += diff * diff;
            }
            variance /= static_cast<double>(num_shards_);
            const double std_dev = std::sqrt(variance);
            s.balance_score = std::max(0.0, 1.0 - std_dev / s.avg_load);
        } else {
            s.balance_score = 1.0;
        }
        s.has_hotspot = static_cast<double>(s.max_load) > hotspot_threshold * s.avg_load;
        s.suspicious_patterns = suspicious_patterns_.load(std::memory_order_relaxed);
        s.blocked_redirects = blocked_redirects_.load(std::memory_order_relaxed);
        return s;
    }

private:
    struct virtual_node {
        std::size_t shard_id;
        std::uint64_t hash_value;
    };

    void init_virtual_nodes() {
        const auto total = num_shards_ * vnodes_per_shard;
        virtual_nodes_.reserve(total);
        for (std::size_t shard = 0; shard < num_shards_; ++shard) {
            for (std::size_t v = 0; v < vnodes_per_shard; ++v) {
                const std::uint64_t seed = shard * vnodes_per_shard + v;
                virtual_nodes_.push_back({shard, mix64(seed)});
            }
        }
        std::ranges::sort(virtual_nodes_, {}, &virtual_node::hash_value);
    }

    std::size_t route_load_aware(std::size_t natural) {
        const auto primary_load = shard_loads_[natural].load(std::memory_order_relaxed);
        std::size_t total = 0;
        for (std::size_t i = 0; i < num_shards_; ++i) {
            total += shard_loads_[i].load(std::memory_order_relaxed);
        }
        const double avg = static_cast<double>(total) / static_cast<double>(num_shards_);
        if (static_cast<double>(primary_load) <= hotspot_threshold * avg) [[likely]] return natural;
        std::size_t best = 0;
        auto min_load = shard_loads_[0].load(std::memory_order_relaxed);
        for (std::size_t i = 1; i < num_shards_; ++i) {
            const auto load = shard_loads_[i].load(std::memory_order_relaxed);
            if (load < min_load) { best = i; min_load = load; }
        }
        if (static_cast<double>(min_load) < avg) return best;
        std::scoped_lock lock{rng_mutex_};
        return xorshift64() % num_shards_;
    }

    std::size_t route_consistent_hash(std::uint64_t hash) const noexcept {
        if (virtual_nodes_.empty()) [[unlikely]] return natural_shard(hash);
        auto it = std::ranges::lower_bound(virtual_nodes_, hash, {}, &virtual_node::hash_value);
        if (it == virtual_nodes_.end()) it = virtual_nodes_.begin();
        return it->shard_id;
    }

    std::size_t route_intelligent(std::size_t natural) {
        const auto interval = adaptive_interval_.load(std::memory_order_relaxed);
        if (interval >= max_cache_interval) [[likely]] return natural;
        const auto ops = ops_since_cache_.fetch_add(1, std::memory_order_relaxed);
        if (ops >= interval) {
            ops_since_cache_.store(0, std::memory_order_relaxed);
            update_stats_cache();
        }
        if (cached_has_hotspot_.load(std::memory_order_relaxed)
            || cached_balance_score_.load(std::memory_order_relaxed) < 0.9) {
            return route_load_aware(natural);
        }
        return natural;
    }

    void update_stats_cache() {
        std::size_t total = 0, mn = (std::numeric_limits<std::size_t>::max)(), mx = 0;
        for (std::size_t i = 0; i < num_shards_; ++i) {
            const auto load = shard_loads_[i].load(std::memory_order_relaxed);
            total += load;
            mn = std::min(mn, load);
            mx = std::max(mx, load);
        }
        const double avg = static_cast<double>(total) / static_cast<double>(num_shards_);
        const double balance = avg > 0 ? std::max(0.0, 1.0 - static_cast<double>(mx - mn) / (2.0 * avg)) : 1.0;
        const bool hotspot = static_cast<double>(mx) > hotspot_threshold * avg;
        cached_balance_score_.store(balance, std::memory_order_relaxed);
        cached_has_hotspot_.store(hotspot, std::memory_order_relaxed);
        std::size_t new_interval;
        if (hotspot || balance < 0.8) new_interval = min_cache_interval;
        else if (balance > 0.95) new_interval = max_cache_interval;
        else new_interval = min_cache_interval + static_cast<std::size_t>((balance - 0.8) * (max_cache_interval - min_cache_interval) / 0.15);
        adaptive_interval_.store(new_interval, std::memory_order_relaxed);
    }

    [[nodiscard]] std::uint64_t xorshift64() noexcept {
        auto x = rng_state_;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        rng_state_ = x;
        return x;
    }

    std::size_t num_shards_;
    std::size_t mask_;
    router_strategy strategy_;
    std::unique_ptr<std::atomic<std::size_t>[]> shard_loads_;
    std::vector<virtual_node> virtual_nodes_;

    std::atomic<std::size_t> ops_since_cache_{0};
    std::atomic<bool> cached_has_hotspot_{false};
    std::atomic<std::size_t> adaptive_interval_{min_cache_interval};
    // Approximate balance metric. Lock-free atomic<double> on x86_64 / ARMv8
    // — same cost as a plain double load, plus TSan can reason about it.
    std::atomic<double> cached_balance_score_{1.0};
    static_assert(std::atomic<double>::is_always_lock_free,
                  "atomic<double> must be lock-free for the intelligent router fast path");

    std::atomic<std::size_t> suspicious_patterns_{0};
    std::atomic<std::size_t> blocked_redirects_{0};

    std::uint64_t rng_state_;
    std::mutex rng_mutex_;
};

}  // namespace pavl
