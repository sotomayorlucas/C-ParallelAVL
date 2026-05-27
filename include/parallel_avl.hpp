#pragma once

#include "common.hpp"
#include "redirect_index.hpp"
#include "router.hpp"
#include "shard.hpp"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <iterator>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <utility>
#include <vector>

namespace pavl {

template <avl_key Key, avl_value Value>
class parallel_avl {
public:
    using shard_type = shard<Key, Value>;
    using key_value = typename shard_type::key_value;

    struct stats {
        std::size_t num_shards{};
        std::size_t total_size{};
        std::size_t total_ops{};
        std::vector<std::size_t> shard_sizes{};
        std::vector<std::size_t> shard_inserts{};
        std::vector<std::size_t> shard_lookups{};
        double balance_score{};
        bool has_hotspot{};
        std::size_t suspicious_patterns{};
        std::size_t blocked_redirects{};
        std::size_t redirect_index_size{};
        std::size_t redirect_index_hits{};
        double redirect_hit_rate{};
        std::size_t redirect_index_memory_bytes{};
    };

    explicit parallel_avl(std::size_t num_shards = 8,
                          router_strategy strategy = router_strategy::intelligent)
        : router_{std::make_unique<router>(num_shards == 0 ? 8 : num_shards, strategy)}
    {
        const auto n = num_shards == 0 ? 8 : num_shards;
        shards_.reserve(n);
        for (std::size_t i = 0; i < n; ++i) {
            shards_.push_back(std::make_unique<shard_type>());
        }
        refresh_cache();
    }

    parallel_avl(const parallel_avl&) = delete;
    parallel_avl& operator=(const parallel_avl&) = delete;
    parallel_avl(parallel_avl&&) = delete;
    parallel_avl& operator=(parallel_avl&&) = delete;
    ~parallel_avl() = default;

    [[nodiscard]] std::size_t num_shards() const noexcept {
        std::shared_lock topo_lock{topology_mutex_};
        return num_shards_;
    }

    [[nodiscard]] PAVL_ALWAYS_INLINE std::size_t size() const noexcept {
        std::shared_lock topo_lock{topology_mutex_};
        std::size_t total = 0;
        for (std::size_t i = 0; i < num_shards_; ++i) total += shards_raw_[i]->size();
        return total;
    }

    [[nodiscard]] bool empty() const noexcept { return size() == 0; }

    PAVL_HOT void insert(const Key& key, Value value) {
        std::shared_lock topo_lock{topology_mutex_};
        total_ops_.fetch_add(1, std::memory_order_relaxed);
        const auto h = key_hash(key);
        const auto natural = static_cast<std::size_t>(h) % num_shards_;
        const auto target = router_raw_->route(h);
        auto* shard = shards_raw_[target];
        const auto old_size = shard->size();
        shard->insert(key, std::move(value));
        const auto new_size = shard->size();
        if (new_size > old_size) {
            router_raw_->record_insertion(target);
            if (target != natural) [[unlikely]] {
                redirect_index_.record(key, natural, target);
                has_redirects_.store(true, std::memory_order_release);
            }
        }
    }

    [[nodiscard]] PAVL_HOT bool contains(const Key& key) {
        std::shared_lock topo_lock{topology_mutex_};
        const auto h = key_hash(key);
        const auto natural = static_cast<std::size_t>(h) % num_shards_;
        if (shards_raw_[natural]->contains(key)) [[likely]] return true;
        const bool has_redirects = has_redirects_.load(std::memory_order_acquire);
        const bool topology_changed = topology_changed_.load(std::memory_order_acquire);
        if (!has_redirects && !topology_changed) [[likely]] return false;
        total_ops_.fetch_add(1, std::memory_order_relaxed);
        if (has_redirects) {
            if (auto r = redirect_index_.lookup(key)) {
                redirect_hits_.fetch_add(1, std::memory_order_relaxed);
                return shards_raw_[*r]->contains(key);
            }
        }
        if (topology_changed) {
            for (std::size_t i = 0; i < num_shards_; ++i) {
                if (i == natural) continue;
                if (shards_raw_[i]->contains(key)) return true;
            }
        }
        return false;
    }

    [[nodiscard]] PAVL_HOT std::optional<Value> get(const Key& key)
        requires std::copyable<Value>
    {
        std::shared_lock topo_lock{topology_mutex_};
        const auto h = key_hash(key);
        const auto natural = static_cast<std::size_t>(h) % num_shards_;
        if (auto v = shards_raw_[natural]->get(key)) [[likely]] return v;
        const bool has_redirects = has_redirects_.load(std::memory_order_acquire);
        const bool topology_changed = topology_changed_.load(std::memory_order_acquire);
        if (!has_redirects && !topology_changed) [[likely]] return std::nullopt;
        total_ops_.fetch_add(1, std::memory_order_relaxed);
        if (has_redirects) {
            if (auto r = redirect_index_.lookup(key)) {
                redirect_hits_.fetch_add(1, std::memory_order_relaxed);
                return shards_raw_[*r]->get(key);
            }
        }
        if (topology_changed) {
            for (std::size_t i = 0; i < num_shards_; ++i) {
                if (i == natural) continue;
                if (auto v = shards_raw_[i]->get(key)) return v;
            }
        }
        return std::nullopt;
    }

    template <std::invocable<Value&> F>
    [[nodiscard]] bool visit(const Key& key, F&& f) {
        std::shared_lock topo_lock{topology_mutex_};
        const auto h = key_hash(key);
        const auto natural = static_cast<std::size_t>(h) % num_shards_;
        if (shards_raw_[natural]->visit(key, f)) [[likely]] return true;
        const bool has_redirects = has_redirects_.load(std::memory_order_acquire);
        const bool topology_changed = topology_changed_.load(std::memory_order_acquire);
        if (!has_redirects && !topology_changed) [[likely]] return false;
        if (has_redirects) {
            if (auto r = redirect_index_.lookup(key)) return shards_raw_[*r]->visit(key, f);
        }
        if (topology_changed) {
            for (std::size_t i = 0; i < num_shards_; ++i) {
                if (i == natural) continue;
                if (shards_raw_[i]->visit(key, f)) return true;
            }
        }
        return false;
    }

    bool remove(const Key& key) {
        std::shared_lock topo_lock{topology_mutex_};
        total_ops_.fetch_add(1, std::memory_order_relaxed);
        const auto h = key_hash(key);
        const auto natural = static_cast<std::size_t>(h) % num_shards_;
        if (shards_raw_[natural]->remove(key)) {
            router_raw_->record_removal(natural);
            redirect_index_.remove(key);
            return true;
        }
        if (auto r = redirect_index_.lookup(key)) {
            if (shards_raw_[*r]->remove(key)) {
                router_raw_->record_removal(*r);
                redirect_index_.remove(key);
                return true;
            }
        }
        if (topology_changed_.load(std::memory_order_acquire)) {
            for (std::size_t i = 0; i < num_shards_; ++i) {
                if (i == natural) continue;
                if (shards_raw_[i]->remove(key)) {
                    router_raw_->record_removal(i);
                    return true;
                }
            }
        }
        return false;
    }

    [[nodiscard]] std::vector<key_value> range_query(const Key& lo, const Key& hi, std::size_t max_results) {
        std::shared_lock topo_lock{topology_mutex_};
        std::vector<key_value> out;
        total_ops_.fetch_add(1, std::memory_order_relaxed);
        out.reserve(std::min(max_results, std::size_t{1024}));
        const std::size_t buffer_cap = max_results * 2;
        for (std::size_t i = 0; i < num_shards_; ++i) {
            if (out.size() >= buffer_cap) break;
            auto* s = shards_raw_[i];
            if (!s->intersects_range(lo, hi)) continue;
            s->range_query(lo, hi, out, buffer_cap);
        }
        std::ranges::sort(out, {}, &key_value::key);
        if (out.size() > max_results) out.resize(max_results);
        return out;
    }

    [[nodiscard]] double balance_score() const {
        std::shared_lock topo_lock{topology_mutex_};
        return router_raw_->snapshot().balance_score;
    }

    void clear() {
        std::shared_lock topo_lock{topology_mutex_};
        for (std::size_t i = 0; i < num_shards_; ++i) shards_raw_[i]->clear();
        redirect_index_.clear();
        total_ops_.store(0, std::memory_order_relaxed);
        redirect_hits_.store(0, std::memory_order_relaxed);
    }

    bool add_shard() {
        std::unique_lock topo_lock{topology_mutex_};
        shards_.push_back(std::make_unique<shard_type>());
        const auto rs = router_raw_->snapshot();
        const auto strategy = rs.balance_score > 0.9
                                  ? router_strategy::intelligent
                                  : router_strategy::load_aware;
        router_ = std::make_unique<router>(shards_.size(), strategy);
        refresh_cache();
        topology_changed_.store(true, std::memory_order_release);
        return true;
    }

    bool remove_shard() {
        std::unique_lock topo_lock{topology_mutex_};
        if (shards_.size() <= 1) return false;
        auto removing = std::move(shards_.back());
        shards_.pop_back();
        auto leftover = removing->extract_all();
        router_ = std::make_unique<router>(shards_.size(), router_strategy::intelligent);
        refresh_cache();
        topology_changed_.store(true, std::memory_order_release);
        for (auto& kv : leftover) {
            const auto h = key_hash(kv.key);
            const auto target = router_raw_->route(h);
            shards_raw_[target]->insert(kv.key, std::move(kv.value));
            router_raw_->record_insertion(target);
        }
        return true;
    }

    void force_rebalance() {
        std::unique_lock topo_lock{topology_mutex_};
        const auto total_size_unlocked = [this] {
            std::size_t total = 0;
            for (std::size_t i = 0; i < num_shards_; ++i) total += shards_raw_[i]->size();
            return total;
        }();
        if (total_size_unlocked == 0) return;
        std::vector<key_value> all;
        all.reserve(total_size_unlocked);
        for (std::size_t i = 0; i < num_shards_; ++i) {
            auto chunk = shards_raw_[i]->extract_all();
            std::ranges::move(chunk, std::back_inserter(all));
        }
        for (std::size_t i = 0; i < num_shards_; ++i) shards_raw_[i]->clear();
        redirect_index_.clear();
        router_ = std::make_unique<router>(shards_.size(), router_strategy::static_hash);
        refresh_cache();
        for (auto& kv : all) {
            const auto h = key_hash(kv.key);
            const auto target = static_cast<std::size_t>(h) % num_shards_;
            shards_raw_[target]->insert(kv.key, std::move(kv.value));
            router_raw_->record_insertion(target);
        }
        total_ops_.store(all.size(), std::memory_order_relaxed);
        redirect_hits_.store(0, std::memory_order_relaxed);
        topology_changed_.store(false, std::memory_order_release);
        has_redirects_.store(false, std::memory_order_release);
    }

    [[nodiscard]] stats snapshot() const {
        std::shared_lock topo_lock{topology_mutex_};
        stats s{};
        s.num_shards = num_shards_;
        s.total_ops = total_ops_.load(std::memory_order_relaxed);
        s.shard_sizes.reserve(num_shards_);
        s.shard_inserts.reserve(num_shards_);
        s.shard_lookups.reserve(num_shards_);
        for (std::size_t i = 0; i < num_shards_; ++i) {
            const auto ss = shards_raw_[i]->snapshot();
            s.total_size += ss.size;
            s.shard_sizes.push_back(ss.size);
            s.shard_inserts.push_back(ss.inserts);
            s.shard_lookups.push_back(ss.lookups);
        }
        const auto rs = router_raw_->snapshot();
        s.balance_score = rs.balance_score;
        s.has_hotspot = rs.has_hotspot;
        s.suspicious_patterns = rs.suspicious_patterns;
        s.blocked_redirects = rs.blocked_redirects;
        const auto ris = redirect_index_.snapshot();
        s.redirect_index_size = ris.index_size;
        s.redirect_index_hits = redirect_hits_.load(std::memory_order_relaxed);
        s.redirect_hit_rate = s.total_ops > 0
                                  ? static_cast<double>(s.redirect_index_hits) * 100.0 / static_cast<double>(s.total_ops)
                                  : 0.0;
        s.redirect_index_memory_bytes = redirect_index_.approximate_memory_bytes();
        return s;
    }

private:
    // Recache raw pointers + num_shards after any structural change.
    // Hot paths use shards_raw_/router_raw_/num_shards_ to skip the
    // vector + unique_ptr double indirection.
    void refresh_cache() {
        shards_storage_.clear();
        shards_storage_.reserve(shards_.size());
        for (auto& s : shards_) shards_storage_.push_back(s.get());
        shards_raw_ = shards_storage_.data();
        num_shards_ = shards_.size();
        router_raw_ = router_.get();
    }

    // topology_mutex_ guards mutation of shards_/router_ (unique_lock on
    // add_shard/remove_shard/force_rebalance) vs concurrent reads of the
    // cached raw pointers from hot paths (shared_lock on insert/contains/...).
    // Without this, concurrent scaling races against in-flight ops.
    mutable std::shared_mutex topology_mutex_;

    std::vector<std::unique_ptr<shard_type>> shards_;
    std::vector<shard_type*> shards_storage_;
    shard_type* const* shards_raw_{nullptr};
    std::size_t num_shards_{0};

    std::unique_ptr<router> router_;
    router* router_raw_{nullptr};

    redirect_index<Key> redirect_index_{};

    std::atomic<bool> topology_changed_{false};
    std::atomic<bool> has_redirects_{false};
    std::atomic<std::size_t> total_ops_{0};
    std::atomic<std::size_t> redirect_hits_{0};
};

}  // namespace pavl
