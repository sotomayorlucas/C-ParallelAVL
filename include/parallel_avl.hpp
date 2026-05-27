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
#include <thread>
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
        read_guard topo_lock{this};
        return num_shards_;
    }

    [[nodiscard]] PAVL_ALWAYS_INLINE std::size_t size() const noexcept {
        read_guard topo_lock{this};
        std::size_t total = 0;
        for (std::size_t i = 0; i < num_shards_; ++i) total += shards_raw_[i]->size();
        return total;
    }

    [[nodiscard]] bool empty() const noexcept { return size() == 0; }

    struct insert_outcome { bool inserted; };

    PAVL_HOT void insert(const Key& key, Value value) {
        (void)insert_or_assign(key, std::move(value));
    }

    // try_insert: no-op if the key is already present anywhere in the tree.
    insert_outcome try_insert(const Key& key, Value value) {
        read_guard topo_lock{this};
        total_ops_.fetch_add(1, std::memory_order_relaxed);
        const auto h = key_hash(key);
        const auto natural = static_cast<std::size_t>(h) % num_shards_;
        const auto target = router_raw_->route(h);
        const auto r = shards_raw_[target]->try_insert(key, std::move(value));
        if (r.inserted) {
            router_raw_->record_insertion(target);
            if (target != natural) [[unlikely]] {
                redirect_index_.record(key, natural, target);
                has_redirects_.store(true, std::memory_order_release);
            }
        }
        return {r.inserted};
    }

    // insert_or_assign: overwrites existing value, reports if it was new.
    insert_outcome insert_or_assign(const Key& key, Value value) {
        read_guard topo_lock{this};
        total_ops_.fetch_add(1, std::memory_order_relaxed);
        const auto h = key_hash(key);
        const auto natural = static_cast<std::size_t>(h) % num_shards_;
        const auto target = router_raw_->route(h);
        const auto r = shards_raw_[target]->insert_or_assign(key, std::move(value));
        if (r.inserted) {
            router_raw_->record_insertion(target);
            if (target != natural) [[unlikely]] {
                redirect_index_.record(key, natural, target);
                has_redirects_.store(true, std::memory_order_release);
            }
        }
        return {r.inserted};
    }

    // try_emplace: construct Value in-place if the key is absent.
    template <typename... Args>
    insert_outcome try_emplace(const Key& key, Args&&... args) {
        read_guard topo_lock{this};
        total_ops_.fetch_add(1, std::memory_order_relaxed);
        const auto h = key_hash(key);
        const auto natural = static_cast<std::size_t>(h) % num_shards_;
        const auto target = router_raw_->route(h);
        const auto r = shards_raw_[target]->try_emplace(key, std::forward<Args>(args)...);
        if (r.inserted) {
            router_raw_->record_insertion(target);
            if (target != natural) [[unlikely]] {
                redirect_index_.record(key, natural, target);
                has_redirects_.store(true, std::memory_order_release);
            }
        }
        return {r.inserted};
    }

    [[nodiscard]] PAVL_HOT bool contains(const Key& key) {
        read_guard topo_lock{this};
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
        read_guard topo_lock{this};
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
        read_guard topo_lock{this};
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
        read_guard topo_lock{this};
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
        read_guard topo_lock{this};
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
        read_guard topo_lock{this};
        return router_raw_->snapshot().balance_score;
    }

    void clear() {
        read_guard topo_lock{this};
        for (std::size_t i = 0; i < num_shards_; ++i) shards_raw_[i]->clear();
        redirect_index_.clear();
        total_ops_.store(0, std::memory_order_relaxed);
        redirect_hits_.store(0, std::memory_order_relaxed);
    }

    bool add_shard() {
        write_guard topo_lock{this};
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
        write_guard topo_lock{this};
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
        write_guard topo_lock{this};
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
        read_guard topo_lock{this};
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

    // ----- topology protection (hand-rolled RW gate) ------------------
    //
    // Hot paths use the cached raw pointers (shards_raw_/router_raw_/
    // num_shards_). A scaling op (add/remove/rebalance/clear) needs to
    // mutate those without freeing storage that an in-flight reader is
    // still touching. The original implementation used std::shared_mutex,
    // which cost ~30% on the pure-read stress test; this hand-rolled
    // counter is the same idea but avoids the pthread_rwlock_t machinery
    // libstdc++ uses underneath shared_mutex.
    //
    // Protocol:
    //   reader::enter  ->  fetch_add(active_readers_, acquire)
    //                      if scaling_wanted_ != 0  rollback + block
    //   reader::exit   ->  fetch_sub(active_readers_, release)
    //   writer::enter  ->  scaling_mutex_.lock()                     // serialize writers
    //                      scaling_wanted_.store(1, release)         // block new readers
    //                      spin/yield until active_readers_ == 0     // drain
    //   writer::exit   ->  scaling_wanted_.store(0, release)
    //                      scaling_mutex_.unlock()                   // unblock readers
    //
    // Padded to its own cache line to keep the writer's flag away from
    // unrelated atomics (size_/router stats).
    alignas(cache_line_size) mutable std::atomic<std::size_t> active_readers_{0};
    alignas(cache_line_size) mutable std::atomic<int>         scaling_wanted_{0};
    mutable std::mutex scaling_mutex_;

    class read_guard {
        const parallel_avl* t_;
    public:
        PAVL_ALWAYS_INLINE explicit read_guard(const parallel_avl* t) noexcept : t_{t} {
            while (true) {
                t_->active_readers_.fetch_add(1, std::memory_order_acquire);
                if (t_->scaling_wanted_.load(std::memory_order_relaxed) == 0) [[likely]] return;
                t_->active_readers_.fetch_sub(1, std::memory_order_release);
                // A writer wants to scale. Park on scaling_mutex_ — it
                // is held by the writer for the duration of the mutation.
                t_->scaling_mutex_.lock();
                t_->scaling_mutex_.unlock();
            }
        }
        PAVL_ALWAYS_INLINE ~read_guard() noexcept {
            t_->active_readers_.fetch_sub(1, std::memory_order_release);
        }
        read_guard(const read_guard&) = delete;
        read_guard& operator=(const read_guard&) = delete;
    };

    class write_guard {
        parallel_avl* t_;
    public:
        explicit write_guard(parallel_avl* t) : t_{t} {
            t_->scaling_mutex_.lock();
            t_->scaling_wanted_.store(1, std::memory_order_release);
            // Drain in-flight readers. After this loop returns we know
            // no thread is observing the *current* shards_raw_/router_raw_.
            while (t_->active_readers_.load(std::memory_order_acquire) > 0) {
                std::this_thread::yield();
            }
        }
        ~write_guard() noexcept {
            t_->scaling_wanted_.store(0, std::memory_order_release);
            t_->scaling_mutex_.unlock();
        }
        write_guard(const write_guard&) = delete;
        write_guard& operator=(const write_guard&) = delete;
    };

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
