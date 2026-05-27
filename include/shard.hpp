#pragma once

#include "avl_tree.hpp"
#include "common.hpp"

#include <atomic>
#include <limits>
#include <mutex>
#include <optional>
#include <vector>

namespace pavl {

template <avl_key Key, avl_value Value>
class shard {
public:
    using tree_type = avl_tree<Key, Value>;
    using key_value = typename tree_type::key_value;

    struct stats {
        std::size_t size{};
        std::size_t inserts{};
        std::size_t removes{};
        std::size_t lookups{};
        std::optional<Key> min_key{};
        std::optional<Key> max_key{};
    };

    shard() = default;
    shard(const shard&) = delete;
    shard& operator=(const shard&) = delete;
    shard(shard&&) = delete;  // mutex/atomic members are not movable
    shard& operator=(shard&&) = delete;
    ~shard() = default;

    // shard's insert_result intentionally omits the value pointer: outside
    // of the shard mutex a concurrent remove could invalidate it. For
    // post-insert access use visit(key, lambda).
    struct insert_outcome { bool inserted; };

    PAVL_HOT void insert(Key key, Value value) {
        std::scoped_lock lock{mutex_};
        const auto r = tree_.insert_or_assign(key, std::move(value));
        if (r.inserted) {
            size_.fetch_add(1, std::memory_order_relaxed);
            update_bounds(key);
        }
        insert_count_.fetch_add(1, std::memory_order_relaxed);
    }

    insert_outcome try_insert(Key key, Value value) {
        std::scoped_lock lock{mutex_};
        const auto r = tree_.try_insert(key, std::move(value));
        if (r.inserted) {
            size_.fetch_add(1, std::memory_order_relaxed);
            update_bounds(key);
        }
        insert_count_.fetch_add(1, std::memory_order_relaxed);
        return {r.inserted};
    }

    insert_outcome insert_or_assign(Key key, Value value) {
        std::scoped_lock lock{mutex_};
        const auto r = tree_.insert_or_assign(key, std::move(value));
        if (r.inserted) {
            size_.fetch_add(1, std::memory_order_relaxed);
            update_bounds(key);
        }
        insert_count_.fetch_add(1, std::memory_order_relaxed);
        return {r.inserted};
    }

    template <typename... Args>
    insert_outcome try_emplace(Key key, Args&&... args) {
        std::scoped_lock lock{mutex_};
        const auto r = tree_.try_emplace(key, std::forward<Args>(args)...);
        if (r.inserted) {
            size_.fetch_add(1, std::memory_order_relaxed);
            update_bounds(key);
        }
        insert_count_.fetch_add(1, std::memory_order_relaxed);
        return {r.inserted};
    }

    bool remove(const Key& key) {
        std::scoped_lock lock{mutex_};
        const bool removed = tree_.remove(key);
        if (removed) {
            size_.fetch_sub(1, std::memory_order_relaxed);
            remove_count_.fetch_add(1, std::memory_order_relaxed);
            const auto cur_min = min_key_.load(std::memory_order_relaxed);
            const auto cur_max = max_key_.load(std::memory_order_relaxed);
            if (key == cur_min || key == cur_max) recompute_bounds();
        }
        return removed;
    }

    [[nodiscard]] PAVL_HOT bool contains(const Key& key) {
        std::scoped_lock lock{mutex_};
        const bool result = tree_.contains(key);
        lookup_count_.fetch_add(1, std::memory_order_relaxed);
        return result;
    }

    template <std::invocable<Value&> F>
    [[nodiscard]] PAVL_HOT bool visit(const Key& key, F&& f) {
        std::scoped_lock lock{mutex_};
        auto* v = tree_.find(key);
        lookup_count_.fetch_add(1, std::memory_order_relaxed);
        if (!v) return false;
        f(*v);
        return true;
    }

    [[nodiscard]] PAVL_HOT std::optional<Value> get(const Key& key)
        requires std::copyable<Value>
    {
        std::scoped_lock lock{mutex_};
        auto* v = tree_.find(key);
        lookup_count_.fetch_add(1, std::memory_order_relaxed);
        if (!v) return std::nullopt;
        return *v;
    }

    [[nodiscard]] std::size_t size() const noexcept {
        return size_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] bool intersects_range(const Key& lo, const Key& hi) const noexcept {
        if (!has_keys_.load(std::memory_order_acquire)) return false;
        const auto smin = min_key_.load(std::memory_order_relaxed);
        const auto smax = max_key_.load(std::memory_order_relaxed);
        return !(smax < lo || hi < smin);
    }

    void range_query(const Key& lo, const Key& hi, std::vector<key_value>& out, std::size_t max_results) {
        std::scoped_lock lock{mutex_};
        tree_.range_for_each(lo, hi, [&](const Key& k, Value& v) {
            if (out.size() >= max_results) return false;
            out.push_back({k, v});
            return true;
        });
    }

    void clear() {
        std::scoped_lock lock{mutex_};
        tree_.clear();
        size_.store(0, std::memory_order_relaxed);
        insert_count_.store(0, std::memory_order_relaxed);
        remove_count_.store(0, std::memory_order_relaxed);
        lookup_count_.store(0, std::memory_order_relaxed);
        has_keys_.store(false, std::memory_order_release);
    }

    [[nodiscard]] std::vector<key_value> extract_all() {
        std::scoped_lock lock{mutex_};
        return tree_.extract_all();
    }

    [[nodiscard]] stats snapshot() const noexcept {
        stats s{};
        s.size = size_.load(std::memory_order_relaxed);
        s.inserts = insert_count_.load(std::memory_order_relaxed);
        s.removes = remove_count_.load(std::memory_order_relaxed);
        s.lookups = lookup_count_.load(std::memory_order_relaxed);
        if (has_keys_.load(std::memory_order_acquire)) {
            s.min_key = min_key_.load(std::memory_order_relaxed);
            s.max_key = max_key_.load(std::memory_order_relaxed);
        }
        return s;
    }

private:
    void update_bounds(const Key& key) {
        if (!has_keys_.load(std::memory_order_relaxed)) {
            min_key_.store(key, std::memory_order_relaxed);
            max_key_.store(key, std::memory_order_relaxed);
            has_keys_.store(true, std::memory_order_release);
        } else {
            const auto cur_min = min_key_.load(std::memory_order_relaxed);
            const auto cur_max = max_key_.load(std::memory_order_relaxed);
            if (key < cur_min) min_key_.store(key, std::memory_order_relaxed);
            if (key > cur_max) max_key_.store(key, std::memory_order_relaxed);
        }
    }

    void recompute_bounds() {
        if (tree_.empty()) {
            has_keys_.store(false, std::memory_order_release);
            min_key_.store((std::numeric_limits<Key>::max)(), std::memory_order_relaxed);
            max_key_.store((std::numeric_limits<Key>::min)(), std::memory_order_relaxed);
        } else {
            const auto mn = tree_.min_key();
            const auto mx = tree_.max_key();
            if (mn) min_key_.store(*mn, std::memory_order_relaxed);
            if (mx) max_key_.store(*mx, std::memory_order_relaxed);
        }
    }

    static_assert(std::atomic<Key>::is_always_lock_free,
                  "shard requires lock-free atomic for Key (use integral keys for best results)");

    tree_type tree_{};
    mutable std::mutex mutex_{};

    alignas(cache_line_size) std::atomic<std::size_t> size_{0};
    std::atomic<std::size_t> insert_count_{0};
    std::atomic<std::size_t> lookup_count_{0};

    alignas(cache_line_size) std::atomic<std::size_t> remove_count_{0};
    std::atomic<Key> min_key_{(std::numeric_limits<Key>::max)()};
    std::atomic<Key> max_key_{(std::numeric_limits<Key>::min)()};
    std::atomic<bool> has_keys_{false};
};

}  // namespace pavl
