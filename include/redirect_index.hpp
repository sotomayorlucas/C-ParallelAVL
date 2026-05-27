#pragma once

#include "common.hpp"
#include "hash_table.hpp"

#include <atomic>
#include <cstddef>
#include <functional>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <vector>

namespace pavl {

template <typename Key>
    requires std::is_trivially_copyable_v<Key> && std::default_initializable<Key>
class redirect_index {
public:
    struct stats {
        std::size_t total_redirects{};
        std::size_t lookups{};
        std::size_t hits{};
        double hit_rate{};
        std::size_t index_size{};
    };

    redirect_index() : table_{64} {}

    redirect_index(const redirect_index&) = delete;
    redirect_index& operator=(const redirect_index&) = delete;
    redirect_index(redirect_index&&) = delete;
    redirect_index& operator=(redirect_index&&) = delete;
    ~redirect_index() = default;

    void record(const Key& key, std::size_t natural_shard, std::size_t actual_shard) {
        if (natural_shard == actual_shard) return;
        std::unique_lock lock{mutex_};
        table_.insert(key, actual_shard);
        total_redirects_.fetch_add(1, std::memory_order_relaxed);
    }

    [[nodiscard]] PAVL_HOT std::optional<std::size_t> lookup(const Key& key) {
        lookups_.fetch_add(1, std::memory_order_relaxed);
        std::shared_lock lock{mutex_};
        const auto* v = table_.find(key);
        if (!v) return std::nullopt;
        hits_.fetch_add(1, std::memory_order_relaxed);
        return *v;
    }

    void remove(const Key& key) {
        std::unique_lock lock{mutex_};
        table_.remove(key);
    }

    void clear() {
        std::unique_lock lock{mutex_};
        table_.clear();
        total_redirects_.store(0, std::memory_order_relaxed);
        lookups_.store(0, std::memory_order_relaxed);
        hits_.store(0, std::memory_order_relaxed);
    }

    [[nodiscard]] stats snapshot() const noexcept {
        stats s{};
        s.total_redirects = total_redirects_.load(std::memory_order_relaxed);
        s.lookups = lookups_.load(std::memory_order_relaxed);
        s.hits = hits_.load(std::memory_order_relaxed);
        s.hit_rate = s.lookups > 0 ? (static_cast<double>(s.hits) * 100.0 / static_cast<double>(s.lookups)) : 0.0;
        std::shared_lock lock{mutex_};
        s.index_size = table_.size();
        return s;
    }

    [[nodiscard]] std::size_t approximate_memory_bytes() const noexcept {
        std::shared_lock lock{mutex_};
        return table_.size() * (sizeof(Key) + sizeof(std::size_t) + 16);
    }

    template <std::invocable<const Key&> CurrentShardFn>
    std::size_t garbage_collect(CurrentShardFn&& current_shard_of) {
        std::unique_lock lock{mutex_};
        if (table_.empty()) return 0;
        std::vector<Key> to_remove;
        to_remove.reserve(table_.size());
        table_.for_each([&](const Key& k, std::size_t actual) {
            if (current_shard_of(k) == actual) to_remove.push_back(k);
        });
        for (const auto& k : to_remove) table_.remove(k);
        return to_remove.size();
    }

private:
    hash_table<Key, std::size_t> table_;
    mutable std::shared_mutex mutex_;
    std::atomic<std::size_t> total_redirects_{0};
    std::atomic<std::size_t> lookups_{0};
    std::atomic<std::size_t> hits_{0};
};

}  // namespace pavl
