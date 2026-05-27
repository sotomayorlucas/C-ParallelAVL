#pragma once

#include "common.hpp"

#include <bit>
#include <cstring>
#include <memory>
#include <utility>

namespace pavl {

// Robin-Hood hash table optimized for trivially-copyable key/value (the only
// instantiation we need is <Key, std::size_t> for the redirect index).
template <typename K, typename V>
    requires std::is_trivially_copyable_v<K> && std::is_trivially_copyable_v<V>
              && std::default_initializable<K> && std::default_initializable<V>
class hash_table {
public:
    using key_type = K;
    using value_type = V;

    static constexpr double max_load_factor = 0.7;
    static constexpr std::size_t initial_capacity = 16;
    static constexpr std::uint8_t max_probe_distance = 255;

private:
    enum slot_state : std::uint8_t { empty_slot = 0, occupied_slot = 1, deleted_slot = 2 };

    struct entry {
        K key{};
        V value{};
        std::uint8_t state{empty_slot};
        std::uint8_t probe_dist{};
        std::uint16_t _pad{};
    };

public:
    explicit hash_table(std::size_t initial = initial_capacity) {
        capacity_ = next_power_of_two(initial < initial_capacity ? initial_capacity : initial);
        mask_ = capacity_ - 1;
        entries_ = std::make_unique<entry[]>(capacity_);
    }

    hash_table(const hash_table&) = delete;
    hash_table& operator=(const hash_table&) = delete;
    hash_table(hash_table&&) noexcept = default;
    hash_table& operator=(hash_table&&) noexcept = default;
    ~hash_table() = default;

    [[nodiscard]] std::size_t size() const noexcept { return size_; }
    [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }
    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }

    bool insert(const K& key, V value) {
        const double load = static_cast<double>(size_ + tombstones_ + 1) / static_cast<double>(capacity_);
        if (load > max_load_factor) {
            if (!resize(capacity_ * 2)) return false;
        }
        return robin_hood_insert(key, value);
    }

    [[nodiscard]] PAVL_HOT const V* find(const K& key) const noexcept {
        const auto hash = key_hash(key);
        std::size_t idx = static_cast<std::size_t>(hash) & mask_;
        std::uint8_t probe = 0;
        while (probe <= max_probe_) {
            const entry& slot = entries_[idx];
            if (slot.state == empty_slot) return nullptr;
            if (slot.state == occupied_slot && slot.key == key) return &slot.value;
            if (slot.state == occupied_slot && probe > slot.probe_dist) return nullptr;
            idx = (idx + 1) & mask_;
            ++probe;
        }
        return nullptr;
    }

    [[nodiscard]] PAVL_HOT V* find(const K& key) noexcept {
        return const_cast<V*>(std::as_const(*this).find(key));
    }

    [[nodiscard]] bool contains(const K& key) const noexcept { return find(key) != nullptr; }

    bool remove(const K& key) noexcept {
        const auto hash = key_hash(key);
        std::size_t idx = static_cast<std::size_t>(hash) & mask_;
        std::uint8_t probe = 0;
        while (probe <= max_probe_) {
            entry& slot = entries_[idx];
            if (slot.state == empty_slot) return false;
            if (slot.state == occupied_slot && slot.key == key) {
                std::size_t curr = idx;
                while (true) {
                    std::size_t next = (curr + 1) & mask_;
                    entry& next_slot = entries_[next];
                    if (next_slot.state != occupied_slot || next_slot.probe_dist == 0) {
                        entries_[curr].state = empty_slot;
                        break;
                    }
                    entries_[curr] = next_slot;
                    entries_[curr].probe_dist--;
                    curr = next;
                }
                --size_;
                return true;
            }
            if (slot.state == occupied_slot && probe > slot.probe_dist) return false;
            idx = (idx + 1) & mask_;
            ++probe;
        }
        return false;
    }

    void clear() noexcept {
        for (std::size_t i = 0; i < capacity_; ++i) entries_[i].state = empty_slot;
        size_ = 0;
        tombstones_ = 0;
        max_probe_ = 0;
    }

    template <std::invocable<const K&, const V&> F>
    void for_each(F&& f) const {
        for (std::size_t i = 0; i < capacity_; ++i) {
            if (entries_[i].state == occupied_slot) {
                f(entries_[i].key, entries_[i].value);
            }
        }
    }

private:
    bool resize(std::size_t new_cap) {
        auto old_entries = std::move(entries_);
        const std::size_t old_capacity = capacity_;
        entries_ = std::make_unique<entry[]>(new_cap);
        capacity_ = new_cap;
        mask_ = new_cap - 1;
        size_ = 0;
        tombstones_ = 0;
        max_probe_ = 0;
        for (std::size_t i = 0; i < old_capacity; ++i) {
            if (old_entries[i].state == occupied_slot) {
                robin_hood_insert(old_entries[i].key, old_entries[i].value);
            }
        }
        return true;
    }

    bool robin_hood_insert(K key, V value) {
        const auto hash = key_hash(key);
        std::size_t idx = static_cast<std::size_t>(hash) & mask_;
        std::uint8_t probe = 0;
        while (true) {
            entry& slot = entries_[idx];
            if (slot.state != occupied_slot) {
                slot.key = key;
                slot.value = value;
                slot.state = occupied_slot;
                slot.probe_dist = probe;
                ++size_;
                if (probe > max_probe_) max_probe_ = probe;
                return true;
            }
            if (slot.key == key) {
                slot.value = value;
                return true;
            }
            if (probe > slot.probe_dist) {
                using std::swap;
                swap(slot.key, key);
                swap(slot.value, value);
                std::swap(slot.probe_dist, probe);
            }
            idx = (idx + 1) & mask_;
            ++probe;
            if (probe > max_probe_distance) [[unlikely]] return false;
        }
    }

    std::unique_ptr<entry[]> entries_;
    std::size_t capacity_{};
    std::size_t mask_{};
    std::size_t size_{};
    std::size_t tombstones_{};
    std::uint8_t max_probe_{};
};

}  // namespace pavl
