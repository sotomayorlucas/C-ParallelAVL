/**
 * FlowShield - Flow Tracker Implementation (C++23)
 */

#include "flow_tracker.hpp"

#include <algorithm>
#include <cstring>
#include <mutex>
#include <utility>

namespace flowshield {

namespace {

constexpr std::size_t initial_pool_reserve = 4096;

// Update circular rate-history buffers.
inline void update_rate_history(flow_stats& s, std::uint32_t pps, std::uint32_t bps_kb) noexcept {
    s.pps_history[s.history_idx] = pps;
    s.bps_history[s.history_idx] = bps_kb;
    s.history_idx                = static_cast<std::uint8_t>((s.history_idx + 1) % flow_history_size);
    if (s.history_count < flow_history_size) {
        ++s.history_count;
    }
}

}  // namespace

flow_tracker::flow_tracker(std::size_t num_shards, pavl::router_strategy routing)
    : avl_(std::make_unique<avl_type>(num_shards == 0 ? 8 : num_shards, routing)),
      routing_(routing)
{
    entry_pool_.reserve(initial_pool_reserve);
}

flow_entry* flow_tracker::alloc_entry() {
    std::scoped_lock lk{pool_lock_};
    entry_pool_.emplace_back(std::make_unique<flow_entry>());
    return entry_pool_.back().get();
}

// ----- Flow operations -----

flow_stats* flow_tracker::record_packet(const flow_key& key,
                                        std::uint32_t   packet_size,
                                        std::uint8_t    tcp_flags) {
    const auto hash = flow_key_hash(key);
    const auto now  = time_now_ns();

    flow_entry* entry = nullptr;
    if (auto existing = avl_->get(hash)) {
        entry = *existing;
    }

    if (entry != nullptr) [[likely]] {
        auto& st = entry->stats;
        ++st.packet_count;
        st.byte_count += packet_size;
        st.last_seen_ns = now;

        if (tcp_flags & tcp_flags::syn) ++st.syn_count;
        if (tcp_flags & tcp_flags::ack) ++st.ack_count;
        if (tcp_flags & tcp_flags::fin) ++st.fin_count;
        if (tcp_flags & tcp_flags::rst) ++st.rst_count;

        const std::uint64_t elapsed_ns = now - st.first_seen_ns;
        if (elapsed_ns > 1'000'000'000ULL) {
            const auto pps    = static_cast<std::uint32_t>(st.packet_count * 1'000'000'000ULL / elapsed_ns);
            const auto bps_kb = static_cast<std::uint32_t>(st.byte_count   * 1'000'000ULL    / elapsed_ns);
            update_rate_history(st, pps, bps_kb);
        }
    } else {
        entry = alloc_entry();
        if (!entry) [[unlikely]] return nullptr;

        entry->key                = key;
        entry->stats.packet_count = 1;
        entry->stats.byte_count   = packet_size;
        entry->stats.first_seen_ns = now;
        entry->stats.last_seen_ns  = now;

        if (tcp_flags & tcp_flags::syn) entry->stats.syn_count = 1;
        if (tcp_flags & tcp_flags::ack) entry->stats.ack_count = 1;
        if (tcp_flags & tcp_flags::fin) entry->stats.fin_count = 1;
        if (tcp_flags & tcp_flags::rst) entry->stats.rst_count = 1;

        avl_->insert(hash, entry);
        new_flows_count_.fetch_add(1, std::memory_order_relaxed);
    }

    total_packets_.fetch_add(1, std::memory_order_relaxed);
    total_bytes_.fetch_add(packet_size, std::memory_order_relaxed);

    return &entry->stats;
}

std::optional<flow_stats> flow_tracker::get_flow(const flow_key& key) {
    const auto hash = flow_key_hash(key);
    if (auto p = avl_->get(hash)) {
        return (*p)->stats;
    }
    return std::nullopt;
}

bool flow_tracker::remove_flow(const flow_key& key) {
    return avl_->remove(flow_key_hash(key));
}

void flow_tracker::flag_flow(const flow_key& key, attack_type type) {
    const auto hash = flow_key_hash(key);
    [[maybe_unused]] const bool found = avl_->visit(hash, [&](flow_entry*& entry) {
        if (entry == nullptr) return;
        if (!entry->stats.is_flagged) {
            entry->stats.is_flagged = 1;
            flagged_count_.fetch_add(1, std::memory_order_relaxed);
        }
        entry->stats.attack_types |=
            static_cast<std::uint8_t>(static_cast<std::uint16_t>(type) & 0xFFu);
    });
}

// ----- Bulk operations -----

std::vector<std::pair<flow_key, flow_stats>>
flow_tracker::get_flows_by_dst(std::uint32_t dst_ip, std::size_t max_results) {
    std::vector<std::pair<flow_key, flow_stats>> out;
    if (max_results == 0) return out;
    out.reserve(std::min<std::size_t>(max_results, 64));

    iterate([&](const flow_key& key, const flow_stats& stats) {
        if (key.dst_ip == dst_ip) {
            out.emplace_back(key, stats);
            if (out.size() >= max_results) return false;
        }
        return true;
    });
    return out;
}

std::size_t flow_tracker::expire_old_flows(std::uint64_t timeout_ns) {
    const auto now    = time_now_ns();
    const auto cutoff = now > timeout_ns ? now - timeout_ns : 0ULL;

    std::vector<std::int64_t> keys_to_remove;
    keys_to_remove.reserve(1024);

    iterate([&](const flow_key& key, const flow_stats& stats) {
        if (stats.last_seen_ns < cutoff) {
            keys_to_remove.push_back(flow_key_hash(key));
        }
        return true;
    });

    std::size_t expired = 0;
    for (auto h : keys_to_remove) {
        if (avl_->remove(h)) ++expired;
    }
    return expired;
}

void flow_tracker::clear() {
    avl_->clear();

    total_packets_.store(0,    std::memory_order_relaxed);
    total_bytes_.store(0,      std::memory_order_relaxed);
    flagged_count_.store(0,    std::memory_order_relaxed);
    new_flows_count_.store(0,  std::memory_order_relaxed);

    std::scoped_lock lk{pool_lock_};
    entry_pool_.clear();
}

// ----- Statistics -----

flow_metrics flow_tracker::get_metrics() const {
    flow_metrics m{};
    m.timestamp_ns     = time_now_ns();
    m.total_packets    = total_packets_.load(std::memory_order_relaxed);
    m.total_bytes      = total_bytes_.load(std::memory_order_relaxed);
    m.unique_flows     = avl_->size();
    m.new_flows        = new_flows_count_.load(std::memory_order_relaxed);
    m.suspicious_flows = flagged_count_.load(std::memory_order_relaxed);
    m.shard_balance    = avl_->balance_score();
    return m;
}

std::size_t flow_tracker::flow_count() const {
    return avl_->size();
}

double flow_tracker::balance_score() const {
    return avl_->balance_score();
}

// ----- Dynamic scaling -----

bool flow_tracker::add_shard()                  { return avl_->add_shard(); }
bool flow_tracker::remove_shard()               { return avl_->remove_shard(); }
std::size_t flow_tracker::num_shards() const    { return avl_->num_shards(); }

// ----- Iteration -----

std::size_t flow_tracker::iterate(const iterator_fn& callback) {
    if (!callback) return 0;

    // Snapshot the pool under the lock to avoid races with allocations.
    std::vector<flow_entry*> snapshot;
    {
        std::scoped_lock lk{pool_lock_};
        snapshot.reserve(entry_pool_.size());
        for (auto& up : entry_pool_) snapshot.push_back(up.get());
    }

    std::size_t count = 0;
    for (auto* entry : snapshot) {
        const auto hash = flow_key_hash(entry->key);
        auto existing   = avl_->get(hash);
        if (existing && *existing == entry) {
            if (!callback(entry->key, entry->stats)) break;
            ++count;
        }
    }
    return count;
}

}  // namespace flowshield
