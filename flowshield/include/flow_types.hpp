/**
 * FlowShield - DDoS/Anomaly Detection Engine (C++23)
 *
 * Core type definitions for network flow tracking and analysis.
 * Built on ParallelAVL for high-performance concurrent operations.
 */

#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <type_traits>

namespace flowshield {

// ============================================================================
// Constants
// ============================================================================

inline constexpr std::size_t flow_history_size       = 16;    // Rolling window
inline constexpr std::size_t max_flows_per_query     = 256;   // Range-query cap
inline constexpr std::uint32_t default_flow_timeout  = 60;    // Seconds

// ============================================================================
// TCP flag bit constants (matches IETF wire format)
// ============================================================================

namespace tcp_flags {
    inline constexpr std::uint8_t fin = 0x01;
    inline constexpr std::uint8_t syn = 0x02;
    inline constexpr std::uint8_t rst = 0x04;
    inline constexpr std::uint8_t psh = 0x08;
    inline constexpr std::uint8_t ack = 0x10;
    inline constexpr std::uint8_t urg = 0x20;
}  // namespace tcp_flags

// ============================================================================
// Enums
// ============================================================================

enum class flow_protocol : std::uint8_t {
    unknown = 0,
    icmp    = 1,
    tcp     = 6,
    udp     = 17,
};

// Bitmask enum: each value is a single bit. The bitwise operators below
// preserve the C semantics of `ATTACK_X | ATTACK_Y` while keeping type safety.
enum class attack_type : std::uint16_t {
    none           = 0,
    syn_flood      = 1u << 0,
    udp_amplify    = 1u << 1,
    icmp_flood     = 1u << 2,
    http_flood     = 1u << 3,
    slowloris      = 1u << 4,
    dns_amplify    = 1u << 5,
    ntp_amplify    = 1u << 6,
    carpet_bomb    = 1u << 7,
    port_scan      = 1u << 8,
    volumetric     = 1u << 9,
};

[[nodiscard]] constexpr attack_type operator|(attack_type a, attack_type b) noexcept {
    using U = std::underlying_type_t<attack_type>;
    return static_cast<attack_type>(static_cast<U>(a) | static_cast<U>(b));
}
[[nodiscard]] constexpr attack_type operator&(attack_type a, attack_type b) noexcept {
    using U = std::underlying_type_t<attack_type>;
    return static_cast<attack_type>(static_cast<U>(a) & static_cast<U>(b));
}
constexpr attack_type& operator|=(attack_type& a, attack_type b) noexcept {
    a = a | b;
    return a;
}
[[nodiscard]] constexpr bool any(attack_type a) noexcept {
    return static_cast<std::underlying_type_t<attack_type>>(a) != 0;
}

enum class alert_severity : std::uint8_t {
    info     = 0,
    low      = 1,
    medium   = 2,
    high     = 3,
    critical = 4,
};

// ============================================================================
// Flow identification (5-tuple)
// ============================================================================

struct flow_key {
    std::uint32_t src_ip{};     // network byte order (interpretation up to caller)
    std::uint32_t dst_ip{};
    std::uint16_t src_port{};
    std::uint16_t dst_port{};
    std::uint8_t  protocol{};   // raw IP protocol number (see flow_protocol)
    std::uint8_t  _pad[3]{};    // Alignment padding (preserve C layout)

    [[nodiscard]] friend constexpr bool operator==(const flow_key&, const flow_key&) = default;
};

// ============================================================================
// Flow statistics
// ============================================================================

struct flow_stats {
    // Counters
    std::uint64_t packet_count{};
    std::uint64_t byte_count{};

    // TCP flag counters
    std::uint32_t syn_count{};
    std::uint32_t ack_count{};
    std::uint32_t fin_count{};
    std::uint32_t rst_count{};

    // Timestamps (nanoseconds since steady_clock epoch)
    std::uint64_t first_seen_ns{};
    std::uint64_t last_seen_ns{};

    // Rate history (circular buffer for rolling averages)
    std::array<std::uint32_t, flow_history_size> pps_history{};
    std::array<std::uint32_t, flow_history_size> bps_history{};
    std::uint8_t  history_idx{};
    std::uint8_t  history_count{};

    // Flags
    std::uint8_t  is_flagged{};
    std::uint8_t  attack_types{};   // bitmask of attack_type values
};

// ============================================================================
// Alert
// ============================================================================

struct flow_alert {
    flow_key       flow{};
    flow_stats     stats{};
    attack_type    type{attack_type::none};
    alert_severity severity{alert_severity::info};
    std::uint64_t  timestamp_ns{};
    double         confidence{};
    std::string    description{};
};

// ============================================================================
// Aggregated metrics (per time window)
// ============================================================================

struct flow_metrics {
    std::uint64_t timestamp_ns{};
    std::uint64_t window_duration_ns{};

    // Global counters
    std::uint64_t total_packets{};
    std::uint64_t total_bytes{};
    std::uint64_t unique_flows{};
    std::uint64_t new_flows{};
    std::uint64_t expired_flows{};

    // Per-protocol
    std::uint64_t tcp_packets{};
    std::uint64_t udp_packets{};
    std::uint64_t icmp_packets{};

    // Attack-related
    std::uint64_t syn_packets{};
    std::uint64_t suspicious_flows{};
    std::uint32_t active_alerts{};

    // Performance
    double        avg_pps{};
    double        peak_pps{};
    double        shard_balance{};
    std::uint64_t processing_latency_ns{};
};

// ============================================================================
// Detection thresholds (configurable)
// ============================================================================

struct detection_config {
    // Volumetric
    std::uint64_t max_pps_per_flow{10'000};
    std::uint64_t max_bps_per_flow{100ULL * 1024ULL * 1024ULL};   // 100 MB/s
    std::uint64_t max_total_pps{1'000'000};

    // SYN flood
    double        syn_ack_ratio_thresh{3.0};
    std::uint32_t syn_per_second_thresh{1000};

    // Rate-spike
    double        rate_spike_sigma{3.0};

    // Entropy
    double        min_src_entropy{2.0};
    double        min_dst_entropy{2.0};

    // Amplification
    double        amplification_ratio{10.0};

    // Timing
    std::uint32_t flow_timeout_sec{60};
    std::uint32_t analysis_interval_ms{1000};
};

[[nodiscard]] inline detection_config detection_config_default() noexcept {
    return detection_config{};
}

// ============================================================================
// Utility functions
// ============================================================================

// 64-bit (positive) hash for use as ParallelAVL key.
[[nodiscard]] inline constexpr std::int64_t flow_key_hash(const flow_key& key) noexcept {
    std::uint64_t h = 0;
    h ^= static_cast<std::uint64_t>(key.src_ip) * 0xcc9e2d51ULL;
    h ^= static_cast<std::uint64_t>(key.dst_ip) * 0x1b873593ULL;
    h ^= (static_cast<std::uint64_t>(key.src_port) << 32) | key.dst_port;
    h ^= static_cast<std::uint64_t>(key.protocol) * 0x85ebca6bULL;
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    return static_cast<std::int64_t>(h & 0x7FFFFFFFFFFFFFFFULL);
}

// Steady-clock based monotonic timestamp in nanoseconds. Matches the
// C version's use of CLOCK_MONOTONIC.
[[nodiscard]] inline std::uint64_t time_now_ns() noexcept {
    using clock = std::chrono::steady_clock;
    const auto d = clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(d).count());
}

// Dotted-quad rendering of a 32-bit IP (host-order interpretation matches
// the original C helper: MSB is the first octet).
[[nodiscard]] inline std::string ip_to_str(std::uint32_t ip) {
    return std::format("{}.{}.{}.{}",
                       (ip >> 24) & 0xFFu,
                       (ip >> 16) & 0xFFu,
                       (ip >> 8) & 0xFFu,
                       ip & 0xFFu);
}

// Parse dotted-quad. Returns 0 on parse failure (matches C behaviour).
[[nodiscard]] inline std::uint32_t str_to_ip(std::string_view str) noexcept {
    unsigned int a = 0, b = 0, c = 0, d = 0;
    // sscanf accepts NUL-terminated; copy into a small buffer.
    char buf[64]{};
    const auto n = std::min(str.size(), sizeof(buf) - 1);
    for (std::size_t i = 0; i < n; ++i) buf[i] = str[i];
    if (std::sscanf(buf, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
        return (a << 24) | (b << 16) | (c << 8) | d;
    }
    return 0;
}

}  // namespace flowshield
