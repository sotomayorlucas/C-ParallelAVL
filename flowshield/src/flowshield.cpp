/**
 * FlowShield - Main Engine Implementation (C++23)
 */

#include "flowshield.hpp"

#include <algorithm>
#include <cstdint>
#include <format>
#include <iostream>
#include <mutex>
#include <string>
#include <vector>

namespace flowshield {

namespace {

// xorshift64
inline std::uint64_t xorshift64(std::uint64_t& state) noexcept {
    std::uint64_t x = state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    state = x;
    return x;
}

inline std::uint32_t random_ip(std::uint64_t& rng) noexcept   { return static_cast<std::uint32_t>(xorshift64(rng)); }
inline std::uint16_t random_port(std::uint64_t& rng) noexcept { return static_cast<std::uint16_t>(xorshift64(rng) % 65535) + 1; }

// Collision-key cache for the hotspot-attack simulation. We retain a static
// cache (lazily rebuilt when the parameters change) to keep parity with the
// C version's amortized cost. Access is serialized by a mutex since the
// simulation may be called from any thread.
struct collision_key_cache {
    std::vector<flow_key> keys;
    std::size_t           shard{0};
    std::size_t           num_shards{0};
};

collision_key_cache& global_collision_cache() {
    static collision_key_cache cache;
    return cache;
}
std::mutex& collision_cache_mutex() {
    static std::mutex m;
    return m;
}

void precompute_collision_keys(std::size_t target_shard, std::size_t num_shards, std::size_t count) {
    auto& cache = global_collision_cache();
    if (cache.shard == target_shard &&
        cache.num_shards == num_shards &&
        cache.keys.size() >= count) {
        return;  // Cache hit
    }

    cache.keys.clear();
    cache.keys.reserve(count * 2);
    cache.shard      = target_shard;
    cache.num_shards = num_shards;

    std::uint64_t rng     = 0x12345678DEADBEEFULL;
    std::uint32_t base_ip = 0x0A000000;  // 10.0.0.0

    const auto target = static_cast<std::int64_t>(target_shard);
    for (std::size_t attempts = 0;
         cache.keys.size() < count && attempts < count * 20;
         ++attempts) {
        flow_key key{};
        key.src_ip   = base_ip + static_cast<std::uint32_t>(attempts & 0xFFFFFFu);
        key.dst_ip   = 0xC0A80001u + static_cast<std::uint32_t>((attempts >> 8) & 0xFFFFu);
        key.src_port = static_cast<std::uint16_t>(1024 + (attempts % 64000));
        key.dst_port = 80;
        key.protocol = static_cast<std::uint8_t>(flow_protocol::tcp);

        auto hash = flow_key_hash(key);
        if ((hash % static_cast<std::int64_t>(num_shards)) == target) {
            cache.keys.push_back(key);
        }

        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;

        key.src_port = static_cast<std::uint16_t>(1024 + (rng % 64000));
        hash = flow_key_hash(key);
        if ((hash % static_cast<std::int64_t>(num_shards)) == target) {
            if (cache.keys.size() < cache.keys.capacity()) {
                cache.keys.push_back(key);
            }
        }
    }
}

}  // namespace

// ----- Lifecycle -----

engine::engine(const std::optional<config>& cfg)
    : config_(cfg.value_or(config_default())),
      tracker_(std::make_unique<flow_tracker>(config_.num_shards, config_.routing)),
      detector_(std::make_unique<anomaly_detector>(*tracker_, config_.detection)),
      rng_state_(time_now_ns() ^ 0xDEADBEEFULL)
{
    if (config_.enable_learning) {
        detector_->start_learning(config_.learning_duration_sec);
    }
}

// ----- Packet processing -----

bool engine::process_packet(std::uint32_t src_ip,
                            std::uint32_t dst_ip,
                            std::uint16_t src_port,
                            std::uint16_t dst_port,
                            std::uint8_t  protocol,
                            std::uint32_t packet_size,
                            std::uint8_t  tcp_flags) {
    flow_key key{};
    key.src_ip   = src_ip;
    key.dst_ip   = dst_ip;
    key.src_port = src_port;
    key.dst_port = dst_port;
    key.protocol = protocol;
    return process_flow_packet(key, packet_size, tcp_flags);
}

bool engine::process_flow_packet(const flow_key& key,
                                 std::uint32_t   packet_size,
                                 std::uint8_t    tcp_flags) {
    flow_stats* stats = tracker_->record_packet(key, packet_size, tcp_flags);
    if (!stats) return false;

    flow_alert alert;
    if (detector_->check_flow(key, *stats, &alert)) {
        tracker_->flag_flow(key, alert.type);
        return true;
    }
    return false;
}

// ----- Analysis -----

std::size_t engine::analyze()                                  { return detector_->analyze(); }
std::vector<flow_alert> engine::get_alerts(std::size_t max)    { return detector_->get_alerts(max); }
void engine::clear_alerts()                                    { detector_->clear_alerts(); }

// ----- Metrics -----

flow_metrics    engine::get_metrics()        const { return tracker_->get_metrics(); }
entropy_analysis engine::get_entropy()       const { return detector_->calc_entropy(); }
detector_stats  engine::get_detector_stats() const { return detector_->get_stats(); }

// ----- Simulation -----

void engine::simulate_normal_traffic(std::size_t num_packets,
                                     std::size_t num_sources,
                                     std::size_t num_dests) {
    if (num_packets == 0 || num_sources == 0 || num_dests == 0) return;

    std::vector<std::uint32_t> src_ips(num_sources);
    std::vector<std::uint32_t> dst_ips(num_dests);
    for (auto& ip : src_ips) ip = random_ip(rng_state_);
    for (auto& ip : dst_ips) ip = random_ip(rng_state_);

    for (std::size_t i = 0; i < num_packets; ++i) {
        const auto src_ip   = src_ips[xorshift64(rng_state_) % num_sources];
        const auto dst_ip   = dst_ips[xorshift64(rng_state_) % num_dests];
        const auto src_port = random_port(rng_state_);
        const auto dst_port = (xorshift64(rng_state_) % 100 < 80)
            ? std::uint16_t{80} : random_port(rng_state_);
        const auto protocol = static_cast<std::uint8_t>(
            (xorshift64(rng_state_) % 100 < 70)
                ? flow_protocol::tcp : flow_protocol::udp);
        const auto size  = static_cast<std::uint32_t>(64 + (xorshift64(rng_state_) % 1400));

        std::uint8_t flags = tcp_flags::ack;
        if (xorshift64(rng_state_) % 100 < 5) flags = tcp_flags::syn;

        process_packet(src_ip, dst_ip, src_port, dst_port, protocol, size, flags);
    }
}

void engine::simulate_syn_flood(std::uint32_t target_ip,
                                std::uint16_t target_port,
                                std::size_t   num_packets,
                                std::size_t   num_sources) {
    if (num_packets == 0) return;
    for (std::size_t i = 0; i < num_packets; ++i) {
        const std::uint32_t src_ip = (num_sources == 1) ? 0x0A000001u : random_ip(rng_state_);
        const auto          src_port = random_port(rng_state_);
        process_packet(src_ip, target_ip, src_port, target_port,
                       static_cast<std::uint8_t>(flow_protocol::tcp),
                       64, tcp_flags::syn);
    }
}

void engine::simulate_udp_amplification(std::uint32_t victim_ip,
                                        std::uint16_t amplifier_port,
                                        std::size_t   num_packets,
                                        double        amplification) {
    if (num_packets == 0) return;
    for (std::size_t i = 0; i < num_packets; ++i) {
        const auto amp_ip      = random_ip(rng_state_);
        const auto victim_port = random_port(rng_state_);
        auto size = static_cast<std::uint32_t>(64.0 * amplification);
        if (size > 65535) size = 65535;
        process_packet(amp_ip, victim_ip, amplifier_port, victim_port,
                       static_cast<std::uint8_t>(flow_protocol::udp),
                       size, 0);
    }
}

void engine::simulate_hotspot_attack(std::size_t target_shard, std::size_t num_packets) {
    if (num_packets == 0) return;

    const auto num_shards = tracker_->num_shards();
    if (num_shards == 0) return;
    if (target_shard >= num_shards) target_shard = 0;

    std::scoped_lock lk{collision_cache_mutex()};
    precompute_collision_keys(target_shard, num_shards, num_packets);
    const auto& keys = global_collision_cache().keys;
    if (keys.empty()) return;

    for (std::size_t i = 0; i < num_packets; ++i) {
        const auto& k = keys[i % keys.size()];
        process_packet(k.src_ip, k.dst_ip, k.src_port, k.dst_port,
                       k.protocol, 128, tcp_flags::syn);
    }
}

// ----- Output formatting -----

namespace {

std::string_view attack_name(attack_type t) noexcept {
    switch (t) {
        case attack_type::syn_flood:   return "syn_flood";
        case attack_type::udp_amplify: return "udp_amplification";
        case attack_type::dns_amplify: return "dns_amplification";
        case attack_type::ntp_amplify: return "ntp_amplification";
        case attack_type::volumetric:  return "volumetric";
        case attack_type::carpet_bomb: return "carpet_bombing";
        default:                       return "unknown";
    }
}

std::string_view severity_name(alert_severity s) noexcept {
    switch (s) {
        case alert_severity::low:      return "low";
        case alert_severity::medium:   return "medium";
        case alert_severity::high:     return "high";
        case alert_severity::critical: return "critical";
        default:                       return "info";
    }
}

std::string_view routing_name(pavl::router_strategy r) noexcept {
    switch (r) {
        case pavl::router_strategy::load_aware:      return "LOAD_AWARE";
        case pavl::router_strategy::static_hash:     return "STATIC";
        case pavl::router_strategy::consistent_hash: return "CONSISTENT";
        case pavl::router_strategy::intelligent:     return "INTELLIGENT";
    }
    return "OTHER";
}

}  // namespace

std::string alert_to_json(const flow_alert& alert) {
    return std::format(
        "{{\"timestamp\":{},"
        "\"attack_type\":\"{}\","
        "\"severity\":\"{}\","
        "\"confidence\":{:.2f},"
        "\"flow\":{{"
            "\"src_ip\":\"{}\","
            "\"dst_ip\":\"{}\","
            "\"src_port\":{},"
            "\"dst_port\":{},"
            "\"protocol\":{}"
        "}},"
        "\"stats\":{{"
            "\"packets\":{},"
            "\"bytes\":{},"
            "\"syn_count\":{},"
            "\"ack_count\":{}"
        "}},"
        "\"description\":\"{}\""
        "}}",
        alert.timestamp_ns / 1'000'000ULL,  // ms
        attack_name(alert.type),
        severity_name(alert.severity),
        alert.confidence,
        ip_to_str(alert.flow.src_ip),
        ip_to_str(alert.flow.dst_ip),
        alert.flow.src_port,
        alert.flow.dst_port,
        alert.flow.protocol,
        alert.stats.packet_count,
        alert.stats.byte_count,
        alert.stats.syn_count,
        alert.stats.ack_count,
        alert.description);
}

std::string metrics_to_prometheus(const flow_metrics& metrics) {
    return std::format(
        "# HELP flowshield_packets_total Total packets processed\n"
        "# TYPE flowshield_packets_total counter\n"
        "flowshield_packets_total {}\n"
        "# HELP flowshield_bytes_total Total bytes processed\n"
        "# TYPE flowshield_bytes_total counter\n"
        "flowshield_bytes_total {}\n"
        "# HELP flowshield_flows_active Number of active flows\n"
        "# TYPE flowshield_flows_active gauge\n"
        "flowshield_flows_active {}\n"
        "# HELP flowshield_flows_suspicious Number of suspicious flows\n"
        "# TYPE flowshield_flows_suspicious gauge\n"
        "flowshield_flows_suspicious {}\n"
        "# HELP flowshield_shard_balance Load balance score (0-1)\n"
        "# TYPE flowshield_shard_balance gauge\n"
        "flowshield_shard_balance {:.4f}\n"
        "# HELP flowshield_alerts_active Number of active alerts\n"
        "# TYPE flowshield_alerts_active gauge\n"
        "flowshield_alerts_active {}\n",
        metrics.total_packets,
        metrics.total_bytes,
        metrics.unique_flows,
        metrics.suspicious_flows,
        metrics.shard_balance,
        metrics.active_alerts);
}

// ----- Console output -----

void engine::print_summary() const {
    const auto m = get_metrics();
    const auto s = get_detector_stats();

    std::cout << "\n";
    std::cout << "+==============================================================+\n";
    std::cout << "|                    FLOWSHIELD SUMMARY                        |\n";
    std::cout << "+==============================================================+\n";
    std::cout << std::format(
        "| Flows:     {:<10}  |  Packets:    {:<15}    |\n"
        "| Flagged:   {:<10}  |  Bytes:      {:<15}    |\n"
        "| Shards:    {:<10}  |  Balance:    {:<6.1f}%            |\n",
        m.unique_flows, m.total_packets,
        m.suspicious_flows, m.total_bytes,
        tracker_->num_shards(), m.shard_balance * 100.0);
    std::cout << "+==============================================================+\n";
    std::cout << "| DETECTION STATS                                              |\n";
    std::cout << std::format(
        "| Analyses:  {:<10}  |  Alerts:     {:<10}         |\n"
        "| Avg Time:  {:<6.2f} ms   |  Flows/Run:  {:<10}         |\n",
        s.total_analyses, s.total_alerts,
        s.avg_analysis_time_ms, s.flows_analyzed);
    std::cout << "+==============================================================+\n";
}

void engine::print_dashboard(bool clear_screen) const {
    if (clear_screen) std::cout << "\033[2J\033[H";

    const auto m  = get_metrics();
    const auto en = get_entropy();
    const auto ns = tracker_->num_shards();

    std::cout << "+----------------------------------------------------------------+\n";
    std::cout << "|  FLOWSHIELD - Real-Time DDoS Detection                         |\n";
    std::cout << std::format(
        "|  Routing: {:<10}  |  Shards: {:<3}                         |\n",
        routing_name(config_.routing), ns);
    std::cout << "+----------------------------------------------------------------+\n";
    std::cout << "|  TRAFFIC                                                       |\n";
    std::cout << std::format(
        "|  Packets: {:<12}    Bytes: {:<12}               |\n"
        "|  Flows:   {:<12}    Flagged: {:<10}                 |\n",
        m.total_packets, m.total_bytes,
        m.unique_flows, m.suspicious_flows);

    std::cout << "+----------------------------------------------------------------+\n";
    std::cout << "|  SHARD BALANCE: ";
    constexpr int bar_width = 40;
    const int filled = static_cast<int>(m.shard_balance * bar_width);
    std::cout << "[";
    for (int i = 0; i < bar_width; ++i) {
        if (i < filled) {
            if (m.shard_balance > 0.8)      std::cout << "\033[32m#\033[0m";
            else if (m.shard_balance > 0.5) std::cout << "\033[33m#\033[0m";
            else                            std::cout << "\033[31m#\033[0m";
        } else {
            std::cout << ".";
        }
    }
    std::cout << std::format("] {:5.1f}%    |\n", m.shard_balance * 100.0);

    std::cout << "+----------------------------------------------------------------+\n";
    std::cout << "|  ENTROPY ANALYSIS                                              |\n";
    std::cout << std::format(
        "|  Source IPs:  {:.2f} bits  (unique: {:<6})                     |\n"
        "|  Dest IPs:    {:.2f} bits  (unique: {:<6})                     |\n",
        en.src_ip_entropy, en.unique_src_ips,
        en.dst_ip_entropy, en.unique_dst_ips);

    const auto alert_n = detector_->alert_count();
    std::cout << "+----------------------------------------------------------------+\n";
    std::cout << std::format("|  ALERTS: {:<3}                                                  |\n",
                             alert_n);
    if (alert_n > 0) {
        const auto top = detector_->get_alerts(5);
        for (const auto& a : top) {
            const char* icon = "[ ]";
            switch (a.severity) {
                case alert_severity::critical: icon = "[!]"; break;
                case alert_severity::high:     icon = "[H]"; break;
                case alert_severity::medium:   icon = "[M]"; break;
                default:                       icon = "[ ]"; break;
            }
            std::string desc = a.description;
            if (desc.size() > 50) desc.resize(50);
            std::cout << std::format("|  {} {:<50} |\n", icon, desc);
        }
    }
    std::cout << "+----------------------------------------------------------------+\n";
}

// ----- Platform detection (stubs; rich detection lives elsewhere) -----

bool engine::is_raspberry_pi5() {
    return false;
}

bool engine::has_hailo() {
    return false;
}

std::string_view engine::get_platform_info() {
    return "generic-x86_64";
}

}  // namespace flowshield
