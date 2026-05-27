/**
 * FlowShield - DDoS/Anomaly Detection Engine (C++23)
 *
 * A high-performance network anomaly detection system built on ParallelAVL.
 * Designed to demonstrate adversary-resistant data structures in security
 * applications.
 */

#pragma once

#include "anomaly_detector.hpp"
#include "flow_tracker.hpp"
#include "flow_types.hpp"

#include "parallel_avl.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace flowshield {

// ============================================================================
// Version
// ============================================================================

inline constexpr std::uint32_t version_major  = 0;
inline constexpr std::uint32_t version_minor  = 1;
inline constexpr std::uint32_t version_patch  = 0;
inline constexpr std::string_view version_string = "0.1.0";

// ============================================================================
// Configuration
// ============================================================================

enum class ai_mode : std::uint8_t {
    off   = 0,
    automatic,    // "auto" is a keyword
    hailo,
    cpu,
};

struct config {
    std::size_t           num_shards{8};
    pavl::router_strategy routing{pavl::router_strategy::load_aware};  // adversary-resistant
    detection_config      detection{detection_config_default()};

    bool          enable_learning{false};
    std::uint32_t learning_duration_sec{60};

    // AI
    ai_mode ai_backend{ai_mode::off};
    float   ai_anomaly_threshold{0.85f};
    bool    ai_online_learning{false};
};

[[nodiscard]] inline config config_default() noexcept { return {}; }

[[nodiscard]] inline config config_ai() noexcept {
    config c{};
    c.ai_backend            = ai_mode::automatic;
    c.ai_anomaly_threshold  = 0.80f;
    c.ai_online_learning    = true;
    return c;
}

// ============================================================================
// Engine
// ============================================================================

class engine {
public:
    explicit engine(const std::optional<config>& cfg = std::nullopt);

    engine(const engine&)            = delete;
    engine& operator=(const engine&) = delete;
    engine(engine&&)                 = delete;
    engine& operator=(engine&&)      = delete;
    ~engine()                        = default;

    // ----- Packet processing -----

    bool process_packet(std::uint32_t src_ip,
                        std::uint32_t dst_ip,
                        std::uint16_t src_port,
                        std::uint16_t dst_port,
                        std::uint8_t  protocol,
                        std::uint32_t packet_size,
                        std::uint8_t  tcp_flags);

    bool process_flow_packet(const flow_key& key,
                             std::uint32_t   packet_size,
                             std::uint8_t    tcp_flags);

    // ----- Analysis -----

    std::size_t                            analyze();
    [[nodiscard]] std::vector<flow_alert>  get_alerts(std::size_t max);
    void                                   clear_alerts();

    // ----- Metrics -----

    [[nodiscard]] flow_metrics     get_metrics() const;
    [[nodiscard]] entropy_analysis get_entropy() const;
    [[nodiscard]] detector_stats   get_detector_stats() const;

    // ----- Accessors -----

    [[nodiscard]] flow_tracker&     tracker()     noexcept { return *tracker_; }
    [[nodiscard]] anomaly_detector& detector()    noexcept { return *detector_; }
    [[nodiscard]] const flowshield::config& cfg() const noexcept { return config_; }

    // ----- Simulation -----

    void simulate_normal_traffic(std::size_t num_packets,
                                 std::size_t num_sources,
                                 std::size_t num_dests);

    void simulate_syn_flood(std::uint32_t target_ip,
                            std::uint16_t target_port,
                            std::size_t   num_packets,
                            std::size_t   num_sources);

    void simulate_udp_amplification(std::uint32_t victim_ip,
                                    std::uint16_t amplifier_port,
                                    std::size_t   num_packets,
                                    double        amplification);

    void simulate_hotspot_attack(std::size_t target_shard, std::size_t num_packets);

    // ----- Output -----

    void print_summary() const;
    void print_dashboard(bool clear_screen) const;

    // ----- Platform -----

    [[nodiscard]] static bool             is_raspberry_pi5();
    [[nodiscard]] static bool             has_hailo();
    [[nodiscard]] static std::string_view get_platform_info();

private:
    config                            config_{};
    std::unique_ptr<flow_tracker>     tracker_;
    std::unique_ptr<anomaly_detector> detector_;
    std::uint64_t                     rng_state_{0};
};

// ----- Output formatting -----

[[nodiscard]] std::string alert_to_json(const flow_alert& alert);
[[nodiscard]] std::string metrics_to_prometheus(const flow_metrics& metrics);

}  // namespace flowshield
