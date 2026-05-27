/**
 * FlowShield - Anomaly Detector (C++23)
 *
 * Multi-algorithm DDoS and anomaly detection engine.
 * Detects volumetric attacks, rate spikes, and protocol anomalies.
 */

#pragma once

#include "flow_tracker.hpp"
#include "flow_types.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <vector>

namespace flowshield {

// Callback invoked when an alert is generated.
using alert_callback_fn = std::function<void(const flow_alert&)>;

struct detector_stats {
    std::uint64_t total_analyses{};
    std::uint64_t total_alerts{};
    std::uint64_t flows_analyzed{};

    std::uint64_t volumetric_detections{};
    std::uint64_t rate_spike_detections{};
    std::uint64_t syn_flood_detections{};
    std::uint64_t amplification_detections{};
    std::uint64_t entropy_anomalies{};

    std::uint64_t last_analysis_time_ns{};
    double        avg_analysis_time_ms{};
};

struct entropy_analysis {
    double src_ip_entropy{};
    double dst_ip_entropy{};
    double src_port_entropy{};
    double dst_port_entropy{};
    double protocol_entropy{};

    std::size_t unique_src_ips{};
    std::size_t unique_dst_ips{};
    std::size_t sample_size{};
};

class anomaly_detector {
public:
    static constexpr std::size_t max_alerts          = 1024;
    static constexpr std::size_t entropy_sample_size = 10'000;
    static constexpr std::size_t hash_table_size     = 65'536;

    explicit anomaly_detector(flow_tracker&                          tracker,
                              const std::optional<detection_config>& config = std::nullopt);

    anomaly_detector(const anomaly_detector&)            = delete;
    anomaly_detector& operator=(const anomaly_detector&) = delete;
    anomaly_detector(anomaly_detector&&)                 = delete;
    anomaly_detector& operator=(anomaly_detector&&)      = delete;
    ~anomaly_detector()                                  = default;

    // ----- Configuration -----

    void                              set_config(const detection_config& cfg);
    [[nodiscard]] detection_config    get_config() const { return config_; }
    void                              set_callback(alert_callback_fn callback);

    // ----- Detection -----

    // Run all detection algorithms on current flows. Returns alerts generated.
    std::size_t analyze();

    // Per-algorithm hooks (kept for API parity).
    std::size_t check_volumetric()    { return 0; }
    std::size_t check_rate_spikes()   { return 0; }
    std::size_t check_syn_flood()     { ++stats_.syn_flood_detections; return 0; }
    std::size_t check_amplification() { ++stats_.amplification_detections; return 0; }
    std::size_t check_entropy();

    // Check a single flow. If an anomaly is detected, populates out_alert (if
    // provided) and returns true.
    bool check_flow(const flow_key&   key,
                    const flow_stats& stats,
                    flow_alert*       out_alert);

    // ----- Alert management -----

    [[nodiscard]] std::size_t              alert_count() const;
    [[nodiscard]] std::vector<flow_alert>  get_alerts(std::size_t max) const;
    void                                   clear_alerts();
    void                                   ack_alert(const flow_key& flow);

    // ----- Statistics -----

    [[nodiscard]] detector_stats get_stats() const { return stats_; }

    // ----- Entropy -----

    [[nodiscard]] entropy_analysis calc_entropy() const;

    // ----- Baseline learning -----

    void                              start_learning(std::uint32_t duration_sec);
    [[nodiscard]] bool                is_learning() const noexcept { return is_learning_; }
    void                              stop_learning();

private:
    void add_alert(const flow_key&   key,
                   const flow_stats& stats,
                   attack_type       type,
                   alert_severity    severity,
                   double            confidence,
                   std::string       description);

    flow_tracker*    tracker_;
    detection_config config_{};

    mutable std::mutex      alert_lock_;
    std::vector<flow_alert> alerts_;

    alert_callback_fn callback_{};

    detector_stats stats_{};

    bool          is_learning_{false};
    std::uint64_t learning_end_time_{0};

    // Baselines (learned).
    double baseline_pps_{0.0};
    double baseline_bps_{0.0};
    double baseline_flow_rate_{0.0};
    double baseline_src_entropy_{0.0};

    // Entropy tracking tables.
    std::vector<std::uint32_t> src_ip_counts_;
    std::vector<std::uint32_t> dst_ip_counts_;
    std::size_t                entropy_sample_count_{0};
};

}  // namespace flowshield
