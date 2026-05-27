/**
 * FlowShield - Anomaly Detector Implementation (C++23)
 */

#include "anomaly_detector.hpp"

#include <algorithm>
#include <cmath>
#include <format>
#include <mutex>
#include <utility>

namespace flowshield {

namespace {

[[nodiscard]] double calculate_entropy(const std::vector<std::uint32_t>& counts, std::size_t total) {
    if (total == 0) return 0.0;
    double entropy = 0.0;
    for (auto c : counts) {
        if (c > 0) {
            const double p = static_cast<double>(c) / static_cast<double>(total);
            entropy -= p * std::log2(p);
        }
    }
    return entropy;
}

[[nodiscard]] inline std::uint32_t hash_ip(std::uint32_t ip) noexcept {
    ip ^= ip >> 16;
    ip *= 0x85ebca6bU;
    ip ^= ip >> 13;
    return ip & (anomaly_detector::hash_table_size - 1);
}

[[nodiscard]] double calc_std_dev(const std::array<std::uint32_t, flow_history_size>& values,
                                  std::uint8_t                                        count) {
    if (count < 2) return 0.0;
    double sum = 0.0;
    for (std::uint8_t i = 0; i < count; ++i) sum += values[i];
    const double mean = sum / count;

    double sq = 0.0;
    for (std::uint8_t i = 0; i < count; ++i) {
        const double diff = static_cast<double>(values[i]) - mean;
        sq += diff * diff;
    }
    return std::sqrt(sq / count);
}

}  // namespace

// ----- Lifecycle -----

anomaly_detector::anomaly_detector(flow_tracker&                          tracker,
                                   const std::optional<detection_config>& config)
    : tracker_(&tracker),
      config_(config.value_or(detection_config_default())),
      src_ip_counts_(hash_table_size, 0),
      dst_ip_counts_(hash_table_size, 0)
{
    alerts_.reserve(max_alerts);
}

// ----- Configuration -----

void anomaly_detector::set_config(const detection_config& cfg) { config_ = cfg; }
void anomaly_detector::set_callback(alert_callback_fn callback) { callback_ = std::move(callback); }

// ----- Helper: add_alert -----

void anomaly_detector::add_alert(const flow_key&   key,
                                 const flow_stats& stats,
                                 attack_type       type,
                                 alert_severity    severity,
                                 double            confidence,
                                 std::string       description) {
    flow_alert alert{};
    alert.flow         = key;
    alert.stats        = stats;
    alert.type         = type;
    alert.severity     = severity;
    alert.timestamp_ns = time_now_ns();
    alert.confidence   = confidence;
    alert.description  = std::move(description);

    {
        std::scoped_lock lk{alert_lock_};
        if (alerts_.size() >= max_alerts) return;
        alerts_.push_back(alert);
        ++stats_.total_alerts;
    }

    if (callback_) callback_(alert);
}

// ----- Detection: single-flow check -----

bool anomaly_detector::check_flow(const flow_key&   key,
                                  const flow_stats& stats,
                                  flow_alert*       out_alert) {
    if (is_learning_) return false;

    std::uint64_t elapsed_ns = stats.last_seen_ns - stats.first_seen_ns;
    if (elapsed_ns == 0) elapsed_ns = 1;

    const double pps = static_cast<double>(stats.packet_count) * 1e9 / static_cast<double>(elapsed_ns);
    const double bps = static_cast<double>(stats.byte_count)   * 1e9 / static_cast<double>(elapsed_ns);
    (void)bps;

    // Volumetric
    if (pps > static_cast<double>(config_.max_pps_per_flow)) {
        if (out_alert) {
            out_alert->flow         = key;
            out_alert->stats        = stats;
            out_alert->type         = attack_type::volumetric;
            out_alert->severity     = alert_severity::high;
            out_alert->confidence   = std::min(1.0, pps / static_cast<double>(config_.max_pps_per_flow));
            out_alert->description  = std::format("Volumetric: {:.0f} pps exceeds threshold {:.0f}",
                                                  pps, static_cast<double>(config_.max_pps_per_flow));
        }
        return true;
    }

    // SYN flood (TCP only)
    if (key.protocol == static_cast<std::uint8_t>(flow_protocol::tcp) && stats.syn_count > 0) {
        const double syn_ack_ratio = (stats.ack_count > 0)
            ? static_cast<double>(stats.syn_count) / static_cast<double>(stats.ack_count)
            : static_cast<double>(stats.syn_count);

        if (syn_ack_ratio > config_.syn_ack_ratio_thresh) {
            if (out_alert) {
                out_alert->flow         = key;
                out_alert->stats        = stats;
                out_alert->type         = attack_type::syn_flood;
                out_alert->severity     = alert_severity::high;
                out_alert->confidence   = std::min(1.0, syn_ack_ratio / 10.0);
                out_alert->description  = std::format("SYN Flood: ratio {:.2f} (SYN={}, ACK={})",
                                                      syn_ack_ratio, stats.syn_count, stats.ack_count);
            }
            return true;
        }
    }

    // Rate spike
    if (stats.history_count >= 3) {
        const double std_dev = calc_std_dev(stats.pps_history, stats.history_count);
        double mean = 0.0;
        for (std::uint8_t i = 0; i < stats.history_count; ++i) mean += stats.pps_history[i];
        mean /= stats.history_count;

        const auto latest_idx = static_cast<std::uint8_t>(
            (stats.history_idx + flow_history_size - 1) % flow_history_size);
        const double latest = stats.pps_history[latest_idx];

        if (std_dev > 0.0 && (latest - mean) > config_.rate_spike_sigma * std_dev) {
            if (out_alert) {
                out_alert->flow         = key;
                out_alert->stats        = stats;
                out_alert->type         = attack_type::volumetric;
                out_alert->severity     = alert_severity::medium;
                out_alert->confidence   = std::min(1.0, (latest - mean) / (3.0 * std_dev));
                out_alert->description  = std::format("Rate Spike: {:.0f} pps (mean={:.0f}, sigma={:.0f})",
                                                      latest, mean, std_dev);
            }
            return true;
        }
    }

    // UDP amplification on well-known ports
    if (key.protocol == static_cast<std::uint8_t>(flow_protocol::udp)) {
        if (key.src_port == 53 || key.src_port == 123 ||
            key.src_port == 1900 || key.src_port == 11211) {
            const double avg_packet_size = stats.packet_count > 0
                ? static_cast<double>(stats.byte_count) / static_cast<double>(stats.packet_count)
                : 0.0;
            if (avg_packet_size > 512.0 && pps > 100.0) {
                attack_type type = attack_type::udp_amplify;
                if      (key.src_port == 53)  type = attack_type::dns_amplify;
                else if (key.src_port == 123) type = attack_type::ntp_amplify;

                if (out_alert) {
                    out_alert->flow         = key;
                    out_alert->stats        = stats;
                    out_alert->type         = type;
                    out_alert->severity     = alert_severity::high;
                    out_alert->confidence   = std::min(1.0, avg_packet_size / 1000.0);
                    out_alert->description  = std::format("UDP Amplification: port {}, avg size {:.0f} bytes",
                                                          key.src_port, avg_packet_size);
                }
                return true;
            }
        }
    }

    return false;
}

// ----- Detection: bulk -----

std::size_t anomaly_detector::analyze() {
    const auto start = time_now_ns();

    if (is_learning_) {
        if (time_now_ns() >= learning_end_time_) {
            stop_learning();
        } else {
            return 0;
        }
    }

    std::ranges::fill(src_ip_counts_, 0u);
    std::ranges::fill(dst_ip_counts_, 0u);
    entropy_sample_count_ = 0;

    std::size_t alerts_generated = 0;
    tracker_->iterate([&](const flow_key& key, const flow_stats& stats) {
        // Update entropy tracking
        ++src_ip_counts_[hash_ip(key.src_ip)];
        ++dst_ip_counts_[hash_ip(key.dst_ip)];
        ++entropy_sample_count_;

        flow_alert alert;
        if (check_flow(key, stats, &alert)) {
            add_alert(key, stats, alert.type, alert.severity, alert.confidence, alert.description);
            tracker_->flag_flow(key, alert.type);
            ++alerts_generated;
        }
        ++stats_.flows_analyzed;
        return true;
    });

    alerts_generated += check_entropy();

    ++stats_.total_analyses;
    stats_.last_analysis_time_ns = time_now_ns() - start;

    const double ms = static_cast<double>(stats_.last_analysis_time_ns) / 1e6;
    stats_.avg_analysis_time_ms =
        (stats_.avg_analysis_time_ms * static_cast<double>(stats_.total_analyses - 1) + ms)
        / static_cast<double>(stats_.total_analyses);

    return alerts_generated;
}

std::size_t anomaly_detector::check_entropy() {
    if (entropy_sample_count_ < 100) return 0;
    std::size_t alerts = 0;

    const double src_entropy = calculate_entropy(src_ip_counts_, entropy_sample_count_);
    const double dst_entropy = calculate_entropy(dst_ip_counts_, entropy_sample_count_);

    if (src_entropy < config_.min_src_entropy && entropy_sample_count_ > 1000) {
        const double conf = 1.0 - src_entropy / config_.min_src_entropy;
        add_alert(flow_key{}, flow_stats{}, attack_type::carpet_bomb, alert_severity::medium, conf,
                  std::format("Low source entropy: {:.2f} (threshold: {:.2f}) - possible botnet",
                              src_entropy, config_.min_src_entropy));
        ++alerts;
        ++stats_.entropy_anomalies;
    }

    if (dst_entropy < config_.min_dst_entropy && entropy_sample_count_ > 1000) {
        const double conf = 1.0 - dst_entropy / config_.min_dst_entropy;
        add_alert(flow_key{}, flow_stats{}, attack_type::volumetric, alert_severity::high, conf,
                  std::format("Low destination entropy: {:.2f} (threshold: {:.2f}) - focused attack",
                              dst_entropy, config_.min_dst_entropy));
        ++alerts;
        ++stats_.entropy_anomalies;
    }

    return alerts;
}

// ----- Alert management -----

std::size_t anomaly_detector::alert_count() const {
    std::scoped_lock lk{alert_lock_};
    return alerts_.size();
}

std::vector<flow_alert> anomaly_detector::get_alerts(std::size_t max) const {
    std::scoped_lock lk{alert_lock_};
    const auto n = std::min(max, alerts_.size());
    return std::vector<flow_alert>(alerts_.begin(), alerts_.begin() + static_cast<std::ptrdiff_t>(n));
}

void anomaly_detector::clear_alerts() {
    std::scoped_lock lk{alert_lock_};
    alerts_.clear();
}

void anomaly_detector::ack_alert(const flow_key& /*flow*/) {
    // Parity with C version (no-op).
}

// ----- Entropy -----

entropy_analysis anomaly_detector::calc_entropy() const {
    entropy_analysis e{};
    if (entropy_sample_count_ == 0) return e;

    e.src_ip_entropy = calculate_entropy(src_ip_counts_, entropy_sample_count_);
    e.dst_ip_entropy = calculate_entropy(dst_ip_counts_, entropy_sample_count_);

    for (std::size_t i = 0; i < hash_table_size; ++i) {
        if (src_ip_counts_[i] > 0) ++e.unique_src_ips;
        if (dst_ip_counts_[i] > 0) ++e.unique_dst_ips;
    }
    e.sample_size = entropy_sample_count_;
    return e;
}

// ----- Baseline learning -----

void anomaly_detector::start_learning(std::uint32_t duration_sec) {
    is_learning_       = true;
    learning_end_time_ = time_now_ns() + static_cast<std::uint64_t>(duration_sec) * 1'000'000'000ULL;
    baseline_pps_         = 0.0;
    baseline_bps_         = 0.0;
    baseline_flow_rate_   = 0.0;
    baseline_src_entropy_ = 0.0;
}

void anomaly_detector::stop_learning() {
    const auto metrics = tracker_->get_metrics();
    const auto entropy = calc_entropy();

    baseline_pps_         = metrics.avg_pps;
    baseline_bps_         = static_cast<double>(metrics.total_bytes);
    baseline_src_entropy_ = entropy.src_ip_entropy;
    is_learning_          = false;
}

}  // namespace flowshield
