// APT Detector — minimum-viable implementation.
//
// The C original had no .c source for apt_detector — the header sat in the
// tree as a planned-but-unimplemented module. The unified_detector wired
// against the API contract, so we provide stubs here that wire the lifecycle
// (graph + GNN ownership, alert vector, start/stop) without implementing the
// detection algorithm itself. Calling detect()/calibrate()/etc returns empty
// results, matching the original "module exists, semantics deferred" state.

#include "../include/apt_detector.hpp"

#include "../include/gnn_gat.hpp"
#include "../include/provenance_graph.hpp"

#include <cstring>
#include <format>
#include <iostream>

namespace flowshield {

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

APTDetector::APTDetector(std::size_t max_nodes,
                         std::size_t max_edges,
                         std::optional<std::string_view> /*model_path*/)
    : graph_{std::make_unique<ProvenanceGraph>(max_nodes, max_edges)}
    , gnn_model_{std::make_unique<GNNModel>(
          /*input_dim*/   64,
          /*hidden_dim*/  64,
          /*output_dim*/  32,
          /*num_layers*/  2,
          /*num_classes*/ 14)}
    , calibration_{nullptr}
    , mimicry_detector_{nullptr}
{
    alerts_.reserve(APT_MAX_ALERTS);
    std::cout << "[APTDetector] Created (max_nodes=" << max_nodes
              << ", max_edges=" << max_edges << ")\n";
}

APTDetector::~APTDetector() {
    stop();
}

bool APTDetector::start() {
    if (is_running_.exchange(true, std::memory_order_acq_rel)) {
        return false;
    }
    std::cout << "[APTDetector] Started\n";
    return true;
}

void APTDetector::stop() {
    if (!is_running_.exchange(false, std::memory_order_acq_rel)) {
        return;
    }
    if (analysis_thread_.joinable()) {
        analysis_thread_.request_stop();
        analysis_thread_.join();
    }
    std::cout << "[APTDetector] Stopped\n";
}

// ---------------------------------------------------------------------------
// Event ingestion
// ---------------------------------------------------------------------------

void APTDetector::ingest_event(const void*   src_entity,
                               NodeType      src_type,
                               const void*   dst_entity,
                               NodeType      dst_type,
                               EdgeType      operation,
                               std::uint64_t timestamp_ns,
                               const void*   /*metadata*/) {
    if (!graph_) return;
    const auto src_id = graph_->add_node(src_type, src_entity);
    const auto dst_id = graph_->add_node(dst_type, dst_entity);
    if (src_id && dst_id) {
        graph_->add_edge(*src_id, *dst_id, operation, timestamp_ns);
    }
}

void APTDetector::ingest_batch(std::span<const void* const>      src_entities,
                               std::span<const NodeType>         src_types,
                               std::span<const void* const>      dst_entities,
                               std::span<const NodeType>         dst_types,
                               std::span<const EdgeType>         operations,
                               std::span<const std::uint64_t>    timestamps) {
    const auto n = std::min({src_entities.size(), src_types.size(),
                             dst_entities.size(), dst_types.size(),
                             operations.size(), timestamps.size()});
    for (std::size_t i = 0; i < n; ++i) {
        ingest_event(src_entities[i], src_types[i],
                     dst_entities[i], dst_types[i],
                     operations[i],   timestamps[i]);
    }
}

// ---------------------------------------------------------------------------
// Detection — stubs (algorithm intentionally deferred)
// ---------------------------------------------------------------------------

std::vector<APTAlert> APTDetector::detect(std::size_t /*max_alerts*/) {
    return {};
}

std::optional<float> APTDetector::detect_phase(APTPhase /*phase*/) {
    return std::nullopt;
}

std::vector<APTAlert> APTDetector::get_alerts(std::size_t max_alerts) const {
    std::scoped_lock lock{alert_lock_};
    std::vector<APTAlert> out;
    out.reserve(std::min(alerts_.size(), max_alerts));
    for (std::size_t i = 0; i < alerts_.size() && out.size() < max_alerts; ++i) {
        out.push_back(alerts_[i]);
    }
    return out;
}

void APTDetector::clear_alerts() {
    std::scoped_lock lock{alert_lock_};
    alerts_.clear();
}

// ---------------------------------------------------------------------------
// Calibration / evasion — stubs
// ---------------------------------------------------------------------------

void APTDetector::calibrate(std::span<ProvenanceGraph* const> /*graphs*/,
                            std::span<const int>              /*labels*/) {}

float APTDetector::apply_calibration(float raw_confidence) const {
    return raw_confidence;
}

double APTDetector::compute_ece(std::span<const float> /*predictions*/,
                                std::span<const int>   /*labels*/) const {
    return 0.0;
}

std::optional<float> APTDetector::detect_mimicry(const CausalChain& /*chain*/) {
    return std::nullopt;
}

void APTDetector::update_mimicry_baseline(const ProvenanceGraph& /*benign_graph*/) {}

APTDetector::MitreMapping APTDetector::map_to_mitre(const CausalChain& /*chain*/) const {
    return {};
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

void APTDetector::print_stats() const {
    std::scoped_lock lock{alert_lock_};
    std::cout << std::format(
        "[APTDetector] alerts={}/{} graph_nodes={} running={}\n",
        alerts_.size(), APT_MAX_ALERTS,
        graph_ ? graph_->num_nodes() : 0,
        is_running_.load(std::memory_order_relaxed));
}

void APTDetector::export_alert_json(const APTAlert& alert, std::string_view filename) {
    std::cout << std::format("[APTDetector] export_alert_json id={} -> {}\n",
                             alert.alert_id, filename);
}

std::string APTDetector::generate_report(const APTAlert& alert) const {
    return std::format("APT alert id={} primary_phase={} severity={}",
                       alert.alert_id,
                       phase_to_string(alert.primary_phase),
                       severity_to_string(alert.severity));
}

void APTDetector::visualize_chain(const CausalChain& /*chain*/,
                                  std::string_view output_file) const {
    std::cout << std::format("[APTDetector] visualize_chain -> {}\n", output_file);
}

// ---------------------------------------------------------------------------
// Static helpers
// ---------------------------------------------------------------------------

std::string_view APTDetector::phase_to_string(APTPhase phase) noexcept {
    using enum APTPhase;
    switch (phase) {
        case None:             return "none";
        case Reconnaissance:   return "reconnaissance";
        case Weaponization:    return "weaponization";
        case Delivery:         return "delivery";
        case Exploitation:     return "exploitation";
        case Installation:     return "installation";
        case C2:               return "c2";
        case LateralMovement:  return "lateral_movement";
        case Exfiltration:     return "exfiltration";
    }
    return "unknown";
}

std::string_view APTDetector::severity_to_string(APTSeverity severity) noexcept {
    using enum APTSeverity;
    switch (severity) {
        case Info:     return "info";
        case Low:      return "low";
        case Medium:   return "medium";
        case High:     return "high";
        case Critical: return "critical";
    }
    return "unknown";
}

}  // namespace flowshield
