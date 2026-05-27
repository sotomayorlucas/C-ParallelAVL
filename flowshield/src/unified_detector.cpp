/**
 * Unified Detector Implementation — C++23 migration.
 *
 * Integrates network-level (engine) and host-level (APT Detector)
 * threat detection with alert correlation and incident management.
 */

#include "../include/unified_detector.hpp"

#include "../include/anomaly_detector.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <format>
#include <iostream>
#include <mutex>
#include <span>
#include <string>
#include <vector>

namespace flowshield {

// =====================================================================
// Internal helpers (file-local)
// =====================================================================

namespace {

[[nodiscard]] std::uint64_t generate_id() noexcept {
    static std::atomic<std::uint64_t> counter{0};
    return counter.fetch_add(1, std::memory_order_seq_cst);
}

[[nodiscard]] bool has_attack(attack_type bitmask, attack_type bit) noexcept {
    return (static_cast<std::uint32_t>(bitmask) &
            static_cast<std::uint32_t>(bit)) != 0;
}

}  // namespace

// =====================================================================
// Lifecycle
// =====================================================================

UnifiedDetector::UnifiedDetector(const flowshield::config& network_config,
                                 std::size_t             max_nodes,
                                 std::size_t             max_edges)
    : flowshield_{std::make_unique<engine>(std::optional<flowshield::config>{network_config})}
    , apt_detector_{std::make_unique<APTDetector>(max_nodes, max_edges)}
{
    alerts_.reserve(max_alerts_);
    incidents_.reserve(max_incidents_);

    // Defaults already set in struct definitions.
    std::cout << "[UnifiedDetector] Created with network + host detection\n"
                 "  engine:   Network-level anomaly detection\n"
                 "  APT Detector: Host-level APT detection (GNN/GAT)\n"
              << std::format("  Correlation:  Enabled (window={} sec)\n",
                             UNIFIED_CORRELATION_WINDOW);
}

UnifiedDetector::~UnifiedDetector() {
    stop();
    // unique_ptrs clean up component detectors automatically.
}

bool UnifiedDetector::start() {
    // The network engine is synchronous (no background threads) — nothing
    // to start. The APT detector spawns its own analysis thread.
    if (config_.enable_host_detection && apt_detector_) {
        if (!apt_detector_->start()) [[unlikely]] {
            std::cerr << "[UnifiedDetector] Failed to start APT Detector\n";
            return false;
        }
    }
    is_running_.store(true, std::memory_order_release);
    std::cout << "[UnifiedDetector] Started successfully\n";
    return true;
}

void UnifiedDetector::stop() {
    if (!is_running_.exchange(false, std::memory_order_acq_rel)) {
        return;
    }
    if (apt_detector_) {
        apt_detector_->stop();
    }
    std::cout << "[UnifiedDetector] Stopped\n";
}

// =====================================================================
// Event ingestion
// =====================================================================

void UnifiedDetector::ingest_packet(std::span<const std::uint8_t> packet,
                                    std::uint64_t                 /*timestamp_ns*/) {
    if (packet.empty() || !config_.enable_network_detection) {
        return;
    }
    // engine has no raw-packet entry point; the demos drive it via
    // process_packet(src_ip, ...) once headers are parsed. Packet parsing
    // is left to the caller / future protocol decoders.
}

void UnifiedDetector::ingest_flow(const flow_key&   flow_key,
                                  const flow_stats& /*flow_stats*/) {
    // engine internally tracks flows; nothing to do for the
    // network path here.

    // Cross-layer enrichment: create a socket node in the provenance
    // graph so host-layer analysis sees the connection.
    if (config_.enable_host_detection && apt_detector_) {
        auto* graph = apt_detector_->graph();
        if (graph) {
            struct SocketMeta {
                std::uint32_t local_ip;
                std::uint32_t remote_ip;
                std::uint16_t local_port;
                std::uint16_t remote_port;
                std::uint8_t  protocol;
            } socket_meta{
                .local_ip    = flow_key.src_ip,
                .remote_ip   = flow_key.dst_ip,
                .local_port  = flow_key.src_port,
                .remote_port = flow_key.dst_port,
                .protocol    = flow_key.protocol,
            };
            graph->add_node(NodeType::SOCKET, &socket_meta);
        }
    }
}

void UnifiedDetector::ingest_syscall(const void*   src_entity,
                                     NodeType      src_type,
                                     const void*   dst_entity,
                                     NodeType      dst_type,
                                     EdgeType      operation,
                                     std::uint64_t timestamp_ns) {
    if (!config_.enable_host_detection || !apt_detector_) {
        return;
    }

    apt_detector_->ingest_event(src_entity, src_type,
                                dst_entity, dst_type,
                                operation, timestamp_ns,
                                /*metadata=*/nullptr);

    // Cross-layer: if this is a network syscall, update engine.
    if (operation == EdgeType::CONNECT ||
        operation == EdgeType::SEND    ||
        operation == EdgeType::RECV) {
        // TODO: Extract network flow info and forward to engine.
    }
}

// =====================================================================
// Alert correlation
// =====================================================================

std::optional<float>
UnifiedDetector::correlate_alerts(const flow_alert& network_alert,
                                  const APTAlert&  host_alert) const {
    float correlation = 0.0f;

    // 1. Temporal proximity
    std::int64_t time_diff_ns =
        static_cast<std::int64_t>(network_alert.timestamp_ns) -
        static_cast<std::int64_t>(host_alert.timestamp_ns);
    if (time_diff_ns < 0) time_diff_ns = -time_diff_ns;

    float time_score = 0.0f;
    if (static_cast<std::uint64_t>(time_diff_ns) < 60ULL * 1'000'000'000ULL) {
        time_score = 1.0f - static_cast<float>(time_diff_ns) / (60.0f * 1e9f);
    }
    correlation += time_score * 0.4f;  // 40% weight

    // 2. IP address overlap
    float ip_score = 0.0f;
    if (apt_detector_) {
        auto* graph = apt_detector_->graph();
        if (graph) {
            for (std::size_t i = 0; i < host_alert.num_affected_nodes; ++i) {
                const std::uint64_t node_id = host_alert.affected_nodes[i];
                auto* node = graph->get_node(node_id);
                if (node != nullptr && node->type == NodeType::SOCKET) {
                    if (node->meta.socket.remote_ip == network_alert.flow.dst_ip ||
                        node->meta.socket.remote_ip == network_alert.flow.src_ip) {
                        ip_score = 1.0f;
                        break;
                    }
                }
            }
        }
    }
    correlation += ip_score * 0.3f;  // 30% weight

    // 3. Attack type similarity
    float attack_score   = 0.0f;
    bool  attack_related = false;

    if (has_attack(network_alert.type, attack_type::port_scan) &&
        any(host_alert.detected_phases & APTPhase::Reconnaissance)) {
        attack_related = true;
    }

    if ((has_attack(network_alert.type, attack_type::syn_flood) ||
         has_attack(network_alert.type, attack_type::udp_amplify)) &&
        any(host_alert.detected_phases & APTPhase::C2)) {
        attack_related = true;
    }

    if (attack_related) {
        attack_score = 0.8f;
    }
    correlation += attack_score * 0.3f;  // 30% weight

    if (correlation >= config_.correlation_threshold) {
        return correlation;
    }
    return std::nullopt;
}

std::vector<UnifiedAlert>
UnifiedDetector::find_related_alerts(const UnifiedAlert& reference_alert,
                                     std::uint64_t       time_window_ns,
                                     std::size_t         max_related) const {
    std::vector<UnifiedAlert> related;
    related.reserve(max_related);

    std::scoped_lock lock{alert_lock_};

    for (const auto& alert : alerts_) {
        if (related.size() >= max_related) break;

        std::int64_t time_diff =
            static_cast<std::int64_t>(alert.timestamp_ns) -
            static_cast<std::int64_t>(reference_alert.timestamp_ns);
        if (time_diff < 0) time_diff = -time_diff;

        if (static_cast<std::uint64_t>(time_diff) <= time_window_ns) {
            related.push_back(alert);
        }
    }

    return related;
}

// =====================================================================
// Alert retrieval
// =====================================================================

std::vector<UnifiedAlert>
UnifiedDetector::get_alerts(std::size_t max_alerts) const {
    std::scoped_lock lock{alert_lock_};

    const std::size_t n = (max_alerts == 0)
        ? alerts_.size()
        : std::min(max_alerts, alerts_.size());

    return std::vector<UnifiedAlert>(alerts_.begin(),
                                     alerts_.begin() + static_cast<std::ptrdiff_t>(n));
}

std::vector<SecurityIncident>
UnifiedDetector::get_incidents(std::size_t max_incidents) const {
    std::scoped_lock lock{incident_lock_};

    const std::size_t n = (max_incidents == 0)
        ? incidents_.size()
        : std::min(max_incidents, incidents_.size());

    return std::vector<SecurityIncident>(incidents_.begin(),
                                         incidents_.begin() + static_cast<std::ptrdiff_t>(n));
}

SecurityIncident* UnifiedDetector::get_incident(std::uint64_t incident_id) {
    std::scoped_lock lock{incident_lock_};
    for (auto& incident : incidents_) {
        if (incident.incident_id == incident_id) {
            return &incident;
        }
    }
    return nullptr;
}

const SecurityIncident*
UnifiedDetector::get_incident(std::uint64_t incident_id) const {
    std::scoped_lock lock{incident_lock_};
    for (const auto& incident : incidents_) {
        if (incident.incident_id == incident_id) {
            return &incident;
        }
    }
    return nullptr;
}

// =====================================================================
// Context enrichment
// =====================================================================

void UnifiedDetector::enrich_network_alert(flow_alert& network_alert) const {
    if (!apt_detector_) return;
    auto* graph = apt_detector_->graph();
    if (graph == nullptr) return;

    // Search for socket nodes matching this flow. Iterate over the dense
    // node storage exposed via nodes_data() / num_nodes().
    const auto* nodes_ptr = graph->nodes_data();
    const auto  n_nodes   = graph->num_nodes();
    for (std::size_t i = 0; i < n_nodes; ++i) {
        const auto& node = nodes_ptr[i];
        if (node.type != NodeType::SOCKET) continue;
        if (node.meta.socket.remote_ip   == network_alert.flow.dst_ip &&
            node.meta.socket.remote_port == network_alert.flow.dst_port) {

            network_alert.description += std::format(
                " [Host Context: Socket node {}, suspicious={}]",
                node.id,
                static_cast<int>(node.is_suspicious));
            break;
            // unreachable bookkeeping below kept disabled
            #if 0
            const std::string enrichment = std::format(
                " [Host Context: Socket node {}, suspicious={}]",
                node.id,
                static_cast<int>(node.is_suspicious));

            // Append safely to the fixed-size description buffer.
            const std::size_t current_len =
                std::strlen(network_alert.description.data());
            const std::size_t cap =
                network_alert.description.size();
            if (current_len + 1 < cap) {
                std::strncat(network_alert.description.data(),
                             enrichment.c_str(),
                             cap - current_len - 1);
            }
            break;
            #endif
        }
    }
}

void UnifiedDetector::enrich_apt_alert(APTAlert& apt_alert) const {
    if (!flowshield_) return;

    const std::string enrichment =
        " [Network Context: Active flows monitored by engine]";

    const std::size_t current_len =
        std::strlen(apt_alert.description.data());
    const std::size_t cap = apt_alert.description.size();
    if (current_len + 1 < cap) {
        std::strncat(apt_alert.description.data(),
                     enrichment.c_str(),
                     cap - current_len - 1);
    }
}

std::string
UnifiedDetector::build_timeline(const SecurityIncident& incident) const {
    std::string out;
    out.reserve(2048);

    const double duration_s =
        static_cast<double>(incident.last_update_ns - incident.start_time_ns) /
        1e9;

    out += std::format(
        "=== Incident Timeline ===\n"
        "Incident ID: {}\n"
        "Duration: {:.2f} seconds\n"
        "Alerts: {}\n\n",
        incident.incident_id, duration_s, incident.num_alerts);

    for (std::size_t i = 0; i < incident.num_alerts; ++i) {
        const UnifiedAlert* alert = incident.alerts[i];
        if (alert == nullptr) continue;

        const float time_offset =
            static_cast<float>(alert->timestamp_ns - incident.start_time_ns) / 1e9f;

        std::string_view source_label = "Correlated";
        switch (alert->source) {
            case AlertSource::Network:    source_label = "Network";    break;
            case AlertSource::Host:       source_label = "Host";       break;
            case AlertSource::Correlated: source_label = "Correlated"; break;
        }

        out += std::format("[+{:.2f}s] {} ({})\n",
                           time_offset,
                           alert->title.data(),
                           source_label);
    }

    return out;
}

// =====================================================================
// Incident management
// =====================================================================

std::optional<std::uint64_t>
UnifiedDetector::create_incident(const UnifiedAlert& alert) {
    std::scoped_lock lock{incident_lock_};

    if (incidents_.size() >= max_incidents_) {
        return std::nullopt;
    }

    SecurityIncident incident{};
    incident.incident_id    = generate_id();
    incident.start_time_ns  = alert.timestamp_ns;
    incident.last_update_ns = alert.timestamp_ns;
    incident.status         = IncidentStatus::Active;

    // Add the triggering alert as a non-owning pointer. NOTE: this
    // matches the C semantics — the pointer's lifetime must outlive
    // the incident. Tracking lifetime is the engine's responsibility.
    incident.alerts[0] = const_cast<UnifiedAlert*>(&alert);
    incident.num_alerts = 1;

    // Classify incident based on alert.
    if (alert.host.has_host_info) {
        const APTPhase phase = alert.host.apt_phase;
        if (any(phase & APTPhase::Reconnaissance)) {
            incident.classification = IncidentClassification::Recon;
        } else if (any(phase & APTPhase::Exploitation) ||
                   any(phase & APTPhase::Installation)) {
            incident.classification = IncidentClassification::InitialCompromise;
        } else if (any(phase & APTPhase::LateralMovement)) {
            incident.classification = IncidentClassification::LateralMovement;
        } else if (any(phase & APTPhase::Exfiltration)) {
            incident.classification = IncidentClassification::DataExfiltration;
        }
    } else if (alert.network.has_network_info) {
        if (has_attack(alert.network.type, attack_type::syn_flood) ||
            has_attack(alert.network.type, attack_type::udp_amplify)) {
            incident.classification = IncidentClassification::DDoS;
        } else if (has_attack(alert.network.type, attack_type::port_scan)) {
            incident.classification = IncidentClassification::Recon;
        }
    }

    // Severity mapping.
    if (alert.combined_severity > 0.8f) {
        incident.severity = IncidentSeverity::Critical;
    } else if (alert.combined_severity > 0.6f) {
        incident.severity = IncidentSeverity::High;
    } else if (alert.combined_severity > 0.4f) {
        incident.severity = IncidentSeverity::Medium;
    } else {
        incident.severity = IncidentSeverity::Low;
    }

    const std::uint64_t new_id = incident.incident_id;
    incidents_.push_back(std::move(incident));

    stats_.total_incidents++;
    stats_.active_incidents++;

    std::cout << std::format(
        "[UnifiedDetector] Created incident {} (severity={}, type={})\n",
        new_id,
        static_cast<int>(incidents_.back().severity),
        static_cast<int>(incidents_.back().classification));

    return new_id;
}

void UnifiedDetector::add_alert_to_incident(std::uint64_t       incident_id,
                                            const UnifiedAlert& alert) {
    std::scoped_lock lock{incident_lock_};

    for (auto& incident : incidents_) {
        if (incident.incident_id != incident_id) continue;
        if (incident.num_alerts < UNIFIED_MAX_ALERTS_PER_INC) {
            incident.alerts[incident.num_alerts++] =
                const_cast<UnifiedAlert*>(&alert);
            incident.last_update_ns = alert.timestamp_ns;
        }
        return;
    }
}

void UnifiedDetector::close_incident(std::uint64_t incident_id) {
    std::scoped_lock lock{incident_lock_};

    for (auto& incident : incidents_) {
        if (incident.incident_id != incident_id) continue;
        incident.status = IncidentStatus::Closed;
        if (stats_.active_incidents > 0) stats_.active_incidents--;
        std::cout << std::format("[UnifiedDetector] Closed incident {}\n",
                                 incident_id);
        return;
    }
}

// =====================================================================
// Statistics
// =====================================================================

void UnifiedDetector::print_stats() const {
    std::cout << std::format(
        "\n=== Unified Detector Statistics ===\n"
        "Total Alerts:      {}\n"
        "  Network:         {}\n"
        "  Host:            {}\n"
        "  Correlated:      {}\n"
        "Incidents:         {} total, {} active\n"
        "Correlation time:  {:.2f} ms avg\n"
        "=====================================\n\n",
        stats_.total_alerts,
        stats_.network_alerts,
        stats_.host_alerts,
        stats_.correlated_alerts,
        stats_.total_incidents,
        stats_.active_incidents,
        stats_.avg_correlation_time_ms);

    if (flowshield_) {
        std::cout << "engine (Network Layer):\n";
        flowshield_->print_summary();
    }
    if (apt_detector_) {
        std::cout << "APT Detector (Host Layer):\n";
        apt_detector_->print_stats();
    }
}

std::string
UnifiedDetector::generate_report(std::uint64_t start_time_ns,
                                 std::uint64_t end_time_ns) const {
    return std::format(
        "=== Security Report ({} -> {}) ===\n"
        "Total Alerts:    {}\n"
        "Total Incidents: {} ({} active)\n",
        start_time_ns, end_time_ns,
        stats_.total_alerts,
        stats_.total_incidents, stats_.active_incidents);
}

void UnifiedDetector::export_incident_json(const SecurityIncident& incident,
                                           std::string_view        filename) {
    // Defer to a free-function implementation; for now, simply log
    // the call. A full JSON serializer should be added when the
    // SecurityIncident schema stabilizes.
    std::cout << std::format(
        "[UnifiedDetector] Export incident {} to {} (stub)\n",
        incident.incident_id,
        std::string{filename});
}

std::string UnifiedDetector::alert_to_string(const UnifiedAlert& alert) {
    return std::format("UnifiedAlert{{id={}, ts={}, title=\"{}\"}}",
                       alert.alert_id,
                       alert.timestamp_ns,
                       alert.title.data());
}

std::string UnifiedDetector::incident_to_string(const SecurityIncident& incident) {
    return std::format("SecurityIncident{{id={}, alerts={}, severity={}}}",
                       incident.incident_id,
                       incident.num_alerts,
                       static_cast<int>(incident.severity));
}

// =====================================================================
// Response actions
// =====================================================================

bool UnifiedDetector::execute_response(const UnifiedAlert& alert) {
    switch (alert.recommended_response) {
        case UnifiedResponse::Monitor:
            std::cout << std::format("[Response] Monitoring alert: {}\n",
                                     alert.title.data());
            return true;

        case UnifiedResponse::BlockIp:
            if (alert.network.has_network_info) {
                block_ip(alert.network.flow.dst_ip, /*duration_sec=*/0);
                return true;
            }
            break;

        case UnifiedResponse::KillProcess:
            if (alert.host.has_host_info) {
                std::cout << "[Response] Would kill malicious processes\n";
                return true;
            }
            break;

        case UnifiedResponse::IsolateHost:
            std::cout << "[Response] Would isolate host from network\n";
            return true;

        case UnifiedResponse::Emergency:
            std::cout << "[Response] EMERGENCY - Immediate action required!\n";
            return true;

        default:
            break;
    }

    return false;
}

void UnifiedDetector::block_ip(std::uint32_t ip_address,
                               std::uint64_t duration_sec) {
    std::cout << std::format(
        "[Response] Blocking IP {}.{}.{}.{} for {} seconds\n",
        (ip_address >> 24) & 0xFFu,
        (ip_address >> 16) & 0xFFu,
        (ip_address >> 8)  & 0xFFu,
        (ip_address)       & 0xFFu,
        duration_sec);

    // TODO: Implement actual firewall rule injection.
}

void UnifiedDetector::isolate_host(std::string_view hostname) {
    std::cout << std::format("[Response] Would isolate host '{}'\n",
                             std::string{hostname});
}

void UnifiedDetector::kill_process(std::uint32_t pid) {
    std::cout << std::format(
        "[Response] Terminating malicious process PID={}\n", pid);
    // TODO: Implement process termination.
}

}  // namespace flowshield
