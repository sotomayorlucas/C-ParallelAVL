/**
 * Unified Detection Engine — C++23 migration.
 *
 * Integrates engine (network-level) with the GNN/GAT APT Detector
 * (host-level) for comprehensive multi-layer threat detection.
 * See unified_detector.h for the original design notes.
 */

#pragma once

#include "apt_detector.hpp"
#include "flow_types.hpp"
#include "flowshield.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace flowshield {

// =====================================================================
// Configuration
// =====================================================================

inline constexpr std::size_t UNIFIED_MAX_INCIDENTS      = 256;   // Max concurrent incidents
inline constexpr std::size_t UNIFIED_CORRELATION_WINDOW = 300;   // Correlation window (s)
inline constexpr std::size_t UNIFIED_MAX_ALERTS_PER_INC = 64;    // Max alerts per incident

// =====================================================================
// Alert source / response / severity / status / classification enums
// =====================================================================

enum class AlertSource {
    Network,     // engine network detection
    Host,        // APT detector host detection
    Correlated,  // Correlated from both layers
};

enum class UnifiedResponse {
    Monitor,
    Investigate,
    IsolateNetwork,   // Block network traffic
    IsolateHost,      // Quarantine host
    KillProcess,      // Terminate malicious process
    BlockIp,          // Block external IP
    Emergency,        // Immediate action required
};

enum class IncidentClassification {
    Recon,                 // Reconnaissance
    InitialCompromise,     // Initial access
    LateralMovement,       // Lateral movement
    DataExfiltration,      // Data theft
    DDoS,                  // DDoS attack
    MultiStageAPT,         // Complex APT campaign
    Unknown,
};

enum class IncidentSeverity {
    Low,
    Medium,
    High,
    Critical,
};

enum class IncidentStatus {
    Active,
    Investigating,
    Mitigated,
    Closed,
};

// =====================================================================
// Unified Alert
// =====================================================================

struct UnifiedAlert {
    std::uint64_t alert_id     = 0;
    std::uint64_t timestamp_ns = 0;

    AlertSource source = AlertSource::Network;

    // Network-level information (if available)
    struct Network {
        bool       has_network_info = false;
        flow_alert  network_alert{};
        flow_key    flow{};
        flow_stats  stats{};
        attack_type type = attack_type::none;
    } network{};

    // Host-level information (if available)
    struct Host {
        bool        has_host_info = false;
        APTAlert    apt_alert{};
        CausalChain causal_chain{};
        APTPhase    apt_phase = APTPhase::None;
    } host{};

    // Unified assessment
    float combined_severity = 0.0f;     // Combined severity [0-1]
    float correlation_score = 0.0f;     // How related are net/host events

    // Incident association
    std::uint64_t incident_id = 0;

    // MITRE ATT&CK mapping
    std::array<std::array<char, 64>, 8>  mitre_tactics{};
    std::array<std::array<char, 64>, 16> mitre_techniques{};
    std::size_t num_tactics    = 0;
    std::size_t num_techniques = 0;

    // Description
    std::array<char, 256>  title{};
    std::array<char, 1024> description{};

    UnifiedResponse recommended_response = UnifiedResponse::Monitor;
};

// =====================================================================
// Affected assets
// =====================================================================

struct IncidentAssets {
    std::array<std::uint32_t, 32>             affected_ips{};
    std::array<std::uint32_t, 32>             affected_pids{};
    std::array<std::array<char, 128>, 16>     affected_users{};
    std::size_t num_ips   = 0;
    std::size_t num_pids  = 0;
    std::size_t num_users = 0;
};

// =====================================================================
// Security Incident
// =====================================================================

/// Security incident aggregating multiple related alerts.
struct SecurityIncident {
    std::uint64_t incident_id    = 0;
    std::uint64_t start_time_ns  = 0;
    std::uint64_t last_update_ns = 0;

    // Associated alerts (non-owning pointers into the engine's alert buffer)
    std::array<UnifiedAlert*, UNIFIED_MAX_ALERTS_PER_INC> alerts{};
    std::size_t num_alerts = 0;

    IncidentClassification classification = IncidentClassification::Unknown;
    IncidentSeverity       severity       = IncidentSeverity::Low;
    IncidentAssets         assets{};
    IncidentStatus         status         = IncidentStatus::Active;

    // Timeline (human-readable)
    std::array<char, 2048> timeline{};
};

// =====================================================================
// Configuration / Stats sub-structs
// =====================================================================

struct UnifiedDetectorConfig {
    bool          enable_network_detection = true;
    bool          enable_host_detection    = true;
    bool          enable_correlation       = true;
    std::uint64_t correlation_window_ns    =
        static_cast<std::uint64_t>(UNIFIED_CORRELATION_WINDOW) * 1'000'000'000ULL;
    float         correlation_threshold    = 0.5f;
};

struct UnifiedDetectorStats {
    std::uint64_t total_alerts             = 0;
    std::uint64_t network_alerts           = 0;
    std::uint64_t host_alerts              = 0;
    std::uint64_t correlated_alerts        = 0;
    std::uint64_t total_incidents          = 0;
    std::uint64_t active_incidents         = 0;
    double        avg_correlation_time_ms  = 0.0;
};

// =====================================================================
// Unified Detector Engine
// =====================================================================

class UnifiedDetector {
public:
    /// Construct a unified detector.
    UnifiedDetector(const config& network_config,
                    std::size_t             max_nodes,
                    std::size_t             max_edges);

    ~UnifiedDetector();

    UnifiedDetector(const UnifiedDetector&) = delete;
    UnifiedDetector& operator=(const UnifiedDetector&) = delete;
    UnifiedDetector(UnifiedDetector&&) = delete;
    UnifiedDetector& operator=(UnifiedDetector&&) = delete;

    // -----------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------

    /// Start detection engines and background threads.
    bool start();

    /// Stop detection engines.
    void stop();

    [[nodiscard]] bool running() const noexcept {
        return is_running_.load(std::memory_order_acquire);
    }

    // -----------------------------------------------------------------
    // Event ingestion
    // -----------------------------------------------------------------

    /// Ingest a raw network packet (engine path).
    void ingest_packet(std::span<const std::uint8_t> packet,
                       std::uint64_t                 timestamp_ns);

    /// Ingest a network flow (engine path).
    void ingest_flow(const flow_key&   flow_key,
                     const flow_stats& flow_stats);

    /// Ingest a system event (APT detector path).
    void ingest_syscall(const void*   src_entity,
                        NodeType      src_type,
                        const void*   dst_entity,
                        NodeType      dst_type,
                        EdgeType      operation,
                        std::uint64_t timestamp_ns);

    // -----------------------------------------------------------------
    // Detection
    // -----------------------------------------------------------------

    /// Get a snapshot of current alerts.
    [[nodiscard]] std::vector<UnifiedAlert> get_alerts(std::size_t max_alerts = 0) const;

    /// Get a snapshot of active incidents.
    [[nodiscard]] std::vector<SecurityIncident>
        get_incidents(std::size_t max_incidents = 0) const;

    /// Look up an incident by ID. Returns nullptr if not present.
    [[nodiscard]] SecurityIncident* get_incident(std::uint64_t incident_id);
    [[nodiscard]] const SecurityIncident*
        get_incident(std::uint64_t incident_id) const;

    // -----------------------------------------------------------------
    // Alert correlation
    // -----------------------------------------------------------------

    /// Correlate network and host alerts. Returns the correlation score
    /// if the pair is considered correlated.
    [[nodiscard]] std::optional<float>
        correlate_alerts(const flow_alert& network_alert,
                         const APTAlert&  host_alert) const;

    /// Find alerts related to `reference_alert` within a time window.
    [[nodiscard]] std::vector<UnifiedAlert>
        find_related_alerts(const UnifiedAlert& reference_alert,
                            std::uint64_t       time_window_ns,
                            std::size_t         max_related) const;

    // -----------------------------------------------------------------
    // Context enrichment
    // -----------------------------------------------------------------

    void enrich_network_alert(flow_alert& network_alert) const;
    void enrich_apt_alert(APTAlert& apt_alert) const;

    [[nodiscard]] std::string build_timeline(const SecurityIncident& incident) const;

    // -----------------------------------------------------------------
    // Incident management
    // -----------------------------------------------------------------

    /// Create a new incident from an alert. Returns the new incident ID,
    /// or std::nullopt if the incident pool is exhausted.
    [[nodiscard]] std::optional<std::uint64_t>
        create_incident(const UnifiedAlert& alert);

    void add_alert_to_incident(std::uint64_t       incident_id,
                               const UnifiedAlert& alert);

    void close_incident(std::uint64_t incident_id);

    // -----------------------------------------------------------------
    // Response actions
    // -----------------------------------------------------------------

    bool execute_response(const UnifiedAlert& alert);

    void block_ip(std::uint32_t ip_address, std::uint64_t duration_sec);
    void isolate_host(std::string_view hostname);
    void kill_process(std::uint32_t pid);

    // -----------------------------------------------------------------
    // Statistics & reporting
    // -----------------------------------------------------------------

    [[nodiscard]] const UnifiedDetectorStats&  stats()  const noexcept { return stats_;  }
    [[nodiscard]] const UnifiedDetectorConfig& config() const noexcept { return config_; }
    [[nodiscard]] UnifiedDetectorConfig&       config()       noexcept { return config_; }

    void print_stats() const;

    /// Generate a security report spanning a given time window.
    [[nodiscard]] std::string generate_report(std::uint64_t start_time_ns,
                                              std::uint64_t end_time_ns) const;

    static void export_incident_json(const SecurityIncident& incident,
                                     std::string_view        filename);

    // -----------------------------------------------------------------
    // Utility
    // -----------------------------------------------------------------

    [[nodiscard]] static std::string alert_to_string(const UnifiedAlert& alert);
    [[nodiscard]] static std::string incident_to_string(const SecurityIncident& incident);

    // -----------------------------------------------------------------
    // Component accessors
    // -----------------------------------------------------------------

    [[nodiscard]] engine*       flowshield_engine()       noexcept { return flowshield_.get(); }
    [[nodiscard]] const engine* flowshield_engine() const noexcept { return flowshield_.get(); }

    [[nodiscard]] APTDetector*       apt_detector()       noexcept { return apt_detector_.get(); }
    [[nodiscard]] const APTDetector* apt_detector() const noexcept { return apt_detector_.get(); }

private:
    // Component detectors
    std::unique_ptr<engine>  flowshield_;
    std::unique_ptr<APTDetector> apt_detector_;

    // Alert queue
    mutable std::mutex          alert_lock_;
    std::vector<UnifiedAlert>   alerts_;
    std::size_t                 max_alerts_ = 1000;

    // Incidents
    mutable std::mutex                 incident_lock_;
    std::vector<SecurityIncident>      incidents_;
    std::size_t                        max_incidents_ = UNIFIED_MAX_INCIDENTS;

    // Configuration & stats
    UnifiedDetectorConfig config_{};
    UnifiedDetectorStats  stats_{};

    // Background threads
    std::jthread correlation_thread_;
    std::jthread incident_thread_;

    alignas(64) std::atomic<bool> is_running_{false};
};

}  // namespace flowshield
