/**
 * APT (Advanced Persistent Threat) Detector — C++23 migration.
 *
 * Detects multi-stage APT attacks using GNN/GAT on provenance graphs.
 * See apt_detector.h for the original design notes.
 */

#pragma once

#include "provenance_graph.hpp"
#include "gnn_gat.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace flowshield {

// =====================================================================
// Configuration
// =====================================================================

inline constexpr std::size_t APT_MAX_ALERTS           = 1024;   // Max concurrent alerts
inline constexpr std::size_t APT_DETECTION_WINDOW_SEC = 3600;   // Analysis window (1 hour)
inline constexpr std::size_t APT_MIN_CHAIN_LENGTH     = 3;      // Min events in attack chain
inline constexpr float       APT_CONFIDENCE_THRESHOLD = 0.85f;  // Detection threshold
inline constexpr std::size_t APT_CALIBRATION_BINS     = 10;     // ECE calibration bins

// =====================================================================
// APT Phase Classification (bitmask)
// =====================================================================

enum class APTPhase : std::uint32_t {
    None              = 0,
    Reconnaissance    = 1u << 0,    // Network scanning, enumeration
    Weaponization     = 1u << 1,    // Exploit crafting
    Delivery          = 1u << 2,    // Phishing, watering hole
    Exploitation      = 1u << 3,    // Initial compromise
    Installation      = 1u << 4,    // Backdoor, persistence
    C2                = 1u << 5,    // Command & control
    LateralMovement   = 1u << 6,    // Privilege escalation
    Exfiltration      = 1u << 7,    // Data theft
};

[[nodiscard]] constexpr APTPhase operator|(APTPhase a, APTPhase b) noexcept {
    return static_cast<APTPhase>(static_cast<std::uint32_t>(a) | static_cast<std::uint32_t>(b));
}
[[nodiscard]] constexpr APTPhase operator&(APTPhase a, APTPhase b) noexcept {
    return static_cast<APTPhase>(static_cast<std::uint32_t>(a) & static_cast<std::uint32_t>(b));
}
constexpr APTPhase& operator|=(APTPhase& a, APTPhase b) noexcept { a = a | b; return a; }
constexpr APTPhase& operator&=(APTPhase& a, APTPhase b) noexcept { a = a & b; return a; }
[[nodiscard]] constexpr bool any(APTPhase p) noexcept {
    return static_cast<std::uint32_t>(p) != 0;
}

// =====================================================================
// Severity / Response enums
// =====================================================================

enum class APTSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
};

enum class APTResponse {
    Monitor,        // Continue monitoring
    Investigate,    // Manual investigation
    Isolate,        // Isolate affected systems
    Block,          // Block immediately
    Kill,           // Terminate processes
};

// =====================================================================
// Indicators of Compromise (IOCs)
// =====================================================================

struct IOCs {
    std::array<std::uint32_t, 64>             ip_addresses{};
    std::array<std::array<char, 65>, 32>      file_hashes{};
    std::array<std::array<char, 256>, 32>     domains{};
    std::array<std::uint16_t, 32>             ports{};
    std::size_t num_ips     = 0;
    std::size_t num_hashes  = 0;
    std::size_t num_domains = 0;
    std::size_t num_ports   = 0;
};

// =====================================================================
// APT Alert
// =====================================================================

struct APTAlert {
    std::uint64_t alert_id     = 0;
    std::uint64_t timestamp_ns = 0;

    // Detected attack chain
    CausalChain chain{};

    // Classification
    APTPhase detected_phases = APTPhase::None;   // Bitmask of detected phases
    APTPhase primary_phase   = APTPhase::None;   // Most likely phase

    // Confidence & calibration
    float confidence            = 0.0f;          // Model confidence [0, 1]
    float calibrated_confidence = 0.0f;          // ECE-calibrated confidence
    float apt_score             = 0.0f;          // Overall APT likelihood

    // Tactics, Techniques, and Procedures (MITRE ATT&CK)
    std::array<std::array<char, 64>, 8>  mitre_tactics{};
    std::array<std::array<char, 64>, 16> mitre_techniques{};
    std::size_t num_tactics    = 0;
    std::size_t num_techniques = 0;

    // Severity assessment
    APTSeverity severity = APTSeverity::Info;

    // Affected entities
    std::array<std::uint64_t, 256> affected_nodes{};
    std::size_t num_affected_nodes = 0;

    // Indicators of Compromise
    IOCs iocs{};

    // Description
    std::array<char, 256>  title{};
    std::array<char, 1024> description{};

    // Evasion detection
    bool  possible_mimicry = false;   // Mimicry attack suspected
    float evasion_score    = 0.0f;    // Likelihood of evasion

    // Response recommendation
    APTResponse recommended_response = APTResponse::Monitor;
};

// =====================================================================
// Calibration (ECE Reduction)
// =====================================================================

/// Calibration map for reducing Expected Calibration Error.
/// Maps raw model confidence to calibrated probability.
struct CalibrationMap {
    std::array<float,       APT_CALIBRATION_BINS + 1> bin_edges{};
    std::array<float,       APT_CALIBRATION_BINS>     bin_accuracies{};
    std::array<std::size_t, APT_CALIBRATION_BINS>     bin_counts{};
    float temperature = 1.0f;
};

// =====================================================================
// Mimicry / Evasion detection
// =====================================================================

/// Mimicry attack detection. Detects when attackers interleave benign
/// actions to evade detection.
struct MimicryDetector {
    // Statistical baselines
    float benign_action_rate    = 0.0f;
    float benign_action_entropy = 0.0f;

    // Mimicry indicators
    float observed_benign_rate = 0.0f;
    float deviation_score      = 0.0f;

    // Timing analysis
    double avg_inter_event_time_ms      = 0.0;
    double expected_inter_event_time_ms = 0.0;

    bool is_mimicry_likely = false;
};

// =====================================================================
// Statistics & configuration sub-structs
// =====================================================================

struct APTDetectorConfig {
    float         confidence_threshold = APT_CONFIDENCE_THRESHOLD;
    std::size_t   min_chain_length     = APT_MIN_CHAIN_LENGTH;
    std::uint64_t detection_window_ns  =
        static_cast<std::uint64_t>(APT_DETECTION_WINDOW_SEC) * 1'000'000'000ULL;
    bool enable_calibration       = true;
    bool enable_mimicry_detection = true;
    bool enable_causal_inference  = true;
};

struct APTDetectorStats {
    std::uint64_t total_detections          = 0;
    std::uint64_t true_positives            = 0;
    std::uint64_t false_positives           = 0;
    std::uint64_t false_negatives           = 0;
    double        precision                 = 0.0;
    double        recall                    = 0.0;
    double        f1_score                  = 0.0;
    double        avg_detection_time_ms     = 0.0;
    double        expected_calibration_error = 0.0;
};

// =====================================================================
// APT Detector Engine
// =====================================================================

class APTDetector {
public:
    /// Construct an APT detector.
    ///
    /// @param max_nodes   Max nodes in provenance graph.
    /// @param max_edges   Max edges in provenance graph.
    /// @param model_path  Optional path to pretrained GNN model.
    APTDetector(std::size_t max_nodes,
                std::size_t max_edges,
                std::optional<std::string_view> model_path = std::nullopt);

    ~APTDetector();

    APTDetector(const APTDetector&) = delete;
    APTDetector& operator=(const APTDetector&) = delete;
    APTDetector(APTDetector&&) = delete;
    APTDetector& operator=(APTDetector&&) = delete;

    // -----------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------

    /// Start the background analysis thread. Returns true on success.
    bool start();

    /// Stop the background analysis thread.
    void stop();

    [[nodiscard]] bool running() const noexcept {
        return is_running_.load(std::memory_order_acquire);
    }

    // -----------------------------------------------------------------
    // Event ingestion
    // -----------------------------------------------------------------

    /// Ingest a single system event (syscall, audit log).
    void ingest_event(const void* src_entity,
                      NodeType    src_type,
                      const void* dst_entity,
                      NodeType    dst_type,
                      EdgeType    operation,
                      std::uint64_t timestamp_ns,
                      const void* metadata = nullptr);

    /// Ingest a batch of events.
    void ingest_batch(std::span<const void* const>      src_entities,
                      std::span<const NodeType>         src_types,
                      std::span<const void* const>      dst_entities,
                      std::span<const NodeType>         dst_types,
                      std::span<const EdgeType>         operations,
                      std::span<const std::uint64_t>    timestamps);

    // -----------------------------------------------------------------
    // Detection
    // -----------------------------------------------------------------

    /// Run APT detection on the current graph.
    /// Returns the produced alerts (up to `max_alerts`).
    [[nodiscard]] std::vector<APTAlert> detect(std::size_t max_alerts = APT_MAX_ALERTS);

    /// Detect a specific APT phase. Returns the confidence if detected.
    [[nodiscard]] std::optional<float> detect_phase(APTPhase phase);

    /// Get a snapshot of current alerts.
    [[nodiscard]] std::vector<APTAlert> get_alerts(std::size_t max_alerts = APT_MAX_ALERTS) const;

    /// Clear processed alerts.
    void clear_alerts();

    // -----------------------------------------------------------------
    // Calibration
    // -----------------------------------------------------------------

    /// Calibrate model using labeled data. Reduces ECE.
    void calibrate(std::span<ProvenanceGraph* const> graphs,
                   std::span<const int>              labels);

    /// Apply calibration to a raw confidence score.
    [[nodiscard]] float apply_calibration(float raw_confidence) const;

    /// Compute Expected Calibration Error.
    [[nodiscard]] double compute_ece(std::span<const float> predictions,
                                     std::span<const int>   labels) const;

    // -----------------------------------------------------------------
    // Evasion detection
    // -----------------------------------------------------------------

    /// Detect mimicry attacks. Returns mimicry-likelihood score [0,1]
    /// when a mimicry pattern is detected.
    [[nodiscard]] std::optional<float> detect_mimicry(const CausalChain& chain);

    /// Update mimicry baseline using a known-benign provenance graph.
    void update_mimicry_baseline(const ProvenanceGraph& benign_graph);

    // -----------------------------------------------------------------
    // MITRE ATT&CK mapping
    // -----------------------------------------------------------------

    struct MitreMapping {
        std::vector<std::string> tactics;
        std::vector<std::string> techniques;
    };

    /// Map detected behaviour to the MITRE ATT&CK framework.
    [[nodiscard]] MitreMapping map_to_mitre(const CausalChain& chain) const;

    // -----------------------------------------------------------------
    // Utility / accessors
    // -----------------------------------------------------------------

    [[nodiscard]] const APTDetectorStats&  stats()  const noexcept { return stats_;  }
    [[nodiscard]] const APTDetectorConfig& config() const noexcept { return config_; }
    [[nodiscard]] APTDetectorConfig&       config()       noexcept { return config_; }

    [[nodiscard]] ProvenanceGraph*       graph()       noexcept { return graph_.get(); }
    [[nodiscard]] const ProvenanceGraph* graph() const noexcept { return graph_.get(); }

    [[nodiscard]] GNNModel*       gnn_model()       noexcept { return gnn_model_.get(); }
    [[nodiscard]] const GNNModel* gnn_model() const noexcept { return gnn_model_.get(); }

    void print_stats() const;

    /// Export alert to JSON file.
    static void export_alert_json(const APTAlert& alert, std::string_view filename);

    /// Generate human-readable report.
    [[nodiscard]] std::string generate_report(const APTAlert& alert) const;

    /// Visualize an attack chain.
    void visualize_chain(const CausalChain& chain, std::string_view output_file) const;

    // -----------------------------------------------------------------
    // Static helpers
    // -----------------------------------------------------------------

    [[nodiscard]] static std::string_view phase_to_string(APTPhase phase) noexcept;
    [[nodiscard]] static std::string_view severity_to_string(APTSeverity severity) noexcept;

private:
    // Core components
    std::unique_ptr<ProvenanceGraph> graph_;
    std::unique_ptr<GNNModel>        gnn_model_;
    std::unique_ptr<CalibrationMap>  calibration_;
    std::unique_ptr<MimicryDetector> mimicry_detector_;

    // Alert queue
    mutable std::mutex     alert_lock_;
    std::vector<APTAlert>  alerts_;

    // Configuration & stats
    APTDetectorConfig config_{};
    APTDetectorStats  stats_{};

    // Thread safety for engine-wide state
    mutable std::shared_mutex lock_;

    // Background analysis thread
    std::jthread       analysis_thread_;
    alignas(64) std::atomic<bool> is_running_{false};
};

}  // namespace flowshield
