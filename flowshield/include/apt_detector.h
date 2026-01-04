/**
 * APT (Advanced Persistent Threat) Detector
 *
 * Detects multi-stage APT attacks using GNN/GAT on provenance graphs.
 * Addresses key challenges:
 *   - Scalability: handles million-node graphs efficiently
 *   - Calibration: reduces ECE (Expected Calibration Error)
 *   - Evasion resistance: detects mimicry attacks
 *   - Causal reasoning: distinguishes true attack chains from noise
 *
 * APT Kill Chain Detection:
 *   1. Reconnaissance (scanning, enumeration)
 *   2. Weaponization (crafting exploits)
 *   3. Delivery (phishing, drive-by)
 *   4. Exploitation (code execution)
 *   5. Installation (persistence)
 *   6. C2 (command & control)
 *   7. Actions on Objective (exfiltration, lateral movement)
 */

#ifndef FLOWSHIELD_APT_DETECTOR_H
#define FLOWSHIELD_APT_DETECTOR_H

#include "provenance_graph.h"
#include "gnn_gat.h"
#include <stdbool.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Configuration
 * ============================================================================ */

#define APT_MAX_ALERTS              1024    /* Max concurrent alerts */
#define APT_DETECTION_WINDOW_SEC    3600    /* Analysis window (1 hour) */
#define APT_MIN_CHAIN_LENGTH        3       /* Min events in attack chain */
#define APT_CONFIDENCE_THRESHOLD    0.85f   /* Detection threshold */
#define APT_CALIBRATION_BINS        10      /* ECE calibration bins */

/* ============================================================================
 * APT Phase Classification
 * ============================================================================ */

typedef enum {
    APT_PHASE_NONE = 0,
    APT_PHASE_RECONNAISSANCE    = 1 << 0,   /* Network scanning, enumeration */
    APT_PHASE_WEAPONIZATION     = 1 << 1,   /* Exploit crafting */
    APT_PHASE_DELIVERY          = 1 << 2,   /* Phishing, watering hole */
    APT_PHASE_EXPLOITATION      = 1 << 3,   /* Initial compromise */
    APT_PHASE_INSTALLATION      = 1 << 4,   /* Backdoor, persistence */
    APT_PHASE_C2                = 1 << 5,   /* Command & control */
    APT_PHASE_LATERAL_MOVEMENT  = 1 << 6,   /* Privilege escalation */
    APT_PHASE_EXFILTRATION      = 1 << 7    /* Data theft */
} APTPhase;

/* ============================================================================
 * APT Alert
 * ============================================================================ */

typedef struct {
    uint64_t alert_id;                      /* Unique alert ID */
    uint64_t timestamp_ns;                  /* Alert generation time */

    /* Detected attack chain */
    CausalChain chain;                      /* Causal chain of events */

    /* Classification */
    APTPhase detected_phases;               /* Bitmask of detected phases */
    APTPhase primary_phase;                 /* Most likely phase */

    /* Confidence & calibration */
    float confidence;                       /* Model confidence [0, 1] */
    float calibrated_confidence;            /* ECE-calibrated confidence */
    float apt_score;                        /* Overall APT likelihood */

    /* Tactics, Techniques, and Procedures (MITRE ATT&CK) */
    char mitre_tactics[8][64];              /* ATT&CK tactics */
    char mitre_techniques[16][64];          /* ATT&CK techniques */
    size_t num_tactics;
    size_t num_techniques;

    /* Severity assessment */
    enum {
        APT_SEVERITY_INFO,
        APT_SEVERITY_LOW,
        APT_SEVERITY_MEDIUM,
        APT_SEVERITY_HIGH,
        APT_SEVERITY_CRITICAL
    } severity;

    /* Affected entities */
    uint64_t affected_nodes[256];           /* Node IDs */
    size_t num_affected_nodes;

    /* Indicators of Compromise (IOCs) */
    struct {
        uint32_t ip_addresses[64];          /* Malicious IPs */
        char file_hashes[32][65];           /* File SHA256 hashes */
        char domains[32][256];              /* Malicious domains */
        uint16_t ports[32];                 /* Suspicious ports */
        size_t num_ips;
        size_t num_hashes;
        size_t num_domains;
        size_t num_ports;
    } iocs;

    /* Description */
    char title[256];
    char description[1024];

    /* Evasion detection */
    bool possible_mimicry;                  /* Mimicry attack suspected */
    float evasion_score;                    /* Likelihood of evasion */

    /* Response recommendation */
    enum {
        RESPONSE_MONITOR,                   /* Continue monitoring */
        RESPONSE_INVESTIGATE,               /* Manual investigation */
        RESPONSE_ISOLATE,                   /* Isolate affected systems */
        RESPONSE_BLOCK,                     /* Block immediately */
        RESPONSE_KILL                       /* Terminate processes */
    } recommended_response;
} APTAlert;

/* ============================================================================
 * Calibration (ECE Reduction)
 * ============================================================================ */

/**
 * Calibration map for reducing Expected Calibration Error.
 * Maps raw model confidence to calibrated probability.
 */
typedef struct {
    float bin_edges[APT_CALIBRATION_BINS + 1];  /* Bin boundaries */
    float bin_accuracies[APT_CALIBRATION_BINS]; /* Actual accuracy per bin */
    size_t bin_counts[APT_CALIBRATION_BINS];    /* Samples per bin */
    float temperature;                          /* Temperature scaling param */
} CalibrationMap;

/* ============================================================================
 * Evasion Detection
 * ============================================================================ */

/**
 * Mimicry attack detection.
 * Detects when attacker interleaves benign actions to evade detection.
 */
typedef struct {
    /* Statistical baselines */
    float benign_action_rate;               /* Normal benign action frequency */
    float benign_action_entropy;            /* Entropy of benign actions */

    /* Mimicry indicators */
    float observed_benign_rate;             /* Current benign action rate */
    float deviation_score;                  /* Deviation from baseline */

    /* Timing analysis */
    double avg_inter_event_time_ms;         /* Average time between events */
    double expected_inter_event_time_ms;    /* Expected for normal behavior */

    /* Flags */
    bool is_mimicry_likely;
} MimicryDetector;

/* ============================================================================
 * APT Detector Engine
 * ============================================================================ */

typedef struct {
    /* Core components */
    ProvenanceGraph* graph;                 /* System provenance graph */
    GNNModel* gnn_model;                    /* GNN/GAT model */

    /* Calibration */
    CalibrationMap* calibration;            /* ECE calibration */

    /* Evasion detection */
    MimicryDetector* mimicry_detector;

    /* Alert queue */
    APTAlert alerts[APT_MAX_ALERTS];
    size_t num_alerts;
    pthread_mutex_t alert_lock;

    /* Detection configuration */
    struct {
        float confidence_threshold;         /* Min confidence to alert */
        size_t min_chain_length;            /* Min events in attack chain */
        uint64_t detection_window_ns;       /* Time window for analysis */
        bool enable_calibration;            /* Use ECE calibration */
        bool enable_mimicry_detection;      /* Detect evasion attacks */
        bool enable_causal_inference;       /* Use SCM for causal analysis */
    } config;

    /* Statistics */
    struct {
        uint64_t total_detections;
        uint64_t true_positives;
        uint64_t false_positives;
        uint64_t false_negatives;
        double precision;
        double recall;
        double f1_score;
        double avg_detection_time_ms;
        double expected_calibration_error;  /* ECE metric */
    } stats;

    /* Thread safety */
    pthread_rwlock_t lock;

    /* Background analysis thread */
    pthread_t analysis_thread;
    bool is_running;
} APTDetector;

/* ============================================================================
 * API - Lifecycle
 * ============================================================================ */

/**
 * Create APT detector.
 *
 * @param max_nodes     Max nodes in provenance graph
 * @param max_edges     Max edges in provenance graph
 * @param model_path    Path to pretrained GNN model (NULL = default)
 * @return              Detector instance
 */
APTDetector* apt_detector_create(
    size_t max_nodes,
    size_t max_edges,
    const char* model_path
);

/**
 * Destroy detector and free resources.
 */
void apt_detector_destroy(APTDetector* detector);

/**
 * Start background analysis thread.
 */
bool apt_detector_start(APTDetector* detector);

/**
 * Stop background analysis thread.
 */
void apt_detector_stop(APTDetector* detector);

/* ============================================================================
 * API - Event Ingestion
 * ============================================================================ */

/**
 * Ingest system event (syscall, audit log).
 *
 * @param detector      APT detector
 * @param src_entity    Source entity (process, file, etc.)
 * @param dst_entity    Destination entity
 * @param operation     Operation type (fork, exec, read, write, etc.)
 * @param timestamp_ns  Event timestamp
 * @param metadata      Additional metadata (optional)
 */
void apt_ingest_event(
    APTDetector* detector,
    const void* src_entity,
    NodeType src_type,
    const void* dst_entity,
    NodeType dst_type,
    EdgeType operation,
    uint64_t timestamp_ns,
    const void* metadata
);

/**
 * Ingest batch of events (for performance).
 */
void apt_ingest_batch(
    APTDetector* detector,
    const void** src_entities,
    const NodeType* src_types,
    const void** dst_entities,
    const NodeType* dst_types,
    const EdgeType* operations,
    const uint64_t* timestamps,
    size_t count
);

/* ============================================================================
 * API - Detection
 * ============================================================================ */

/**
 * Run APT detection on current graph.
 *
 * @param detector      APT detector
 * @param out_alerts    Output alerts
 * @param max_alerts    Max alerts to return
 * @param out_count     Number of alerts generated
 * @return              true if APT detected
 */
bool apt_detect(
    APTDetector* detector,
    APTAlert* out_alerts,
    size_t max_alerts,
    size_t* out_count
);

/**
 * Detect specific APT phase.
 *
 * @param detector      APT detector
 * @param phase         Phase to detect
 * @param out_confidence Output confidence
 * @return              true if phase detected
 */
bool apt_detect_phase(
    APTDetector* detector,
    APTPhase phase,
    float* out_confidence
);

/**
 * Get current alerts.
 */
void apt_get_alerts(
    const APTDetector* detector,
    APTAlert* out_alerts,
    size_t max_alerts,
    size_t* out_count
);

/**
 * Clear processed alerts.
 */
void apt_clear_alerts(APTDetector* detector);

/* ============================================================================
 * API - Calibration
 * ============================================================================ */

/**
 * Calibrate model using labeled data.
 * Reduces Expected Calibration Error (ECE).
 *
 * @param detector      APT detector
 * @param graphs        Provenance graphs (training set)
 * @param labels        Ground truth labels (0 = benign, 1 = APT)
 * @param count         Number of samples
 */
void apt_calibrate(
    APTDetector* detector,
    ProvenanceGraph** graphs,
    const int* labels,
    size_t count
);

/**
 * Apply calibration to raw confidence.
 *
 * @param detector      APT detector
 * @param raw_confidence Raw model output
 * @return              Calibrated probability
 */
float apt_apply_calibration(
    const APTDetector* detector,
    float raw_confidence
);

/**
 * Compute Expected Calibration Error (ECE).
 */
double apt_compute_ece(
    const APTDetector* detector,
    const float* predictions,
    const int* labels,
    size_t count
);

/* ============================================================================
 * API - Evasion Detection
 * ============================================================================ */

/**
 * Detect mimicry attacks (attacker trying to evade by adding benign actions).
 *
 * @param detector      APT detector
 * @param chain         Causal chain to analyze
 * @param out_score     Mimicry likelihood [0, 1]
 * @return              true if mimicry detected
 */
bool apt_detect_mimicry(
    APTDetector* detector,
    const CausalChain* chain,
    float* out_score
);

/**
 * Update mimicry baseline with new benign behavior.
 */
void apt_update_mimicry_baseline(
    APTDetector* detector,
    const ProvenanceGraph* benign_graph
);

/* ============================================================================
 * API - MITRE ATT&CK Mapping
 * ============================================================================ */

/**
 * Map detected behavior to MITRE ATT&CK framework.
 *
 * @param detector      APT detector
 * @param chain         Causal chain
 * @param out_tactics   Output tactics
 * @param out_techniques Output techniques
 * @param max_out       Max entries to return
 * @param out_count     Number of mappings
 */
void apt_map_to_mitre(
    const APTDetector* detector,
    const CausalChain* chain,
    char out_tactics[][64],
    char out_techniques[][64],
    size_t max_out,
    size_t* out_count
);

/* ============================================================================
 * API - Utility
 * ============================================================================ */

/**
 * Get detector statistics.
 */
void apt_get_stats(const APTDetector* detector, void* out_stats);

/**
 * Print statistics.
 */
void apt_print_stats(const APTDetector* detector);

/**
 * Export alert to JSON.
 */
void apt_export_alert_json(const APTAlert* alert, const char* filename);

/**
 * Generate human-readable report.
 */
void apt_generate_report(
    const APTDetector* detector,
    const APTAlert* alert,
    char* out_report,
    size_t report_size
);

/**
 * Visualize attack chain.
 */
void apt_visualize_chain(
    const APTDetector* detector,
    const CausalChain* chain,
    const char* output_file
);

/**
 * Convert APT phase to string.
 */
const char* apt_phase_to_string(APTPhase phase);

/**
 * Convert APT severity to string.
 */
const char* apt_severity_to_string(int severity);

#ifdef __cplusplus
}
#endif

#endif /* FLOWSHIELD_APT_DETECTOR_H */
