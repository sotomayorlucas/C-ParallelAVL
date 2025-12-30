/**
 * FlowShield - Anomaly Detector
 *
 * Multi-algorithm DDoS and anomaly detection engine.
 * Detects volumetric attacks, rate spikes, and protocol anomalies.
 */

#ifndef FLOWSHIELD_ANOMALY_DETECTOR_H
#define FLOWSHIELD_ANOMALY_DETECTOR_H

#include "flow_types.h"
#include "flow_tracker.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Anomaly Detector Handle
 * ============================================================================ */

typedef struct AnomalyDetector AnomalyDetector;

/* ============================================================================
 * Alert Callback
 * ============================================================================ */

/**
 * Callback invoked when an alert is generated.
 *
 * @param alert         Alert details
 * @param user_data     User-provided context
 */
typedef void (*AlertCallbackFn)(const FlowAlert* alert, void* user_data);

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

/**
 * Create anomaly detector.
 *
 * @param tracker       Flow tracker to analyze
 * @param config        Detection thresholds (NULL for defaults)
 * @return              New detector or NULL on error
 */
AnomalyDetector* anomaly_detector_create(
    FlowTracker* tracker,
    const DetectionConfig* config
);

/**
 * Destroy anomaly detector.
 */
void anomaly_detector_destroy(AnomalyDetector* detector);

/* ============================================================================
 * Configuration
 * ============================================================================ */

/**
 * Update detection configuration.
 */
void anomaly_detector_set_config(
    AnomalyDetector* detector,
    const DetectionConfig* config
);

/**
 * Get current configuration.
 */
void anomaly_detector_get_config(
    const AnomalyDetector* detector,
    DetectionConfig* out_config
);

/**
 * Register alert callback.
 */
void anomaly_detector_set_callback(
    AnomalyDetector* detector,
    AlertCallbackFn callback,
    void* user_data
);

/* ============================================================================
 * Detection Algorithms
 * ============================================================================ */

/**
 * Run all detection algorithms on current flows.
 * This is the main detection entry point.
 *
 * @param detector      Detector instance
 * @return              Number of alerts generated
 */
size_t anomaly_detector_analyze(AnomalyDetector* detector);

/**
 * Run specific detection algorithm.
 */
size_t anomaly_detector_check_volumetric(AnomalyDetector* detector);
size_t anomaly_detector_check_rate_spikes(AnomalyDetector* detector);
size_t anomaly_detector_check_syn_flood(AnomalyDetector* detector);
size_t anomaly_detector_check_amplification(AnomalyDetector* detector);
size_t anomaly_detector_check_entropy(AnomalyDetector* detector);

/**
 * Analyze a single flow for anomalies.
 *
 * @param detector      Detector instance
 * @param key           Flow to analyze
 * @param stats         Flow statistics
 * @param out_alert     Alert output (if anomaly detected)
 * @return              true if anomaly detected
 */
bool anomaly_detector_check_flow(
    AnomalyDetector* detector,
    const FlowKey* key,
    const FlowStats* stats,
    FlowAlert* out_alert
);

/* ============================================================================
 * Alert Management
 * ============================================================================ */

/**
 * Get number of active alerts.
 */
size_t anomaly_detector_alert_count(const AnomalyDetector* detector);

/**
 * Get recent alerts.
 *
 * @param detector      Detector instance
 * @param out_alerts    Output buffer for alerts
 * @param max_alerts    Maximum alerts to return
 * @return              Number of alerts returned
 */
size_t anomaly_detector_get_alerts(
    const AnomalyDetector* detector,
    FlowAlert* out_alerts,
    size_t max_alerts
);

/**
 * Clear all alerts.
 */
void anomaly_detector_clear_alerts(AnomalyDetector* detector);

/**
 * Acknowledge an alert (mark as handled).
 */
void anomaly_detector_ack_alert(
    AnomalyDetector* detector,
    const FlowKey* flow
);

/* ============================================================================
 * Statistics
 * ============================================================================ */

typedef struct {
    uint64_t total_analyses;        /* Number of analysis runs */
    uint64_t total_alerts;          /* Total alerts generated */
    uint64_t flows_analyzed;        /* Total flows checked */

    /* Per-algorithm stats */
    uint64_t volumetric_detections;
    uint64_t rate_spike_detections;
    uint64_t syn_flood_detections;
    uint64_t amplification_detections;
    uint64_t entropy_anomalies;

    /* Performance */
    uint64_t last_analysis_time_ns; /* Duration of last analysis */
    double   avg_analysis_time_ms;  /* Average analysis time */
} DetectorStats;

/**
 * Get detector statistics.
 */
void anomaly_detector_get_stats(
    const AnomalyDetector* detector,
    DetectorStats* out_stats
);

/* ============================================================================
 * Entropy Analysis (for research/conference demo)
 * ============================================================================ */

typedef struct {
    double src_ip_entropy;      /* Source IP distribution entropy */
    double dst_ip_entropy;      /* Destination IP distribution entropy */
    double src_port_entropy;    /* Source port distribution entropy */
    double dst_port_entropy;    /* Destination port distribution entropy */
    double protocol_entropy;    /* Protocol distribution entropy */

    size_t unique_src_ips;      /* Number of unique source IPs */
    size_t unique_dst_ips;      /* Number of unique destination IPs */
    size_t sample_size;         /* Number of flows in sample */
} EntropyAnalysis;

/**
 * Calculate entropy metrics for current traffic.
 * Useful for detecting botnets (low source entropy) or
 * DDoS attacks (low destination entropy).
 */
void anomaly_detector_calc_entropy(
    AnomalyDetector* detector,
    EntropyAnalysis* out_entropy
);

/* ============================================================================
 * Baseline Learning
 * ============================================================================ */

/**
 * Start learning baseline traffic patterns.
 * During learning, no alerts are generated.
 *
 * @param duration_sec  Learning duration in seconds
 */
void anomaly_detector_start_learning(
    AnomalyDetector* detector,
    uint32_t duration_sec
);

/**
 * Check if detector is in learning mode.
 */
bool anomaly_detector_is_learning(const AnomalyDetector* detector);

/**
 * Stop learning and switch to detection mode.
 */
void anomaly_detector_stop_learning(AnomalyDetector* detector);

#ifdef __cplusplus
}
#endif

#endif /* FLOWSHIELD_ANOMALY_DETECTOR_H */
