/**
 * FlowShield - DDoS/Anomaly Detection Engine
 *
 * A high-performance network anomaly detection system built on ParallelAVL.
 * Designed to demonstrate adversary-resistant data structures in security applications.
 *
 * Key Features:
 * - Concurrent flow tracking (millions of flows)
 * - Real-time anomaly detection
 * - Resistance to algorithmic complexity attacks
 * - Dynamic scaling under load
 *
 * For conference demos, research, and production security tools.
 *
 * Author: Built on ParallelAVL
 * License: MIT
 */

#ifndef FLOWSHIELD_H
#define FLOWSHIELD_H

#include "flow_types.h"
#include "flow_tracker.h"
#include "anomaly_detector.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Version
 * ============================================================================ */

#define FLOWSHIELD_VERSION_MAJOR 0
#define FLOWSHIELD_VERSION_MINOR 1
#define FLOWSHIELD_VERSION_PATCH 0
#define FLOWSHIELD_VERSION_STRING "0.1.0"

/* ============================================================================
 * FlowShield Engine (combines tracker + detector)
 * ============================================================================ */

typedef struct FlowShield FlowShield;

/* Engine configuration */
typedef struct {
    size_t num_shards;              /* Number of AVL shards */
    RouterStrategy routing;          /* Routing strategy */
    DetectionConfig detection;       /* Detection thresholds */
    bool enable_learning;            /* Start in learning mode */
    uint32_t learning_duration_sec;  /* Learning period */
} FlowShieldConfig;

/* Default configuration */
static inline FlowShieldConfig flowshield_config_default(void) {
    return (FlowShieldConfig) {
        .num_shards             = 8,
        .routing                = ROUTER_LOAD_AWARE,  /* Adversary-resistant! */
        .detection              = detection_config_default(),
        .enable_learning        = false,
        .learning_duration_sec  = 60
    };
}

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

/**
 * Create FlowShield engine.
 *
 * @param config    Configuration (NULL for defaults)
 * @return          New engine or NULL on error
 */
FlowShield* flowshield_create(const FlowShieldConfig* config);

/**
 * Destroy FlowShield engine.
 */
void flowshield_destroy(FlowShield* engine);

/* ============================================================================
 * Packet Processing
 * ============================================================================ */

/**
 * Process a single packet.
 * This is the main ingestion point.
 *
 * @param engine        FlowShield instance
 * @param src_ip        Source IP
 * @param dst_ip        Destination IP
 * @param src_port      Source port
 * @param dst_port      Destination port
 * @param protocol      Protocol (PROTO_TCP, PROTO_UDP, etc.)
 * @param packet_size   Packet size in bytes
 * @param tcp_flags     TCP flags (0 for non-TCP)
 * @return              true if packet triggered an alert
 */
bool flowshield_process_packet(
    FlowShield* engine,
    uint32_t src_ip,
    uint32_t dst_ip,
    uint16_t src_port,
    uint16_t dst_port,
    uint8_t protocol,
    uint32_t packet_size,
    uint8_t tcp_flags
);

/**
 * Process packet from FlowKey structure.
 */
bool flowshield_process_flow_packet(
    FlowShield* engine,
    const FlowKey* key,
    uint32_t packet_size,
    uint8_t tcp_flags
);

/* ============================================================================
 * Analysis
 * ============================================================================ */

/**
 * Run detection analysis.
 * Call periodically (e.g., every second).
 *
 * @return              Number of new alerts
 */
size_t flowshield_analyze(FlowShield* engine);

/**
 * Get current alerts.
 */
size_t flowshield_get_alerts(
    FlowShield* engine,
    FlowAlert* out_alerts,
    size_t max_alerts
);

/**
 * Clear alerts.
 */
void flowshield_clear_alerts(FlowShield* engine);

/* ============================================================================
 * Metrics
 * ============================================================================ */

/**
 * Get flow metrics.
 */
void flowshield_get_metrics(FlowShield* engine, FlowMetrics* out_metrics);

/**
 * Get entropy analysis.
 */
void flowshield_get_entropy(FlowShield* engine, EntropyAnalysis* out_entropy);

/**
 * Get detector statistics.
 */
void flowshield_get_detector_stats(FlowShield* engine, DetectorStats* out_stats);

/* ============================================================================
 * Accessors
 * ============================================================================ */

/**
 * Get underlying flow tracker.
 */
FlowTracker* flowshield_get_tracker(FlowShield* engine);

/**
 * Get underlying anomaly detector.
 */
AnomalyDetector* flowshield_get_detector(FlowShield* engine);

/* ============================================================================
 * Utility: Packet Simulation (for testing/demos)
 * ============================================================================ */

/**
 * Generate random normal traffic.
 *
 * @param engine        FlowShield instance
 * @param num_packets   Number of packets to generate
 * @param num_sources   Number of unique source IPs
 * @param num_dests     Number of unique destination IPs
 */
void flowshield_simulate_normal_traffic(
    FlowShield* engine,
    size_t num_packets,
    size_t num_sources,
    size_t num_dests
);

/**
 * Simulate SYN flood attack.
 *
 * @param engine        FlowShield instance
 * @param target_ip     Target IP
 * @param target_port   Target port
 * @param num_packets   Number of SYN packets
 * @param num_sources   Number of spoofed source IPs (1 = single source)
 */
void flowshield_simulate_syn_flood(
    FlowShield* engine,
    uint32_t target_ip,
    uint16_t target_port,
    size_t num_packets,
    size_t num_sources
);

/**
 * Simulate UDP amplification attack.
 *
 * @param engine            FlowShield instance
 * @param victim_ip         Victim IP (spoofed source)
 * @param amplifier_port    Amplifier port (53=DNS, 123=NTP, etc.)
 * @param num_packets       Number of amplified packets
 * @param amplification     Amplification factor (response/request size)
 */
void flowshield_simulate_udp_amplification(
    FlowShield* engine,
    uint32_t victim_ip,
    uint16_t amplifier_port,
    size_t num_packets,
    double amplification
);

/**
 * Simulate algorithmic complexity attack (hotspot attack).
 * This demonstrates the advantage of ROUTER_LOAD_AWARE over ROUTER_STATIC_HASH.
 *
 * @param engine        FlowShield instance
 * @param target_shard  Shard to attack (keys hash to this shard)
 * @param num_packets   Number of attack packets
 */
void flowshield_simulate_hotspot_attack(
    FlowShield* engine,
    size_t target_shard,
    size_t num_packets
);

/* ============================================================================
 * Output Formatting
 * ============================================================================ */

/**
 * Format alert as JSON.
 */
size_t flowshield_alert_to_json(
    const FlowAlert* alert,
    char* buf,
    size_t buf_size
);

/**
 * Format metrics as Prometheus exposition format.
 */
size_t flowshield_metrics_to_prometheus(
    const FlowMetrics* metrics,
    char* buf,
    size_t buf_size
);

/**
 * Print summary to stdout.
 */
void flowshield_print_summary(FlowShield* engine);

/**
 * Print real-time dashboard to stdout.
 * Use in a loop with sleep for live monitoring.
 *
 * @param engine        FlowShield instance
 * @param clear_screen  Whether to clear screen before printing
 */
void flowshield_print_dashboard(FlowShield* engine, bool clear_screen);

#ifdef __cplusplus
}
#endif

#endif /* FLOWSHIELD_H */
