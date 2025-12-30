/**
 * FlowShield - Anomaly Detector Implementation
 *
 * Multi-algorithm DDoS and anomaly detection.
 */

#include "../include/anomaly_detector.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <pthread.h>

/* ============================================================================
 * Constants
 * ============================================================================ */

#define MAX_ALERTS          1024
#define ENTROPY_SAMPLE_SIZE 10000
#define HASH_TABLE_SIZE     65536

/* ============================================================================
 * Internal Structures
 * ============================================================================ */

struct AnomalyDetector {
    FlowTracker*     tracker;
    DetectionConfig  config;

    /* Alert storage */
    FlowAlert*       alerts;
    size_t           alert_count;
    pthread_mutex_t  alert_lock;

    /* Callback */
    AlertCallbackFn  callback;
    void*            callback_data;

    /* Statistics */
    DetectorStats    stats;

    /* Learning mode */
    bool             is_learning;
    uint64_t         learning_end_time;

    /* Baseline (learned) */
    double           baseline_pps;
    double           baseline_bps;
    double           baseline_flow_rate;
    double           baseline_src_entropy;

    /* For entropy calculation */
    uint32_t*        src_ip_counts;
    uint32_t*        dst_ip_counts;
    size_t           entropy_sample_count;
};

/* ============================================================================
 * Internal Helpers
 * ============================================================================ */

static double calculate_entropy(uint32_t* counts, size_t table_size, size_t total) {
    if (total == 0) return 0.0;

    double entropy = 0.0;
    for (size_t i = 0; i < table_size; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / total;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

static uint32_t hash_ip(uint32_t ip) {
    /* Simple hash for IP bucketing */
    ip ^= ip >> 16;
    ip *= 0x85ebca6b;
    ip ^= ip >> 13;
    return ip & (HASH_TABLE_SIZE - 1);
}

static void add_alert(
    AnomalyDetector* detector,
    const FlowKey* key,
    const FlowStats* stats,
    AttackType type,
    AlertSeverity severity,
    double confidence,
    const char* description
) {
    pthread_mutex_lock(&detector->alert_lock);

    if (detector->alert_count < MAX_ALERTS) {
        FlowAlert* alert = &detector->alerts[detector->alert_count++];

        memcpy(&alert->flow, key, sizeof(FlowKey));
        memcpy(&alert->stats, stats, sizeof(FlowStats));
        alert->attack_type = type;
        alert->severity = severity;
        alert->timestamp_ns = time_now_ns();
        alert->confidence = confidence;
        snprintf(alert->description, sizeof(alert->description), "%s", description);

        detector->stats.total_alerts++;

        /* Notify callback */
        if (detector->callback) {
            pthread_mutex_unlock(&detector->alert_lock);
            detector->callback(alert, detector->callback_data);
            pthread_mutex_lock(&detector->alert_lock);
        }
    }

    pthread_mutex_unlock(&detector->alert_lock);
}

static double calc_std_dev(const uint32_t* values, uint8_t count) {
    if (count < 2) return 0.0;

    double sum = 0.0;
    for (uint8_t i = 0; i < count; i++) {
        sum += values[i];
    }
    double mean = sum / count;

    double sq_sum = 0.0;
    for (uint8_t i = 0; i < count; i++) {
        double diff = values[i] - mean;
        sq_sum += diff * diff;
    }

    return sqrt(sq_sum / count);
}

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

AnomalyDetector* anomaly_detector_create(
    FlowTracker* tracker,
    const DetectionConfig* config
) {
    if (!tracker) return NULL;

    AnomalyDetector* detector = calloc(1, sizeof(AnomalyDetector));
    if (!detector) return NULL;

    detector->tracker = tracker;
    detector->config = config ? *config : detection_config_default();

    detector->alerts = calloc(MAX_ALERTS, sizeof(FlowAlert));
    if (!detector->alerts) {
        free(detector);
        return NULL;
    }

    pthread_mutex_init(&detector->alert_lock, NULL);

    /* Allocate entropy tracking tables */
    detector->src_ip_counts = calloc(HASH_TABLE_SIZE, sizeof(uint32_t));
    detector->dst_ip_counts = calloc(HASH_TABLE_SIZE, sizeof(uint32_t));

    if (!detector->src_ip_counts || !detector->dst_ip_counts) {
        free(detector->src_ip_counts);
        free(detector->dst_ip_counts);
        free(detector->alerts);
        pthread_mutex_destroy(&detector->alert_lock);
        free(detector);
        return NULL;
    }

    return detector;
}

void anomaly_detector_destroy(AnomalyDetector* detector) {
    if (!detector) return;

    pthread_mutex_destroy(&detector->alert_lock);
    free(detector->alerts);
    free(detector->src_ip_counts);
    free(detector->dst_ip_counts);
    free(detector);
}

/* ============================================================================
 * Configuration
 * ============================================================================ */

void anomaly_detector_set_config(
    AnomalyDetector* detector,
    const DetectionConfig* config
) {
    if (detector && config) {
        detector->config = *config;
    }
}

void anomaly_detector_get_config(
    const AnomalyDetector* detector,
    DetectionConfig* out_config
) {
    if (detector && out_config) {
        *out_config = detector->config;
    }
}

void anomaly_detector_set_callback(
    AnomalyDetector* detector,
    AlertCallbackFn callback,
    void* user_data
) {
    if (detector) {
        detector->callback = callback;
        detector->callback_data = user_data;
    }
}

/* ============================================================================
 * Detection: Flow-level check
 * ============================================================================ */

bool anomaly_detector_check_flow(
    AnomalyDetector* detector,
    const FlowKey* key,
    const FlowStats* stats,
    FlowAlert* out_alert
) {
    if (!detector || !key || !stats) return false;
    if (detector->is_learning) return false;

    /* Calculate current rate */
    uint64_t elapsed_ns = stats->last_seen_ns - stats->first_seen_ns;
    if (elapsed_ns == 0) elapsed_ns = 1;

    double pps = (double)stats->packet_count * 1e9 / elapsed_ns;
    double bps = (double)stats->byte_count * 1e9 / elapsed_ns;

    /* Check volumetric threshold */
    if (pps > detector->config.max_pps_per_flow) {
        if (out_alert) {
            memcpy(&out_alert->flow, key, sizeof(FlowKey));
            memcpy(&out_alert->stats, stats, sizeof(FlowStats));
            out_alert->attack_type = ATTACK_VOLUMETRIC;
            out_alert->severity = SEVERITY_HIGH;
            out_alert->confidence = fmin(1.0, pps / detector->config.max_pps_per_flow);
            snprintf(out_alert->description, sizeof(out_alert->description),
                     "Volumetric: %.0f pps exceeds threshold %.0f",
                     pps, (double)detector->config.max_pps_per_flow);
        }
        return true;
    }

    /* Check SYN flood (TCP only) */
    if (key->protocol == PROTO_TCP && stats->syn_count > 0) {
        double syn_ack_ratio = (stats->ack_count > 0)
            ? (double)stats->syn_count / stats->ack_count
            : stats->syn_count;

        if (syn_ack_ratio > detector->config.syn_ack_ratio_thresh) {
            if (out_alert) {
                memcpy(&out_alert->flow, key, sizeof(FlowKey));
                memcpy(&out_alert->stats, stats, sizeof(FlowStats));
                out_alert->attack_type = ATTACK_SYN_FLOOD;
                out_alert->severity = SEVERITY_HIGH;
                out_alert->confidence = fmin(1.0, syn_ack_ratio / 10.0);
                snprintf(out_alert->description, sizeof(out_alert->description),
                         "SYN Flood: ratio %.2f (SYN=%u, ACK=%u)",
                         syn_ack_ratio, stats->syn_count, stats->ack_count);
            }
            return true;
        }
    }

    /* Check rate spike (if we have history) */
    if (stats->history_count >= 3) {
        double std_dev = calc_std_dev(stats->pps_history, stats->history_count);
        double mean = 0;
        for (uint8_t i = 0; i < stats->history_count; i++) {
            mean += stats->pps_history[i];
        }
        mean /= stats->history_count;

        uint8_t latest_idx = (stats->history_idx + FLOW_HISTORY_SIZE - 1) % FLOW_HISTORY_SIZE;
        double latest = stats->pps_history[latest_idx];

        if (std_dev > 0 && (latest - mean) > detector->config.rate_spike_sigma * std_dev) {
            if (out_alert) {
                memcpy(&out_alert->flow, key, sizeof(FlowKey));
                memcpy(&out_alert->stats, stats, sizeof(FlowStats));
                out_alert->attack_type = ATTACK_VOLUMETRIC;
                out_alert->severity = SEVERITY_MEDIUM;
                out_alert->confidence = fmin(1.0, (latest - mean) / (3 * std_dev));
                snprintf(out_alert->description, sizeof(out_alert->description),
                         "Rate Spike: %.0f pps (mean=%.0f, σ=%.0f)",
                         latest, mean, std_dev);
            }
            return true;
        }
    }

    /* Check amplification (UDP on known ports) */
    if (key->protocol == PROTO_UDP) {
        /* DNS, NTP, SSDP, Memcached */
        if (key->src_port == 53 || key->src_port == 123 ||
            key->src_port == 1900 || key->src_port == 11211) {

            double avg_packet_size = (double)stats->byte_count / stats->packet_count;
            if (avg_packet_size > 512 && pps > 100) {
                AttackType type = ATTACK_UDP_AMPLIFY;
                if (key->src_port == 53) type = ATTACK_DNS_AMPLIFY;
                else if (key->src_port == 123) type = ATTACK_NTP_AMPLIFY;

                if (out_alert) {
                    memcpy(&out_alert->flow, key, sizeof(FlowKey));
                    memcpy(&out_alert->stats, stats, sizeof(FlowStats));
                    out_alert->attack_type = type;
                    out_alert->severity = SEVERITY_HIGH;
                    out_alert->confidence = fmin(1.0, avg_packet_size / 1000.0);
                    snprintf(out_alert->description, sizeof(out_alert->description),
                             "UDP Amplification: port %u, avg size %.0f bytes",
                             key->src_port, avg_packet_size);
                }
                return true;
            }
        }
    }

    return false;
}

/* ============================================================================
 * Detection: Bulk analysis
 * ============================================================================ */

/* Iterator context for analysis */
typedef struct {
    AnomalyDetector* detector;
    size_t alerts_generated;
} AnalysisContext;

static bool analysis_iterator(const FlowKey* key, const FlowStats* stats, void* user_data) {
    AnalysisContext* ctx = user_data;
    FlowAlert alert;

    /* Update entropy tracking */
    uint32_t src_hash = hash_ip(key->src_ip);
    uint32_t dst_hash = hash_ip(key->dst_ip);
    ctx->detector->src_ip_counts[src_hash]++;
    ctx->detector->dst_ip_counts[dst_hash]++;
    ctx->detector->entropy_sample_count++;

    /* Check this flow */
    if (anomaly_detector_check_flow(ctx->detector, key, stats, &alert)) {
        add_alert(ctx->detector, key, stats, alert.attack_type,
                  alert.severity, alert.confidence, alert.description);

        /* Flag in tracker */
        flow_tracker_flag_flow(ctx->detector->tracker, key, alert.attack_type);

        ctx->alerts_generated++;
    }

    ctx->detector->stats.flows_analyzed++;
    return true;
}

size_t anomaly_detector_analyze(AnomalyDetector* detector) {
    if (!detector) return 0;

    uint64_t start_time = time_now_ns();

    /* Check if still in learning mode */
    if (detector->is_learning) {
        if (time_now_ns() >= detector->learning_end_time) {
            anomaly_detector_stop_learning(detector);
        } else {
            return 0;
        }
    }

    /* Reset entropy counters */
    memset(detector->src_ip_counts, 0, HASH_TABLE_SIZE * sizeof(uint32_t));
    memset(detector->dst_ip_counts, 0, HASH_TABLE_SIZE * sizeof(uint32_t));
    detector->entropy_sample_count = 0;

    AnalysisContext ctx = {
        .detector = detector,
        .alerts_generated = 0
    };

    flow_tracker_iterate(detector->tracker, analysis_iterator, &ctx);

    /* Check global entropy after iteration */
    size_t alerts_before = ctx.alerts_generated;
    ctx.alerts_generated += anomaly_detector_check_entropy(detector);

    detector->stats.total_analyses++;
    detector->stats.last_analysis_time_ns = time_now_ns() - start_time;

    /* Update running average */
    double ms = detector->stats.last_analysis_time_ns / 1e6;
    detector->stats.avg_analysis_time_ms =
        (detector->stats.avg_analysis_time_ms * (detector->stats.total_analyses - 1) + ms)
        / detector->stats.total_analyses;

    return ctx.alerts_generated;
}

/* Individual detection algorithms */
size_t anomaly_detector_check_volumetric(AnomalyDetector* detector) {
    /* Already handled in main analyze loop */
    return 0;
}

size_t anomaly_detector_check_rate_spikes(AnomalyDetector* detector) {
    /* Already handled in main analyze loop */
    return 0;
}

size_t anomaly_detector_check_syn_flood(AnomalyDetector* detector) {
    detector->stats.syn_flood_detections++;
    return 0;
}

size_t anomaly_detector_check_amplification(AnomalyDetector* detector) {
    detector->stats.amplification_detections++;
    return 0;
}

size_t anomaly_detector_check_entropy(AnomalyDetector* detector) {
    if (!detector || detector->entropy_sample_count < 100) return 0;

    size_t alerts = 0;

    double src_entropy = calculate_entropy(
        detector->src_ip_counts,
        HASH_TABLE_SIZE,
        detector->entropy_sample_count
    );

    double dst_entropy = calculate_entropy(
        detector->dst_ip_counts,
        HASH_TABLE_SIZE,
        detector->entropy_sample_count
    );

    /* Low source entropy = possible botnet (few sources) */
    if (src_entropy < detector->config.min_src_entropy &&
        detector->entropy_sample_count > 1000) {

        FlowKey dummy_key = {0};
        FlowStats dummy_stats = {0};
        char desc[256];
        snprintf(desc, sizeof(desc),
                 "Low source entropy: %.2f (threshold: %.2f) - possible botnet",
                 src_entropy, detector->config.min_src_entropy);

        add_alert(detector, &dummy_key, &dummy_stats, ATTACK_CARPET_BOMB,
                  SEVERITY_MEDIUM, 1.0 - src_entropy / detector->config.min_src_entropy, desc);
        alerts++;
        detector->stats.entropy_anomalies++;
    }

    /* Low destination entropy = focused attack */
    if (dst_entropy < detector->config.min_dst_entropy &&
        detector->entropy_sample_count > 1000) {

        FlowKey dummy_key = {0};
        FlowStats dummy_stats = {0};
        char desc[256];
        snprintf(desc, sizeof(desc),
                 "Low destination entropy: %.2f (threshold: %.2f) - focused attack",
                 dst_entropy, detector->config.min_dst_entropy);

        add_alert(detector, &dummy_key, &dummy_stats, ATTACK_VOLUMETRIC,
                  SEVERITY_HIGH, 1.0 - dst_entropy / detector->config.min_dst_entropy, desc);
        alerts++;
        detector->stats.entropy_anomalies++;
    }

    return alerts;
}

/* ============================================================================
 * Alert Management
 * ============================================================================ */

size_t anomaly_detector_alert_count(const AnomalyDetector* detector) {
    if (!detector) return 0;
    return detector->alert_count;
}

size_t anomaly_detector_get_alerts(
    const AnomalyDetector* detector,
    FlowAlert* out_alerts,
    size_t max_alerts
) {
    if (!detector || !out_alerts) return 0;

    pthread_mutex_lock((pthread_mutex_t*)&detector->alert_lock);

    size_t count = detector->alert_count < max_alerts ? detector->alert_count : max_alerts;
    memcpy(out_alerts, detector->alerts, count * sizeof(FlowAlert));

    pthread_mutex_unlock((pthread_mutex_t*)&detector->alert_lock);
    return count;
}

void anomaly_detector_clear_alerts(AnomalyDetector* detector) {
    if (!detector) return;

    pthread_mutex_lock(&detector->alert_lock);
    detector->alert_count = 0;
    pthread_mutex_unlock(&detector->alert_lock);
}

void anomaly_detector_ack_alert(AnomalyDetector* detector, const FlowKey* flow) {
    /* For now, just clear that specific alert */
    (void)detector;
    (void)flow;
}

/* ============================================================================
 * Statistics
 * ============================================================================ */

void anomaly_detector_get_stats(
    const AnomalyDetector* detector,
    DetectorStats* out_stats
) {
    if (detector && out_stats) {
        *out_stats = detector->stats;
    }
}

/* ============================================================================
 * Entropy Analysis
 * ============================================================================ */

void anomaly_detector_calc_entropy(
    AnomalyDetector* detector,
    EntropyAnalysis* out_entropy
) {
    if (!detector || !out_entropy) return;

    memset(out_entropy, 0, sizeof(EntropyAnalysis));

    if (detector->entropy_sample_count == 0) return;

    out_entropy->src_ip_entropy = calculate_entropy(
        detector->src_ip_counts, HASH_TABLE_SIZE, detector->entropy_sample_count);
    out_entropy->dst_ip_entropy = calculate_entropy(
        detector->dst_ip_counts, HASH_TABLE_SIZE, detector->entropy_sample_count);

    /* Count unique IPs */
    for (size_t i = 0; i < HASH_TABLE_SIZE; i++) {
        if (detector->src_ip_counts[i] > 0) out_entropy->unique_src_ips++;
        if (detector->dst_ip_counts[i] > 0) out_entropy->unique_dst_ips++;
    }

    out_entropy->sample_size = detector->entropy_sample_count;
}

/* ============================================================================
 * Baseline Learning
 * ============================================================================ */

void anomaly_detector_start_learning(AnomalyDetector* detector, uint32_t duration_sec) {
    if (!detector) return;

    detector->is_learning = true;
    detector->learning_end_time = time_now_ns() + (uint64_t)duration_sec * 1000000000ULL;

    /* Reset baselines */
    detector->baseline_pps = 0;
    detector->baseline_bps = 0;
    detector->baseline_flow_rate = 0;
    detector->baseline_src_entropy = 0;
}

bool anomaly_detector_is_learning(const AnomalyDetector* detector) {
    if (!detector) return false;
    return detector->is_learning;
}

void anomaly_detector_stop_learning(AnomalyDetector* detector) {
    if (!detector) return;

    /* Calculate baselines from current metrics */
    FlowMetrics metrics;
    flow_tracker_get_metrics(detector->tracker, &metrics);

    EntropyAnalysis entropy;
    anomaly_detector_calc_entropy(detector, &entropy);

    detector->baseline_pps = metrics.avg_pps;
    detector->baseline_bps = (double)metrics.total_bytes;  /* Will be refined */
    detector->baseline_src_entropy = entropy.src_ip_entropy;

    detector->is_learning = false;
}
