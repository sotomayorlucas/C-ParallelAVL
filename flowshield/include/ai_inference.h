/**
 * FlowShield AI - Machine Learning Anomaly Detection
 *
 * Hardware-accelerated inference using Hailo-8L on Raspberry Pi 5.
 * Falls back to CPU inference when Hailo is not available.
 *
 * Models:
 *   - Autoencoder: Unsupervised anomaly detection
 *   - Classifier: Attack type classification (SYN flood, UDP amp, etc.)
 *   - Flow Predictor: Next-flow prediction for proactive defense
 *
 * Features extracted from network flows:
 *   - Packet rate, byte rate, duration
 *   - Protocol distribution, port entropy
 *   - TCP flag ratios, connection states
 *   - Source/destination IP entropy
 */

#ifndef FLOWSHIELD_AI_INFERENCE_H
#define FLOWSHIELD_AI_INFERENCE_H

#include "flow_types.h"
#include "anomaly_detector.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Configuration
 * ============================================================================ */

#define AI_FEATURE_DIM          32      /* Input feature vector size */
#define AI_LATENT_DIM           8       /* Autoencoder latent space */
#define AI_NUM_ATTACK_CLASSES   8       /* Number of attack types */
#define AI_BATCH_SIZE           64      /* Inference batch size */
#define AI_ANOMALY_THRESHOLD    0.85    /* Reconstruction error threshold */

/* Backend selection */
typedef enum {
    AI_BACKEND_AUTO,        /* Auto-detect (Hailo → CPU) */
    AI_BACKEND_HAILO,       /* Force Hailo-8L */
    AI_BACKEND_CPU,         /* Force CPU (for testing) */
    AI_BACKEND_ONNX         /* ONNX Runtime (optional) */
} AIBackend;

/* Model types */
typedef enum {
    AI_MODEL_AUTOENCODER,       /* Anomaly detection via reconstruction */
    AI_MODEL_CLASSIFIER,        /* Attack type classification */
    AI_MODEL_FLOW_PREDICTOR,    /* Next-flow prediction */
    AI_MODEL_ENSEMBLE           /* Combined models */
} AIModelType;

/* ============================================================================
 * Feature Vector
 * ============================================================================ */

/**
 * Network flow features for ML inference.
 * Normalized to [0, 1] range for neural network input.
 */
typedef struct {
    /* Rate features (normalized) */
    float packets_per_sec;      /* [0] PPS / max_pps */
    float bytes_per_sec;        /* [1] BPS / max_bps */
    float avg_packet_size;      /* [2] avg_size / 1500 */

    /* Duration features */
    float flow_duration;        /* [3] duration / max_duration */
    float inter_arrival_time;   /* [4] avg IAT / max_iat */

    /* Protocol features (one-hot) */
    float is_tcp;               /* [5] */
    float is_udp;               /* [6] */
    float is_icmp;              /* [7] */

    /* TCP flag ratios */
    float syn_ratio;            /* [8] SYN / total */
    float ack_ratio;            /* [9] ACK / total */
    float fin_ratio;            /* [10] FIN / total */
    float rst_ratio;            /* [11] RST / total */
    float syn_ack_ratio;        /* [12] SYN / ACK */

    /* Port features */
    float src_port_norm;        /* [13] src_port / 65535 */
    float dst_port_norm;        /* [14] dst_port / 65535 */
    float is_well_known_port;   /* [15] dst_port < 1024 */
    float is_dns_port;          /* [16] port 53 */
    float is_ntp_port;          /* [17] port 123 */
    float is_http_port;         /* [18] port 80/443 */

    /* Entropy features */
    float src_ip_entropy;       /* [19] normalized entropy */
    float dst_ip_entropy;       /* [20] */
    float src_port_entropy;     /* [21] */
    float dst_port_entropy;     /* [22] */

    /* Aggregated flow stats */
    float unique_src_ips;       /* [23] count / max_count */
    float unique_dst_ips;       /* [24] */
    float flows_per_src;        /* [25] flows / unique_src */
    float flows_per_dst;        /* [26] */

    /* Historical features */
    float rate_delta;           /* [27] (current - avg) / avg */
    float rate_acceleration;    /* [28] delta of delta */
    float burst_score;          /* [29] burstiness metric */

    /* Reserved for future */
    float reserved[2];          /* [30-31] */
} AIFeatureVector;

/* ============================================================================
 * Inference Results
 * ============================================================================ */

/**
 * Autoencoder result (anomaly detection)
 */
typedef struct {
    float reconstruction_error; /* MSE between input and output */
    float anomaly_score;        /* 0.0 = normal, 1.0 = anomaly */
    bool  is_anomaly;           /* anomaly_score > threshold */
    float latent[AI_LATENT_DIM];/* Latent space representation */
} AIAnomalyResult;

/**
 * Classifier result (attack type)
 */
typedef struct {
    AttackType predicted_class; /* Most likely attack type */
    float confidence;           /* Confidence of prediction */
    float probabilities[AI_NUM_ATTACK_CLASSES]; /* Per-class probabilities */
} AIClassifierResult;

/**
 * Combined inference result
 */
typedef struct {
    AIAnomalyResult anomaly;
    AIClassifierResult classification;
    float inference_time_ms;    /* Time taken for inference */
    bool  used_accelerator;     /* True if Hailo was used */
} AIInferenceResult;

/* ============================================================================
 * AI Engine Handle
 * ============================================================================ */

typedef struct AIEngine AIEngine;

/* Engine statistics */
typedef struct {
    uint64_t total_inferences;
    uint64_t anomalies_detected;
    uint64_t attacks_classified;
    double   avg_inference_time_ms;
    double   peak_inference_time_ms;
    size_t   batch_count;
    bool     hailo_available;
    char     hailo_device[64];
} AIEngineStats;

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

/**
 * Create AI inference engine.
 *
 * @param backend       Preferred backend (AUTO recommended)
 * @param model_dir     Directory containing model files (NULL = built-in)
 * @return              Engine handle or NULL on error
 */
AIEngine* ai_engine_create(AIBackend backend, const char* model_dir);

/**
 * Destroy AI engine and free resources.
 */
void ai_engine_destroy(AIEngine* engine);

/**
 * Check if Hailo accelerator is available.
 */
bool ai_engine_has_hailo(void);

/**
 * Get engine statistics.
 */
void ai_engine_get_stats(const AIEngine* engine, AIEngineStats* out_stats);

/* ============================================================================
 * Feature Extraction
 * ============================================================================ */

/**
 * Extract features from a single flow.
 *
 * @param key           Flow key (5-tuple)
 * @param stats         Flow statistics
 * @param out_features  Output feature vector
 */
void ai_extract_features(
    const FlowKey* key,
    const FlowStats* stats,
    AIFeatureVector* out_features
);

/**
 * Extract features from aggregated flow metrics.
 *
 * @param metrics       Aggregated flow metrics
 * @param entropy       Entropy analysis
 * @param out_features  Output feature vector
 */
void ai_extract_aggregate_features(
    const FlowMetrics* metrics,
    const EntropyAnalysis* entropy,
    AIFeatureVector* out_features
);

/* ============================================================================
 * Inference
 * ============================================================================ */

/**
 * Run anomaly detection on a single flow.
 *
 * @param engine        AI engine
 * @param features      Input feature vector
 * @param out_result    Output result
 * @return              true on success
 */
bool ai_detect_anomaly(
    AIEngine* engine,
    const AIFeatureVector* features,
    AIAnomalyResult* out_result
);

/**
 * Classify attack type.
 *
 * @param engine        AI engine
 * @param features      Input feature vector
 * @param out_result    Output result
 * @return              true on success
 */
bool ai_classify_attack(
    AIEngine* engine,
    const AIFeatureVector* features,
    AIClassifierResult* out_result
);

/**
 * Run full inference (anomaly + classification).
 *
 * @param engine        AI engine
 * @param features      Input feature vector
 * @param out_result    Output result
 * @return              true on success
 */
bool ai_infer(
    AIEngine* engine,
    const AIFeatureVector* features,
    AIInferenceResult* out_result
);

/**
 * Batch inference for multiple flows.
 *
 * @param engine        AI engine
 * @param features      Array of feature vectors
 * @param count         Number of features
 * @param out_results   Output results array
 * @return              Number of successful inferences
 */
size_t ai_infer_batch(
    AIEngine* engine,
    const AIFeatureVector* features,
    size_t count,
    AIInferenceResult* out_results
);

/* ============================================================================
 * Model Management
 * ============================================================================ */

/**
 * Load model from HEF file (Hailo Executable Format).
 *
 * @param engine        AI engine
 * @param model_type    Type of model to load
 * @param hef_path      Path to .hef file
 * @return              true on success
 */
bool ai_load_model_hef(
    AIEngine* engine,
    AIModelType model_type,
    const char* hef_path
);

/**
 * Load model from ONNX file (for CPU fallback).
 *
 * @param engine        AI engine
 * @param model_type    Type of model to load
 * @param onnx_path     Path to .onnx file
 * @return              true on success
 */
bool ai_load_model_onnx(
    AIEngine* engine,
    AIModelType model_type,
    const char* onnx_path
);

/**
 * Use built-in lightweight models.
 * These are simple models that work without external files.
 */
bool ai_use_builtin_models(AIEngine* engine);

/* ============================================================================
 * Online Learning (Edge Training)
 * ============================================================================ */

/**
 * Update model with new labeled sample.
 * For incremental learning on edge devices.
 *
 * @param engine        AI engine
 * @param features      Input features
 * @param label         Ground truth label
 * @param is_anomaly    Whether this is an anomaly
 */
void ai_update_model(
    AIEngine* engine,
    const AIFeatureVector* features,
    AttackType label,
    bool is_anomaly
);

/**
 * Get model's learned baseline.
 * Returns the "normal" feature centroid.
 */
void ai_get_baseline(
    const AIEngine* engine,
    AIFeatureVector* out_baseline
);

/* ============================================================================
 * Utility
 * ============================================================================ */

/**
 * Print feature vector (for debugging).
 */
void ai_print_features(const AIFeatureVector* features);

/**
 * Print inference result.
 */
void ai_print_result(const AIInferenceResult* result);

/**
 * Convert AttackType to string.
 */
const char* ai_attack_type_str(AttackType type);

#ifdef __cplusplus
}
#endif

#endif /* FLOWSHIELD_AI_INFERENCE_H */
