// FlowShield AI - Machine Learning Anomaly Detection (C++23 migration)
//
// Hardware-accelerated inference using Hailo-8L on Raspberry Pi 5.
// Falls back to CPU inference when Hailo is not available.

#pragma once

#include "common.hpp"
#include "flow_types.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

namespace flowshield {

// entropy_analysis lives in anomaly_detector.hpp; forward-declared here so
// this header does not pull in the entire anomaly detector translation unit.
struct entropy_analysis;

// ============================================================================
// Configuration
// ============================================================================

inline constexpr std::size_t ai_feature_dim        = 32;
inline constexpr std::size_t ai_latent_dim         = 8;
inline constexpr std::size_t ai_num_attack_classes = 8;
inline constexpr std::size_t ai_batch_size         = 64;
inline constexpr float       ai_anomaly_threshold  = 0.85f;

// Compile-time aliases preserving the original C macro names for callers
// that still rely on them.
inline constexpr std::size_t AI_FEATURE_DIM        = ai_feature_dim;
inline constexpr std::size_t AI_LATENT_DIM         = ai_latent_dim;
inline constexpr std::size_t AI_NUM_ATTACK_CLASSES = ai_num_attack_classes;
inline constexpr std::size_t AI_BATCH_SIZE         = ai_batch_size;
inline constexpr float       AI_ANOMALY_THRESHOLD  = ai_anomaly_threshold;

// ============================================================================
// Backend / Model selection
// ============================================================================

enum class ai_backend : std::uint8_t {
    automatic,  // Auto-detect (Hailo -> CPU)
    hailo,      // Force Hailo-8L
    cpu,        // Force CPU
    onnx,       // ONNX Runtime
};

enum class ai_model_type : std::uint8_t {
    autoencoder,
    classifier,
    flow_predictor,
    ensemble,
};

// ============================================================================
// Feature Vector
// ============================================================================

struct ai_feature_vector {
    // Rate features (normalized)
    float packets_per_sec   = 0.0f;
    float bytes_per_sec     = 0.0f;
    float avg_packet_size   = 0.0f;

    // Duration features
    float flow_duration     = 0.0f;
    float inter_arrival_time = 0.0f;

    // Protocol features (one-hot)
    float is_tcp            = 0.0f;
    float is_udp            = 0.0f;
    float is_icmp           = 0.0f;

    // TCP flag ratios
    float syn_ratio         = 0.0f;
    float ack_ratio         = 0.0f;
    float fin_ratio         = 0.0f;
    float rst_ratio         = 0.0f;
    float syn_ack_ratio     = 0.0f;

    // Port features
    float src_port_norm     = 0.0f;
    float dst_port_norm     = 0.0f;
    float is_well_known_port = 0.0f;
    float is_dns_port       = 0.0f;
    float is_ntp_port       = 0.0f;
    float is_http_port      = 0.0f;

    // Entropy features
    float src_ip_entropy    = 0.0f;
    float dst_ip_entropy    = 0.0f;
    float src_port_entropy  = 0.0f;
    float dst_port_entropy  = 0.0f;

    // Aggregated flow stats
    float unique_src_ips    = 0.0f;
    float unique_dst_ips    = 0.0f;
    float flows_per_src     = 0.0f;
    float flows_per_dst     = 0.0f;

    // Historical features
    float rate_delta        = 0.0f;
    float rate_acceleration = 0.0f;
    float burst_score       = 0.0f;

    // Reserved
    float reserved[2]       = {};

    // Treat the struct as a contiguous float[ai_feature_dim] view.
    [[nodiscard]] float*       data()       noexcept { return reinterpret_cast<float*>(this); }
    [[nodiscard]] const float* data() const noexcept { return reinterpret_cast<const float*>(this); }
};

static_assert(sizeof(ai_feature_vector) == ai_feature_dim * sizeof(float),
              "ai_feature_vector must be tightly packed as float[ai_feature_dim]");

// ============================================================================
// Inference Results
// ============================================================================

struct ai_anomaly_result {
    float reconstruction_error = 0.0f;
    float anomaly_score        = 0.0f;
    bool  is_anomaly           = false;
    float latent[ai_latent_dim] = {};
};

struct ai_classifier_result {
    attack_type predicted_class = attack_type::none;
    float       confidence      = 0.0f;
    float       probabilities[ai_num_attack_classes] = {};
};

struct ai_inference_result {
    ai_anomaly_result    anomaly         {};
    ai_classifier_result classification  {};
    float                inference_time_ms = 0.0f;
    bool                 used_accelerator  = false;
};

// ============================================================================
// Engine statistics
// ============================================================================

struct ai_engine_stats {
    std::uint64_t total_inferences      = 0;
    std::uint64_t anomalies_detected    = 0;
    std::uint64_t attacks_classified    = 0;
    double        avg_inference_time_ms = 0.0;
    double        peak_inference_time_ms = 0.0;
    std::size_t   batch_count           = 0;
    bool          hailo_available       = false;
    char          hailo_device[64]      = {};
};

// ============================================================================
// AI Engine
// ============================================================================

class ai_engine {
public:
    ai_engine(ai_backend backend, const char* model_dir = nullptr);
    ~ai_engine();

    ai_engine(const ai_engine&)            = delete;
    ai_engine& operator=(const ai_engine&) = delete;
    ai_engine(ai_engine&&)                 = delete;
    ai_engine& operator=(ai_engine&&)      = delete;

    [[nodiscard]] static bool has_hailo() noexcept;

    void get_stats(ai_engine_stats& out_stats) const;

    // Inference
    bool detect_anomaly  (const ai_feature_vector& features, ai_anomaly_result& out_result);
    bool classify_attack (const ai_feature_vector& features, ai_classifier_result& out_result);
    bool infer           (const ai_feature_vector& features, ai_inference_result& out_result);
    std::size_t infer_batch(const ai_feature_vector* features,
                            std::size_t count,
                            ai_inference_result* out_results);

    // Model management
    bool load_model_hef (ai_model_type model_type, const char* hef_path);
    bool load_model_onnx(ai_model_type model_type, const char* onnx_path);
    bool use_builtin_models();

    // Online learning
    void update_model(const ai_feature_vector& features, attack_type label, bool is_anomaly);
    void get_baseline(ai_feature_vector& out_baseline) const;

    [[nodiscard]] ai_backend backend() const noexcept { return backend_; }
    [[nodiscard]] bool hailo_available() const noexcept { return hailo_available_; }

private:
    ai_backend backend_;
    bool       hailo_available_ = false;

    // Dynamic weights for online learning
    float encoder_w1_[ai_feature_dim][16] {};
    float encoder_b1_[16] {};
    float encoder_w2_[16][ai_latent_dim] {};
    float encoder_b2_[ai_latent_dim] {};
    float decoder_w1_[ai_latent_dim][16] {};
    float decoder_b1_[16] {};
    float decoder_w2_[16][ai_feature_dim] {};
    float decoder_b2_[ai_feature_dim] {};

    // Classifier weights
    float classifier_w_[ai_latent_dim][ai_num_attack_classes] {};
    float classifier_b_[ai_num_attack_classes] {};

    // Baseline for normalization
    float       baseline_mean_[ai_feature_dim] {};
    float       baseline_std_ [ai_feature_dim] {};
    std::size_t baseline_samples_ = 0;

    ai_engine_stats     stats_ {};
    mutable std::mutex  stats_lock_;

    float anomaly_threshold_ = ai_anomaly_threshold;

    // Internal helpers
    void autoencoder_forward(const float* input, float* latent, float* output) const;
    void classifier_forward (const float* latent, float* probabilities) const;
};

// ============================================================================
// Free helpers
// ============================================================================

void ai_extract_features(const flow_key& key,
                         const flow_stats& stats,
                         ai_feature_vector& out_features);

void ai_extract_aggregate_features(const flow_metrics& metrics,
                                   const entropy_analysis* entropy,
                                   ai_feature_vector& out_features);

void ai_print_features(const ai_feature_vector& features);
void ai_print_result  (const ai_inference_result& result);

[[nodiscard]] const char* ai_attack_type_str(attack_type type) noexcept;

}  // namespace flowshield
