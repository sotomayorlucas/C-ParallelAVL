// Temporal GNN - Spatio-Temporal Graph Neural Networks (C++23 migration)
//
// Extends gnn_gat.hpp with temporal modeling for APT detection: temporal
// position encoding, temporal self-attention, temporal convolutions,
// time-aware message passing and multi-scale temporal aggregation.

#pragma once

#include "common.hpp"
#include "gnn_gat.hpp"
#include "provenance_graph.hpp"

#include <array>
#include <cstdint>
#include <cstddef>
#include <memory>
#include <vector>

namespace flowshield {

// Forward-declared (defined in apt_detector.hpp). The original C code
// referenced ATPPhase from the apt_detector module via temporal_gnn.h's
// public API.
enum class APTPhase : std::uint32_t;

// ============================================================================
// Configuration
// ============================================================================

inline constexpr std::size_t TEMPORAL_ENCODING_DIM = 64;
inline constexpr std::size_t TEMPORAL_MAX_SEQ_LEN  = 1024;
inline constexpr std::size_t TEMPORAL_NUM_HEADS    = 4;
inline constexpr std::size_t TEMPORAL_KERNEL_SIZE  = 5;
inline constexpr std::size_t TEMPORAL_NUM_SCALES   = 3;

// ============================================================================
// Temporal Position Encoding
// ============================================================================

class TemporalPositionEncoding {
public:
    TemporalPositionEncoding(std::size_t max_timesteps,
                             std::size_t encoding_dim,
                             std::uint64_t time_scale_ns);

    void get(std::uint64_t timestamp_ns, float* out_encoding) const;

    void add_to_features(const float* features,
                         const std::uint64_t* timestamps,
                         std::size_t num_nodes,
                         std::size_t feature_dim,
                         float* out_features) const;

    [[nodiscard]] std::size_t  max_timesteps() const noexcept { return max_timesteps_; }
    [[nodiscard]] std::size_t  encoding_dim()  const noexcept { return encoding_dim_; }
    [[nodiscard]] std::uint64_t time_scale_ns() const noexcept { return time_scale_ns_; }

private:
    std::vector<float> encodings_;
    std::size_t   max_timesteps_;
    std::size_t   encoding_dim_;
    std::uint64_t time_scale_ns_;
    float         base_period_ = 10000.0f;
};

// ============================================================================
// Temporal Attention Layer (multi-head self-attention)
// ============================================================================

class TemporalAttentionLayer {
public:
    TemporalAttentionLayer(std::size_t num_heads, std::size_t total_dim, bool use_causal_mask);

    bool forward(const float* sequence,
                 std::size_t seq_len,
                 float* out_sequence,
                 float* out_attention) const;

    [[nodiscard]] std::size_t num_heads() const noexcept { return num_heads_; }
    [[nodiscard]] std::size_t total_dim() const noexcept { return total_dim_; }
    [[nodiscard]] std::size_t dim_per_head() const noexcept { return dim_per_head_; }

private:
    std::vector<float> W_q_;
    std::vector<float> W_k_;
    std::vector<float> W_v_;
    std::vector<float> W_o_;

    std::vector<float> bias_q_;
    std::vector<float> bias_k_;
    std::vector<float> bias_v_;
    std::vector<float> bias_o_;

    std::size_t num_heads_;
    std::size_t total_dim_;
    std::size_t dim_per_head_;

    float dropout_rate_   = 0.1f;
    bool  use_causal_mask_ = false;
};

// ============================================================================
// Temporal Convolution Layer
// ============================================================================

enum class TemporalConvActivation : std::uint8_t {
    ReLU,
    Tanh,
    None,
};

class TemporalConvLayer {
public:
    TemporalConvLayer(std::size_t kernel_size,
                      std::size_t in_channels,
                      std::size_t out_channels,
                      std::size_t stride);

    bool forward(const float* input,
                 std::size_t seq_len,
                 float* output,
                 std::size_t* out_seq_len) const;

    [[nodiscard]] std::size_t kernel_size()  const noexcept { return kernel_size_; }
    [[nodiscard]] std::size_t in_channels()  const noexcept { return in_channels_; }
    [[nodiscard]] std::size_t out_channels() const noexcept { return out_channels_; }
    [[nodiscard]] std::size_t stride()       const noexcept { return stride_; }

    TemporalConvActivation activation = TemporalConvActivation::ReLU;

private:
    std::vector<float> kernel_;
    std::vector<float> bias_;
    std::size_t kernel_size_;
    std::size_t in_channels_;
    std::size_t out_channels_;
    std::size_t stride_;
    std::size_t padding_ = 0;
};

// ============================================================================
// Time-Aware Message Passing
// ============================================================================

struct TimeAwareWeighting {
    float         decay_rate       = 0.0001f;
    float         min_weight       = 0.01f;
    std::uint64_t current_time_ns  = 0;
};

[[nodiscard]] float time_aware_weight(const TimeAwareWeighting& weighting,
                                      std::uint64_t edge_timestamp_ns);

void time_aware_compute_edge_weights(const ProvenanceGraph& graph,
                                     const TimeAwareWeighting& weighting,
                                     float* out_weights);

// ============================================================================
// Temporal Event Sequence
// ============================================================================

struct TemporalEventSequence {
    std::uint64_t node_ids   [TEMPORAL_MAX_SEQ_LEN] {};
    std::uint64_t edge_ids   [TEMPORAL_MAX_SEQ_LEN] {};
    std::uint64_t timestamps [TEMPORAL_MAX_SEQ_LEN] {};
    float         features   [TEMPORAL_MAX_SEQ_LEN][64] {};

    std::size_t length = 0;

    std::uint64_t start_time_ns = 0;
    std::uint64_t end_time_ns   = 0;
    float         duration_sec  = 0.0f;

    bool  is_anomalous = false;
    float anomaly_score = 0.0f;
};

bool temporal_extract_sequence(ProvenanceGraph& graph,
                               std::uint64_t start_node_id,
                               std::size_t max_length,
                               TemporalEventSequence& out_sequence);

void temporal_extract_sequences_sliding(ProvenanceGraph& graph,
                                        std::size_t window_size,
                                        std::size_t stride,
                                        TemporalEventSequence* out_sequences,
                                        std::size_t max_sequences,
                                        std::size_t* out_count);

// ============================================================================
// Multi-scale Temporal Aggregation
// ============================================================================

struct TemporalScaleStats {
    std::size_t num_events  = 0;
    float       avg_rate    = 0.0f;
    float       burstiness  = 0.0f;
};

struct TemporalMultiScaleAggregation {
    std::uint64_t window_sizes_ns[TEMPORAL_NUM_SCALES] {};
    float aggregated_features[TEMPORAL_NUM_SCALES][64] {};
    TemporalScaleStats stats[TEMPORAL_NUM_SCALES] {};
};

[[nodiscard]] std::unique_ptr<TemporalMultiScaleAggregation>
temporal_multiscale_create(std::uint64_t short_window_sec,
                           std::uint64_t medium_window_sec,
                           std::uint64_t long_window_sec);

void temporal_multiscale_aggregate(TemporalMultiScaleAggregation& agg,
                                   const TemporalEventSequence* sequences,
                                   std::size_t num_sequences,
                                   std::uint64_t current_time_ns);

// ============================================================================
// Spatio-Temporal GNN
// ============================================================================

struct SpatioTemporalConfig {
    bool use_temporal_encoding  = true;
    bool use_temporal_attention = true;
    bool use_temporal_conv      = false;
    bool use_time_decay         = true;
    bool use_multiscale         = false;
};

class SpatioTemporalGNN {
public:
    SpatioTemporalGNN(GNNModel& spatial_gnn, std::size_t encoding_dim);

    SpatioTemporalGNN(const SpatioTemporalGNN&)            = delete;
    SpatioTemporalGNN& operator=(const SpatioTemporalGNN&) = delete;

    bool forward(ProvenanceGraph& graph,
                 const std::uint64_t* timestamps,
                 float* out_embeddings);

    bool predict_sequence(const TemporalEventSequence& sequence,
                          float& out_anomaly_score) const;

    std::size_t detect_apt_phases(ProvenanceGraph& graph,
                                  const TemporalEventSequence* sequences,
                                  std::size_t num_sequences,
                                  APTPhase* out_phases,
                                  float* out_scores);

    [[nodiscard]] GNNModel& spatial() noexcept { return *spatial_gnn_; }
    SpatioTemporalConfig config {};
    TimeAwareWeighting   time_weighting {};

private:
    GNNModel* spatial_gnn_;
    std::unique_ptr<TemporalPositionEncoding>            temporal_encoding_;
    std::vector<std::unique_ptr<TemporalAttentionLayer>> temporal_attention_layers_;
    std::vector<std::unique_ptr<TemporalConvLayer>>      temporal_conv_layers_;
    std::unique_ptr<TemporalMultiScaleAggregation>       multiscale_agg_;

    std::vector<float> fusion_W_;
    std::vector<float> fusion_b_;
    std::size_t        fusion_output_dim_ = 0;
};

// ============================================================================
// Temporal Pattern Detection
// ============================================================================

bool temporal_detect_periodicity(const TemporalEventSequence& sequence,
                                 float& out_period_sec,
                                 float& out_confidence);

bool temporal_detect_burst(const TemporalEventSequence& sequence,
                           float& out_burst_score);

bool temporal_detect_slow_exfiltration(const TemporalEventSequence& sequence,
                                       float& out_rate_bps,
                                       float& out_duration_sec);

// ============================================================================
// Utilities
// ============================================================================

void temporal_compute_iet_stats(const TemporalEventSequence& sequence,
                                float& out_mean_ms,
                                float& out_std_ms,
                                float& out_cv);

void temporal_print_sequence(const TemporalEventSequence& sequence);

}  // namespace flowshield
