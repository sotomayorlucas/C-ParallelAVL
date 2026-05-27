// GNN with Graph Attention Networks (GAT) for APT detection (C++23 migration)
//
// Multi-head GAT layers with attention, spatio-temporal graph convolutions,
// graph pooling/aggregation, and sparse operations for million-node graphs.

#pragma once

#include "common.hpp"
#include "provenance_graph.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace flowshield {

// ============================================================================
// Configuration
// ============================================================================

inline constexpr std::size_t GAT_NUM_HEADS      = 8;
inline constexpr std::size_t GAT_HIDDEN_DIM     = 128;
inline constexpr std::size_t GAT_OUTPUT_DIM     = 64;
inline constexpr std::size_t GAT_NUM_LAYERS     = 3;
inline constexpr float       GAT_DROPOUT_RATE   = 0.1f;
inline constexpr float       GAT_ALPHA          = 0.2f;
inline constexpr std::size_t GAT_TEMPORAL_HEADS = 4;

// ============================================================================
// Attention Mechanism
// ============================================================================

class AttentionHead {
public:
    AttentionHead(std::size_t in_dim, std::size_t out_dim, float alpha);
    ~AttentionHead() = default;

    AttentionHead(const AttentionHead&)            = delete;
    AttentionHead& operator=(const AttentionHead&) = delete;

    [[nodiscard]] std::size_t in_dim()  const noexcept { return in_dim_; }
    [[nodiscard]] std::size_t out_dim() const noexcept { return out_dim_; }
    [[nodiscard]] float       alpha()   const noexcept { return alpha_; }

    [[nodiscard]] const float* W()     const noexcept { return W_.data(); }
    [[nodiscard]] const float* a_src() const noexcept { return a_src_.data(); }
    [[nodiscard]] const float* a_dst() const noexcept { return a_dst_.data(); }
    [[nodiscard]] const float* bias()  const noexcept { return bias_.data(); }

    [[nodiscard]] float* W_mut()     noexcept { return W_.data(); }
    [[nodiscard]] float* a_src_mut() noexcept { return a_src_.data(); }
    [[nodiscard]] float* a_dst_mut() noexcept { return a_dst_.data(); }

private:
    std::vector<float> W_;
    std::vector<float> a_src_;
    std::vector<float> a_dst_;
    std::vector<float> bias_;

    std::size_t in_dim_;
    std::size_t out_dim_;

    float alpha_;
    float dropout_rate_ = GAT_DROPOUT_RATE;
};

enum class AttentionAggregation : std::uint8_t {
    Concat,
    Average,
};

class MultiHeadAttention {
public:
    MultiHeadAttention(std::size_t num_heads, std::size_t in_dim, std::size_t out_dim_per_head);

    [[nodiscard]] std::size_t num_heads()        const noexcept { return heads_.size(); }
    [[nodiscard]] std::size_t in_dim()           const noexcept { return in_dim_; }
    [[nodiscard]] std::size_t out_dim_per_head() const noexcept { return out_dim_per_head_; }

    [[nodiscard]] AttentionHead&       head(std::size_t i)       noexcept { return *heads_[i]; }
    [[nodiscard]] const AttentionHead& head(std::size_t i) const noexcept { return *heads_[i]; }

    AttentionAggregation aggregation = AttentionAggregation::Concat;

private:
    std::vector<std::unique_ptr<AttentionHead>> heads_;
    std::size_t in_dim_;
    std::size_t out_dim_per_head_;
};

// ============================================================================
// GAT Layer
// ============================================================================

enum class GATActivation : std::uint8_t {
    ReLU,
    ELU,
    LeakyReLU,
    Tanh,
};

class GATLayer {
public:
    GATLayer(std::size_t in_dim, std::size_t out_dim, std::size_t num_heads);

    [[nodiscard]] MultiHeadAttention& attention() noexcept { return attention_; }
    [[nodiscard]] const MultiHeadAttention& attention() const noexcept { return attention_; }

    [[nodiscard]] std::size_t in_dim()  const noexcept { return in_dim_; }
    [[nodiscard]] std::size_t out_dim() const noexcept { return out_dim_; }

    [[nodiscard]] float* norm_gamma() noexcept { return norm_gamma_.data(); }
    [[nodiscard]] float* norm_beta()  noexcept { return norm_beta_.data(); }
    [[nodiscard]] const float* norm_gamma() const noexcept { return norm_gamma_.data(); }
    [[nodiscard]] const float* norm_beta()  const noexcept { return norm_beta_.data(); }

    [[nodiscard]] float* skip_W() noexcept { return skip_W_.empty() ? nullptr : skip_W_.data(); }

    GATActivation activation = GATActivation::ELU;

private:
    MultiHeadAttention attention_;
    std::vector<float> norm_gamma_;
    std::vector<float> norm_beta_;
    std::vector<float> skip_W_;

    std::size_t in_dim_;
    std::size_t out_dim_;
};

// ============================================================================
// Sparse Graph Operations (for scalability)
// ============================================================================

struct SparseAdjacency {
    std::vector<std::uint64_t> src_indices;
    std::vector<std::uint64_t> dst_indices;
    std::vector<float>         values;
    std::size_t                num_nodes = 0;

    [[nodiscard]] std::size_t num_edges() const noexcept { return values.size(); }
};

void sparse_matmul(const SparseAdjacency& adj,
                   const float* features,
                   std::size_t feature_dim,
                   float* out_features);

void sparse_attention_aggregate(const SparseAdjacency& adj,
                                const float* node_features,
                                const float* attention_scores,
                                std::size_t feature_dim,
                                float* out_features);

// ============================================================================
// Complete GNN Model
// ============================================================================

enum class GraphPooling : std::uint8_t {
    Mean,
    Max,
    Attention,
    Set2Set,
};

struct GNNStats {
    std::uint64_t forward_passes = 0;
    double avg_attention_entropy = 0.0;
    double avg_inference_time_ms = 0.0;
};

class GNNModel {
public:
    GNNModel(std::size_t input_dim,
             std::size_t hidden_dim,
             std::size_t output_dim,
             std::size_t num_layers,
             std::size_t num_classes);

    GNNModel(const GNNModel&)            = delete;
    GNNModel& operator=(const GNNModel&) = delete;

    // Weight initialization
    void init_weights_random(std::uint64_t seed);
    void init_weights_xavier();

    // Inference
    bool forward(ProvenanceGraph& graph, float* out_embeddings);
    bool forward_temporal(ProvenanceGraph& graph,
                          const std::uint64_t* timestamps,
                          float* out_embeddings);

    // Graph- and node-level prediction
    int         predict_graph(ProvenanceGraph& graph, float* out_probs);
    std::size_t predict_nodes(ProvenanceGraph& graph, float* out_scores);

    void print_stats() const;

    // Accessors
    [[nodiscard]] std::size_t input_dim()  const noexcept { return input_dim_; }
    [[nodiscard]] std::size_t hidden_dim() const noexcept { return hidden_dim_; }
    [[nodiscard]] std::size_t output_dim() const noexcept { return output_dim_; }
    [[nodiscard]] std::size_t num_layers() const noexcept { return gat_layers_.size(); }
    [[nodiscard]] std::size_t num_classes() const noexcept { return num_classes_; }

    [[nodiscard]] GATLayer&       layer(std::size_t i)       noexcept { return *gat_layers_[i]; }
    [[nodiscard]] const GATLayer& layer(std::size_t i) const noexcept { return *gat_layers_[i]; }

    [[nodiscard]] float* readout_W() noexcept { return readout_W_.data(); }
    [[nodiscard]] float* readout_b() noexcept { return readout_b_.data(); }

    [[nodiscard]] const GNNStats& stats() const noexcept { return stats_; }

    GraphPooling pooling_type = GraphPooling::Mean;
    bool         is_training  = false;
    float        learning_rate = 0.001f;
    float        weight_decay  = 0.0f;

private:
    std::vector<std::unique_ptr<GATLayer>> gat_layers_;
    std::vector<float> readout_W_;
    std::vector<float> readout_b_;

    std::size_t input_dim_;
    std::size_t hidden_dim_;
    std::size_t output_dim_;
    std::size_t num_classes_;

    GNNStats stats_ {};
};

// ============================================================================
// API - Attention Mechanism
// ============================================================================

[[nodiscard]] float gat_compute_attention(const AttentionHead& head,
                                          const float* src_features,
                                          const float* dst_features);

bool gat_layer_forward(GATLayer& layer,
                       ProvenanceGraph& graph,
                       const float* in_features,
                       float* out_features,
                       float* out_attention);

// ============================================================================
// API - Utility
// ============================================================================

[[nodiscard]] double gnn_compute_attention_entropy(const float* attention_scores, std::size_t n);

}  // namespace flowshield
