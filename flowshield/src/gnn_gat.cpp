// GNN/GAT Implementation (C++23 migration of gnn_gat.c)

#include "gnn_gat.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <format>
#include <iostream>
#include <random>
#include <vector>

namespace flowshield {

namespace {

// ============================================================================
// Activation functions
// ============================================================================

[[gnu::always_inline]] inline float relu(float x) noexcept {
    return x > 0 ? x : 0.0f;
}

[[gnu::always_inline]] inline float leaky_relu(float x, float alpha) noexcept {
    return x > 0 ? x : alpha * x;
}

[[gnu::always_inline]] inline float elu(float x, float alpha) noexcept {
    return x > 0 ? x : alpha * (std::exp(x) - 1.0f);
}

void softmax(float* x, std::size_t n) noexcept {
    if (!x || n == 0) return;
    float max_val = x[0];
    for (std::size_t i = 1; i < n; ++i) {
        if (x[i] > max_val) max_val = x[i];
    }
    float sum = 0.0f;
    for (std::size_t i = 0; i < n; ++i) {
        x[i] = std::exp(x[i] - max_val);
        sum += x[i];
    }
    for (std::size_t i = 0; i < n; ++i) {
        x[i] /= (sum + 1e-10f);
    }
}

// ============================================================================
// Matrix operations
// ============================================================================

void matmul(const float* W, const float* in, float* out,
            std::size_t in_dim, std::size_t out_dim) noexcept {
    for (std::size_t i = 0; i < out_dim; ++i) {
        float sum = 0.0f;
        for (std::size_t j = 0; j < in_dim; ++j) {
            sum += W[i * in_dim + j] * in[j];
        }
        out[i] = sum;
    }
}

[[nodiscard]] float vec_dot(const float* a, const float* b, std::size_t n) noexcept {
    float sum = 0.0f;
    for (std::size_t i = 0; i < n; ++i) {
        sum += a[i] * b[i];
    }
    return sum;
}

// Xavier initialization using a deterministic Mersenne-Twister seeded from
// the supplied seed; matches the original C code's intent without relying on
// the global rand()/srand() state.
void init_xavier(float* W, std::size_t rows, std::size_t cols, std::uint64_t seed) {
    std::mt19937_64 rng(seed);
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    const float scale = std::sqrt(6.0f / static_cast<float>(rows + cols));
    for (std::size_t i = 0; i < rows * cols; ++i) {
        W[i] = dist(rng) * scale;
    }
}

[[nodiscard]] std::uint64_t mt_seed_from_clock() noexcept {
    using clock = std::chrono::steady_clock;
    return static_cast<std::uint64_t>(clock::now().time_since_epoch().count());
}

}  // namespace

// ============================================================================
// Sparse Operations
// ============================================================================

void sparse_matmul(const SparseAdjacency& adj,
                   const float* features,
                   std::size_t feature_dim,
                   float* out_features) {
    if (!features || !out_features) return;

    std::fill_n(out_features, adj.num_nodes * feature_dim, 0.0f);

    const std::size_t num_edges = adj.num_edges();
    for (std::size_t e = 0; e < num_edges; ++e) {
        const std::uint64_t src = adj.src_indices[e];
        const std::uint64_t dst = adj.dst_indices[e];
        const float weight = adj.values[e];
        for (std::size_t f = 0; f < feature_dim; ++f) {
            out_features[dst * feature_dim + f] +=
                weight * features[src * feature_dim + f];
        }
    }
}

void sparse_attention_aggregate(const SparseAdjacency& adj,
                                const float* node_features,
                                const float* attention_scores,
                                std::size_t feature_dim,
                                float* out_features) {
    if (!node_features || !attention_scores || !out_features) return;

    std::fill_n(out_features, adj.num_nodes * feature_dim, 0.0f);

    const std::size_t num_edges = adj.num_edges();
    for (std::size_t e = 0; e < num_edges; ++e) {
        const std::uint64_t src = adj.src_indices[e];
        const std::uint64_t dst = adj.dst_indices[e];
        const float alpha = attention_scores[e];
        for (std::size_t f = 0; f < feature_dim; ++f) {
            out_features[dst * feature_dim + f] +=
                alpha * node_features[src * feature_dim + f];
        }
    }
}

// ============================================================================
// AttentionHead
// ============================================================================

AttentionHead::AttentionHead(std::size_t in_dim, std::size_t out_dim, float alpha)
    : W_(in_dim * out_dim, 0.0f),
      a_src_(out_dim, 0.0f),
      a_dst_(out_dim, 0.0f),
      bias_(out_dim, 0.0f),
      in_dim_(in_dim),
      out_dim_(out_dim),
      alpha_(alpha)
{
    const auto seed = mt_seed_from_clock();
    init_xavier(W_.data(),     out_dim, in_dim,  seed);
    init_xavier(a_src_.data(), 1,       out_dim, seed + 1);
    init_xavier(a_dst_.data(), 1,       out_dim, seed + 2);
}

// ============================================================================
// GAT attention computation
// ============================================================================

float gat_compute_attention(const AttentionHead& head,
                            const float* src_features,
                            const float* dst_features) {
    if (!src_features || !dst_features) return 0.0f;

    const std::size_t out_dim = head.out_dim();
    std::vector<float> Wh_src(out_dim);
    std::vector<float> Wh_dst(out_dim);

    matmul(head.W(), src_features, Wh_src.data(), head.in_dim(), out_dim);
    matmul(head.W(), dst_features, Wh_dst.data(), head.in_dim(), out_dim);

    float e_ij = vec_dot(head.a_src(), Wh_src.data(), out_dim) +
                 vec_dot(head.a_dst(), Wh_dst.data(), out_dim);
    return leaky_relu(e_ij, head.alpha());
}

// ============================================================================
// MultiHeadAttention
// ============================================================================

MultiHeadAttention::MultiHeadAttention(std::size_t num_heads,
                                       std::size_t in_dim,
                                       std::size_t out_dim_per_head)
    : in_dim_(in_dim), out_dim_per_head_(out_dim_per_head)
{
    heads_.reserve(num_heads);
    for (std::size_t i = 0; i < num_heads; ++i) {
        heads_.emplace_back(std::make_unique<AttentionHead>(in_dim, out_dim_per_head, GAT_ALPHA));
    }
}

// ============================================================================
// GAT layer
// ============================================================================

GATLayer::GATLayer(std::size_t in_dim, std::size_t out_dim, std::size_t num_heads)
    : attention_(num_heads, in_dim, out_dim / num_heads),
      norm_gamma_(out_dim, 1.0f),
      norm_beta_(out_dim, 0.0f),
      in_dim_(in_dim),
      out_dim_(out_dim)
{
    if (in_dim != out_dim) {
        skip_W_.assign(in_dim * out_dim, 0.0f);
        init_xavier(skip_W_.data(), out_dim, in_dim, mt_seed_from_clock() + 100);
    }
}

bool gat_layer_forward(GATLayer& layer,
                       ProvenanceGraph& graph,
                       const float* in_features,
                       float* out_features,
                       float* out_attention)
{
    if (!in_features || !out_features) return false;

    const std::size_t num_nodes = graph.num_nodes();
    const std::size_t in_dim    = layer.in_dim();
    const std::size_t out_dim   = layer.out_dim();

    std::vector<float> aggregated(num_nodes * out_dim, 0.0f);

    auto* node_array = graph.nodes_data();
    const auto* node_ids = graph.node_ids_data();

    std::vector<std::uint64_t> neighbors(PG_MAX_NEIGHBORS);
    std::vector<float> attention_scores;
    std::vector<float> attention_logits;

    for (std::size_t i = 0; i < num_nodes; ++i) {
        if (node_ids[i] == static_cast<std::uint64_t>(-1)) continue;

        ProvenanceNode& node = node_array[i];
        const float* h_i = &in_features[i * in_dim];
        float*       out_i = &aggregated[i * out_dim];

        std::size_t num_neighbors = 0;
        graph.get_neighbors(node.id, neighbors.data(), &num_neighbors);

        if (num_neighbors == 0) [[unlikely]] {
            // No neighbors: just transform self for each head.
            const auto num_heads = layer.attention().num_heads();
            for (std::size_t h = 0; h < num_heads; ++h) {
                AttentionHead& head = layer.attention().head(h);
                std::vector<float> transformed(head.out_dim());
                matmul(head.W(), h_i, transformed.data(), head.in_dim(), head.out_dim());
                const std::size_t offset = h * head.out_dim();
                std::memcpy(out_i + offset, transformed.data(),
                            head.out_dim() * sizeof(float));
            }
            continue;
        }

        attention_scores.assign(num_neighbors, 0.0f);
        attention_logits.assign(num_neighbors, 0.0f);

        const auto num_heads = layer.attention().num_heads();
        for (std::size_t h = 0; h < num_heads; ++h) {
            AttentionHead& head = layer.attention().head(h);

            // Compute attention logits.
            for (std::size_t j = 0; j < num_neighbors; ++j) {
                ProvenanceNode* neighbor = graph.get_node(neighbors[j]);
                if (!neighbor) {
                    attention_logits[j] = -1e9f;
                    continue;
                }
                const float* h_j = &in_features[neighbors[j] * in_dim];
                attention_logits[j] = gat_compute_attention(head, h_i, h_j);
            }

            std::memcpy(attention_scores.data(), attention_logits.data(),
                        num_neighbors * sizeof(float));
            softmax(attention_scores.data(), num_neighbors);

            std::vector<float> head_out(head.out_dim(), 0.0f);
            std::vector<float> Wh_j(head.out_dim());

            for (std::size_t j = 0; j < num_neighbors; ++j) {
                const float* h_j = &in_features[neighbors[j] * in_dim];
                const float alpha = attention_scores[j];

                matmul(head.W(), h_j, Wh_j.data(), head.in_dim(), head.out_dim());
                for (std::size_t k = 0; k < head.out_dim(); ++k) {
                    head_out[k] += alpha * Wh_j[k];
                }
            }

            for (std::size_t k = 0; k < head.out_dim(); ++k) {
                head_out[k] += head.bias()[k];
                head_out[k] = elu(head_out[k], 1.0f);
            }

            const std::size_t offset = h * head.out_dim();
            std::memcpy(out_i + offset, head_out.data(),
                        head.out_dim() * sizeof(float));
        }

        if (out_attention && num_neighbors > 0) {
            out_attention[i] = attention_scores[0];
        }
    }

    // Layer normalization.
    const float* gamma = layer.norm_gamma();
    const float* beta  = layer.norm_beta();
    for (std::size_t i = 0; i < num_nodes; ++i) {
        if (node_ids[i] == static_cast<std::uint64_t>(-1)) continue;

        float* out_i = &aggregated[i * out_dim];
        float mean = 0.0f, var = 0.0f;
        for (std::size_t j = 0; j < out_dim; ++j) mean += out_i[j];
        mean /= static_cast<float>(out_dim);
        for (std::size_t j = 0; j < out_dim; ++j) {
            const float diff = out_i[j] - mean;
            var += diff * diff;
        }
        var /= static_cast<float>(out_dim);

        const float std = std::sqrt(var + 1e-5f);
        for (std::size_t j = 0; j < out_dim; ++j) {
            out_i[j] = ((out_i[j] - mean) / std) * gamma[j] + beta[j];
        }
    }

    std::memcpy(out_features, aggregated.data(),
                num_nodes * out_dim * sizeof(float));
    return true;
}

// ============================================================================
// GNN model
// ============================================================================

GNNModel::GNNModel(std::size_t input_dim,
                   std::size_t hidden_dim,
                   std::size_t output_dim,
                   std::size_t num_layers,
                   std::size_t num_classes)
    : input_dim_(input_dim),
      hidden_dim_(hidden_dim),
      output_dim_(output_dim),
      num_classes_(num_classes)
{
    gat_layers_.reserve(num_layers);
    for (std::size_t i = 0; i < num_layers; ++i) {
        const std::size_t in_dim  = (i == 0)              ? input_dim  : hidden_dim;
        const std::size_t out_dim = (i == num_layers - 1) ? output_dim : hidden_dim;
        gat_layers_.emplace_back(std::make_unique<GATLayer>(in_dim, out_dim, GAT_NUM_HEADS));
    }

    readout_W_.assign(output_dim * num_classes, 0.0f);
    readout_b_.assign(num_classes, 0.0f);
    init_xavier(readout_W_.data(), num_classes, output_dim, mt_seed_from_clock() + 1000);

    std::cout << std::format(
        "[GNN] Created model: {} layers, input={}, hidden={}, output={}, classes={}\n",
        num_layers, input_dim, hidden_dim, output_dim, num_classes);
}

void GNNModel::init_weights_random(std::uint64_t seed) {
    for (std::size_t i = 0; i < gat_layers_.size(); ++i) {
        GATLayer& l = *gat_layers_[i];
        for (std::size_t h = 0; h < l.attention().num_heads(); ++h) {
            AttentionHead& head = l.attention().head(h);
            init_xavier(head.W_mut(),     head.out_dim(), head.in_dim(),  seed + i * 100 + h);
            init_xavier(head.a_src_mut(), 1,              head.out_dim(), seed + i * 100 + h + 50);
            init_xavier(head.a_dst_mut(), 1,              head.out_dim(), seed + i * 100 + h + 51);
        }
    }
    init_xavier(readout_W_.data(), num_classes_, output_dim_, seed + 10000);
}

void GNNModel::init_weights_xavier() {
    init_weights_random(mt_seed_from_clock());
    std::cout << "[GNN] Weights re-initialized with Xavier initialization\n";
}

bool GNNModel::forward(ProvenanceGraph& graph, float* out_embeddings) {
    if (!out_embeddings) return false;

    const std::size_t num_nodes = graph.num_nodes();

    std::vector<float> features(num_nodes * input_dim_, 0.0f);
    auto* node_array = graph.nodes_data();
    const auto* node_ids = graph.node_ids_data();
    for (std::size_t i = 0; i < num_nodes; ++i) {
        if (node_ids[i] != static_cast<std::uint64_t>(-1)) {
            pg_extract_node_features(node_array[i], &features[i * input_dim_]);
        }
    }

    std::vector<float> buffer_a = std::move(features);
    std::vector<float> buffer_b(num_nodes * std::max(hidden_dim_, output_dim_), 0.0f);

    const std::size_t num_layers = gat_layers_.size();
    for (std::size_t layer_idx = 0; layer_idx < num_layers; ++layer_idx) {
        GATLayer& l = *gat_layers_[layer_idx];

        // Ensure destination buffer is appropriately sized for this layer's
        // output dimension.
        buffer_b.assign(num_nodes * l.out_dim(), 0.0f);

        if (!gat_layer_forward(l, graph, buffer_a.data(), buffer_b.data(), nullptr)) {
            return false;
        }
        std::swap(buffer_a, buffer_b);
    }

    std::memcpy(out_embeddings, buffer_a.data(),
                num_nodes * output_dim_ * sizeof(float));

    // Update node embeddings inside the graph.
    for (std::size_t i = 0; i < num_nodes; ++i) {
        if (node_ids[i] != static_cast<std::uint64_t>(-1)) {
            ProvenanceNode& node = node_array[i];
            const std::size_t copy_dim = std::min(output_dim_, PG_NODE_FEATURE_DIM);
            std::memcpy(node.embedding, &out_embeddings[i * output_dim_],
                        copy_dim * sizeof(float));
        }
    }

    ++stats_.forward_passes;
    return true;
}

bool GNNModel::forward_temporal(ProvenanceGraph& graph,
                                const std::uint64_t* /*timestamps*/,
                                float* out_embeddings)
{
    // The original C implementation deferred temporal handling to the
    // spatio-temporal GNN module. Match that behavior.
    return forward(graph, out_embeddings);
}

int GNNModel::predict_graph(ProvenanceGraph& graph, float* out_probs) {
    if (!out_probs) return -1;

    const std::size_t num_nodes = graph.num_nodes();
    std::vector<float> embeddings(num_nodes * output_dim_, 0.0f);
    if (!forward(graph, embeddings.data())) {
        return -1;
    }

    // Graph-level mean pooling.
    std::vector<float> graph_embedding(output_dim_, 0.0f);
    std::size_t valid_nodes = 0;
    const auto* node_ids = graph.node_ids_data();
    for (std::size_t i = 0; i < num_nodes; ++i) {
        if (node_ids[i] != static_cast<std::uint64_t>(-1)) {
            for (std::size_t j = 0; j < output_dim_; ++j) {
                graph_embedding[j] += embeddings[i * output_dim_ + j];
            }
            ++valid_nodes;
        }
    }
    const float denom = static_cast<float>(valid_nodes + 1);
    for (std::size_t j = 0; j < output_dim_; ++j) {
        graph_embedding[j] /= denom;
    }

    std::vector<float> logits(num_classes_, 0.0f);
    matmul(readout_W_.data(), graph_embedding.data(), logits.data(),
           output_dim_, num_classes_);
    for (std::size_t i = 0; i < num_classes_; ++i) {
        logits[i] += readout_b_[i];
    }
    softmax(logits.data(), num_classes_);
    std::memcpy(out_probs, logits.data(), num_classes_ * sizeof(float));

    int predicted = 0;
    float max_prob = logits[0];
    for (std::size_t i = 1; i < num_classes_; ++i) {
        if (logits[i] > max_prob) {
            max_prob  = logits[i];
            predicted = static_cast<int>(i);
        }
    }
    return predicted;
}

std::size_t GNNModel::predict_nodes(ProvenanceGraph& graph, float* out_scores) {
    if (!out_scores) return 0;

    const std::size_t num_nodes = graph.num_nodes();
    std::vector<float> embeddings(num_nodes * output_dim_, 0.0f);
    if (!forward(graph, embeddings.data())) return 0;

    std::size_t scored = 0;
    auto* node_array = graph.nodes_data();
    const auto* node_ids = graph.node_ids_data();
    for (std::size_t i = 0; i < num_nodes; ++i) {
        if (node_ids[i] == static_cast<std::uint64_t>(-1)) continue;

        float magnitude = 0.0f;
        for (std::size_t j = 0; j < output_dim_; ++j) {
            const float val = embeddings[i * output_dim_ + j];
            magnitude += val * val;
        }
        out_scores[i] = std::sqrt(magnitude);
        node_array[i].anomaly_score = out_scores[i];
        ++scored;
    }
    return scored;
}

void GNNModel::print_stats() const {
    std::cout << "\n=== GNN Model Statistics ===\n";
    std::cout << std::format("Architecture: {} layers\n", gat_layers_.size());
    std::cout << std::format("Dimensions:   input={}, hidden={}, output={}\n",
                             input_dim_, hidden_dim_, output_dim_);
    std::cout << std::format("Forward passes: {}\n", stats_.forward_passes);
    std::cout << std::format("Avg inference:  {:.2f} ms\n", stats_.avg_inference_time_ms);
    std::cout << "============================\n\n";
}

// ============================================================================
// Utility
// ============================================================================

double gnn_compute_attention_entropy(const float* attention_scores, std::size_t n) {
    if (!attention_scores || n == 0) return 0.0;
    double entropy = 0.0;
    for (std::size_t i = 0; i < n; ++i) {
        const float p = attention_scores[i];
        if (p > 1e-10f) {
            entropy -= static_cast<double>(p) *
                       std::log2(static_cast<double>(p));
        }
    }
    return entropy;
}

}  // namespace flowshield
