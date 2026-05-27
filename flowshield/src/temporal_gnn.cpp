// Temporal GNN Implementation (C++23 migration of temporal_gnn.c)

#include "temporal_gnn.hpp"

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

[[nodiscard]] std::uint64_t mt_seed_from_clock() noexcept {
    return static_cast<std::uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
}

// C = A @ B: A is [m x k], B is [k x n], C is [m x n].
void matmul_simple(const float* A, const float* B, float* C,
                   std::size_t m, std::size_t k, std::size_t n) noexcept {
    for (std::size_t i = 0; i < m; ++i) {
        for (std::size_t j = 0; j < n; ++j) {
            float sum = 0.0f;
            for (std::size_t p = 0; p < k; ++p) {
                sum += A[i * k + p] * B[p * n + j];
            }
            C[i * n + j] = sum;
        }
    }
}

void softmax_row(float* matrix, std::size_t rows, std::size_t cols) noexcept {
    for (std::size_t i = 0; i < rows; ++i) {
        float* row = &matrix[i * cols];
        float max_val = row[0];
        for (std::size_t j = 1; j < cols; ++j) {
            if (row[j] > max_val) max_val = row[j];
        }
        float sum = 0.0f;
        for (std::size_t j = 0; j < cols; ++j) {
            row[j] = std::exp(row[j] - max_val);
            sum += row[j];
        }
        for (std::size_t j = 0; j < cols; ++j) {
            row[j] /= (sum + 1e-10f);
        }
    }
}

}  // namespace

// ============================================================================
// TemporalPositionEncoding
// ============================================================================

TemporalPositionEncoding::TemporalPositionEncoding(std::size_t max_timesteps,
                                                   std::size_t encoding_dim,
                                                   std::uint64_t time_scale_ns)
    : encodings_(max_timesteps * encoding_dim, 0.0f),
      max_timesteps_(max_timesteps),
      encoding_dim_(encoding_dim),
      time_scale_ns_(time_scale_ns)
{
    for (std::size_t t = 0; t < max_timesteps_; ++t) {
        for (std::size_t i = 0; i < encoding_dim_ / 2; ++i) {
            const float freq = 1.0f /
                std::pow(base_period_, (2.0f * static_cast<float>(i)) / static_cast<float>(encoding_dim_));
            const float angle = static_cast<float>(t) * freq;
            encodings_[t * encoding_dim_ + 2 * i]     = std::sin(angle);
            encodings_[t * encoding_dim_ + 2 * i + 1] = std::cos(angle);
        }
    }

    std::cout << std::format("[TemporalEncoding] Created with {} timesteps, dim={}\n",
                             max_timesteps, encoding_dim);
}

void TemporalPositionEncoding::get(std::uint64_t timestamp_ns,
                                   float* out_encoding) const {
    if (!out_encoding) return;

    const std::size_t timestep = static_cast<std::size_t>(timestamp_ns / time_scale_ns_);
    if (timestep < max_timesteps_) {
        std::memcpy(out_encoding,
                    &encodings_[timestep * encoding_dim_],
                    encoding_dim_ * sizeof(float));
    } else {
        for (std::size_t i = 0; i < encoding_dim_ / 2; ++i) {
            const float freq = 1.0f /
                std::pow(base_period_, (2.0f * static_cast<float>(i)) / static_cast<float>(encoding_dim_));
            const float angle = static_cast<float>(timestep) * freq;
            out_encoding[2 * i]     = std::sin(angle);
            out_encoding[2 * i + 1] = std::cos(angle);
        }
    }
}

void TemporalPositionEncoding::add_to_features(const float* features,
                                               const std::uint64_t* timestamps,
                                               std::size_t num_nodes,
                                               std::size_t feature_dim,
                                               float* out_features) const {
    if (!features || !timestamps || !out_features) return;

    std::vector<float> temp_encoding(encoding_dim_);

    for (std::size_t i = 0; i < num_nodes; ++i) {
        get(timestamps[i], temp_encoding.data());
        for (std::size_t j = 0; j < feature_dim; ++j) {
            out_features[i * feature_dim + j] = features[i * feature_dim + j];
            if (j < encoding_dim_) {
                out_features[i * feature_dim + j] += temp_encoding[j];
            }
        }
    }
}

// ============================================================================
// TemporalAttentionLayer
// ============================================================================

TemporalAttentionLayer::TemporalAttentionLayer(std::size_t num_heads,
                                               std::size_t total_dim,
                                               bool use_causal_mask)
    : W_q_(total_dim * total_dim),
      W_k_(total_dim * total_dim),
      W_v_(total_dim * total_dim),
      W_o_(total_dim * total_dim),
      bias_q_(total_dim, 0.0f),
      bias_k_(total_dim, 0.0f),
      bias_v_(total_dim, 0.0f),
      bias_o_(total_dim, 0.0f),
      num_heads_(num_heads),
      total_dim_(total_dim),
      dim_per_head_(total_dim / num_heads),
      use_causal_mask_(use_causal_mask)
{
    std::mt19937_64 rng(mt_seed_from_clock());
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    const float scale = std::sqrt(6.0f / (2.0f * static_cast<float>(total_dim)));

    const std::size_t matrix_size = total_dim * total_dim;
    for (std::size_t i = 0; i < matrix_size; ++i) {
        W_q_[i] = dist(rng) * scale;
        W_k_[i] = dist(rng) * scale;
        W_v_[i] = dist(rng) * scale;
        W_o_[i] = dist(rng) * scale;
    }

    std::cout << std::format("[TemporalAttention] Created with {} heads, dim={}\n",
                             num_heads, total_dim);
}

bool TemporalAttentionLayer::forward(const float* sequence,
                                     std::size_t seq_len,
                                     float* out_sequence,
                                     float* out_attention) const {
    if (!sequence || !out_sequence || seq_len == 0) return false;

    const std::size_t dim = total_dim_;

    std::vector<float> Q(seq_len * dim, 0.0f);
    std::vector<float> K(seq_len * dim, 0.0f);
    std::vector<float> V(seq_len * dim, 0.0f);
    std::vector<float> scores(seq_len * seq_len, 0.0f);

    matmul_simple(sequence, W_q_.data(), Q.data(), seq_len, dim, dim);
    matmul_simple(sequence, W_k_.data(), K.data(), seq_len, dim, dim);
    matmul_simple(sequence, W_v_.data(), V.data(), seq_len, dim, dim);

    for (std::size_t i = 0; i < seq_len; ++i) {
        for (std::size_t j = 0; j < dim; ++j) {
            Q[i * dim + j] += bias_q_[j];
            K[i * dim + j] += bias_k_[j];
            V[i * dim + j] += bias_v_[j];
        }
    }

    // scores = Q @ K^T (we use Q@K transposed by storing K with row stride dim)
    // matmul_simple gives Q @ K which is incorrect in math but matches the
    // original C code which used Q @ K (not Q @ K^T). Preserve the original
    // behavior bit-for-bit.
    matmul_simple(Q.data(), K.data(), scores.data(), seq_len, dim, seq_len);

    const float scale = 1.0f / std::sqrt(static_cast<float>(dim_per_head_));
    for (std::size_t i = 0; i < seq_len * seq_len; ++i) {
        scores[i] *= scale;
    }

    if (use_causal_mask_) {
        for (std::size_t i = 0; i < seq_len; ++i) {
            for (std::size_t j = i + 1; j < seq_len; ++j) {
                scores[i * seq_len + j] = -1e9f;
            }
        }
    }

    softmax_row(scores.data(), seq_len, seq_len);

    matmul_simple(scores.data(), V.data(), out_sequence, seq_len, seq_len, dim);

    std::vector<float> temp(seq_len * dim, 0.0f);
    matmul_simple(out_sequence, W_o_.data(), temp.data(), seq_len, dim, dim);
    std::memcpy(out_sequence, temp.data(), seq_len * dim * sizeof(float));

    for (std::size_t i = 0; i < seq_len; ++i) {
        for (std::size_t j = 0; j < dim; ++j) {
            out_sequence[i * dim + j] += bias_o_[j];
        }
    }

    if (out_attention) {
        std::memcpy(out_attention, scores.data(), seq_len * seq_len * sizeof(float));
    }
    return true;
}

// ============================================================================
// TemporalConvLayer
// ============================================================================

TemporalConvLayer::TemporalConvLayer(std::size_t kernel_size,
                                     std::size_t in_channels,
                                     std::size_t out_channels,
                                     std::size_t stride)
    : kernel_(kernel_size * in_channels * out_channels, 0.0f),
      bias_(out_channels, 0.0f),
      kernel_size_(kernel_size),
      in_channels_(in_channels),
      out_channels_(out_channels),
      stride_(stride)
{}

bool TemporalConvLayer::forward(const float* input,
                                std::size_t seq_len,
                                float* output,
                                std::size_t* out_seq_len) const {
    if (!input || !output || !out_seq_len) return false;
    if (seq_len < kernel_size_) {
        *out_seq_len = 0;
        return false;
    }

    const std::size_t out_len = (seq_len - kernel_size_) / stride_ + 1;
    *out_seq_len = out_len;

    for (std::size_t t = 0; t < out_len; ++t) {
        const std::size_t start = t * stride_;
        for (std::size_t oc = 0; oc < out_channels_; ++oc) {
            float sum = bias_[oc];
            for (std::size_t k = 0; k < kernel_size_; ++k) {
                for (std::size_t ic = 0; ic < in_channels_; ++ic) {
                    const float w = kernel_[(k * in_channels_ + ic) * out_channels_ + oc];
                    sum += w * input[(start + k) * in_channels_ + ic];
                }
            }
            switch (activation) {
                case TemporalConvActivation::ReLU: sum = sum > 0 ? sum : 0; break;
                case TemporalConvActivation::Tanh: sum = std::tanh(sum); break;
                case TemporalConvActivation::None: break;
            }
            output[t * out_channels_ + oc] = sum;
        }
    }
    return true;
}

// ============================================================================
// Time-aware message passing
// ============================================================================

float time_aware_weight(const TimeAwareWeighting& weighting,
                        std::uint64_t edge_timestamp_ns) {
    std::int64_t delta_ns =
        static_cast<std::int64_t>(weighting.current_time_ns) -
        static_cast<std::int64_t>(edge_timestamp_ns);
    if (delta_ns < 0) delta_ns = 0;

    const float delta_sec = static_cast<float>(delta_ns) / 1e9f;
    float weight = std::exp(-weighting.decay_rate * delta_sec);
    if (weight < weighting.min_weight) weight = 0.0f;
    return weight;
}

void time_aware_compute_edge_weights(const ProvenanceGraph& graph,
                                     const TimeAwareWeighting& weighting,
                                     float* out_weights) {
    if (!out_weights) return;

    const std::size_t num_edges = graph.num_edges();
    const ProvenanceEdge* edges = graph.edges_data();
    for (std::size_t i = 0; i < num_edges; ++i) {
        out_weights[i] = time_aware_weight(weighting, edges[i].timestamp_ns);
    }
}

// ============================================================================
// Temporal Event Sequence
// ============================================================================

bool temporal_extract_sequence(ProvenanceGraph& graph,
                               std::uint64_t start_node_id,
                               std::size_t max_length,
                               TemporalEventSequence& out_sequence) {
    out_sequence = TemporalEventSequence{};

    ProvenanceNode* start_node = graph.get_node(start_node_id);
    if (!start_node) return false;

    out_sequence.node_ids[0]   = start_node_id;
    out_sequence.timestamps[0] = start_node->first_seen_ns;
    pg_extract_node_features(*start_node, out_sequence.features[0]);
    out_sequence.length        = 1;
    out_sequence.start_time_ns = start_node->first_seen_ns;

    std::size_t idx = 1;
    std::uint64_t current_node = start_node_id;

    while (idx < max_length && idx < TEMPORAL_MAX_SEQ_LEN) {
        ProvenanceNode* node = graph.get_node(current_node);
        if (!node || node->out_degree == 0) break;

        const std::uint64_t edge_id = node->out_edges[0];
        ProvenanceEdge* edge = graph.get_edge(edge_id);
        if (!edge) break;

        out_sequence.edge_ids[idx - 1] = edge_id;
        out_sequence.node_ids[idx]     = edge->dst_node;
        out_sequence.timestamps[idx]   = edge->timestamp_ns;

        if (ProvenanceNode* dst_node = graph.get_node(edge->dst_node)) {
            pg_extract_node_features(*dst_node, out_sequence.features[idx]);
        }

        current_node = edge->dst_node;
        ++idx;
    }

    out_sequence.length = idx;
    if (idx > 0) {
        out_sequence.end_time_ns = out_sequence.timestamps[idx - 1];
        out_sequence.duration_sec = static_cast<float>(
            out_sequence.end_time_ns - out_sequence.start_time_ns) / 1e9f;
    }
    return true;
}

void temporal_extract_sequences_sliding(ProvenanceGraph& graph,
                                        std::size_t window_size,
                                        std::size_t /*stride*/,
                                        TemporalEventSequence* out_sequences,
                                        std::size_t max_sequences,
                                        std::size_t* out_count) {
    if (!out_sequences || !out_count) return;

    *out_count = 0;
    const auto* node_ids = graph.node_ids_data();
    const std::size_t max_nodes = graph.max_nodes();

    for (std::size_t i = 0; i < max_nodes && *out_count < max_sequences; ++i) {
        if (node_ids[i] == static_cast<std::uint64_t>(-1)) continue;
        const std::uint64_t node_id = node_ids[i];
        if (temporal_extract_sequence(graph, node_id, window_size, out_sequences[*out_count])) {
            if (out_sequences[*out_count].length >= 3) {
                ++(*out_count);
            }
        }
    }
}

// ============================================================================
// Multi-scale aggregation
// ============================================================================

std::unique_ptr<TemporalMultiScaleAggregation>
temporal_multiscale_create(std::uint64_t short_window_sec,
                           std::uint64_t medium_window_sec,
                           std::uint64_t long_window_sec) {
    auto agg = std::make_unique<TemporalMultiScaleAggregation>();
    agg->window_sizes_ns[0] = short_window_sec  * 1'000'000'000ULL;
    agg->window_sizes_ns[1] = medium_window_sec * 1'000'000'000ULL;
    agg->window_sizes_ns[2] = long_window_sec   * 1'000'000'000ULL;
    return agg;
}

void temporal_multiscale_aggregate(TemporalMultiScaleAggregation& /*agg*/,
                                   const TemporalEventSequence* /*sequences*/,
                                   std::size_t /*num_sequences*/,
                                   std::uint64_t /*current_time_ns*/) {
    // Original C implementation left this as a placeholder; preserve behavior.
}

// ============================================================================
// Temporal pattern detection
// ============================================================================

bool temporal_detect_periodicity(const TemporalEventSequence& sequence,
                                 float& out_period_sec,
                                 float& out_confidence) {
    if (sequence.length < 4) return false;

    std::array<float, TEMPORAL_MAX_SEQ_LEN - 1> iets {};
    std::size_t num_iets = 0;

    for (std::size_t i = 1; i < sequence.length; ++i) {
        iets[num_iets++] = static_cast<float>(
            sequence.timestamps[i] - sequence.timestamps[i - 1]) / 1e9f;
    }

    float mean = 0.0f, variance = 0.0f;
    for (std::size_t i = 0; i < num_iets; ++i) mean += iets[i];
    mean /= static_cast<float>(num_iets);
    for (std::size_t i = 0; i < num_iets; ++i) {
        const float diff = iets[i] - mean;
        variance += diff * diff;
    }
    variance /= static_cast<float>(num_iets);

    const float std  = std::sqrt(variance);
    const float cv   = std / (mean + 1e-6f);

    out_period_sec  = mean;
    out_confidence  = std::max(0.0f, 1.0f - cv);
    return cv < 0.3f;
}

bool temporal_detect_burst(const TemporalEventSequence& sequence,
                           float& out_burst_score) {
    if (sequence.length < 3) return false;

    const float duration_sec = sequence.duration_sec;
    if (duration_sec < 0.001f) return false;

    const float avg_rate = static_cast<float>(sequence.length) / duration_sec;

    std::size_t window = sequence.length / 4;
    if (window < 2) window = 2;

    float max_rate = 0.0f;
    for (std::size_t i = 0; i + window <= sequence.length; ++i) {
        const std::uint64_t window_start = sequence.timestamps[i];
        const std::uint64_t window_end   = sequence.timestamps[i + window - 1];
        const float window_duration = static_cast<float>(window_end - window_start) / 1e9f;

        if (window_duration > 0) {
            const float rate = static_cast<float>(window) / window_duration;
            if (rate > max_rate) max_rate = rate;
        }
    }

    out_burst_score = max_rate / (avg_rate + 1e-6f);
    return out_burst_score > 3.0f;
}

bool temporal_detect_slow_exfiltration(const TemporalEventSequence& sequence,
                                       float& out_rate_bps,
                                       float& out_duration_sec) {
    if (sequence.length == 0) return false;

    std::uint64_t total_bytes = 0;
    std::size_t num_network_ops = 0;

    for (std::size_t i = 0; i + 1 < sequence.length; ++i) {
        total_bytes += 1024;  // placeholder, matching original C
        ++num_network_ops;
    }

    if (num_network_ops == 0 || sequence.duration_sec < 60.0f) {
        return false;
    }

    out_rate_bps     = static_cast<float>(total_bytes) / sequence.duration_sec;
    out_duration_sec = sequence.duration_sec;
    return out_rate_bps < 10240.0f && out_duration_sec > 60.0f;
}

void temporal_compute_iet_stats(const TemporalEventSequence& sequence,
                                float& out_mean_ms,
                                float& out_std_ms,
                                float& out_cv) {
    if (sequence.length < 2) {
        out_mean_ms = 0; out_std_ms = 0; out_cv = 0; return;
    }

    float mean = 0.0f, variance = 0.0f;
    const std::size_t num_iets = sequence.length - 1;

    for (std::size_t i = 1; i < sequence.length; ++i) {
        const float iet_ms = static_cast<float>(
            sequence.timestamps[i] - sequence.timestamps[i - 1]) / 1e6f;
        mean += iet_ms;
    }
    mean /= static_cast<float>(num_iets);

    for (std::size_t i = 1; i < sequence.length; ++i) {
        const float iet_ms = static_cast<float>(
            sequence.timestamps[i] - sequence.timestamps[i - 1]) / 1e6f;
        const float diff = iet_ms - mean;
        variance += diff * diff;
    }
    variance /= static_cast<float>(num_iets);

    out_mean_ms = mean;
    out_std_ms  = std::sqrt(variance);
    out_cv      = out_std_ms / (mean + 1e-6f);
}

void temporal_print_sequence(const TemporalEventSequence& sequence) {
    std::cout << "\n=== Temporal Event Sequence ===\n";
    std::cout << std::format("Length:      {} events\n", sequence.length);
    std::cout << std::format("Duration:    {:.2f} seconds\n", sequence.duration_sec);
    std::cout << std::format("Anomalous:   {} (score={:.3f})\n",
                             sequence.is_anomalous ? "YES" : "no",
                             sequence.anomaly_score);

    std::cout << "Events:\n";
    const std::size_t max_print = std::min<std::size_t>(sequence.length, 10);
    for (std::size_t i = 0; i < max_print; ++i) {
        const float rel_sec = static_cast<float>(
            sequence.timestamps[i] - sequence.start_time_ns) / 1e9f;
        std::cout << std::format("  [{}] Node {} @ {:.3f} sec\n",
                                 i, sequence.node_ids[i], rel_sec);
    }
    if (sequence.length > 10) {
        std::cout << std::format("  ... ({} more events)\n", sequence.length - 10);
    }
    std::cout << "================================\n\n";
}

// ============================================================================
// SpatioTemporalGNN
// ============================================================================

SpatioTemporalGNN::SpatioTemporalGNN(GNNModel& spatial_gnn, std::size_t encoding_dim)
    : spatial_gnn_(&spatial_gnn)
{
    temporal_encoding_ = std::make_unique<TemporalPositionEncoding>(
        3600,                           // 1 hour of 1-second timesteps
        encoding_dim,
        1'000'000'000ULL                // 1 second in nanoseconds
    );

    constexpr std::size_t num_temporal_layers = 2;
    temporal_attention_layers_.reserve(num_temporal_layers);
    for (std::size_t i = 0; i < num_temporal_layers; ++i) {
        temporal_attention_layers_.emplace_back(
            std::make_unique<TemporalAttentionLayer>(
                TEMPORAL_NUM_HEADS, encoding_dim, /*use_causal_mask=*/false));
    }

    time_weighting.decay_rate      = 0.0001f;
    time_weighting.min_weight      = 0.01f;
    time_weighting.current_time_ns = 0;

    config.use_temporal_encoding  = true;
    config.use_temporal_attention = true;
    config.use_time_decay         = true;

    std::cout << std::format("[SpatioTemporalGNN] Created with {} temporal layers\n",
                             num_temporal_layers);
}

bool SpatioTemporalGNN::forward(ProvenanceGraph& graph,
                                const std::uint64_t* timestamps,
                                float* out_embeddings) {
    if (!timestamps || !out_embeddings) return false;

    const std::size_t num_nodes  = graph.num_nodes();
    const std::size_t output_dim = spatial_gnn_->output_dim();

    std::vector<float> spatial_features(num_nodes * output_dim, 0.0f);
    if (!spatial_gnn_->forward(graph, spatial_features.data())) {
        return false;
    }

    if (config.use_temporal_encoding) {
        temporal_encoding_->add_to_features(spatial_features.data(),
                                            timestamps,
                                            num_nodes,
                                            output_dim,
                                            out_embeddings);
    } else {
        std::memcpy(out_embeddings, spatial_features.data(),
                    num_nodes * output_dim * sizeof(float));
    }
    return true;
}

bool SpatioTemporalGNN::predict_sequence(const TemporalEventSequence& sequence,
                                         float& out_anomaly_score) const {
    if (sequence.length == 0) return false;

    std::vector<float> attended_features(sequence.length * 64, 0.0f);

    const bool success = temporal_attention_layers_[0]->forward(
        reinterpret_cast<const float*>(sequence.features),
        sequence.length,
        attended_features.data(),
        nullptr);

    if (!success) return false;

    float mean_magnitude = 0.0f;
    for (std::size_t i = 0; i < sequence.length; ++i) {
        float mag = 0.0f;
        for (std::size_t j = 0; j < 64; ++j) {
            const float val = attended_features[i * 64 + j];
            mag += val * val;
        }
        mean_magnitude += std::sqrt(mag);
    }
    mean_magnitude /= static_cast<float>(sequence.length);

    out_anomaly_score = std::min(mean_magnitude / 10.0f, 1.0f);
    return out_anomaly_score > 0.5f;
}

std::size_t SpatioTemporalGNN::detect_apt_phases(ProvenanceGraph& /*graph*/,
                                                 const TemporalEventSequence* /*sequences*/,
                                                 std::size_t num_sequences,
                                                 APTPhase* /*out_phases*/,
                                                 float* /*out_scores*/) {
    // The original C implementation left this body unwritten; keep the same
    // surface and return the input count to remain ABI/behaviour-compatible
    // with downstream callers that only read out_phases when set.
    return num_sequences;
}

}  // namespace flowshield
