/**
 * Temporal GNN Implementation
 *
 * Implements spatio-temporal graph neural networks for APT detection.
 * Captures multi-stage attacks that unfold over time.
 */

#define _GNU_SOURCE
#include "../include/temporal_gnn.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <time.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* ============================================================================
 * Temporal Position Encoding
 * ============================================================================ */

TemporalPositionEncoding* temporal_encoding_create(
    size_t max_timesteps,
    size_t encoding_dim,
    uint64_t time_scale_ns
) {
    TemporalPositionEncoding* encoding = calloc(1, sizeof(TemporalPositionEncoding));
    if (!encoding) return NULL;

    encoding->max_timesteps = max_timesteps;
    encoding->encoding_dim = encoding_dim;
    encoding->time_scale_ns = time_scale_ns;
    encoding->base_period = 10000.0f;

    /* Pre-compute encodings for common timesteps */
    encoding->encodings = calloc(max_timesteps * encoding_dim, sizeof(float));
    if (!encoding->encodings) {
        free(encoding);
        return NULL;
    }

    /* Compute sinusoidal encodings: PE(t, 2i) = sin(t / 10000^(2i/d)) */
    for (size_t t = 0; t < max_timesteps; t++) {
        for (size_t i = 0; i < encoding_dim / 2; i++) {
            float freq = 1.0f / powf(encoding->base_period, (2.0f * i) / encoding_dim);
            float angle = t * freq;

            encoding->encodings[t * encoding_dim + 2 * i] = sinf(angle);
            encoding->encodings[t * encoding_dim + 2 * i + 1] = cosf(angle);
        }
    }

    printf("[TemporalEncoding] Created with %zu timesteps, dim=%zu\n",
           max_timesteps, encoding_dim);

    return encoding;
}

void temporal_encoding_destroy(TemporalPositionEncoding* encoding) {
    if (!encoding) return;
    free(encoding->encodings);
    free(encoding);
}

void temporal_encoding_get(
    const TemporalPositionEncoding* encoding,
    uint64_t timestamp_ns,
    float* out_encoding
) {
    if (!encoding || !out_encoding) return;

    /* Convert timestamp to timestep */
    size_t timestep = timestamp_ns / encoding->time_scale_ns;

    if (timestep < encoding->max_timesteps) {
        /* Use pre-computed encoding */
        memcpy(out_encoding,
               &encoding->encodings[timestep * encoding->encoding_dim],
               encoding->encoding_dim * sizeof(float));
    } else {
        /* Compute on-the-fly for timestamps beyond cache */
        for (size_t i = 0; i < encoding->encoding_dim / 2; i++) {
            float freq = 1.0f / powf(encoding->base_period, (2.0f * i) / encoding->encoding_dim);
            float angle = timestep * freq;

            out_encoding[2 * i] = sinf(angle);
            out_encoding[2 * i + 1] = cosf(angle);
        }
    }
}

void temporal_encoding_add_to_features(
    const TemporalPositionEncoding* encoding,
    const float* features,
    const uint64_t* timestamps,
    size_t num_nodes,
    size_t feature_dim,
    float* out_features
) {
    if (!encoding || !features || !timestamps || !out_features) return;

    float* temp_encoding = alloca(encoding->encoding_dim * sizeof(float));

    for (size_t i = 0; i < num_nodes; i++) {
        /* Get temporal encoding for this timestamp */
        temporal_encoding_get(encoding, timestamps[i], temp_encoding);

        /* Add to features */
        for (size_t j = 0; j < feature_dim; j++) {
            out_features[i * feature_dim + j] = features[i * feature_dim + j];

            /* Add temporal encoding (only if dimension matches) */
            if (j < encoding->encoding_dim) {
                out_features[i * feature_dim + j] += temp_encoding[j];
            }
        }
    }
}

/* ============================================================================
 * Temporal Attention Layer
 * ============================================================================ */

TemporalAttentionLayer* temporal_attention_create(
    size_t num_heads,
    size_t total_dim,
    bool use_causal_mask
) {
    TemporalAttentionLayer* layer = calloc(1, sizeof(TemporalAttentionLayer));
    if (!layer) return NULL;

    layer->num_heads = num_heads;
    layer->total_dim = total_dim;
    layer->dim_per_head = total_dim / num_heads;
    layer->use_causal_mask = use_causal_mask;
    layer->dropout_rate = 0.1f;

    /* Allocate weight matrices */
    size_t matrix_size = total_dim * total_dim;
    layer->W_q = calloc(matrix_size, sizeof(float));
    layer->W_k = calloc(matrix_size, sizeof(float));
    layer->W_v = calloc(matrix_size, sizeof(float));
    layer->W_o = calloc(matrix_size, sizeof(float));

    layer->bias_q = calloc(total_dim, sizeof(float));
    layer->bias_k = calloc(total_dim, sizeof(float));
    layer->bias_v = calloc(total_dim, sizeof(float));
    layer->bias_o = calloc(total_dim, sizeof(float));

    if (!layer->W_q || !layer->W_k || !layer->W_v || !layer->W_o ||
        !layer->bias_q || !layer->bias_k || !layer->bias_v || !layer->bias_o) {
        temporal_attention_destroy(layer);
        return NULL;
    }

    /* Xavier initialization */
    srand(time(NULL));
    float scale = sqrtf(6.0f / (2.0f * total_dim));

    for (size_t i = 0; i < matrix_size; i++) {
        layer->W_q[i] = ((float)rand() / RAND_MAX - 0.5f) * 2.0f * scale;
        layer->W_k[i] = ((float)rand() / RAND_MAX - 0.5f) * 2.0f * scale;
        layer->W_v[i] = ((float)rand() / RAND_MAX - 0.5f) * 2.0f * scale;
        layer->W_o[i] = ((float)rand() / RAND_MAX - 0.5f) * 2.0f * scale;
    }

    printf("[TemporalAttention] Created with %zu heads, dim=%zu\n", num_heads, total_dim);

    return layer;
}

void temporal_attention_destroy(TemporalAttentionLayer* layer) {
    if (!layer) return;
    free(layer->W_q);
    free(layer->W_k);
    free(layer->W_v);
    free(layer->W_o);
    free(layer->bias_q);
    free(layer->bias_k);
    free(layer->bias_v);
    free(layer->bias_o);
    free(layer);
}

static void matmul_simple(const float* A, const float* B, float* C,
                          size_t m, size_t k, size_t n) {
    /* C = A @ B, where A is [m x k], B is [k x n], C is [m x n] */
    for (size_t i = 0; i < m; i++) {
        for (size_t j = 0; j < n; j++) {
            C[i * n + j] = 0;
            for (size_t p = 0; p < k; p++) {
                C[i * n + j] += A[i * k + p] * B[p * n + j];
            }
        }
    }
}

static void softmax_row(float* matrix, size_t rows, size_t cols) {
    for (size_t i = 0; i < rows; i++) {
        float* row = &matrix[i * cols];

        /* Find max for numerical stability */
        float max_val = row[0];
        for (size_t j = 1; j < cols; j++) {
            if (row[j] > max_val) max_val = row[j];
        }

        /* Exp and sum */
        float sum = 0;
        for (size_t j = 0; j < cols; j++) {
            row[j] = expf(row[j] - max_val);
            sum += row[j];
        }

        /* Normalize */
        for (size_t j = 0; j < cols; j++) {
            row[j] /= (sum + 1e-10f);
        }
    }
}

bool temporal_attention_forward(
    TemporalAttentionLayer* layer,
    const float* sequence,
    size_t seq_len,
    float* out_sequence,
    float* out_attention
) {
    if (!layer || !sequence || !out_sequence || seq_len == 0) return false;

    size_t dim = layer->total_dim;

    /* Allocate temporary buffers */
    float* Q = calloc(seq_len * dim, sizeof(float));
    float* K = calloc(seq_len * dim, sizeof(float));
    float* V = calloc(seq_len * dim, sizeof(float));
    float* scores = calloc(seq_len * seq_len, sizeof(float));

    if (!Q || !K || !V || !scores) {
        free(Q); free(K); free(V); free(scores);
        return false;
    }

    /* Project to Q, K, V */
    matmul_simple(sequence, layer->W_q, Q, seq_len, dim, dim);
    matmul_simple(sequence, layer->W_k, K, seq_len, dim, dim);
    matmul_simple(sequence, layer->W_v, V, seq_len, dim, dim);

    /* Add biases */
    for (size_t i = 0; i < seq_len; i++) {
        for (size_t j = 0; j < dim; j++) {
            Q[i * dim + j] += layer->bias_q[j];
            K[i * dim + j] += layer->bias_k[j];
            V[i * dim + j] += layer->bias_v[j];
        }
    }

    /* Compute attention scores: QK^T / sqrt(d_k) */
    matmul_simple(Q, K, scores, seq_len, dim, seq_len);

    float scale = 1.0f / sqrtf((float)layer->dim_per_head);
    for (size_t i = 0; i < seq_len * seq_len; i++) {
        scores[i] *= scale;
    }

    /* Apply causal mask if needed */
    if (layer->use_causal_mask) {
        for (size_t i = 0; i < seq_len; i++) {
            for (size_t j = i + 1; j < seq_len; j++) {
                scores[i * seq_len + j] = -1e9f;  /* Mask future positions */
            }
        }
    }

    /* Softmax to get attention weights */
    softmax_row(scores, seq_len, seq_len);

    /* Attention output: scores @ V */
    matmul_simple(scores, V, out_sequence, seq_len, seq_len, dim);

    /* Output projection */
    float* temp = calloc(seq_len * dim, sizeof(float));
    matmul_simple(out_sequence, layer->W_o, temp, seq_len, dim, dim);
    memcpy(out_sequence, temp, seq_len * dim * sizeof(float));
    free(temp);

    /* Add output bias */
    for (size_t i = 0; i < seq_len; i++) {
        for (size_t j = 0; j < dim; j++) {
            out_sequence[i * dim + j] += layer->bias_o[j];
        }
    }

    /* Copy attention weights if requested */
    if (out_attention) {
        memcpy(out_attention, scores, seq_len * seq_len * sizeof(float));
    }

    free(Q);
    free(K);
    free(V);
    free(scores);

    return true;
}

/* ============================================================================
 * Time-Aware Message Passing
 * ============================================================================ */

float time_aware_weight(
    const TimeAwareWeighting* weighting,
    uint64_t edge_timestamp_ns
) {
    if (!weighting) return 1.0f;

    /* Compute time delta in seconds */
    int64_t delta_ns = weighting->current_time_ns - edge_timestamp_ns;
    if (delta_ns < 0) delta_ns = 0;  /* Future events */

    float delta_sec = (float)delta_ns / 1e9f;

    /* Exponential decay: w(t) = exp(-λ * Δt) */
    float weight = expf(-weighting->decay_rate * delta_sec);

    /* Apply minimum threshold */
    if (weight < weighting->min_weight) {
        weight = 0.0f;
    }

    return weight;
}

void time_aware_compute_edge_weights(
    const ProvenanceGraph* graph,
    const TimeAwareWeighting* weighting,
    float* out_weights
) {
    if (!graph || !weighting || !out_weights) return;

    for (size_t i = 0; i < graph->num_edges; i++) {
        ProvenanceEdge* edge = &graph->edges[i];
        out_weights[i] = time_aware_weight(weighting, edge->timestamp_ns);
    }
}

/* ============================================================================
 * Temporal Event Sequence
 * ============================================================================ */

bool temporal_extract_sequence(
    const ProvenanceGraph* graph,
    uint64_t start_node_id,
    size_t max_length,
    TemporalEventSequence* out_sequence
) {
    if (!graph || !out_sequence) return false;

    memset(out_sequence, 0, sizeof(TemporalEventSequence));

    ProvenanceNode* start_node = pg_get_node((ProvenanceGraph*)graph, start_node_id);
    if (!start_node) return false;

    /* DFS traversal to extract sequence */
    out_sequence->node_ids[0] = start_node_id;
    out_sequence->timestamps[0] = start_node->first_seen_ns;
    pg_extract_node_features(start_node, out_sequence->features[0]);
    out_sequence->length = 1;
    out_sequence->start_time_ns = start_node->first_seen_ns;

    /* Traverse out-edges */
    size_t idx = 1;
    uint64_t current_node = start_node_id;

    while (idx < max_length && idx < TEMPORAL_MAX_SEQ_LEN) {
        ProvenanceNode* node = pg_get_node((ProvenanceGraph*)graph, current_node);
        if (!node || node->out_degree == 0) break;

        /* Get first out-edge */
        uint64_t edge_id = node->out_edges[0];
        ProvenanceEdge* edge = pg_get_edge((ProvenanceGraph*)graph, edge_id);
        if (!edge) break;

        /* Add to sequence */
        out_sequence->edge_ids[idx - 1] = edge_id;
        out_sequence->node_ids[idx] = edge->dst_node;
        out_sequence->timestamps[idx] = edge->timestamp_ns;

        ProvenanceNode* dst_node = pg_get_node((ProvenanceGraph*)graph, edge->dst_node);
        if (dst_node) {
            pg_extract_node_features(dst_node, out_sequence->features[idx]);
        }

        current_node = edge->dst_node;
        idx++;
    }

    out_sequence->length = idx;
    if (idx > 0) {
        out_sequence->end_time_ns = out_sequence->timestamps[idx - 1];
        out_sequence->duration_sec = (float)(out_sequence->end_time_ns - out_sequence->start_time_ns) / 1e9f;
    }

    return true;
}

void temporal_extract_sequences_sliding(
    const ProvenanceGraph* graph,
    size_t window_size,
    size_t stride,
    TemporalEventSequence* out_sequences,
    size_t max_sequences,
    size_t* out_count
) {
    if (!graph || !out_sequences || !out_count) return;

    *out_count = 0;

    /* Extract sequences from all nodes */
    for (size_t i = 0; i < graph->max_nodes && *out_count < max_sequences; i++) {
        if (graph->node_ids[i] == UINT64_MAX) continue;

        uint64_t node_id = graph->node_ids[i];
        if (temporal_extract_sequence(graph, node_id, window_size, &out_sequences[*out_count])) {
            if (out_sequences[*out_count].length >= 3) {  /* Minimum sequence length */
                (*out_count)++;
            }
        }
    }
}

/* ============================================================================
 * Temporal Pattern Detection
 * ============================================================================ */

bool temporal_detect_periodicity(
    const TemporalEventSequence* sequence,
    float* out_period_sec,
    float* out_confidence
) {
    if (!sequence || !out_period_sec || !out_confidence || sequence->length < 4) {
        return false;
    }

    /* Compute inter-event times */
    float iets[TEMPORAL_MAX_SEQ_LEN - 1];
    size_t num_iets = 0;

    for (size_t i = 1; i < sequence->length; i++) {
        float iet_sec = (float)(sequence->timestamps[i] - sequence->timestamps[i - 1]) / 1e9f;
        iets[num_iets++] = iet_sec;
    }

    /* Compute mean and variance of IETs */
    float mean = 0, variance = 0;
    for (size_t i = 0; i < num_iets; i++) {
        mean += iets[i];
    }
    mean /= num_iets;

    for (size_t i = 0; i < num_iets; i++) {
        float diff = iets[i] - mean;
        variance += diff * diff;
    }
    variance /= num_iets;

    float std = sqrtf(variance);
    float cv = std / (mean + 1e-6f);  /* Coefficient of variation */

    /* Low CV indicates periodicity */
    *out_period_sec = mean;
    *out_confidence = fmaxf(0.0f, 1.0f - cv);

    /* Threshold: CV < 0.3 indicates strong periodicity */
    return cv < 0.3f;
}

bool temporal_detect_burst(
    const TemporalEventSequence* sequence,
    float* out_burst_score
) {
    if (!sequence || !out_burst_score || sequence->length < 3) {
        return false;
    }

    /* Compute event rate over time */
    float duration_sec = sequence->duration_sec;
    if (duration_sec < 0.001f) return false;

    float avg_rate = (float)sequence->length / duration_sec;

    /* Look for short bursts (high rate in small window) */
    size_t window = sequence->length / 4;  /* Quarter of sequence */
    if (window < 2) window = 2;

    float max_rate = 0;
    for (size_t i = 0; i + window <= sequence->length; i++) {
        uint64_t window_start = sequence->timestamps[i];
        uint64_t window_end = sequence->timestamps[i + window - 1];
        float window_duration = (float)(window_end - window_start) / 1e9f;

        if (window_duration > 0) {
            float rate = (float)window / window_duration;
            if (rate > max_rate) max_rate = rate;
        }
    }

    /* Burst score: ratio of max rate to average rate */
    *out_burst_score = max_rate / (avg_rate + 1e-6f);

    /* Threshold: burst if max rate > 3x average */
    return *out_burst_score > 3.0f;
}

bool temporal_detect_slow_exfiltration(
    const TemporalEventSequence* sequence,
    float* out_rate_bps,
    float* out_duration_sec
) {
    if (!sequence || !out_rate_bps || !out_duration_sec) {
        return false;
    }

    /* Count network write/send operations */
    uint64_t total_bytes = 0;
    size_t num_network_ops = 0;

    for (size_t i = 0; i < sequence->length - 1; i++) {
        /* Simplified: assume each network operation transfers data */
        /* In real implementation, extract from edge details */
        total_bytes += 1024;  /* Placeholder */
        num_network_ops++;
    }

    if (num_network_ops == 0 || sequence->duration_sec < 60.0f) {
        return false;
    }

    *out_rate_bps = (float)total_bytes / sequence->duration_sec;
    *out_duration_sec = sequence->duration_sec;

    /* Slow exfiltration: sustained low-rate transfer */
    /* Threshold: < 10 KB/s but > 60 seconds */
    return *out_rate_bps < 10240.0f && *out_duration_sec > 60.0f;
}

void temporal_compute_iet_stats(
    const TemporalEventSequence* sequence,
    float* out_mean_ms,
    float* out_std_ms,
    float* out_cv
) {
    if (!sequence || !out_mean_ms || !out_std_ms || !out_cv) return;

    if (sequence->length < 2) {
        *out_mean_ms = 0;
        *out_std_ms = 0;
        *out_cv = 0;
        return;
    }

    /* Compute inter-event times in milliseconds */
    float mean = 0, variance = 0;
    size_t num_iets = sequence->length - 1;

    for (size_t i = 1; i < sequence->length; i++) {
        float iet_ms = (float)(sequence->timestamps[i] - sequence->timestamps[i - 1]) / 1e6f;
        mean += iet_ms;
    }
    mean /= num_iets;

    for (size_t i = 1; i < sequence->length; i++) {
        float iet_ms = (float)(sequence->timestamps[i] - sequence->timestamps[i - 1]) / 1e6f;
        float diff = iet_ms - mean;
        variance += diff * diff;
    }
    variance /= num_iets;

    *out_mean_ms = mean;
    *out_std_ms = sqrtf(variance);
    *out_cv = *out_std_ms / (mean + 1e-6f);
}

void temporal_print_sequence(const TemporalEventSequence* sequence) {
    if (!sequence) return;

    printf("\n=== Temporal Event Sequence ===\n");
    printf("Length:      %zu events\n", sequence->length);
    printf("Duration:    %.2f seconds\n", sequence->duration_sec);
    printf("Anomalous:   %s (score=%.3f)\n",
           sequence->is_anomalous ? "YES" : "no",
           sequence->anomaly_score);

    printf("Events:\n");
    for (size_t i = 0; i < fmin(sequence->length, 10); i++) {
        printf("  [%zu] Node %lu @ %.3f sec\n",
               i, sequence->node_ids[i],
               (float)(sequence->timestamps[i] - sequence->start_time_ns) / 1e9f);
    }
    if (sequence->length > 10) {
        printf("  ... (%zu more events)\n", sequence->length - 10);
    }
    printf("================================\n\n");
}

/* ============================================================================
 * Spatio-Temporal GNN
 * ============================================================================ */

SpatioTemporalGNN* st_gnn_create(GNNModel* spatial_gnn, size_t encoding_dim) {
    if (!spatial_gnn) return NULL;

    SpatioTemporalGNN* st_gnn = calloc(1, sizeof(SpatioTemporalGNN));
    if (!st_gnn) return NULL;

    st_gnn->spatial_gnn = spatial_gnn;

    /* Create temporal encoding */
    st_gnn->temporal_encoding = temporal_encoding_create(
        3600,           /* 1 hour of 1-second timesteps */
        encoding_dim,
        1000000000ULL   /* 1 second in nanoseconds */
    );

    /* Create temporal attention layers */
    st_gnn->num_temporal_layers = 2;
    for (size_t i = 0; i < st_gnn->num_temporal_layers; i++) {
        st_gnn->temporal_attention_layers[i] = temporal_attention_create(
            TEMPORAL_NUM_HEADS,
            encoding_dim,
            false  /* No causal mask */
        );
    }

    /* Time-aware weighting */
    st_gnn->time_weighting.decay_rate = 0.0001f;  /* Slow decay: ~2.7 hours half-life */
    st_gnn->time_weighting.min_weight = 0.01f;
    st_gnn->time_weighting.current_time_ns = 0;

    /* Configuration */
    st_gnn->config.use_temporal_encoding = true;
    st_gnn->config.use_temporal_attention = true;
    st_gnn->config.use_time_decay = true;

    printf("[SpatioTemporalGNN] Created with %zu temporal layers\n",
           st_gnn->num_temporal_layers);

    return st_gnn;
}

void st_gnn_destroy(SpatioTemporalGNN* st_gnn) {
    if (!st_gnn) return;

    temporal_encoding_destroy(st_gnn->temporal_encoding);

    for (size_t i = 0; i < st_gnn->num_temporal_layers; i++) {
        temporal_attention_destroy(st_gnn->temporal_attention_layers[i]);
    }

    free(st_gnn->fusion_W);
    free(st_gnn->fusion_b);
    free(st_gnn);
}

bool st_gnn_forward(
    SpatioTemporalGNN* st_gnn,
    ProvenanceGraph* graph,
    const uint64_t* timestamps,
    float* out_embeddings
) {
    if (!st_gnn || !graph || !timestamps || !out_embeddings) return false;

    /* 1. Extract spatial features using base GNN */
    size_t num_nodes = graph->num_nodes;
    float* spatial_features = calloc(num_nodes * st_gnn->spatial_gnn->output_dim, sizeof(float));

    if (!gnn_forward(st_gnn->spatial_gnn, graph, spatial_features)) {
        free(spatial_features);
        return false;
    }

    /* 2. Add temporal encoding */
    if (st_gnn->config.use_temporal_encoding) {
        temporal_encoding_add_to_features(
            st_gnn->temporal_encoding,
            spatial_features,
            timestamps,
            num_nodes,
            st_gnn->spatial_gnn->output_dim,
            out_embeddings
        );
    } else {
        memcpy(out_embeddings, spatial_features,
               num_nodes * st_gnn->spatial_gnn->output_dim * sizeof(float));
    }

    free(spatial_features);
    return true;
}

bool st_gnn_predict_sequence(
    SpatioTemporalGNN* st_gnn,
    const TemporalEventSequence* sequence,
    float* out_anomaly_score
) {
    if (!st_gnn || !sequence || !out_anomaly_score || sequence->length == 0) {
        return false;
    }

    /* Apply temporal attention to sequence features */
    float* attended_features = calloc(sequence->length * 64, sizeof(float));
    if (!attended_features) return false;

    bool success = temporal_attention_forward(
        st_gnn->temporal_attention_layers[0],
        (float*)sequence->features,
        sequence->length,
        attended_features,
        NULL
    );

    if (!success) {
        free(attended_features);
        return false;
    }

    /* Compute anomaly score as deviation from mean */
    float mean_magnitude = 0;
    for (size_t i = 0; i < sequence->length; i++) {
        float mag = 0;
        for (size_t j = 0; j < 64; j++) {
            float val = attended_features[i * 64 + j];
            mag += val * val;
        }
        mean_magnitude += sqrtf(mag);
    }
    mean_magnitude /= sequence->length;

    *out_anomaly_score = fminf(mean_magnitude / 10.0f, 1.0f);

    free(attended_features);
    return *out_anomaly_score > 0.5f;
}
