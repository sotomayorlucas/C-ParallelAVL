/**
 * Temporal GNN - Spatio-Temporal Graph Neural Networks
 *
 * Extends GNN/GAT with temporal modeling for APT detection.
 * Critical for capturing multi-stage attacks that unfold over days/weeks.
 *
 * Key techniques:
 *   - Temporal Position Encoding (sinusoidal)
 *   - Temporal Self-Attention (captures sequential dependencies)
 *   - Temporal Convolutions (local temporal patterns)
 *   - Time-aware Message Passing (decay older information)
 *   - Temporal Aggregation (multi-timescale pooling)
 */

#ifndef FLOWSHIELD_TEMPORAL_GNN_H
#define FLOWSHIELD_TEMPORAL_GNN_H

#include "gnn_gat.h"
#include "provenance_graph.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Configuration
 * ============================================================================ */

#define TEMPORAL_ENCODING_DIM   64      /* Temporal encoding dimension */
#define TEMPORAL_MAX_SEQ_LEN    1024    /* Max sequence length */
#define TEMPORAL_NUM_HEADS      4       /* Temporal attention heads */
#define TEMPORAL_KERNEL_SIZE    5       /* Temporal convolution kernel */
#define TEMPORAL_NUM_SCALES     3       /* Multi-scale aggregation levels */

/* ============================================================================
 * Temporal Position Encoding
 * ============================================================================ */

/**
 * Sinusoidal position encoding for temporal information.
 * PE(t, 2i) = sin(t / 10000^(2i/d))
 * PE(t, 2i+1) = cos(t / 10000^(2i/d))
 *
 * This allows the model to learn relative temporal positions.
 */
typedef struct {
    float* encodings;                   /* Pre-computed encodings [max_timesteps x dim] */
    size_t max_timesteps;               /* Maximum timesteps cached */
    size_t encoding_dim;                /* Encoding dimension */

    /* For dynamic timestamps (not pre-cached) */
    uint64_t time_scale_ns;             /* Nanosecond scale factor */
    float base_period;                  /* Base period for sinusoid */
} TemporalPositionEncoding;

/**
 * Create temporal position encoding.
 *
 * @param max_timesteps     Maximum timesteps to pre-compute
 * @param encoding_dim      Dimension of encoding
 * @param time_scale_ns     Time scale in nanoseconds (e.g., 1e9 for 1 second)
 * @return                  Encoding handle
 */
TemporalPositionEncoding* temporal_encoding_create(
    size_t max_timesteps,
    size_t encoding_dim,
    uint64_t time_scale_ns
);

void temporal_encoding_destroy(TemporalPositionEncoding* encoding);

/**
 * Get temporal encoding for a specific timestamp.
 *
 * @param encoding          Temporal encoding
 * @param timestamp_ns      Timestamp in nanoseconds
 * @param out_encoding      Output encoding vector [encoding_dim]
 */
void temporal_encoding_get(
    const TemporalPositionEncoding* encoding,
    uint64_t timestamp_ns,
    float* out_encoding
);

/**
 * Add temporal encoding to node features.
 *
 * @param encoding          Temporal encoding
 * @param features          Node features [num_nodes x feature_dim]
 * @param timestamps        Node timestamps [num_nodes]
 * @param num_nodes         Number of nodes
 * @param feature_dim       Feature dimension
 * @param out_features      Output features with temporal encoding added
 */
void temporal_encoding_add_to_features(
    const TemporalPositionEncoding* encoding,
    const float* features,
    const uint64_t* timestamps,
    size_t num_nodes,
    size_t feature_dim,
    float* out_features
);

/* ============================================================================
 * Temporal Attention Layer
 * ============================================================================ */

/**
 * Multi-head temporal self-attention.
 * Captures dependencies between events in temporal sequence.
 *
 * For a sequence of events [e_1, e_2, ..., e_T]:
 *   Attention(Q, K, V) = softmax(QK^T / sqrt(d_k)) V
 * where Q, K, V are query, key, value projections.
 */
typedef struct {
    /* Attention parameters */
    float* W_q;                         /* Query projection [dim x dim] */
    float* W_k;                         /* Key projection [dim x dim] */
    float* W_v;                         /* Value projection [dim x dim] */
    float* W_o;                         /* Output projection [dim x dim] */

    /* Multi-head parameters */
    size_t num_heads;
    size_t dim_per_head;
    size_t total_dim;

    /* Bias terms */
    float* bias_q;
    float* bias_k;
    float* bias_v;
    float* bias_o;

    /* Dropout for regularization */
    float dropout_rate;

    /* Causal masking (for autoregressive models) */
    bool use_causal_mask;
} TemporalAttentionLayer;

/**
 * Create temporal attention layer.
 */
TemporalAttentionLayer* temporal_attention_create(
    size_t num_heads,
    size_t total_dim,
    bool use_causal_mask
);

void temporal_attention_destroy(TemporalAttentionLayer* layer);

/**
 * Forward pass through temporal attention.
 *
 * @param layer             Temporal attention layer
 * @param sequence          Input sequence [seq_len x dim]
 * @param seq_len           Sequence length
 * @param out_sequence      Output sequence [seq_len x dim]
 * @param out_attention     Attention weights (optional) [seq_len x seq_len]
 * @return                  true on success
 */
bool temporal_attention_forward(
    TemporalAttentionLayer* layer,
    const float* sequence,
    size_t seq_len,
    float* out_sequence,
    float* out_attention
);

/* ============================================================================
 * Temporal Convolution Layer
 * ============================================================================ */

/**
 * 1D temporal convolution for local pattern detection.
 * Useful for detecting periodic behaviors (e.g., C2 beaconing).
 */
typedef struct {
    float* kernel;                      /* Convolution kernel [kernel_size x in_channels x out_channels] */
    float* bias;                        /* Bias [out_channels] */

    size_t kernel_size;
    size_t in_channels;
    size_t out_channels;
    size_t stride;
    size_t padding;

    /* Activation */
    enum {
        TEMPORAL_ACT_RELU,
        TEMPORAL_ACT_TANH,
        TEMPORAL_ACT_NONE
    } activation;
} TemporalConvLayer;

/**
 * Create temporal convolution layer.
 */
TemporalConvLayer* temporal_conv_create(
    size_t kernel_size,
    size_t in_channels,
    size_t out_channels,
    size_t stride
);

void temporal_conv_destroy(TemporalConvLayer* layer);

/**
 * Forward pass through temporal convolution.
 *
 * @param layer             Convolution layer
 * @param input             Input sequence [seq_len x in_channels]
 * @param seq_len           Sequence length
 * @param output            Output sequence [out_seq_len x out_channels]
 * @param out_seq_len       Output sequence length (computed)
 * @return                  true on success
 */
bool temporal_conv_forward(
    TemporalConvLayer* layer,
    const float* input,
    size_t seq_len,
    float* output,
    size_t* out_seq_len
);

/* ============================================================================
 * Time-Aware Message Passing
 * ============================================================================ */

/**
 * Time-aware edge weights for message passing.
 * Recent events have higher influence than older events.
 *
 * w(t) = exp(-λ * Δt)
 * where Δt is time difference, λ is decay rate.
 */
typedef struct {
    float decay_rate;                   /* Decay rate λ (per second) */
    float min_weight;                   /* Minimum weight threshold */
    uint64_t current_time_ns;           /* Current reference time */
} TimeAwareWeighting;

/**
 * Compute time-aware edge weight.
 *
 * @param weighting         Time-aware weighting
 * @param edge_timestamp_ns Edge timestamp
 * @return                  Weight in [0, 1]
 */
float time_aware_weight(
    const TimeAwareWeighting* weighting,
    uint64_t edge_timestamp_ns
);

/**
 * Apply time-aware weighting to edges in graph.
 *
 * @param graph             Provenance graph
 * @param weighting         Time-aware weighting
 * @param out_weights       Output weights [num_edges]
 */
void time_aware_compute_edge_weights(
    const ProvenanceGraph* graph,
    const TimeAwareWeighting* weighting,
    float* out_weights
);

/* ============================================================================
 * Temporal Event Sequence
 * ============================================================================ */

/**
 * Sequence of events for temporal modeling.
 * Used to model chains of syscalls/operations.
 */
typedef struct {
    uint64_t node_ids[TEMPORAL_MAX_SEQ_LEN];       /* Node sequence */
    uint64_t edge_ids[TEMPORAL_MAX_SEQ_LEN];       /* Edge sequence */
    uint64_t timestamps[TEMPORAL_MAX_SEQ_LEN];     /* Timestamps (ns) */
    float features[TEMPORAL_MAX_SEQ_LEN][64];      /* Event features */

    size_t length;                                  /* Sequence length */

    /* Sequence metadata */
    uint64_t start_time_ns;
    uint64_t end_time_ns;
    float duration_sec;

    /* Sequence classification */
    bool is_anomalous;
    float anomaly_score;
} TemporalEventSequence;

/**
 * Extract temporal event sequence from provenance graph.
 *
 * @param graph             Provenance graph
 * @param start_node_id     Starting node
 * @param max_length        Maximum sequence length
 * @param out_sequence      Output sequence
 * @return                  true on success
 */
bool temporal_extract_sequence(
    const ProvenanceGraph* graph,
    uint64_t start_node_id,
    size_t max_length,
    TemporalEventSequence* out_sequence
);

/**
 * Extract all temporal sequences (sliding window).
 *
 * @param graph             Provenance graph
 * @param window_size       Window size in events
 * @param stride            Stride for sliding window
 * @param out_sequences     Output sequences
 * @param max_sequences     Maximum sequences to extract
 * @param out_count         Number of sequences extracted
 */
void temporal_extract_sequences_sliding(
    const ProvenanceGraph* graph,
    size_t window_size,
    size_t stride,
    TemporalEventSequence* out_sequences,
    size_t max_sequences,
    size_t* out_count
);

/* ============================================================================
 * Temporal Aggregation (Multi-scale)
 * ============================================================================ */

/**
 * Multi-scale temporal aggregation.
 * Captures patterns at different timescales (seconds, minutes, hours).
 */
typedef struct {
    /* Aggregation windows */
    uint64_t window_sizes_ns[TEMPORAL_NUM_SCALES];  /* [short, medium, long] */

    /* Aggregated features per scale */
    float aggregated_features[TEMPORAL_NUM_SCALES][64];

    /* Statistics per scale */
    struct {
        size_t num_events;
        float avg_rate;                             /* Events per second */
        float burstiness;                           /* Burstiness metric */
    } stats[TEMPORAL_NUM_SCALES];
} TemporalMultiScaleAggregation;

/**
 * Create multi-scale temporal aggregation.
 *
 * @param short_window_sec  Short timescale (e.g., 60 seconds)
 * @param medium_window_sec Medium timescale (e.g., 600 seconds)
 * @param long_window_sec   Long timescale (e.g., 3600 seconds)
 * @return                  Aggregation handle
 */
TemporalMultiScaleAggregation* temporal_multiscale_create(
    uint64_t short_window_sec,
    uint64_t medium_window_sec,
    uint64_t long_window_sec
);

void temporal_multiscale_destroy(TemporalMultiScaleAggregation* agg);

/**
 * Aggregate temporal events at multiple scales.
 *
 * @param agg               Multi-scale aggregation
 * @param sequences         Event sequences
 * @param num_sequences     Number of sequences
 * @param current_time_ns   Current time
 */
void temporal_multiscale_aggregate(
    TemporalMultiScaleAggregation* agg,
    const TemporalEventSequence* sequences,
    size_t num_sequences,
    uint64_t current_time_ns
);

/* ============================================================================
 * Spatio-Temporal GNN Model
 * ============================================================================ */

/**
 * Complete Spatio-Temporal GNN combining spatial and temporal modeling.
 */
typedef struct {
    /* Base GNN model (spatial) */
    GNNModel* spatial_gnn;

    /* Temporal components */
    TemporalPositionEncoding* temporal_encoding;
    TemporalAttentionLayer* temporal_attention_layers[GAT_NUM_LAYERS];
    TemporalConvLayer* temporal_conv_layers[GAT_NUM_LAYERS];
    size_t num_temporal_layers;

    /* Time-aware message passing */
    TimeAwareWeighting time_weighting;

    /* Multi-scale aggregation */
    TemporalMultiScaleAggregation* multiscale_agg;

    /* Fusion layer (spatial + temporal) */
    float* fusion_W;                    /* Fusion weights [spatial_dim + temporal_dim x output_dim] */
    float* fusion_b;                    /* Fusion bias */
    size_t fusion_output_dim;

    /* Configuration */
    struct {
        bool use_temporal_encoding;
        bool use_temporal_attention;
        bool use_temporal_conv;
        bool use_time_decay;
        bool use_multiscale;
    } config;
} SpatioTemporalGNN;

/**
 * Create spatio-temporal GNN.
 *
 * @param spatial_gnn       Base spatial GNN model
 * @param encoding_dim      Temporal encoding dimension
 * @return                  Spatio-temporal GNN handle
 */
SpatioTemporalGNN* st_gnn_create(
    GNNModel* spatial_gnn,
    size_t encoding_dim
);

void st_gnn_destroy(SpatioTemporalGNN* st_gnn);

/**
 * Forward pass through spatio-temporal GNN.
 *
 * @param st_gnn            Spatio-temporal GNN
 * @param graph             Provenance graph
 * @param timestamps        Node timestamps [num_nodes]
 * @param out_embeddings    Output embeddings [num_nodes x output_dim]
 * @return                  true on success
 */
bool st_gnn_forward(
    SpatioTemporalGNN* st_gnn,
    ProvenanceGraph* graph,
    const uint64_t* timestamps,
    float* out_embeddings
);

/**
 * Predict on temporal event sequence.
 *
 * @param st_gnn            Spatio-temporal GNN
 * @param sequence          Event sequence
 * @param out_anomaly_score Output anomaly score
 * @return                  true if sequence is anomalous
 */
bool st_gnn_predict_sequence(
    SpatioTemporalGNN* st_gnn,
    const TemporalEventSequence* sequence,
    float* out_anomaly_score
);

/**
 * Detect temporal patterns indicative of APT phases.
 *
 * @param st_gnn            Spatio-temporal GNN
 * @param graph             Provenance graph
 * @param sequences         Event sequences
 * @param num_sequences     Number of sequences
 * @param out_phases        Detected APT phases per sequence
 * @param out_scores        Confidence scores
 * @return                  Number of sequences classified
 */
size_t st_gnn_detect_apt_phases(
    SpatioTemporalGNN* st_gnn,
    ProvenanceGraph* graph,
    const TemporalEventSequence* sequences,
    size_t num_sequences,
    APTPhase* out_phases,
    float* out_scores
);

/* ============================================================================
 * Temporal Pattern Detection
 * ============================================================================ */

/**
 * Detect periodic behavior (e.g., C2 beaconing).
 *
 * @param sequence          Event sequence
 * @param out_period_sec    Detected period in seconds
 * @param out_confidence    Detection confidence
 * @return                  true if periodic pattern detected
 */
bool temporal_detect_periodicity(
    const TemporalEventSequence* sequence,
    float* out_period_sec,
    float* out_confidence
);

/**
 * Detect burst behavior (sudden spike in activity).
 *
 * @param sequence          Event sequence
 * @param out_burst_score   Burstiness score
 * @return                  true if burst detected
 */
bool temporal_detect_burst(
    const TemporalEventSequence* sequence,
    float* out_burst_score
);

/**
 * Detect slow exfiltration (gradual data transfer over time).
 *
 * @param sequence          Event sequence
 * @param out_rate_bps      Data rate in bytes per second
 * @param out_duration_sec  Duration of exfiltration
 * @return                  true if slow exfiltration detected
 */
bool temporal_detect_slow_exfiltration(
    const TemporalEventSequence* sequence,
    float* out_rate_bps,
    float* out_duration_sec
);

/* ============================================================================
 * Utilities
 * ============================================================================ */

/**
 * Compute inter-event time statistics.
 */
void temporal_compute_iet_stats(
    const TemporalEventSequence* sequence,
    float* out_mean_ms,
    float* out_std_ms,
    float* out_cv  /* Coefficient of variation */
);

/**
 * Print temporal sequence.
 */
void temporal_print_sequence(const TemporalEventSequence* sequence);

#ifdef __cplusplus
}
#endif

#endif /* FLOWSHIELD_TEMPORAL_GNN_H */
