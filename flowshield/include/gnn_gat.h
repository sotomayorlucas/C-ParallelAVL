/**
 * GNN with Graph Attention Networks (GAT) for APT Detection
 *
 * Implements:
 *   - Multi-head GAT layers with attention mechanism
 *   - Spatio-temporal graph convolutions
 *   - Graph pooling and aggregation
 *   - Scalable sparse operations for million-node graphs
 *
 * Key insight: GAT learns which neighbors are important (e.g., process
 * connecting to external IP is more suspicious than reading config file)
 */

#ifndef FLOWSHIELD_GNN_GAT_H
#define FLOWSHIELD_GNN_GAT_H

#include "provenance_graph.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Configuration
 * ============================================================================ */

#define GAT_NUM_HEADS           8       /* Multi-head attention */
#define GAT_HIDDEN_DIM          128     /* Hidden layer dimension */
#define GAT_OUTPUT_DIM          64      /* Output embedding dimension */
#define GAT_NUM_LAYERS          3       /* Number of GAT layers */
#define GAT_DROPOUT_RATE        0.1f    /* Dropout for regularization */
#define GAT_ALPHA               0.2f    /* LeakyReLU alpha */
#define GAT_TEMPORAL_HEADS      4       /* Temporal attention heads */

/* ============================================================================
 * Attention Mechanism
 * ============================================================================ */

/**
 * Multi-head attention for GAT layer.
 * Computes attention coefficients: α_ij = softmax(LeakyReLU(a^T [Wh_i || Wh_j]))
 */
typedef struct {
    /* Learnable parameters */
    float* W;                           /* Weight matrix [in_dim x out_dim] */
    float* a_src;                       /* Attention weights (source) [out_dim] */
    float* a_dst;                       /* Attention weights (destination) [out_dim] */
    float* bias;                        /* Bias term [out_dim] */

    /* Dimensions */
    size_t in_dim;
    size_t out_dim;

    /* Hyperparameters */
    float alpha;                        /* LeakyReLU slope */
    float dropout_rate;
} AttentionHead;

/**
 * Multi-head attention aggregates multiple attention heads.
 */
typedef struct {
    AttentionHead* heads[GAT_NUM_HEADS];
    size_t num_heads;
    size_t in_dim;
    size_t out_dim_per_head;

    /* Aggregation: concat or average */
    enum {
        AGG_CONCAT,                     /* Concatenate heads */
        AGG_AVERAGE                     /* Average heads */
    } aggregation;
} MultiHeadAttention;

/* ============================================================================
 * GAT Layer
 * ============================================================================ */

/**
 * Single GAT layer: h'_i = σ(Σ_{j∈N(i)} α_ij W h_j)
 */
typedef struct {
    MultiHeadAttention* attention;      /* Multi-head attention */

    /* Layer normalization */
    float* norm_gamma;                  /* Scale [out_dim] */
    float* norm_beta;                   /* Shift [out_dim] */

    /* Skip connection */
    float* skip_W;                      /* Transform for residual [in_dim x out_dim] */

    /* Dimensions */
    size_t in_dim;
    size_t out_dim;

    /* Activation */
    enum {
        ACT_RELU,
        ACT_ELU,
        ACT_LEAKY_RELU,
        ACT_TANH
    } activation;
} GATLayer;

/* ============================================================================
 * Temporal Encoding
 * ============================================================================ */

/**
 * Temporal position encoding for sequence of events.
 * Uses sinusoidal encoding: PE(t, 2i) = sin(t / 10000^(2i/d))
 */
typedef struct {
    float* encoding;                    /* Pre-computed encodings */
    size_t max_timesteps;
    size_t encoding_dim;
} TemporalEncoding;

/**
 * Temporal attention layer for spatio-temporal GNN.
 * Captures temporal dependencies between events.
 */
typedef struct {
    /* Temporal self-attention */
    float* W_q;                         /* Query weights */
    float* W_k;                         /* Key weights */
    float* W_v;                         /* Value weights */
    float* W_o;                         /* Output projection */

    size_t num_heads;
    size_t dim;

    /* Temporal encoding */
    TemporalEncoding* encoding;
} TemporalAttentionLayer;

/* ============================================================================
 * Complete GNN Model
 * ============================================================================ */

/**
 * Full GNN model with multiple GAT layers and temporal encoding.
 */
typedef struct {
    /* GAT layers (spatial) */
    GATLayer* gat_layers[GAT_NUM_LAYERS];
    size_t num_gat_layers;

    /* Temporal layers */
    TemporalAttentionLayer* temporal_layers[GAT_NUM_LAYERS];
    size_t num_temporal_layers;

    /* Input/output dimensions */
    size_t input_dim;
    size_t hidden_dim;
    size_t output_dim;

    /* Graph pooling for graph-level prediction */
    enum {
        POOL_MEAN,                      /* Average pooling */
        POOL_MAX,                       /* Max pooling */
        POOL_ATTENTION,                 /* Attention-based pooling */
        POOL_SET2SET                    /* Set2Set aggregation */
    } pooling_type;

    /* Readout layer (graph-level classification) */
    float* readout_W;                   /* [output_dim x num_classes] */
    float* readout_b;                   /* [num_classes] */
    size_t num_classes;

    /* Training state */
    bool is_training;
    float learning_rate;
    float weight_decay;

    /* Statistics */
    struct {
        uint64_t forward_passes;
        double avg_attention_entropy;   /* Measure of attention diversity */
        double avg_inference_time_ms;
    } stats;
} GNNModel;

/* ============================================================================
 * Sparse Graph Operations (for scalability)
 * ============================================================================ */

/**
 * Sparse adjacency matrix in COO (Coordinate) format.
 * More memory-efficient for large graphs.
 */
typedef struct {
    uint64_t* src_indices;              /* Source node indices */
    uint64_t* dst_indices;              /* Destination node indices */
    float* values;                      /* Edge weights/attention scores */
    size_t num_edges;
    size_t num_nodes;
} SparseAdjacency;

/**
 * Sparse matrix-vector multiplication for GNN message passing.
 * out = A @ features (where A is adjacency, features are node embeddings)
 */
void sparse_matmul(
    const SparseAdjacency* adj,
    const float* features,
    size_t feature_dim,
    float* out_features
);

/**
 * Sparse attention-weighted aggregation.
 * out_i = Σ_{j∈N(i)} α_ij * h_j
 */
void sparse_attention_aggregate(
    const SparseAdjacency* adj,
    const float* node_features,
    const float* attention_scores,
    size_t feature_dim,
    float* out_features
);

/* ============================================================================
 * API - Model Lifecycle
 * ============================================================================ */

/* Create/destroy */
GNNModel* gnn_create(size_t input_dim, size_t hidden_dim, size_t output_dim,
                     size_t num_layers, size_t num_classes);
void gnn_destroy(GNNModel* model);

/* Load/save weights */
bool gnn_load_weights(GNNModel* model, const char* weights_file);
bool gnn_save_weights(const GNNModel* model, const char* weights_file);

/* Initialize with pretrained weights or random */
void gnn_init_weights_random(GNNModel* model, uint64_t seed);
void gnn_init_weights_xavier(GNNModel* model);

/* ============================================================================
 * API - Inference
 * ============================================================================ */

/**
 * Forward pass: compute node embeddings.
 *
 * @param model         GNN model
 * @param graph         Provenance graph
 * @param out_embeddings Output embeddings [num_nodes x output_dim]
 * @return              true on success
 */
bool gnn_forward(
    GNNModel* model,
    ProvenanceGraph* graph,
    float* out_embeddings
);

/**
 * Forward pass with temporal encoding.
 *
 * @param model         GNN model
 * @param graph         Provenance graph
 * @param timestamps    Node timestamps [num_nodes]
 * @param out_embeddings Output embeddings [num_nodes x output_dim]
 * @return              true on success
 */
bool gnn_forward_temporal(
    GNNModel* model,
    ProvenanceGraph* graph,
    const uint64_t* timestamps,
    float* out_embeddings
);

/**
 * Graph-level prediction (for entire provenance graph).
 *
 * @param model         GNN model
 * @param graph         Provenance graph
 * @param out_probs     Output class probabilities [num_classes]
 * @return              Predicted class
 */
int gnn_predict_graph(
    GNNModel* model,
    ProvenanceGraph* graph,
    float* out_probs
);

/**
 * Node-level prediction (anomaly score per node).
 *
 * @param model         GNN model
 * @param graph         Provenance graph
 * @param out_scores    Output anomaly scores [num_nodes]
 * @return              Number of nodes scored
 */
size_t gnn_predict_nodes(
    GNNModel* model,
    ProvenanceGraph* graph,
    float* out_scores
);

/* ============================================================================
 * API - Attention Mechanism
 * ============================================================================ */

/**
 * Compute attention coefficients between node pairs.
 *
 * @param head          Attention head
 * @param src_features  Source node features [in_dim]
 * @param dst_features  Destination node features [in_dim]
 * @return              Attention coefficient α_ij ∈ [0, 1]
 */
float gat_compute_attention(
    const AttentionHead* head,
    const float* src_features,
    const float* dst_features
);

/**
 * Apply GAT layer to all nodes in graph.
 *
 * @param layer         GAT layer
 * @param graph         Provenance graph
 * @param in_features   Input features [num_nodes x in_dim]
 * @param out_features  Output features [num_nodes x out_dim]
 * @param out_attention Output attention scores (optional)
 * @return              true on success
 */
bool gat_layer_forward(
    GATLayer* layer,
    ProvenanceGraph* graph,
    const float* in_features,
    float* out_features,
    float* out_attention
);

/* ============================================================================
 * API - Training (Online Learning)
 * ============================================================================ */

/**
 * Update model weights with new labeled sample.
 *
 * @param model         GNN model
 * @param graph         Provenance graph
 * @param label         Ground truth (0 = benign, 1 = APT)
 * @param learning_rate Learning rate
 */
void gnn_update_online(
    GNNModel* model,
    ProvenanceGraph* graph,
    int label,
    float learning_rate
);

/**
 * Compute loss (for training).
 *
 * @param predictions   Model predictions [batch_size x num_classes]
 * @param labels        Ground truth labels [batch_size]
 * @param batch_size    Batch size
 * @return              Cross-entropy loss
 */
float gnn_compute_loss(
    const float* predictions,
    const int* labels,
    size_t batch_size,
    size_t num_classes
);

/* ============================================================================
 * API - Causal Inference (SCM)
 * ============================================================================ */

/**
 * Compute causal weights for edges using structural causal models.
 * Distinguishes correlation from causation.
 *
 * @param graph         Provenance graph
 * @param model         GNN model (for embeddings)
 * @param out_causal_weights Output causal weights [num_edges]
 */
void gnn_compute_causal_weights(
    ProvenanceGraph* graph,
    GNNModel* model,
    float* out_causal_weights
);

/**
 * Detect causal chains (multi-hop paths) that indicate APT behavior.
 *
 * @param graph         Provenance graph
 * @param model         GNN model
 * @param out_chains    Output causal chains
 * @param max_chains    Maximum chains to return
 * @param out_count     Number of chains found
 */
void gnn_detect_causal_chains(
    ProvenanceGraph* graph,
    GNNModel* model,
    CausalChain* out_chains,
    size_t max_chains,
    size_t* out_count
);

/* ============================================================================
 * API - Utility
 * ============================================================================ */

/**
 * Compute attention entropy (measure of diversity).
 * Low entropy = model focuses on few neighbors (good for interpretability)
 * High entropy = model spreads attention (may indicate uncertainty)
 */
double gnn_compute_attention_entropy(const float* attention_scores, size_t n);

/**
 * Print model statistics.
 */
void gnn_print_stats(const GNNModel* model);

/**
 * Export attention visualization.
 */
void gnn_export_attention_viz(
    const GNNModel* model,
    const ProvenanceGraph* graph,
    const char* output_file
);

#ifdef __cplusplus
}
#endif

#endif /* FLOWSHIELD_GNN_GAT_H */
