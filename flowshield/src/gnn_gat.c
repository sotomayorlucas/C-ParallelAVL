/**
 * GNN/GAT Implementation - Graph Attention Networks
 *
 * Core implementation of Graph Attention mechanism for APT detection.
 */

#define _GNU_SOURCE
#include "../include/gnn_gat.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <time.h>

/* ============================================================================
 * Activation Functions
 * ============================================================================ */

static inline float relu(float x) {
    return x > 0 ? x : 0;
}

static inline float leaky_relu(float x, float alpha) {
    return x > 0 ? x : alpha * x;
}

static inline float elu(float x, float alpha) {
    return x > 0 ? x : alpha * (expf(x) - 1.0f);
}

static inline float sigmoid(float x) {
    return 1.0f / (1.0f + expf(-x));
}

static void softmax(float* x, size_t n) {
    if (!x || n == 0) return;

    float max_val = x[0];
    for (size_t i = 1; i < n; i++) {
        if (x[i] > max_val) max_val = x[i];
    }

    float sum = 0;
    for (size_t i = 0; i < n; i++) {
        x[i] = expf(x[i] - max_val);
        sum += x[i];
    }

    for (size_t i = 0; i < n; i++) {
        x[i] /= (sum + 1e-10f);
    }
}

/* ============================================================================
 * Matrix Operations
 * ============================================================================ */

/**
 * Matrix-vector multiplication: out = W @ in
 */
static void matmul(const float* W, const float* in, float* out,
                   size_t in_dim, size_t out_dim) {
    for (size_t i = 0; i < out_dim; i++) {
        out[i] = 0;
        for (size_t j = 0; j < in_dim; j++) {
            out[i] += W[i * in_dim + j] * in[j];
        }
    }
}

/**
 * Vector addition: out = a + b
 */
static void vec_add(const float* a, const float* b, float* out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        out[i] = a[i] + b[i];
    }
}

/**
 * Vector dot product: a · b
 */
static float vec_dot(const float* a, const float* b, size_t n) {
    float sum = 0;
    for (size_t i = 0; i < n; i++) {
        sum += a[i] * b[i];
    }
    return sum;
}

/**
 * Xavier initialization for weights
 */
static void init_xavier(float* W, size_t rows, size_t cols, uint64_t seed) {
    srand(seed);
    float scale = sqrtf(6.0f / (rows + cols));

    for (size_t i = 0; i < rows * cols; i++) {
        W[i] = ((float)rand() / RAND_MAX - 0.5f) * 2.0f * scale;
    }
}

/* ============================================================================
 * Sparse Operations
 * ============================================================================ */

void sparse_matmul(
    const SparseAdjacency* adj,
    const float* features,
    size_t feature_dim,
    float* out_features
) {
    if (!adj || !features || !out_features) return;

    /* Initialize output to zero */
    memset(out_features, 0, adj->num_nodes * feature_dim * sizeof(float));

    /* Sparse matrix-vector multiplication */
    for (size_t e = 0; e < adj->num_edges; e++) {
        uint64_t src = adj->src_indices[e];
        uint64_t dst = adj->dst_indices[e];
        float weight = adj->values[e];

        /* Accumulate: out[dst] += weight * features[src] */
        for (size_t f = 0; f < feature_dim; f++) {
            out_features[dst * feature_dim + f] +=
                weight * features[src * feature_dim + f];
        }
    }
}

void sparse_attention_aggregate(
    const SparseAdjacency* adj,
    const float* node_features,
    const float* attention_scores,
    size_t feature_dim,
    float* out_features
) {
    if (!adj || !node_features || !attention_scores || !out_features) return;

    /* Initialize output */
    memset(out_features, 0, adj->num_nodes * feature_dim * sizeof(float));

    /* Attention-weighted aggregation */
    for (size_t e = 0; e < adj->num_edges; e++) {
        uint64_t src = adj->src_indices[e];
        uint64_t dst = adj->dst_indices[e];
        float alpha = attention_scores[e];

        /* out[dst] += alpha * features[src] */
        for (size_t f = 0; f < feature_dim; f++) {
            out_features[dst * feature_dim + f] +=
                alpha * node_features[src * feature_dim + f];
        }
    }
}

/* ============================================================================
 * Attention Head
 * ============================================================================ */

static AttentionHead* attention_head_create(size_t in_dim, size_t out_dim, float alpha) {
    AttentionHead* head = calloc(1, sizeof(AttentionHead));
    if (!head) return NULL;

    head->in_dim = in_dim;
    head->out_dim = out_dim;
    head->alpha = alpha;
    head->dropout_rate = GAT_DROPOUT_RATE;

    /* Allocate weight matrices */
    head->W = calloc(in_dim * out_dim, sizeof(float));
    head->a_src = calloc(out_dim, sizeof(float));
    head->a_dst = calloc(out_dim, sizeof(float));
    head->bias = calloc(out_dim, sizeof(float));

    if (!head->W || !head->a_src || !head->a_dst || !head->bias) {
        free(head->W);
        free(head->a_src);
        free(head->a_dst);
        free(head->bias);
        free(head);
        return NULL;
    }

    /* Initialize weights */
    init_xavier(head->W, out_dim, in_dim, time(NULL));
    init_xavier(head->a_src, 1, out_dim, time(NULL) + 1);
    init_xavier(head->a_dst, 1, out_dim, time(NULL) + 2);

    return head;
}

static void attention_head_destroy(AttentionHead* head) {
    if (!head) return;
    free(head->W);
    free(head->a_src);
    free(head->a_dst);
    free(head->bias);
    free(head);
}

/* ============================================================================
 * GAT Attention Computation
 * ============================================================================ */

float gat_compute_attention(
    const AttentionHead* head,
    const float* src_features,
    const float* dst_features
) {
    if (!head || !src_features || !dst_features) return 0;

    /* Transform features: Wh_i, Wh_j */
    float* Wh_src = alloca(head->out_dim * sizeof(float));
    float* Wh_dst = alloca(head->out_dim * sizeof(float));

    matmul(head->W, src_features, Wh_src, head->in_dim, head->out_dim);
    matmul(head->W, dst_features, Wh_dst, head->in_dim, head->out_dim);

    /* Compute attention coefficient: e_ij = a^T [Wh_i || Wh_j] */
    float e_ij = vec_dot(head->a_src, Wh_src, head->out_dim) +
                 vec_dot(head->a_dst, Wh_dst, head->out_dim);

    /* Apply LeakyReLU */
    e_ij = leaky_relu(e_ij, head->alpha);

    return e_ij;
}

/* ============================================================================
 * Multi-Head Attention
 * ============================================================================ */

static MultiHeadAttention* multi_head_create(size_t num_heads, size_t in_dim,
                                              size_t out_dim_per_head) {
    MultiHeadAttention* mha = calloc(1, sizeof(MultiHeadAttention));
    if (!mha) return NULL;

    mha->num_heads = num_heads;
    mha->in_dim = in_dim;
    mha->out_dim_per_head = out_dim_per_head;
    mha->aggregation = AGG_CONCAT;

    for (size_t i = 0; i < num_heads; i++) {
        mha->heads[i] = attention_head_create(in_dim, out_dim_per_head, GAT_ALPHA);
        if (!mha->heads[i]) {
            for (size_t j = 0; j < i; j++) {
                attention_head_destroy(mha->heads[j]);
            }
            free(mha);
            return NULL;
        }
    }

    return mha;
}

static void multi_head_destroy(MultiHeadAttention* mha) {
    if (!mha) return;
    for (size_t i = 0; i < mha->num_heads; i++) {
        attention_head_destroy(mha->heads[i]);
    }
    free(mha);
}

/* ============================================================================
 * GAT Layer
 * ============================================================================ */

static GATLayer* gat_layer_create(size_t in_dim, size_t out_dim, size_t num_heads) {
    GATLayer* layer = calloc(1, sizeof(GATLayer));
    if (!layer) return NULL;

    layer->in_dim = in_dim;
    layer->out_dim = out_dim;
    layer->activation = ACT_ELU;

    /* Create multi-head attention */
    size_t out_per_head = out_dim / num_heads;
    layer->attention = multi_head_create(num_heads, in_dim, out_per_head);
    if (!layer->attention) {
        free(layer);
        return NULL;
    }

    /* Layer normalization parameters */
    layer->norm_gamma = calloc(out_dim, sizeof(float));
    layer->norm_beta = calloc(out_dim, sizeof(float));

    /* Initialize to identity normalization */
    for (size_t i = 0; i < out_dim; i++) {
        layer->norm_gamma[i] = 1.0f;
        layer->norm_beta[i] = 0.0f;
    }

    /* Skip connection weights */
    if (in_dim != out_dim) {
        layer->skip_W = calloc(in_dim * out_dim, sizeof(float));
        init_xavier(layer->skip_W, out_dim, in_dim, time(NULL) + 100);
    }

    return layer;
}

static void gat_layer_destroy(GATLayer* layer) {
    if (!layer) return;
    multi_head_destroy(layer->attention);
    free(layer->norm_gamma);
    free(layer->norm_beta);
    free(layer->skip_W);
    free(layer);
}

bool gat_layer_forward(
    GATLayer* layer,
    ProvenanceGraph* graph,
    const float* in_features,
    float* out_features,
    float* out_attention
) {
    if (!layer || !graph || !in_features || !out_features) return false;

    size_t num_nodes = graph->num_nodes;
    size_t in_dim = layer->in_dim;
    size_t out_dim = layer->out_dim;

    /* Temporary buffers */
    float* aggregated = calloc(num_nodes * out_dim, sizeof(float));
    if (!aggregated) return false;

    /* For each node, aggregate neighbor features with attention */
    for (size_t i = 0; i < num_nodes; i++) {
        ProvenanceNode* node = &graph->nodes[i];
        if (graph->node_ids[i] == UINT64_MAX) continue;

        const float* h_i = &in_features[i * in_dim];
        float* out_i = &aggregated[i * out_dim];

        /* Get neighbors */
        uint64_t neighbors[PG_MAX_NEIGHBORS];
        size_t num_neighbors;
        pg_get_neighbors(graph, node->id, neighbors, &num_neighbors);

        if (num_neighbors == 0) {
            /* No neighbors - just transform self */
            for (size_t h = 0; h < layer->attention->num_heads; h++) {
                AttentionHead* head = layer->attention->heads[h];
                float* transformed = alloca(head->out_dim * sizeof(float));
                matmul(head->W, h_i, transformed, head->in_dim, head->out_dim);

                /* Copy to output */
                size_t offset = h * head->out_dim;
                memcpy(&out_i[offset], transformed, head->out_dim * sizeof(float));
            }
            continue;
        }

        /* Compute attention scores for all neighbors */
        float* attention_scores = alloca(num_neighbors * sizeof(float));
        float* attention_logits = alloca(num_neighbors * sizeof(float));

        for (size_t h = 0; h < layer->attention->num_heads; h++) {
            AttentionHead* head = layer->attention->heads[h];

            /* Compute attention logits */
            for (size_t j = 0; j < num_neighbors; j++) {
                ProvenanceNode* neighbor = pg_get_node(graph, neighbors[j]);
                if (!neighbor) {
                    attention_logits[j] = -1e9f;
                    continue;
                }
                const float* h_j = &in_features[neighbors[j] * in_dim];
                attention_logits[j] = gat_compute_attention(head, h_i, h_j);
            }

            /* Softmax to get attention weights */
            memcpy(attention_scores, attention_logits, num_neighbors * sizeof(float));
            softmax(attention_scores, num_neighbors);

            /* Aggregate with attention weights */
            float* head_out = alloca(head->out_dim * sizeof(float));
            memset(head_out, 0, head->out_dim * sizeof(float));

            for (size_t j = 0; j < num_neighbors; j++) {
                const float* h_j = &in_features[neighbors[j] * in_dim];
                float alpha = attention_scores[j];

                /* Transform neighbor: Wh_j */
                float* Wh_j = alloca(head->out_dim * sizeof(float));
                matmul(head->W, h_j, Wh_j, head->in_dim, head->out_dim);

                /* Accumulate: head_out += alpha * Wh_j */
                for (size_t k = 0; k < head->out_dim; k++) {
                    head_out[k] += alpha * Wh_j[k];
                }
            }

            /* Add bias and activation */
            for (size_t k = 0; k < head->out_dim; k++) {
                head_out[k] += head->bias[k];
                head_out[k] = elu(head_out[k], 1.0f);
            }

            /* Concatenate heads */
            size_t offset = h * head->out_dim;
            memcpy(&out_i[offset], head_out, head->out_dim * sizeof(float));
        }

        /* Store attention scores if requested */
        if (out_attention && num_neighbors > 0) {
            out_attention[i] = attention_scores[0];  /* Store first neighbor's attention */
        }
    }

    /* Layer normalization */
    for (size_t i = 0; i < num_nodes; i++) {
        if (graph->node_ids[i] == UINT64_MAX) continue;

        float* out_i = &aggregated[i * out_dim];

        /* Compute mean and variance */
        float mean = 0, var = 0;
        for (size_t j = 0; j < out_dim; j++) {
            mean += out_i[j];
        }
        mean /= out_dim;

        for (size_t j = 0; j < out_dim; j++) {
            float diff = out_i[j] - mean;
            var += diff * diff;
        }
        var /= out_dim;

        /* Normalize: (x - mean) / sqrt(var + eps) * gamma + beta */
        float std = sqrtf(var + 1e-5f);
        for (size_t j = 0; j < out_dim; j++) {
            out_i[j] = ((out_i[j] - mean) / std) * layer->norm_gamma[j] + layer->norm_beta[j];
        }
    }

    /* Copy to output */
    memcpy(out_features, aggregated, num_nodes * out_dim * sizeof(float));

    free(aggregated);
    return true;
}

/* ============================================================================
 * GNN Model
 * ============================================================================ */

GNNModel* gnn_create(size_t input_dim, size_t hidden_dim, size_t output_dim,
                     size_t num_layers, size_t num_classes) {
    GNNModel* model = calloc(1, sizeof(GNNModel));
    if (!model) return NULL;

    model->input_dim = input_dim;
    model->hidden_dim = hidden_dim;
    model->output_dim = output_dim;
    model->num_gat_layers = num_layers;
    model->num_classes = num_classes;
    model->pooling_type = POOL_MEAN;
    model->learning_rate = 0.001f;

    /* Create GAT layers */
    for (size_t i = 0; i < num_layers; i++) {
        size_t in_dim = (i == 0) ? input_dim : hidden_dim;
        size_t out_dim = (i == num_layers - 1) ? output_dim : hidden_dim;

        model->gat_layers[i] = gat_layer_create(in_dim, out_dim, GAT_NUM_HEADS);
        if (!model->gat_layers[i]) {
            gnn_destroy(model);
            return NULL;
        }
    }

    /* Readout layer for graph-level classification */
    model->readout_W = calloc(output_dim * num_classes, sizeof(float));
    model->readout_b = calloc(num_classes, sizeof(float));
    init_xavier(model->readout_W, num_classes, output_dim, time(NULL) + 1000);

    printf("[GNN] Created model: %zu layers, input=%zu, hidden=%zu, output=%zu, classes=%zu\n",
           num_layers, input_dim, hidden_dim, output_dim, num_classes);

    return model;
}

void gnn_destroy(GNNModel* model) {
    if (!model) return;

    for (size_t i = 0; i < model->num_gat_layers; i++) {
        gat_layer_destroy(model->gat_layers[i]);
    }

    free(model->readout_W);
    free(model->readout_b);
    free(model);
}

bool gnn_forward(
    GNNModel* model,
    ProvenanceGraph* graph,
    float* out_embeddings
) {
    if (!model || !graph || !out_embeddings) return false;

    size_t num_nodes = graph->num_nodes;

    /* Extract initial node features */
    float* features = calloc(num_nodes * model->input_dim, sizeof(float));
    if (!features) return false;

    for (size_t i = 0; i < num_nodes; i++) {
        if (graph->node_ids[i] != UINT64_MAX) {
            ProvenanceNode* node = &graph->nodes[i];
            pg_extract_node_features(node, &features[i * model->input_dim]);
        }
    }

    /* Forward pass through GAT layers */
    float* current_features = features;
    float* next_features = calloc(num_nodes * model->hidden_dim, sizeof(float));

    for (size_t layer_idx = 0; layer_idx < model->num_gat_layers; layer_idx++) {
        GATLayer* layer = model->gat_layers[layer_idx];

        if (!gat_layer_forward(layer, graph, current_features, next_features, NULL)) {
            free(features);
            free(next_features);
            return false;
        }

        /* Swap buffers */
        if (layer_idx > 0) {
            free(current_features);
        }
        current_features = next_features;

        if (layer_idx < model->num_gat_layers - 1) {
            next_features = calloc(num_nodes * model->hidden_dim, sizeof(float));
        }
    }

    /* Copy final embeddings */
    memcpy(out_embeddings, current_features, num_nodes * model->output_dim * sizeof(float));

    /* Update node embeddings in graph */
    for (size_t i = 0; i < num_nodes; i++) {
        if (graph->node_ids[i] != UINT64_MAX) {
            ProvenanceNode* node = &graph->nodes[i];
            memcpy(node->embedding, &out_embeddings[i * model->output_dim],
                   fmin(model->output_dim, PG_NODE_FEATURE_DIM) * sizeof(float));
        }
    }

    free(features);
    free(current_features);

    model->stats.forward_passes++;
    return true;
}

int gnn_predict_graph(
    GNNModel* model,
    ProvenanceGraph* graph,
    float* out_probs
) {
    if (!model || !graph || !out_probs) return -1;

    size_t num_nodes = graph->num_nodes;

    /* Get node embeddings */
    float* embeddings = calloc(num_nodes * model->output_dim, sizeof(float));
    if (!embeddings) return -1;

    if (!gnn_forward(model, graph, embeddings)) {
        free(embeddings);
        return -1;
    }

    /* Graph pooling (mean pooling) */
    float* graph_embedding = calloc(model->output_dim, sizeof(float));
    size_t valid_nodes = 0;

    for (size_t i = 0; i < num_nodes; i++) {
        if (graph->node_ids[i] != UINT64_MAX) {
            for (size_t j = 0; j < model->output_dim; j++) {
                graph_embedding[j] += embeddings[i * model->output_dim + j];
            }
            valid_nodes++;
        }
    }

    for (size_t j = 0; j < model->output_dim; j++) {
        graph_embedding[j] /= (valid_nodes + 1);
    }

    /* Readout: logits = W @ graph_embedding + b */
    float* logits = calloc(model->num_classes, sizeof(float));
    matmul(model->readout_W, graph_embedding, logits, model->output_dim, model->num_classes);

    for (size_t i = 0; i < model->num_classes; i++) {
        logits[i] += model->readout_b[i];
    }

    /* Softmax to get probabilities */
    softmax(logits, model->num_classes);
    memcpy(out_probs, logits, model->num_classes * sizeof(float));

    /* Find predicted class */
    int predicted = 0;
    float max_prob = logits[0];
    for (size_t i = 1; i < model->num_classes; i++) {
        if (logits[i] > max_prob) {
            max_prob = logits[i];
            predicted = i;
        }
    }

    free(embeddings);
    free(graph_embedding);
    free(logits);

    return predicted;
}

size_t gnn_predict_nodes(
    GNNModel* model,
    ProvenanceGraph* graph,
    float* out_scores
) {
    if (!model || !graph || !out_scores) return 0;

    size_t num_nodes = graph->num_nodes;
    float* embeddings = calloc(num_nodes * model->output_dim, sizeof(float));
    if (!embeddings) return 0;

    if (!gnn_forward(model, graph, embeddings)) {
        free(embeddings);
        return 0;
    }

    /* Compute anomaly score as magnitude of embedding */
    size_t scored = 0;
    for (size_t i = 0; i < num_nodes; i++) {
        if (graph->node_ids[i] == UINT64_MAX) continue;

        float magnitude = 0;
        for (size_t j = 0; j < model->output_dim; j++) {
            float val = embeddings[i * model->output_dim + j];
            magnitude += val * val;
        }
        out_scores[i] = sqrtf(magnitude);

        /* Update node anomaly score */
        graph->nodes[i].anomaly_score = out_scores[i];
        scored++;
    }

    free(embeddings);
    return scored;
}

void gnn_print_stats(const GNNModel* model) {
    if (!model) return;

    printf("\n=== GNN Model Statistics ===\n");
    printf("Architecture: %zu layers\n", model->num_gat_layers);
    printf("Dimensions:   input=%zu, hidden=%zu, output=%zu\n",
           model->input_dim, model->hidden_dim, model->output_dim);
    printf("Forward passes: %lu\n", model->stats.forward_passes);
    printf("Avg inference:  %.2f ms\n", model->stats.avg_inference_time_ms);
    printf("============================\n\n");
}

void gnn_init_weights_xavier(GNNModel* model) {
    if (!model) return;

    /* Re-initialize all layer weights */
    for (size_t i = 0; i < model->num_gat_layers; i++) {
        GATLayer* layer = model->gat_layers[i];
        if (!layer || !layer->attention) continue;

        for (size_t h = 0; h < layer->attention->num_heads; h++) {
            AttentionHead* head = layer->attention->heads[h];
            if (!head) continue;

            init_xavier(head->W, head->out_dim, head->in_dim, time(NULL) + i * 100 + h);
            init_xavier(head->a_src, 1, head->out_dim, time(NULL) + i * 100 + h + 50);
            init_xavier(head->a_dst, 1, head->out_dim, time(NULL) + i * 100 + h + 51);
        }
    }

    init_xavier(model->readout_W, model->num_classes, model->output_dim, time(NULL) + 10000);
    printf("[GNN] Weights re-initialized with Xavier initialization\n");
}

double gnn_compute_attention_entropy(const float* attention_scores, size_t n) {
    if (!attention_scores || n == 0) return 0;

    double entropy = 0;
    for (size_t i = 0; i < n; i++) {
        float p = attention_scores[i];
        if (p > 1e-10f) {
            entropy -= p * log2f(p);
        }
    }
    return entropy;
}
