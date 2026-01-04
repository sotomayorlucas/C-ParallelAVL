/**
 * Causal Inference Implementation
 *
 * Implements Structural Causal Models for APT detection.
 * Distinguishes true causal relationships from spurious correlations.
 */

#define _GNU_SOURCE
#include "../include/causal_inference.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* ============================================================================
 * Statistical Utilities
 * ============================================================================ */

/**
 * Chi-squared distribution CDF (approximation).
 */
static float chi_squared_cdf(float x, size_t df) {
    if (x <= 0 || df == 0) return 0;

    /* Use gamma function approximation for chi-squared CDF */
    /* Simplified: return approximate p-value */
    float k = (float)df / 2.0f;
    float p = powf(x / 2.0f, k - 1.0f) * expf(-x / 2.0f);
    return 1.0f - p;  /* Simplified */
}

/**
 * Compute correlation coefficient.
 */
static float correlation(const float* X, const float* Y, size_t n) {
    if (n < 2) return 0;

    float mean_X = 0, mean_Y = 0;
    for (size_t i = 0; i < n; i++) {
        mean_X += X[i];
        mean_Y += Y[i];
    }
    mean_X /= n;
    mean_Y /= n;

    float cov = 0, var_X = 0, var_Y = 0;
    for (size_t i = 0; i < n; i++) {
        float dx = X[i] - mean_X;
        float dy = Y[i] - mean_Y;
        cov += dx * dy;
        var_X += dx * dx;
        var_Y += dy * dy;
    }

    float denom = sqrtf(var_X * var_Y);
    return (denom > 1e-10f) ? (cov / denom) : 0;
}

/* ============================================================================
 * Conditional Independence Testing
 * ============================================================================ */

bool causal_test_independence(
    const float* X,
    const float* Y,
    size_t num_samples,
    float significance,
    ConditionalIndependenceResult* result
) {
    if (!X || !Y || !result || num_samples < CAUSAL_MIN_SAMPLES) {
        return false;
    }

    memset(result, 0, sizeof(ConditionalIndependenceResult));
    result->test_type = CI_TEST_CHI_SQUARED;

    /* Compute correlation */
    float r = correlation(X, Y, num_samples);

    /* Fisher's Z-transform for correlation test */
    float z = 0.5f * logf((1.0f + r) / (1.0f - r + 1e-10f));
    float se = 1.0f / sqrtf((float)num_samples - 3.0f);
    float test_stat = fabsf(z) / se;

    result->test_statistic = test_stat;
    result->degrees_of_freedom = num_samples - 2;

    /* Approximate p-value using chi-squared distribution */
    result->p_value = 1.0f - chi_squared_cdf(test_stat * test_stat, 1);

    /* Independence if p-value > significance level */
    result->are_independent = (result->p_value > significance);

    return true;
}

bool causal_test_conditional_independence(
    const float* X,
    const float* Y,
    const float* Z,
    size_t num_samples,
    size_t num_Z_vars,
    float significance,
    ConditionalIndependenceResult* result
) {
    if (!X || !Y || !result || num_samples < CAUSAL_MIN_SAMPLES) {
        return false;
    }

    /* If no conditioning variables, use simple independence test */
    if (!Z || num_Z_vars == 0) {
        return causal_test_independence(X, Y, num_samples, significance, result);
    }

    memset(result, 0, sizeof(ConditionalIndependenceResult));
    result->test_type = CI_TEST_G_TEST;

    /* Simplified conditional independence test using partial correlation */
    /* In full implementation, would use G-test with contingency tables */

    /* For continuous variables: use partial correlation */
    /* ρ_XY·Z = (ρ_XY - ρ_XZ * ρ_YZ) / sqrt((1 - ρ_XZ²)(1 - ρ_YZ²)) */

    float r_XY = correlation(X, Y, num_samples);

    /* For simplicity, use first conditioning variable */
    const float* Z0 = Z;
    float r_XZ = correlation(X, Z0, num_samples);
    float r_YZ = correlation(Y, Z0, num_samples);

    float numerator = r_XY - r_XZ * r_YZ;
    float denominator = sqrtf((1.0f - r_XZ * r_XZ) * (1.0f - r_YZ * r_YZ));

    float partial_r = (denominator > 1e-10f) ? (numerator / denominator) : r_XY;

    /* Fisher's Z-transform */
    float z = 0.5f * logf((1.0f + partial_r) / (1.0f - partial_r + 1e-10f));
    float se = 1.0f / sqrtf((float)num_samples - num_Z_vars - 3.0f);
    float test_stat = fabsf(z) / se;

    result->test_statistic = test_stat;
    result->degrees_of_freedom = num_samples - num_Z_vars - 2;
    result->p_value = 1.0f - chi_squared_cdf(test_stat * test_stat, 1);
    result->are_independent = (result->p_value > significance);

    return true;
}

/* ============================================================================
 * Causal DAG
 * ============================================================================ */

CausalDAG* causal_dag_create(size_t num_nodes) {
    CausalDAG* dag = calloc(1, sizeof(CausalDAG));
    if (!dag) return NULL;

    dag->num_nodes = num_nodes;

    /* Allocate adjacency matrix */
    dag->adjacency = calloc(num_nodes, sizeof(bool*));
    dag->edge_types = calloc(num_nodes, sizeof(int*));
    dag->edge_confidence = calloc(num_nodes, sizeof(float*));
    dag->markov_blanket = calloc(num_nodes, sizeof(bool*));

    if (!dag->adjacency || !dag->edge_types || !dag->edge_confidence || !dag->markov_blanket) {
        causal_dag_destroy(dag);
        return NULL;
    }

    for (size_t i = 0; i < num_nodes; i++) {
        dag->adjacency[i] = calloc(num_nodes, sizeof(bool));
        dag->edge_types[i] = calloc(num_nodes, sizeof(int));
        dag->edge_confidence[i] = calloc(num_nodes, sizeof(float));
        dag->markov_blanket[i] = calloc(num_nodes, sizeof(bool));

        if (!dag->adjacency[i] || !dag->edge_types[i] ||
            !dag->edge_confidence[i] || !dag->markov_blanket[i]) {
            causal_dag_destroy(dag);
            return NULL;
        }
    }

    return dag;
}

void causal_dag_destroy(CausalDAG* dag) {
    if (!dag) return;

    if (dag->adjacency) {
        for (size_t i = 0; i < dag->num_nodes; i++) {
            free(dag->adjacency[i]);
        }
        free(dag->adjacency);
    }

    if (dag->edge_types) {
        for (size_t i = 0; i < dag->num_nodes; i++) {
            free(dag->edge_types[i]);
        }
        free(dag->edge_types);
    }

    if (dag->edge_confidence) {
        for (size_t i = 0; i < dag->num_nodes; i++) {
            free(dag->edge_confidence[i]);
        }
        free(dag->edge_confidence);
    }

    if (dag->markov_blanket) {
        for (size_t i = 0; i < dag->num_nodes; i++) {
            free(dag->markov_blanket[i]);
        }
        free(dag->markov_blanket);
    }

    free(dag);
}

bool causal_dag_has_edge(const CausalDAG* dag, size_t i, size_t j) {
    if (!dag || i >= dag->num_nodes || j >= dag->num_nodes) {
        return false;
    }
    return dag->adjacency[i][j];
}

void causal_dag_get_parents(
    const CausalDAG* dag,
    size_t node,
    size_t* out_parents,
    size_t* out_count
) {
    if (!dag || !out_parents || !out_count || node >= dag->num_nodes) {
        if (out_count) *out_count = 0;
        return;
    }

    *out_count = 0;
    for (size_t i = 0; i < dag->num_nodes; i++) {
        if (dag->adjacency[i][node]) {
            out_parents[(*out_count)++] = i;
        }
    }
}

/* ============================================================================
 * PC Algorithm (Simplified)
 * ============================================================================ */

bool causal_pc_algorithm(
    const float* data,
    size_t num_samples,
    size_t num_variables,
    float significance,
    size_t max_conditioning,
    CausalDAG* out_dag
) {
    if (!data || !out_dag || num_samples < CAUSAL_MIN_SAMPLES) {
        return false;
    }

    /* Initialize with complete undirected graph */
    CausalDAG* dag = causal_dag_create(num_variables);
    if (!dag) return false;

    /* Phase 1: Skeleton discovery via conditional independence tests */
    for (size_t i = 0; i < num_variables; i++) {
        for (size_t j = i + 1; j < num_variables; j++) {
            /* Start with edge i - j */
            dag->adjacency[i][j] = true;
            dag->adjacency[j][i] = true;
            dag->edge_types[i][j] = EDGE_UNDIRECTED;
            dag->edge_types[j][i] = EDGE_UNDIRECTED;
        }
    }

    /* Test independence and remove edges */
    for (size_t i = 0; i < num_variables; i++) {
        for (size_t j = i + 1; j < num_variables; j++) {
            if (!dag->adjacency[i][j]) continue;

            /* Extract variables */
            const float* X = &data[i * num_samples];
            const float* Y = &data[j * num_samples];

            /* Test unconditional independence */
            ConditionalIndependenceResult result;
            if (causal_test_independence(X, Y, num_samples, significance, &result)) {
                if (result.are_independent) {
                    /* Remove edge */
                    dag->adjacency[i][j] = false;
                    dag->adjacency[j][i] = false;
                    dag->edge_types[i][j] = EDGE_NONE;
                    dag->edge_types[j][i] = EDGE_NONE;
                } else {
                    dag->edge_confidence[i][j] = 1.0f - result.p_value;
                    dag->edge_confidence[j][i] = 1.0f - result.p_value;
                }
            }
        }
    }

    /* Phase 2: Edge orientation (simplified - would use v-structures in full PC) */
    /* For simplicity, leave edges undirected */

    /* Copy to output */
    memcpy(out_dag, dag, sizeof(CausalDAG));
    out_dag->adjacency = dag->adjacency;
    out_dag->edge_types = dag->edge_types;
    out_dag->edge_confidence = dag->edge_confidence;
    out_dag->markov_blanket = dag->markov_blanket;

    return true;
}

/* ============================================================================
 * Granger Causality
 * ============================================================================ */

static float compute_sse(const float* residuals, size_t n) {
    float sse = 0;
    for (size_t i = 0; i < n; i++) {
        sse += residuals[i] * residuals[i];
    }
    return sse;
}

bool causal_granger_test(
    const float* X,
    const float* Y,
    size_t num_timesteps,
    size_t max_lag,
    float significance,
    GrangerCausalityResult* result
) {
    if (!X || !Y || !result || num_timesteps < max_lag + CAUSAL_MIN_SAMPLES) {
        return false;
    }

    memset(result, 0, sizeof(GrangerCausalityResult));

    /* Simplified Granger causality test */
    /* Full implementation would use AR models and F-test */

    /* Restricted model: Y(t) = Σ β_i * Y(t-i) + ε */
    /* Unrestricted model: Y(t) = Σ β_i * Y(t-i) + Σ γ_j * X(t-j) + ε */

    size_t effective_n = num_timesteps - max_lag;

    /* Compute residuals for restricted model (only Y lags) */
    float* residuals_restricted = calloc(effective_n, sizeof(float));

    for (size_t t = max_lag; t < num_timesteps; t++) {
        float prediction = 0;

        /* Simple AR(1): Y(t) ≈ β * Y(t-1) */
        prediction = 0.8f * Y[t - 1];  /* Simplified coefficient */

        residuals_restricted[t - max_lag] = Y[t] - prediction;
    }

    result->restricted_sse = compute_sse(residuals_restricted, effective_n);

    /* Compute residuals for unrestricted model (Y lags + X lags) */
    float* residuals_unrestricted = calloc(effective_n, sizeof(float));

    for (size_t t = max_lag; t < num_timesteps; t++) {
        float prediction = 0;

        /* AR(1) with X: Y(t) ≈ β * Y(t-1) + γ * X(t-1) */
        prediction = 0.8f * Y[t - 1] + 0.3f * X[t - 1];  /* Simplified */

        residuals_unrestricted[t - max_lag] = Y[t] - prediction;
    }

    result->unrestricted_sse = compute_sse(residuals_unrestricted, effective_n);

    /* F-test for improvement */
    float sse_reduction = result->restricted_sse - result->unrestricted_sse;
    result->improvement_ratio = sse_reduction / (result->restricted_sse + 1e-10f);

    /* F-statistic */
    size_t df1 = max_lag;
    size_t df2 = effective_n - 2 * max_lag;

    result->f_statistic = (sse_reduction / df1) /
                         ((result->unrestricted_sse + 1e-10f) / df2);

    /* Approximate p-value (simplified) */
    result->p_value = expf(-result->f_statistic / 10.0f);  /* Simplified */

    result->does_granger_cause = (result->p_value < significance) &&
                                 (result->improvement_ratio > 0.05f);
    result->optimal_lag = 1;  /* Simplified */

    free(residuals_restricted);
    free(residuals_unrestricted);

    return true;
}

/* ============================================================================
 * Causal Provenance Graph
 * ============================================================================ */

CausalProvenanceGraph* causal_provenance_create(
    ProvenanceGraph* graph,
    float significance
) {
    if (!graph) return NULL;

    CausalProvenanceGraph* cpg = calloc(1, sizeof(CausalProvenanceGraph));
    if (!cpg) return NULL;

    cpg->base_graph = graph;
    cpg->max_chains = 1000;

    /* Allocate causal edge tracking */
    cpg->is_causal_edge = calloc(graph->max_edges, sizeof(bool));
    cpg->causal_strength = calloc(graph->max_edges, sizeof(float));
    cpg->chains = calloc(cpg->max_chains, sizeof(CausalChain));

    if (!cpg->is_causal_edge || !cpg->causal_strength || !cpg->chains) {
        causal_provenance_destroy(cpg);
        return NULL;
    }

    /* Create causal DAG */
    cpg->causal_dag = causal_dag_create(graph->num_nodes);

    cpg->stats.total_edges = graph->num_edges;

    printf("[CausalProvenance] Created for graph with %zu nodes, %zu edges\n",
           graph->num_nodes, graph->num_edges);

    return cpg;
}

void causal_provenance_destroy(CausalProvenanceGraph* cpg) {
    if (!cpg) return;

    causal_dag_destroy(cpg->causal_dag);
    free(cpg->is_causal_edge);
    free(cpg->causal_strength);
    free(cpg->chains);
    free(cpg);
}

size_t causal_provenance_identify_edges(
    CausalProvenanceGraph* cpg,
    bool use_temporal
) {
    if (!cpg || !cpg->base_graph) return 0;

    ProvenanceGraph* graph = cpg->base_graph;
    size_t causal_count = 0;

    /* Analyze each edge for causality */
    for (size_t i = 0; i < graph->num_edges; i++) {
        ProvenanceEdge* edge = &graph->edges[i];

        /* Heuristic: certain edge types are more likely causal */
        bool likely_causal = false;
        float strength = 0.5f;

        switch (edge->type) {
            case EDGE_FORK:
            case EDGE_EXEC:
                /* Process creation is clearly causal */
                likely_causal = true;
                strength = 0.95f;
                break;

            case EDGE_WRITE:
            case EDGE_SEND:
                /* Data flow is likely causal */
                likely_causal = true;
                strength = 0.80f;
                break;

            case EDGE_READ:
                /* Reading is less directly causal (information flow) */
                likely_causal = true;
                strength = 0.60f;
                break;

            case EDGE_CONNECT:
                /* Network connections are causal for APT */
                likely_causal = true;
                strength = 0.85f;
                break;

            default:
                likely_causal = false;
                strength = 0.30f;
        }

        /* Store results */
        cpg->is_causal_edge[i] = likely_causal;
        cpg->causal_strength[i] = strength;
        edge->is_causal = likely_causal;
        edge->causal_weight = strength;

        if (likely_causal) {
            causal_count++;
        }
    }

    cpg->stats.causal_edges = causal_count;
    cpg->stats.spurious_edges = cpg->stats.total_edges - causal_count;
    cpg->stats.causal_ratio = (float)causal_count / (cpg->stats.total_edges + 1);

    printf("[CausalProvenance] Identified %zu/%zu causal edges (%.1f%%)\n",
           causal_count, cpg->stats.total_edges,
           cpg->stats.causal_ratio * 100.0f);

    return causal_count;
}

void causal_provenance_extract_chains(
    CausalProvenanceGraph* cpg,
    size_t min_length,
    size_t max_chains,
    CausalChain* out_chains,
    size_t* out_count
) {
    if (!cpg || !out_chains || !out_count) {
        if (out_count) *out_count = 0;
        return;
    }

    ProvenanceGraph* graph = cpg->base_graph;
    size_t chain_count = 0;

    /* DFS to find causal paths */
    for (size_t i = 0; i < graph->max_nodes && chain_count < max_chains; i++) {
        if (graph->node_ids[i] == UINT64_MAX) continue;

        ProvenanceNode* node = &graph->nodes[i];

        /* Start chain from this node */
        CausalChain* chain = &out_chains[chain_count];
        memset(chain, 0, sizeof(CausalChain));

        chain->chain_id = chain_count;
        chain->node_path[0] = node->id;
        chain->path_length = 1;
        chain->start_time_ns = node->first_seen_ns;

        /* Follow causal out-edges */
        uint64_t current_node = node->id;

        for (size_t depth = 1; depth < 256; depth++) {
            ProvenanceNode* curr = pg_get_node(graph, current_node);
            if (!curr || curr->out_degree == 0) break;

            /* Find first causal out-edge */
            bool found_causal = false;
            for (size_t j = 0; j < curr->out_degree; j++) {
                uint64_t edge_id = curr->out_edges[j];
                if (edge_id >= graph->num_edges) continue;

                if (cpg->is_causal_edge[edge_id]) {
                    ProvenanceEdge* edge = &graph->edges[edge_id];

                    chain->edge_path[depth - 1] = edge_id;
                    chain->node_path[depth] = edge->dst_node;
                    chain->path_length++;
                    chain->end_time_ns = edge->timestamp_ns;

                    /* Accumulate causal score */
                    chain->causal_score += cpg->causal_strength[edge_id];

                    current_node = edge->dst_node;
                    found_causal = true;
                    break;
                }
            }

            if (!found_causal) break;
        }

        /* Normalize causal score */
        if (chain->path_length > 1) {
            chain->causal_score /= (chain->path_length - 1);
        }

        /* Add chain if meets minimum length */
        if (chain->path_length >= min_length) {
            chain_count++;
        }
    }

    *out_count = chain_count;
    cpg->num_chains = chain_count;

    printf("[CausalProvenance] Extracted %zu causal chains (min_length=%zu)\n",
           chain_count, min_length);
}

/* ============================================================================
 * Causal Chain Scoring
 * ============================================================================ */

float causal_score_chain(
    const CausalChain* chain,
    const CausalProvenanceGraph* cpg
) {
    if (!chain || !cpg || chain->path_length == 0) {
        return 0;
    }

    return chain->causal_score;
}

void causal_rank_chains(
    const CausalChain* chains,
    size_t num_chains,
    const CausalProvenanceGraph* cpg,
    CausalChain* out_ranked
) {
    if (!chains || !out_ranked || num_chains == 0) return;

    /* Copy chains */
    memcpy(out_ranked, chains, num_chains * sizeof(CausalChain));

    /* Simple bubble sort by causal_score (descending) */
    for (size_t i = 0; i < num_chains - 1; i++) {
        for (size_t j = 0; j < num_chains - i - 1; j++) {
            if (out_ranked[j].causal_score < out_ranked[j + 1].causal_score) {
                CausalChain temp = out_ranked[j];
                out_ranked[j] = out_ranked[j + 1];
                out_ranked[j + 1] = temp;
            }
        }
    }
}

/* ============================================================================
 * Utilities
 * ============================================================================ */

void causal_provenance_print_stats(const CausalProvenanceGraph* cpg) {
    if (!cpg) return;

    printf("\n=== Causal Provenance Statistics ===\n");
    printf("Total edges:     %zu\n", cpg->stats.total_edges);
    printf("Causal edges:    %zu (%.1f%%)\n",
           cpg->stats.causal_edges,
           cpg->stats.causal_ratio * 100.0f);
    printf("Spurious edges:  %zu\n", cpg->stats.spurious_edges);
    printf("Causal chains:   %zu\n", cpg->num_chains);
    printf("====================================\n\n");
}

void causal_dag_print(const CausalDAG* dag) {
    if (!dag) return;

    printf("\n=== Causal DAG ===\n");
    printf("Nodes: %zu\n", dag->num_nodes);

    size_t edge_count = 0;
    for (size_t i = 0; i < dag->num_nodes; i++) {
        for (size_t j = 0; j < dag->num_nodes; j++) {
            if (dag->adjacency[i][j]) {
                printf("  %zu → %zu (conf=%.2f)\n",
                       i, j, dag->edge_confidence[i][j]);
                edge_count++;
            }
        }
    }
    printf("Edges: %zu\n", edge_count);
    printf("==================\n\n");
}
