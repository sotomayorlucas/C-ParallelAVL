/**
 * Causal Inference for APT Detection
 *
 * Implements Structural Causal Models (SCM) and causal discovery algorithms
 * to distinguish true causal relationships from spurious correlations in
 * provenance graphs.
 *
 * Key insight: Not all edges in provenance graph are causal.
 * Example: proceso_A --read--> config.txt --read--> proceso_B
 *          This is correlation, not causation (config.txt doesn't cause B)
 *
 * Techniques:
 *   - Conditional Independence Testing (G-test, Chi-squared)
 *   - PC Algorithm (constraint-based causal discovery)
 *   - Granger Causality (temporal causality)
 *   - Do-calculus (interventional reasoning)
 *   - Counterfactual analysis
 */

#ifndef FLOWSHIELD_CAUSAL_INFERENCE_H
#define FLOWSHIELD_CAUSAL_INFERENCE_H

#include "provenance_graph.h"
#include "temporal_gnn.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Configuration
 * ============================================================================ */

#define CAUSAL_SIGNIFICANCE_LEVEL   0.05f   /* Statistical significance α */
#define CAUSAL_MAX_CONDITIONING_SET 5       /* Max variables in conditioning set */
#define CAUSAL_MIN_SAMPLES          30      /* Min samples for statistical tests */
#define CAUSAL_GRANGER_LAG_MAX      10      /* Max lag for Granger causality */

/* ============================================================================
 * Conditional Independence Test
 * ============================================================================ */

/**
 * Result of conditional independence test.
 */
typedef struct {
    bool are_independent;               /* X ⊥ Y | Z */
    float p_value;                      /* Statistical p-value */
    float test_statistic;               /* Test statistic value */
    size_t degrees_of_freedom;          /* DOF for chi-squared */

    /* Test type used */
    enum {
        CI_TEST_G_TEST,                 /* G-test (log-likelihood ratio) */
        CI_TEST_CHI_SQUARED,            /* Chi-squared test */
        CI_TEST_FISHER_Z,               /* Fisher's Z-transform */
        CI_TEST_MUTUAL_INFO             /* Mutual information */
    } test_type;
} ConditionalIndependenceResult;

/**
 * Test conditional independence: X ⊥ Y | Z
 *
 * @param X                 Variable X data [num_samples]
 * @param Y                 Variable Y data [num_samples]
 * @param Z                 Conditioning variables Z [num_samples x num_Z_vars]
 * @param num_samples       Number of samples
 * @param num_Z_vars        Number of conditioning variables
 * @param significance      Significance level (e.g., 0.05)
 * @param result            Output result
 * @return                  true if test completed successfully
 */
bool causal_test_conditional_independence(
    const float* X,
    const float* Y,
    const float* Z,
    size_t num_samples,
    size_t num_Z_vars,
    float significance,
    ConditionalIndependenceResult* result
);

/**
 * Test pairwise independence: X ⊥ Y (no conditioning)
 */
bool causal_test_independence(
    const float* X,
    const float* Y,
    size_t num_samples,
    float significance,
    ConditionalIndependenceResult* result
);

/* ============================================================================
 * PC Algorithm (Constraint-based Causal Discovery)
 * ============================================================================ */

/**
 * Discovered causal graph (DAG).
 */
typedef struct {
    size_t num_nodes;
    bool** adjacency;                   /* adjacency[i][j] = true if i → j */

    /* Edge orientations */
    enum {
        EDGE_NONE = 0,
        EDGE_DIRECTED,                  /* i → j */
        EDGE_UNDIRECTED,                /* i - j */
        EDGE_BIDIRECTED                 /* i ↔ j */
    } **edge_types;

    /* Confidence scores for edges */
    float** edge_confidence;

    /* Markov blanket for each node */
    bool** markov_blanket;
} CausalDAG;

/**
 * Run PC algorithm to discover causal structure.
 *
 * @param data              Data matrix [num_samples x num_variables]
 * @param num_samples       Number of samples
 * @param num_variables     Number of variables
 * @param significance      Significance level for CI tests
 * @param max_conditioning  Max size of conditioning set
 * @param out_dag           Output causal DAG
 * @return                  true on success
 */
bool causal_pc_algorithm(
    const float* data,
    size_t num_samples,
    size_t num_variables,
    float significance,
    size_t max_conditioning,
    CausalDAG* out_dag
);

/**
 * Create/destroy causal DAG.
 */
CausalDAG* causal_dag_create(size_t num_nodes);
void causal_dag_destroy(CausalDAG* dag);

/**
 * Check if edge exists: i → j
 */
bool causal_dag_has_edge(const CausalDAG* dag, size_t i, size_t j);

/**
 * Get causal parents of node.
 */
void causal_dag_get_parents(
    const CausalDAG* dag,
    size_t node,
    size_t* out_parents,
    size_t* out_count
);

/* ============================================================================
 * Granger Causality (Temporal Causality)
 * ============================================================================ */

/**
 * Granger causality test result.
 * Tests if X "Granger-causes" Y (i.e., past X helps predict future Y).
 */
typedef struct {
    bool does_granger_cause;            /* X → Y (Granger) */
    float f_statistic;                  /* F-test statistic */
    float p_value;                      /* P-value */
    size_t optimal_lag;                 /* Optimal lag order */

    /* Model comparison */
    float restricted_sse;               /* SSE of restricted model (no X) */
    float unrestricted_sse;             /* SSE of unrestricted model (with X) */
    float improvement_ratio;            /* How much X improves prediction */
} GrangerCausalityResult;

/**
 * Test Granger causality: Does X Granger-cause Y?
 *
 * @param X                 Time series X [num_timesteps]
 * @param Y                 Time series Y [num_timesteps]
 * @param num_timesteps     Length of time series
 * @param max_lag           Maximum lag to test
 * @param significance      Significance level
 * @param result            Output result
 * @return                  true on success
 */
bool causal_granger_test(
    const float* X,
    const float* Y,
    size_t num_timesteps,
    size_t max_lag,
    float significance,
    GrangerCausalityResult* result
);

/* ============================================================================
 * Causal Graph from Provenance Graph
 * ============================================================================ */

/**
 * Causal provenance graph (subset of provenance graph with only causal edges).
 */
typedef struct {
    ProvenanceGraph* base_graph;        /* Original provenance graph */
    CausalDAG* causal_dag;              /* Discovered causal structure */

    /* Mapping: provenance edge → causal edge */
    bool* is_causal_edge;               /* [num_edges] */
    float* causal_strength;             /* [num_edges] strength ∈ [0, 1] */

    /* Causal chains */
    CausalChain* chains;
    size_t num_chains;
    size_t max_chains;

    /* Statistics */
    struct {
        size_t total_edges;
        size_t causal_edges;
        size_t spurious_edges;
        float causal_ratio;             /* Fraction of edges that are causal */
    } stats;
} CausalProvenanceGraph;

/**
 * Create causal provenance graph from provenance graph.
 *
 * @param graph             Provenance graph
 * @param significance      Significance level for causality tests
 * @return                  Causal provenance graph
 */
CausalProvenanceGraph* causal_provenance_create(
    ProvenanceGraph* graph,
    float significance
);

void causal_provenance_destroy(CausalProvenanceGraph* cpg);

/**
 * Identify causal edges using SCM.
 *
 * @param cpg               Causal provenance graph
 * @param use_temporal      Use Granger causality for temporal edges
 * @return                  Number of causal edges identified
 */
size_t causal_provenance_identify_edges(
    CausalProvenanceGraph* cpg,
    bool use_temporal
);

/**
 * Extract causal chains (attack paths).
 *
 * @param cpg               Causal provenance graph
 * @param min_length        Minimum chain length
 * @param max_chains        Maximum chains to extract
 * @param out_chains        Output chains
 * @param out_count         Number of chains extracted
 */
void causal_provenance_extract_chains(
    CausalProvenanceGraph* cpg,
    size_t min_length,
    size_t max_chains,
    CausalChain* out_chains,
    size_t* out_count
);

/* ============================================================================
 * Do-Calculus (Interventional Reasoning)
 * ============================================================================ */

/**
 * Intervention on a variable (do-operator).
 * Represents setting a variable to a specific value.
 */
typedef struct {
    size_t variable_index;              /* Which variable to intervene on */
    float intervention_value;           /* Value to set */
} Intervention;

/**
 * Compute interventional distribution: P(Y | do(X = x))
 *
 * @param dag               Causal DAG
 * @param intervention      Intervention do(X = x)
 * @param target_variable   Target variable Y
 * @param data              Observational data [num_samples x num_variables]
 * @param num_samples       Number of samples
 * @param out_distribution  Output distribution P(Y | do(X = x))
 * @param num_bins          Number of bins for discretization
 * @return                  true on success
 */
bool causal_do_calculus(
    const CausalDAG* dag,
    const Intervention* intervention,
    size_t target_variable,
    const float* data,
    size_t num_samples,
    float* out_distribution,
    size_t num_bins
);

/**
 * Compute causal effect: E[Y | do(X = 1)] - E[Y | do(X = 0)]
 *
 * @param dag               Causal DAG
 * @param cause_variable    X (cause)
 * @param effect_variable   Y (effect)
 * @param data              Observational data
 * @param num_samples       Number of samples
 * @param out_effect        Causal effect
 * @return                  true on success
 */
bool causal_compute_effect(
    const CausalDAG* dag,
    size_t cause_variable,
    size_t effect_variable,
    const float* data,
    size_t num_samples,
    float* out_effect
);

/* ============================================================================
 * Counterfactual Reasoning
 * ============================================================================ */

/**
 * Counterfactual query: "What would Y be if X had been x?"
 */
typedef struct {
    size_t cause_variable;              /* X */
    float counterfactual_value;         /* x (counterfactual value) */
    size_t effect_variable;             /* Y */

    /* Observed values */
    const float* observed_data;         /* Actual observations */

    /* Result */
    float counterfactual_outcome;       /* Y(x) - counterfactual outcome */
    float factual_outcome;              /* Y(X) - actual outcome */
    float causal_effect;                /* Y(x) - Y(X) */
} CounterfactualQuery;

/**
 * Answer counterfactual query.
 *
 * @param dag               Causal DAG
 * @param query             Counterfactual query
 * @param data              Training data
 * @param num_samples       Number of samples
 * @return                  true on success
 */
bool causal_counterfactual(
    const CausalDAG* dag,
    CounterfactualQuery* query,
    const float* data,
    size_t num_samples
);

/* ============================================================================
 * Causal Chain Scoring
 * ============================================================================ */

/**
 * Score causal chain based on causal strength.
 *
 * @param chain             Causal chain
 * @param cpg               Causal provenance graph
 * @return                  Causal score ∈ [0, 1]
 */
float causal_score_chain(
    const CausalChain* chain,
    const CausalProvenanceGraph* cpg
);

/**
 * Rank chains by causal strength.
 *
 * @param chains            Chains to rank
 * @param num_chains        Number of chains
 * @param cpg               Causal provenance graph
 * @param out_ranked        Output ranked chains (sorted by score)
 */
void causal_rank_chains(
    const CausalChain* chains,
    size_t num_chains,
    const CausalProvenanceGraph* cpg,
    CausalChain* out_ranked
);

/* ============================================================================
 * Utilities
 * ============================================================================ */

/**
 * Compute mutual information: I(X; Y)
 */
float causal_mutual_information(
    const float* X,
    const float* Y,
    size_t num_samples
);

/**
 * Compute conditional mutual information: I(X; Y | Z)
 */
float causal_conditional_mutual_information(
    const float* X,
    const float* Y,
    const float* Z,
    size_t num_samples,
    size_t num_Z_vars
);

/**
 * Print causal DAG.
 */
void causal_dag_print(const CausalDAG* dag);

/**
 * Export causal DAG to DOT format.
 */
void causal_dag_export_dot(const CausalDAG* dag, const char* filename);

/**
 * Print causal provenance statistics.
 */
void causal_provenance_print_stats(const CausalProvenanceGraph* cpg);

#ifdef __cplusplus
}
#endif

#endif /* FLOWSHIELD_CAUSAL_INFERENCE_H */
