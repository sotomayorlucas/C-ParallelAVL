// Causal Inference for APT Detection (C++23 migration)
//
// Structural Causal Models (SCM) and causal discovery algorithms used to
// distinguish true causal relationships from spurious correlations in
// provenance graphs.

#pragma once

#include "common.hpp"
#include "provenance_graph.hpp"
#include "temporal_gnn.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace flowshield {

// ============================================================================
// Configuration
// ============================================================================

inline constexpr float       CAUSAL_SIGNIFICANCE_LEVEL   = 0.05f;
inline constexpr std::size_t CAUSAL_MAX_CONDITIONING_SET = 5;
inline constexpr std::size_t CAUSAL_MIN_SAMPLES          = 30;
inline constexpr std::size_t CAUSAL_GRANGER_LAG_MAX      = 10;

// ============================================================================
// Conditional Independence Test
// ============================================================================

enum class CIIndependenceTest : std::uint8_t {
    GTest,
    ChiSquared,
    FisherZ,
    MutualInfo,
};

struct ConditionalIndependenceResult {
    bool        are_independent     = false;
    float       p_value             = 0.0f;
    float       test_statistic      = 0.0f;
    std::size_t degrees_of_freedom  = 0;
    CIIndependenceTest test_type    = CIIndependenceTest::ChiSquared;
};

bool causal_test_conditional_independence(const float* X,
                                          const float* Y,
                                          const float* Z,
                                          std::size_t num_samples,
                                          std::size_t num_Z_vars,
                                          float significance,
                                          ConditionalIndependenceResult& result);

bool causal_test_independence(const float* X,
                              const float* Y,
                              std::size_t num_samples,
                              float significance,
                              ConditionalIndependenceResult& result);

// ============================================================================
// Causal DAG (constraint-based)
// ============================================================================

enum class CausalEdgeKind : std::uint8_t {
    None        = 0,
    Directed    = 1,    // i -> j
    Undirected  = 2,    // i - j
    Bidirected  = 3,    // i <-> j
};

class CausalDAG {
public:
    explicit CausalDAG(std::size_t num_nodes);

    CausalDAG(const CausalDAG&)            = delete;
    CausalDAG& operator=(const CausalDAG&) = delete;

    [[nodiscard]] std::size_t num_nodes() const noexcept { return num_nodes_; }

    [[nodiscard]] bool   has_edge   (std::size_t i, std::size_t j) const noexcept;
    void                 set_edge   (std::size_t i, std::size_t j, bool v) noexcept {
        adjacency_[i * num_nodes_ + j] = v ? 1u : 0u;
    }
    [[nodiscard]] CausalEdgeKind& edge_type(std::size_t i, std::size_t j) noexcept {
        return edge_types_[i * num_nodes_ + j];
    }
    [[nodiscard]] float& edge_confidence(std::size_t i, std::size_t j) noexcept {
        return edge_confidence_[i * num_nodes_ + j];
    }
    void set_markov_blanket(std::size_t i, std::size_t j, bool v) noexcept {
        markov_blanket_[i * num_nodes_ + j] = v ? 1u : 0u;
    }
    [[nodiscard]] bool markov_blanket(std::size_t i, std::size_t j) const noexcept {
        return markov_blanket_[i * num_nodes_ + j] != 0;
    }

    void get_parents(std::size_t node,
                     std::size_t* out_parents,
                     std::size_t* out_count) const;

    void print() const;

private:
    std::size_t                   num_nodes_;
    std::vector<std::uint8_t>     adjacency_;       // bool stored as byte (avoid vector<bool>)
    std::vector<CausalEdgeKind>   edge_types_;
    std::vector<float>            edge_confidence_;
    std::vector<std::uint8_t>     markov_blanket_;  // bool stored as byte
};

bool causal_pc_algorithm(const float* data,
                         std::size_t num_samples,
                         std::size_t num_variables,
                         float significance,
                         std::size_t max_conditioning,
                         CausalDAG& out_dag);

// ============================================================================
// Granger Causality (temporal)
// ============================================================================

struct GrangerCausalityResult {
    bool        does_granger_cause = false;
    float       f_statistic        = 0.0f;
    float       p_value            = 0.0f;
    std::size_t optimal_lag        = 0;
    float       restricted_sse     = 0.0f;
    float       unrestricted_sse   = 0.0f;
    float       improvement_ratio  = 0.0f;
};

bool causal_granger_test(const float* X,
                         const float* Y,
                         std::size_t num_timesteps,
                         std::size_t max_lag,
                         float significance,
                         GrangerCausalityResult& result);

// ============================================================================
// Causal Provenance Graph
// ============================================================================

struct CausalProvenanceStats {
    std::size_t total_edges    = 0;
    std::size_t causal_edges   = 0;
    std::size_t spurious_edges = 0;
    float       causal_ratio   = 0.0f;
};

class CausalProvenanceGraph {
public:
    CausalProvenanceGraph(ProvenanceGraph& graph, float significance);

    CausalProvenanceGraph(const CausalProvenanceGraph&)            = delete;
    CausalProvenanceGraph& operator=(const CausalProvenanceGraph&) = delete;

    std::size_t identify_edges(bool use_temporal);

    void extract_chains(std::size_t min_length,
                        std::size_t max_chains,
                        CausalChain* out_chains,
                        std::size_t* out_count);

    void print_stats() const;

    [[nodiscard]] ProvenanceGraph& base_graph() noexcept { return *base_graph_; }
    [[nodiscard]] CausalDAG&       dag()        noexcept { return *causal_dag_; }
    [[nodiscard]] const CausalProvenanceStats& stats() const noexcept { return stats_; }

    [[nodiscard]] const std::uint8_t* is_causal_edge() const noexcept { return is_causal_edge_.data(); }
    [[nodiscard]] const float*        causal_strength() const noexcept { return causal_strength_.data(); }

private:
    ProvenanceGraph*               base_graph_;
    std::unique_ptr<CausalDAG>     causal_dag_;
    std::vector<std::uint8_t>      is_causal_edge_;   // bool stored as byte
    std::vector<float>             causal_strength_;
    std::vector<CausalChain>       chains_;
    std::size_t                    num_chains_ = 0;
    std::size_t                    max_chains_ = 1000;
    CausalProvenanceStats          stats_ {};
};

// ============================================================================
// Do-calculus / interventions
// ============================================================================

struct Intervention {
    std::size_t variable_index    = 0;
    float       intervention_value = 0.0f;
};

bool causal_do_calculus(const CausalDAG& dag,
                        const Intervention& intervention,
                        std::size_t target_variable,
                        const float* data,
                        std::size_t num_samples,
                        float* out_distribution,
                        std::size_t num_bins);

bool causal_compute_effect(const CausalDAG& dag,
                           std::size_t cause_variable,
                           std::size_t effect_variable,
                           const float* data,
                           std::size_t num_samples,
                           float& out_effect);

// ============================================================================
// Counterfactual reasoning
// ============================================================================

struct CounterfactualQuery {
    std::size_t  cause_variable        = 0;
    float        counterfactual_value  = 0.0f;
    std::size_t  effect_variable       = 0;
    const float* observed_data         = nullptr;
    float        counterfactual_outcome = 0.0f;
    float        factual_outcome        = 0.0f;
    float        causal_effect          = 0.0f;
};

bool causal_counterfactual(const CausalDAG& dag,
                           CounterfactualQuery& query,
                           const float* data,
                           std::size_t num_samples);

// ============================================================================
// Chain scoring / ranking
// ============================================================================

[[nodiscard]] float causal_score_chain(const CausalChain& chain,
                                       const CausalProvenanceGraph& cpg);

void causal_rank_chains(const CausalChain* chains,
                        std::size_t num_chains,
                        const CausalProvenanceGraph& cpg,
                        CausalChain* out_ranked);

// ============================================================================
// Utilities
// ============================================================================

[[nodiscard]] float causal_mutual_information(const float* X,
                                              const float* Y,
                                              std::size_t num_samples);

[[nodiscard]] float causal_conditional_mutual_information(const float* X,
                                                          const float* Y,
                                                          const float* Z,
                                                          std::size_t num_samples,
                                                          std::size_t num_Z_vars);

void causal_dag_export_dot(const CausalDAG& dag, const char* filename);

}  // namespace flowshield
