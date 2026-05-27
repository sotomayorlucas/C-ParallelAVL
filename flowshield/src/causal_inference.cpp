// Causal Inference Implementation (C++23 migration of causal_inference.c)

#include "causal_inference.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <format>
#include <iostream>
#include <ranges>
#include <vector>

namespace flowshield {

namespace {

// ============================================================================
// Statistical utilities
// ============================================================================

[[nodiscard]] float chi_squared_cdf(float x, std::size_t df) noexcept {
    if (x <= 0 || df == 0) return 0.0f;
    const float k = static_cast<float>(df) / 2.0f;
    const float p = std::pow(x / 2.0f, k - 1.0f) * std::exp(-x / 2.0f);
    return 1.0f - p;  // matches the original (simplified) approximation
}

[[nodiscard]] float correlation(const float* X, const float* Y, std::size_t n) noexcept {
    if (n < 2) return 0.0f;
    float mean_X = 0.0f, mean_Y = 0.0f;
    for (std::size_t i = 0; i < n; ++i) {
        mean_X += X[i];
        mean_Y += Y[i];
    }
    mean_X /= static_cast<float>(n);
    mean_Y /= static_cast<float>(n);

    float cov = 0.0f, var_X = 0.0f, var_Y = 0.0f;
    for (std::size_t i = 0; i < n; ++i) {
        const float dx = X[i] - mean_X;
        const float dy = Y[i] - mean_Y;
        cov   += dx * dy;
        var_X += dx * dx;
        var_Y += dy * dy;
    }
    const float denom = std::sqrt(var_X * var_Y);
    return denom > 1e-10f ? (cov / denom) : 0.0f;
}

[[nodiscard]] float compute_sse(const float* residuals, std::size_t n) noexcept {
    float sse = 0.0f;
    for (std::size_t i = 0; i < n; ++i) sse += residuals[i] * residuals[i];
    return sse;
}

}  // namespace

// ============================================================================
// Conditional Independence Testing
// ============================================================================

bool causal_test_independence(const float* X,
                              const float* Y,
                              std::size_t num_samples,
                              float significance,
                              ConditionalIndependenceResult& result) {
    if (!X || !Y || num_samples < CAUSAL_MIN_SAMPLES) return false;

    result = ConditionalIndependenceResult{};
    result.test_type = CIIndependenceTest::ChiSquared;

    const float r = correlation(X, Y, num_samples);
    const float z = 0.5f * std::log((1.0f + r) / (1.0f - r + 1e-10f));
    const float se = 1.0f / std::sqrt(static_cast<float>(num_samples) - 3.0f);
    const float test_stat = std::abs(z) / se;

    result.test_statistic     = test_stat;
    result.degrees_of_freedom = num_samples - 2;
    result.p_value            = 1.0f - chi_squared_cdf(test_stat * test_stat, 1);
    result.are_independent    = result.p_value > significance;
    return true;
}

bool causal_test_conditional_independence(const float* X,
                                          const float* Y,
                                          const float* Z,
                                          std::size_t num_samples,
                                          std::size_t num_Z_vars,
                                          float significance,
                                          ConditionalIndependenceResult& result) {
    if (!X || !Y || num_samples < CAUSAL_MIN_SAMPLES) return false;
    if (!Z || num_Z_vars == 0) {
        return causal_test_independence(X, Y, num_samples, significance, result);
    }

    result = ConditionalIndependenceResult{};
    result.test_type = CIIndependenceTest::GTest;

    const float r_XY = correlation(X, Y, num_samples);
    const float* Z0  = Z;
    const float r_XZ = correlation(X, Z0, num_samples);
    const float r_YZ = correlation(Y, Z0, num_samples);

    const float numerator   = r_XY - r_XZ * r_YZ;
    const float denominator = std::sqrt((1.0f - r_XZ * r_XZ) * (1.0f - r_YZ * r_YZ));
    const float partial_r   = (denominator > 1e-10f) ? (numerator / denominator) : r_XY;

    const float z = 0.5f * std::log((1.0f + partial_r) / (1.0f - partial_r + 1e-10f));
    const float se = 1.0f / std::sqrt(static_cast<float>(num_samples) - static_cast<float>(num_Z_vars) - 3.0f);
    const float test_stat = std::abs(z) / se;

    result.test_statistic     = test_stat;
    result.degrees_of_freedom = num_samples - num_Z_vars - 2;
    result.p_value            = 1.0f - chi_squared_cdf(test_stat * test_stat, 1);
    result.are_independent    = result.p_value > significance;
    return true;
}

// ============================================================================
// CausalDAG
// ============================================================================

CausalDAG::CausalDAG(std::size_t num_nodes)
    : num_nodes_(num_nodes),
      adjacency_(num_nodes * num_nodes, 0u),
      edge_types_(num_nodes * num_nodes, CausalEdgeKind::None),
      edge_confidence_(num_nodes * num_nodes, 0.0f),
      markov_blanket_(num_nodes * num_nodes, 0u)
{}

bool CausalDAG::has_edge(std::size_t i, std::size_t j) const noexcept {
    if (i >= num_nodes_ || j >= num_nodes_) return false;
    return adjacency_[i * num_nodes_ + j] != 0;
}

void CausalDAG::get_parents(std::size_t node,
                            std::size_t* out_parents,
                            std::size_t* out_count) const {
    if (!out_parents || !out_count || node >= num_nodes_) {
        if (out_count) *out_count = 0;
        return;
    }
    std::size_t count = 0;
    for (std::size_t i = 0; i < num_nodes_; ++i) {
        if (adjacency_[i * num_nodes_ + node] != 0) {
            out_parents[count++] = i;
        }
    }
    *out_count = count;
}

void CausalDAG::print() const {
    std::cout << "\n=== Causal DAG ===\n";
    std::cout << std::format("Nodes: {}\n", num_nodes_);
    std::size_t edge_count = 0;
    for (std::size_t i = 0; i < num_nodes_; ++i) {
        for (std::size_t j = 0; j < num_nodes_; ++j) {
            if (adjacency_[i * num_nodes_ + j] != 0) {
                std::cout << std::format("  {} -> {} (conf={:.2f})\n",
                                         i, j, edge_confidence_[i * num_nodes_ + j]);
                ++edge_count;
            }
        }
    }
    std::cout << std::format("Edges: {}\n", edge_count);
    std::cout << "==================\n\n";
}

// ============================================================================
// PC algorithm (simplified, matches original C behaviour)
// ============================================================================

bool causal_pc_algorithm(const float* data,
                         std::size_t num_samples,
                         std::size_t num_variables,
                         float significance,
                         std::size_t /*max_conditioning*/,
                         CausalDAG& out_dag) {
    if (!data || num_samples < CAUSAL_MIN_SAMPLES) return false;

    // Initialise with complete undirected graph.
    for (std::size_t i = 0; i < num_variables; ++i) {
        for (std::size_t j = i + 1; j < num_variables; ++j) {
            out_dag.set_edge(i, j, true);
            out_dag.set_edge(j, i, true);
            out_dag.edge_type(i, j) = CausalEdgeKind::Undirected;
            out_dag.edge_type(j, i) = CausalEdgeKind::Undirected;
        }
    }

    for (std::size_t i = 0; i < num_variables; ++i) {
        for (std::size_t j = i + 1; j < num_variables; ++j) {
            if (!out_dag.has_edge(i, j)) continue;

            const float* X = &data[i * num_samples];
            const float* Y = &data[j * num_samples];

            ConditionalIndependenceResult result;
            if (causal_test_independence(X, Y, num_samples, significance, result)) {
                if (result.are_independent) {
                    out_dag.set_edge(i, j, false);
                    out_dag.set_edge(j, i, false);
                    out_dag.edge_type(i, j) = CausalEdgeKind::None;
                    out_dag.edge_type(j, i) = CausalEdgeKind::None;
                } else {
                    out_dag.edge_confidence(i, j) = 1.0f - result.p_value;
                    out_dag.edge_confidence(j, i) = 1.0f - result.p_value;
                }
            }
        }
    }

    return true;
}

// ============================================================================
// Granger causality
// ============================================================================

bool causal_granger_test(const float* X,
                         const float* Y,
                         std::size_t num_timesteps,
                         std::size_t max_lag,
                         float significance,
                         GrangerCausalityResult& result) {
    if (!X || !Y || num_timesteps < max_lag + CAUSAL_MIN_SAMPLES) return false;

    result = GrangerCausalityResult{};

    const std::size_t effective_n = num_timesteps - max_lag;
    std::vector<float> residuals_restricted(effective_n, 0.0f);
    std::vector<float> residuals_unrestricted(effective_n, 0.0f);

    for (std::size_t t = max_lag; t < num_timesteps; ++t) {
        const float prediction = 0.8f * Y[t - 1];
        residuals_restricted[t - max_lag] = Y[t] - prediction;
    }
    result.restricted_sse = compute_sse(residuals_restricted.data(), effective_n);

    for (std::size_t t = max_lag; t < num_timesteps; ++t) {
        const float prediction = 0.8f * Y[t - 1] + 0.3f * X[t - 1];
        residuals_unrestricted[t - max_lag] = Y[t] - prediction;
    }
    result.unrestricted_sse = compute_sse(residuals_unrestricted.data(), effective_n);

    const float sse_reduction = result.restricted_sse - result.unrestricted_sse;
    result.improvement_ratio  = sse_reduction / (result.restricted_sse + 1e-10f);

    const std::size_t df1 = max_lag;
    const std::size_t df2 = effective_n - 2 * max_lag;
    result.f_statistic = (sse_reduction / static_cast<float>(df1)) /
                         ((result.unrestricted_sse + 1e-10f) / static_cast<float>(df2));

    result.p_value           = std::exp(-result.f_statistic / 10.0f);
    result.does_granger_cause = (result.p_value < significance) &&
                                (result.improvement_ratio > 0.05f);
    result.optimal_lag = 1;

    return true;
}

// ============================================================================
// CausalProvenanceGraph
// ============================================================================

CausalProvenanceGraph::CausalProvenanceGraph(ProvenanceGraph& graph, float /*significance*/)
    : base_graph_(&graph),
      causal_dag_(std::make_unique<CausalDAG>(graph.num_nodes())),
      is_causal_edge_(graph.max_edges(), 0u),
      causal_strength_(graph.max_edges(), 0.0f),
      chains_(max_chains_)
{
    stats_.total_edges = graph.num_edges();
    std::cout << std::format(
        "[CausalProvenance] Created for graph with {} nodes, {} edges\n",
        graph.num_nodes(), graph.num_edges());
}

std::size_t CausalProvenanceGraph::identify_edges(bool /*use_temporal*/) {
    ProvenanceGraph& graph = *base_graph_;
    std::size_t causal_count = 0;

    const std::size_t num_edges = graph.num_edges();
    ProvenanceEdge*   edges     = graph.edges_data();

    for (std::size_t i = 0; i < num_edges; ++i) {
        ProvenanceEdge& edge = edges[i];

        bool  likely_causal = false;
        float strength      = 0.5f;
        switch (edge.type) {
            case EdgeType::FORK:
            case EdgeType::EXEC:
                likely_causal = true; strength = 0.95f; break;
            case EdgeType::WRITE:
            case EdgeType::SEND:
                likely_causal = true; strength = 0.80f; break;
            case EdgeType::READ:
                likely_causal = true; strength = 0.60f; break;
            case EdgeType::CONNECT:
                likely_causal = true; strength = 0.85f; break;
            default:
                likely_causal = false; strength = 0.30f; break;
        }

        is_causal_edge_[i]  = likely_causal ? 1u : 0u;
        causal_strength_[i] = strength;
        edge.is_causal      = likely_causal;
        edge.causal_weight  = strength;

        if (likely_causal) ++causal_count;
    }

    stats_.causal_edges   = causal_count;
    stats_.spurious_edges = stats_.total_edges - causal_count;
    stats_.causal_ratio   = static_cast<float>(causal_count) /
                            static_cast<float>(stats_.total_edges + 1);

    std::cout << std::format(
        "[CausalProvenance] Identified {}/{} causal edges ({:.1f}%)\n",
        causal_count, stats_.total_edges, stats_.causal_ratio * 100.0f);

    return causal_count;
}

void CausalProvenanceGraph::extract_chains(std::size_t min_length,
                                           std::size_t max_chains,
                                           CausalChain* out_chains,
                                           std::size_t* out_count) {
    if (!out_chains || !out_count) {
        if (out_count) *out_count = 0;
        return;
    }

    ProvenanceGraph& graph = *base_graph_;
    std::size_t chain_count = 0;

    const auto* node_ids = graph.node_ids_data();
    auto* nodes_arr      = graph.nodes_data();
    const std::size_t max_nodes = graph.max_nodes();
    const std::size_t total_edges_count = graph.num_edges();

    for (std::size_t i = 0; i < max_nodes && chain_count < max_chains; ++i) {
        if (node_ids[i] == static_cast<std::uint64_t>(-1)) continue;

        ProvenanceNode& node = nodes_arr[i];

        CausalChain& chain = out_chains[chain_count];
        chain = CausalChain{};

        chain.chain_id      = chain_count;
        chain.node_path[0]  = node.id;
        chain.path_length   = 1;
        chain.start_time_ns = node.first_seen_ns;

        std::uint64_t current_node = node.id;

        for (std::size_t depth = 1; depth < 256; ++depth) {
            ProvenanceNode* curr = graph.get_node(current_node);
            if (!curr || curr->out_degree == 0) break;

            bool found_causal = false;
            for (std::size_t j = 0; j < curr->out_degree; ++j) {
                const std::uint64_t edge_id = curr->out_edges[j];
                if (edge_id >= total_edges_count) continue;
                if (is_causal_edge_[edge_id] == 0) continue;

                ProvenanceEdge* edge = graph.get_edge(edge_id);
                if (!edge) continue;

                chain.edge_path[depth - 1] = edge_id;
                chain.node_path[depth]     = edge->dst_node;
                ++chain.path_length;
                chain.end_time_ns          = edge->timestamp_ns;

                chain.causal_score += causal_strength_[edge_id];
                current_node = edge->dst_node;
                found_causal = true;
                break;
            }
            if (!found_causal) break;
        }

        if (chain.path_length > 1) {
            chain.causal_score /= static_cast<float>(chain.path_length - 1);
        }

        if (chain.path_length >= min_length) {
            ++chain_count;
        }
    }

    *out_count = chain_count;
    num_chains_ = chain_count;

    std::cout << std::format(
        "[CausalProvenance] Extracted {} causal chains (min_length={})\n",
        chain_count, min_length);
}

void CausalProvenanceGraph::print_stats() const {
    std::cout << "\n=== Causal Provenance Statistics ===\n";
    std::cout << std::format("Total edges:     {}\n",         stats_.total_edges);
    std::cout << std::format("Causal edges:    {} ({:.1f}%)\n",
                             stats_.causal_edges, stats_.causal_ratio * 100.0f);
    std::cout << std::format("Spurious edges:  {}\n",         stats_.spurious_edges);
    std::cout << std::format("Causal chains:   {}\n",         num_chains_);
    std::cout << "====================================\n\n";
}

// ============================================================================
// Chain scoring / ranking
// ============================================================================

float causal_score_chain(const CausalChain& chain,
                         const CausalProvenanceGraph& /*cpg*/) {
    if (chain.path_length == 0) return 0.0f;
    return chain.causal_score;
}

void causal_rank_chains(const CausalChain* chains,
                        std::size_t num_chains,
                        const CausalProvenanceGraph& /*cpg*/,
                        CausalChain* out_ranked) {
    if (!chains || !out_ranked || num_chains == 0) return;

    std::memcpy(out_ranked, chains, num_chains * sizeof(CausalChain));
    std::ranges::sort(out_ranked, out_ranked + num_chains,
                      [](const CausalChain& a, const CausalChain& b) {
                          return a.causal_score > b.causal_score;
                      });
}

// ============================================================================
// Stubs for advanced operations (preserved from C placeholder behaviour)
// ============================================================================

bool causal_do_calculus(const CausalDAG& /*dag*/,
                        const Intervention& /*intervention*/,
                        std::size_t /*target_variable*/,
                        const float* /*data*/,
                        std::size_t /*num_samples*/,
                        float* /*out_distribution*/,
                        std::size_t /*num_bins*/) {
    return false;
}

bool causal_compute_effect(const CausalDAG& /*dag*/,
                           std::size_t /*cause_variable*/,
                           std::size_t /*effect_variable*/,
                           const float* /*data*/,
                           std::size_t /*num_samples*/,
                           float& /*out_effect*/) {
    return false;
}

bool causal_counterfactual(const CausalDAG& /*dag*/,
                           CounterfactualQuery& /*query*/,
                           const float* /*data*/,
                           std::size_t /*num_samples*/) {
    return false;
}

float causal_mutual_information(const float* /*X*/,
                                const float* /*Y*/,
                                std::size_t /*num_samples*/) {
    return 0.0f;
}

float causal_conditional_mutual_information(const float* /*X*/,
                                            const float* /*Y*/,
                                            const float* /*Z*/,
                                            std::size_t /*num_samples*/,
                                            std::size_t /*num_Z_vars*/) {
    return 0.0f;
}

void causal_dag_export_dot(const CausalDAG& /*dag*/, const char* /*filename*/) {
    // Original C left this unimplemented; preserve behaviour.
}

}  // namespace flowshield
