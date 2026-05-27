// Provenance Graph Implementation (C++23 migration of provenance_graph.c)

#include "provenance_graph.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <format>
#include <iostream>
#include <mutex>
#include <shared_mutex>
#include <string_view>

namespace flowshield {

namespace {

[[nodiscard]] std::uint64_t now_ns() noexcept {
    using clock = std::chrono::steady_clock;
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            clock::now().time_since_epoch()).count());
}

}  // namespace

// ============================================================================
// Hash helper
// ============================================================================

std::uint64_t ProvenanceGraph::hash_node_id(std::uint64_t id) noexcept {
    id ^= id >> 33;
    id *= 0xff51afd7ed558ccdULL;
    id ^= id >> 33;
    id *= 0xc4ceb9fe1a85ec53ULL;
    id ^= id >> 33;
    return id;
}

// ============================================================================
// Lifecycle
// ============================================================================

ProvenanceGraph::ProvenanceGraph(std::size_t max_nodes, std::size_t max_edges)
    : nodes_(max_nodes),
      node_ids_(max_nodes, kEmptySlot),
      max_nodes_(max_nodes),
      edges_(max_edges),
      max_edges_(max_edges)
{
    window_start_ns_ = now_ns();
    window_end_ns_   = window_start_ns_ + (PG_TEMPORAL_WINDOW_SEC * 1'000'000'000ULL);

    std::cout << std::format("[ProvenanceGraph] Created with capacity: {} nodes, {} edges\n",
                             max_nodes, max_edges);
}

void ProvenanceGraph::clear() {
    std::unique_lock lock(lock_);
    num_nodes_ = 0;
    num_edges_ = 0;
    std::ranges::fill(node_ids_, kEmptySlot);
    stats_ = {};
}

// ============================================================================
// Node Operations
// ============================================================================

std::optional<std::uint64_t> ProvenanceGraph::add_node(NodeType type, const void* metadata) {
    std::unique_lock lock(lock_);

    if (num_nodes_ >= max_nodes_) [[unlikely]] {
        return std::nullopt;
    }

    const std::uint64_t node_id = num_nodes_;

    // Linear-probed open-addressing slot lookup.
    const std::uint64_t hash = hash_node_id(node_id);
    std::size_t slot = static_cast<std::size_t>(hash) % max_nodes_;
    while (node_ids_[slot] != kEmptySlot) {
        slot = (slot + 1) % max_nodes_;
    }

    ProvenanceNode& node = nodes_[slot];
    node = ProvenanceNode{};
    node.id   = node_id;
    node.type = type;
    node.first_seen_ns = now_ns();
    node.last_seen_ns  = node.first_seen_ns;

    if (metadata) {
        switch (type) {
            case NodeType::PROCESS:
                std::memcpy(&node.meta.process, metadata, sizeof(ProcessMeta));
                node.is_root = (node.meta.process.uid == 0) ? 1 : 0;
                break;
            case NodeType::FILE:
                std::memcpy(&node.meta.file, metadata, sizeof(FileMeta));
                break;
            case NodeType::SOCKET: {
                std::memcpy(&node.meta.socket, metadata, sizeof(SocketMeta));
                const std::uint32_t ip = node.meta.socket.remote_ip;
                const bool is_private =
                    ((ip >> 24) == 10) ||
                    (((ip >> 24) == 172) && (((ip >> 16) & 0xF0) == 16)) ||
                    (((ip >> 24) == 192) && ((ip >> 16) == 168));
                node.is_external = is_private ? 0 : 1;
                break;
            }
            case NodeType::REGISTRY:
                std::memcpy(&node.meta.registry, metadata, sizeof(RegistryMeta));
                break;
            case NodeType::USER:
                std::memcpy(&node.meta.user, metadata, sizeof(UserMeta));
                break;
            default:
                break;
        }
    }

    node_ids_[slot] = node_id;
    ++num_nodes_;

    return node_id;
}

ProvenanceNode* ProvenanceGraph::get_node(std::uint64_t node_id) {
    std::shared_lock lock(lock_);

    const std::uint64_t hash = hash_node_id(node_id);
    std::size_t slot = static_cast<std::size_t>(hash) % max_nodes_;

    for (std::size_t i = 0; i < max_nodes_; ++i) {
        if (node_ids_[slot] == node_id) {
            return &nodes_[slot];
        }
        if (node_ids_[slot] == kEmptySlot) {
            return nullptr;
        }
        slot = (slot + 1) % max_nodes_;
    }
    return nullptr;
}

ProvenanceNode* ProvenanceGraph::find_node_by_pid(std::uint32_t pid) {
    std::shared_lock lock(lock_);
    for (std::size_t i = 0; i < max_nodes_; ++i) {
        if (node_ids_[i] != kEmptySlot) {
            ProvenanceNode& node = nodes_[i];
            if (node.type == NodeType::PROCESS && node.meta.process.pid == pid) {
                return &node;
            }
        }
    }
    return nullptr;
}

ProvenanceNode* ProvenanceGraph::find_node_by_path(std::string_view path) {
    std::shared_lock lock(lock_);
    for (std::size_t i = 0; i < max_nodes_; ++i) {
        if (node_ids_[i] == kEmptySlot) continue;
        ProvenanceNode& node = nodes_[i];
        if (node.type == NodeType::FILE) {
            if (path == std::string_view{node.meta.file.path}) {
                return &node;
            }
        } else if (node.type == NodeType::PROCESS) {
            if (path == std::string_view{node.meta.process.exe_path}) {
                return &node;
            }
        }
    }
    return nullptr;
}

// ============================================================================
// Edge Operations
// ============================================================================

std::optional<std::uint64_t> ProvenanceGraph::add_edge(std::uint64_t src,
                                                       std::uint64_t dst,
                                                       EdgeType type,
                                                       std::uint64_t timestamp_ns) {
    std::unique_lock lock(lock_);

    if (num_edges_ >= max_edges_) [[unlikely]] {
        return std::nullopt;
    }

    const std::uint64_t edge_id = num_edges_;
    ProvenanceEdge& edge = edges_[edge_id];
    edge = ProvenanceEdge{};
    edge.id          = edge_id;
    edge.src_node    = src;
    edge.dst_node    = dst;
    edge.type        = type;
    edge.timestamp_ns = timestamp_ns ? timestamp_ns : now_ns();

    // Update node adjacency (manual hash-table lookup without re-locking).
    auto lookup_node = [&](std::uint64_t nid) -> ProvenanceNode* {
        const std::uint64_t h = hash_node_id(nid);
        std::size_t s = static_cast<std::size_t>(h) % max_nodes_;
        for (std::size_t i = 0; i < max_nodes_; ++i) {
            if (node_ids_[s] == nid) return &nodes_[s];
            if (node_ids_[s] == kEmptySlot) return nullptr;
            s = (s + 1) % max_nodes_;
        }
        return nullptr;
    };

    ProvenanceNode* src_node = lookup_node(src);
    ProvenanceNode* dst_node = lookup_node(dst);

    if (src_node && src_node->out_degree < PG_MAX_NEIGHBORS) {
        src_node->out_edges[src_node->out_degree++] = edge_id;
        src_node->last_seen_ns = edge.timestamp_ns;
        ++src_node->event_count;
    }
    if (dst_node && dst_node->in_degree < PG_MAX_NEIGHBORS) {
        dst_node->in_edges[dst_node->in_degree++] = edge_id;
        dst_node->last_seen_ns = edge.timestamp_ns;
        ++dst_node->event_count;
    }

    ++num_edges_;
    ++stats_.total_events;
    return edge_id;
}

ProvenanceEdge* ProvenanceGraph::get_edge(std::uint64_t edge_id) {
    if (edge_id >= num_edges_) return nullptr;
    return &edges_[edge_id];
}

// ============================================================================
// Graph Queries
// ============================================================================

void ProvenanceGraph::get_neighbors(std::uint64_t node_id,
                                    std::uint64_t* out_neighbors,
                                    std::size_t* out_count) {
    if (!out_neighbors || !out_count) return;

    ProvenanceNode* node = get_node(node_id);
    if (!node) {
        *out_count = 0;
        return;
    }

    std::size_t count = 0;
    for (std::size_t i = 0; i < node->out_degree; ++i) {
        if (ProvenanceEdge* edge = get_edge(node->out_edges[i])) {
            out_neighbors[count++] = edge->dst_node;
        }
    }
    for (std::size_t i = 0; i < node->in_degree; ++i) {
        if (ProvenanceEdge* edge = get_edge(node->in_edges[i])) {
            out_neighbors[count++] = edge->src_node;
        }
    }
    *out_count = count;
}

void ProvenanceGraph::get_out_neighbors(std::uint64_t node_id,
                                        std::uint64_t* out_neighbors,
                                        std::size_t* out_count) {
    if (!out_neighbors || !out_count) return;

    ProvenanceNode* node = get_node(node_id);
    if (!node) {
        *out_count = 0;
        return;
    }

    std::size_t count = 0;
    for (std::size_t i = 0; i < node->out_degree; ++i) {
        if (ProvenanceEdge* edge = get_edge(node->out_edges[i])) {
            out_neighbors[count++] = edge->dst_node;
        }
    }
    *out_count = count;
}

void ProvenanceGraph::get_in_neighbors(std::uint64_t node_id,
                                       std::uint64_t* out_neighbors,
                                       std::size_t* out_count) {
    if (!out_neighbors || !out_count) return;

    ProvenanceNode* node = get_node(node_id);
    if (!node) {
        *out_count = 0;
        return;
    }

    std::size_t count = 0;
    for (std::size_t i = 0; i < node->in_degree; ++i) {
        if (ProvenanceEdge* edge = get_edge(node->in_edges[i])) {
            out_neighbors[count++] = edge->src_node;
        }
    }
    *out_count = count;
}

// ============================================================================
// Temporal Operations
// ============================================================================

void ProvenanceGraph::advance_window(std::uint64_t new_end_ns) {
    std::unique_lock lock(lock_);
    window_end_ns_   = new_end_ns;
    window_start_ns_ = new_end_ns - (PG_TEMPORAL_WINDOW_SEC * 1'000'000'000ULL);
}

void ProvenanceGraph::prune_old_nodes(std::uint64_t cutoff_ns) {
    std::unique_lock lock(lock_);

    std::size_t removed = 0;
    for (std::size_t i = 0; i < max_nodes_; ++i) {
        if (node_ids_[i] == kEmptySlot) continue;
        ProvenanceNode& node = nodes_[i];
        if (node.last_seen_ns < cutoff_ns && node.is_critical == 0) {
            node_ids_[i] = kEmptySlot;
            ++removed;
        }
    }

    if (removed > 0) {
        std::cout << std::format("[ProvenanceGraph] Pruned {} old nodes\n", removed);
    }
}

// ============================================================================
// Statistics
// ============================================================================

void ProvenanceGraph::compute_stats() {
    std::shared_lock lock(lock_);

    std::uint64_t total_degree = 0;
    for (std::size_t i = 0; i < max_nodes_; ++i) {
        if (node_ids_[i] != kEmptySlot) {
            const ProvenanceNode& node = nodes_[i];
            total_degree += static_cast<std::uint64_t>(node.in_degree) +
                            static_cast<std::uint64_t>(node.out_degree);
        }
    }
    stats_.avg_node_degree = static_cast<double>(total_degree) /
                              static_cast<double>(num_nodes_ + 1);

    const std::uint64_t denom = static_cast<std::uint64_t>(num_nodes_) *
                                static_cast<std::uint64_t>(num_nodes_ - 1);
    stats_.graph_density = static_cast<double>(num_edges_) /
                            static_cast<double>(denom + 1);
}

void ProvenanceGraph::print_stats() const {
    std::cout << "\n=== Provenance Graph Statistics ===\n";
    std::cout << std::format("Nodes:      {} / {} ({:.1f}% full)\n",
                             num_nodes_, max_nodes_,
                             100.0 * static_cast<double>(num_nodes_) / static_cast<double>(max_nodes_));
    std::cout << std::format("Edges:      {} / {} ({:.1f}% full)\n",
                             num_edges_, max_edges_,
                             100.0 * static_cast<double>(num_edges_) / static_cast<double>(max_edges_));
    std::cout << std::format("Avg Degree: {:.2f}\n", stats_.avg_node_degree);
    std::cout << std::format("Density:    {:.6f}\n", stats_.graph_density);
    std::cout << std::format("Events:     {} total, {} suspicious\n",
                             stats_.total_events, stats_.suspicious_events);
    std::cout << "===================================\n\n";
}

// ============================================================================
// Causal Analysis (Simplified placeholder, like original)
// ============================================================================

void ProvenanceGraph::extract_causal_chains(CausalChain* /*out_chains*/,
                                            std::size_t  /*max_chains*/,
                                            std::size_t* out_count) {
    if (out_count) *out_count = 0;
}

bool ProvenanceGraph::is_causal_edge(std::uint64_t edge_id) {
    ProvenanceEdge* edge = get_edge(edge_id);
    return edge ? edge->is_causal : false;
}

void ProvenanceGraph::export_dot (const char* /*filename*/) const {}
void ProvenanceGraph::export_json(const char* /*filename*/) const {}

// ============================================================================
// Feature Extraction (free functions)
// ============================================================================

void pg_extract_node_features(const ProvenanceNode& node, float* out_features) {
    if (!out_features) return;

    std::fill_n(out_features, PG_NODE_FEATURE_DIM, 0.0f);

    // Type one-hot encoding [0-7]
    const auto type_idx = static_cast<std::size_t>(node.type);
    if (type_idx < 8) out_features[type_idx] = 1.0f;

    // Degree features [8-11]
    out_features[8]  = static_cast<float>(node.in_degree)  / static_cast<float>(PG_MAX_NEIGHBORS);
    out_features[9]  = static_cast<float>(node.out_degree) / static_cast<float>(PG_MAX_NEIGHBORS);
    out_features[10] = static_cast<float>(node.in_degree + node.out_degree) /
                       (2.0f * static_cast<float>(PG_MAX_NEIGHBORS));

    // Temporal features [12-15]
    const std::uint64_t age_ns = now_ns() - node.first_seen_ns;
    out_features[12] = std::min(static_cast<float>(age_ns) / 3'600e9f, 1.0f);
    out_features[13] = std::min(static_cast<float>(node.event_count) / 1000.0f, 1.0f);

    // Flags [16-19]
    out_features[16] = node.is_suspicious ? 1.0f : 0.0f;
    out_features[17] = node.is_critical   ? 1.0f : 0.0f;
    out_features[18] = node.is_external   ? 1.0f : 0.0f;
    out_features[19] = node.is_root       ? 1.0f : 0.0f;

    // Anomaly scores [20-22]
    out_features[20] = node.anomaly_score;
    out_features[21] = node.causal_score;

    // Node-specific features [23+]
    if (node.type == NodeType::PROCESS) {
        out_features[23] = static_cast<float>(node.meta.process.uid) / 65535.0f;
        out_features[24] = (node.meta.process.ppid > 0) ? 1.0f : 0.0f;
    } else if (node.type == NodeType::SOCKET) {
        out_features[25] = static_cast<float>(node.meta.socket.local_port)  / 65535.0f;
        out_features[26] = static_cast<float>(node.meta.socket.remote_port) / 65535.0f;
        out_features[27] = (node.meta.socket.protocol == 6) ? 1.0f : 0.0f; // TCP
    }
}

void pg_extract_edge_features(const ProvenanceEdge& edge, float* out_features) {
    if (!out_features) return;

    std::fill_n(out_features, PG_EDGE_FEATURE_DIM, 0.0f);

    // Type one-hot encoding [0-23]
    const auto type_idx = static_cast<std::size_t>(edge.type);
    if (type_idx < 24) {
        out_features[type_idx] = 1.0f;
    }

    // Temporal features
    const std::uint64_t age_ns = now_ns() - edge.timestamp_ns;
    out_features[24] = std::min(static_cast<float>(age_ns) / 3'600e9f, 1.0f);
    out_features[25] = std::min(static_cast<float>(edge.duration_ns) / 1e9f, 1.0f);

    out_features[26] = edge.is_suspicious ? 1.0f : 0.0f;
    out_features[27] = edge.is_rare       ? 1.0f : 0.0f;
    out_features[28] = edge.is_causal     ? 1.0f : 0.0f;

    out_features[29] = edge.causal_weight;
    out_features[30] = edge.attention_score;
}

}  // namespace flowshield
