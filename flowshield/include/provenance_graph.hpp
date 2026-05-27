// Provenance Graph for APT Detection (C++23 migration)
//
// Represents system behavior as a directed graph where nodes are system
// entities (processes, files, sockets, registry, users) and edges are
// syscalls/operations (fork, exec, read, write, connect, ...).
//
// Designed for scalability (millions of nodes) and temporal analysis.

#pragma once

#include "common.hpp"

#include <array>
#include <cstdint>
#include <cstddef>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string_view>
#include <vector>

namespace flowshield {

// ============================================================================
// Configuration
// ============================================================================

inline constexpr std::size_t PG_MAX_NODES        = 1'000'000;
inline constexpr std::size_t PG_MAX_EDGES        = 5'000'000;
inline constexpr std::size_t PG_NODE_FEATURE_DIM = 64;
inline constexpr std::size_t PG_EDGE_FEATURE_DIM = 32;
inline constexpr std::uint64_t PG_TEMPORAL_WINDOW_SEC = 3600;
inline constexpr std::size_t PG_MAX_NEIGHBORS    = 256;

// ============================================================================
// Node Types (System Entities)
// ============================================================================

enum class NodeType : std::uint8_t {
    PROCESS = 0,
    FILE,
    SOCKET,
    REGISTRY,
    USER,
    MEMORY,
    KERNEL_MODULE,
    UNKNOWN,
};

// ============================================================================
// Edge Types (System Operations)
// ============================================================================

enum class EdgeType : std::uint8_t {
    FORK = 0,
    EXEC,
    READ,
    WRITE,
    CONNECT,
    BIND,
    SEND,
    RECV,
    OPEN,
    CLOSE,
    DELETE,
    RENAME,
    CHMOD,
    CLONE,
    KILL,
    MMAP,
    MPROTECT,
    LOAD_MODULE,
    SETUID,
    SUDO,
    DNS_QUERY,
    HTTP_REQUEST,
    UNKNOWN,
};

// ============================================================================
// Node-type-specific metadata
// ============================================================================

struct ProcessMeta {
    std::uint32_t pid       = 0;
    std::uint32_t ppid      = 0;
    char          cmdline[256]  {};
    char          exe_path[256] {};
    std::uint32_t uid       = 0;
    std::uint32_t gid       = 0;
    std::uint64_t start_time = 0;
};

struct FileMeta {
    char          path[512] {};
    std::uint32_t inode = 0;
    std::uint16_t mode  = 0;
    std::uint64_t size  = 0;
    std::uint64_t mtime = 0;
};

struct SocketMeta {
    std::uint32_t local_ip    = 0;
    std::uint32_t remote_ip   = 0;
    std::uint16_t local_port  = 0;
    std::uint16_t remote_port = 0;
    std::uint8_t  protocol    = 0;
};

struct RegistryMeta {
    char key_path[512]   {};
    char value_name[256] {};
};

struct UserMeta {
    std::uint32_t uid = 0;
    char          username[128] {};
};

// Tagged-union-style metadata. Discriminated by ProvenanceNode::type.
union NodeMetaUnion {
    ProcessMeta  process;
    FileMeta     file;
    SocketMeta   socket;
    RegistryMeta registry;
    UserMeta     user;

    NodeMetaUnion() noexcept : process{} {}
};

// ============================================================================
// Node Structure
// ============================================================================

struct ProvenanceNode {
    std::uint64_t id = 0;
    NodeType      type = NodeType::UNKNOWN;

    NodeMetaUnion meta {};

    // Graph structure
    std::uint64_t in_edges [PG_MAX_NEIGHBORS] {};
    std::uint64_t out_edges[PG_MAX_NEIGHBORS] {};
    std::uint16_t in_degree  = 0;
    std::uint16_t out_degree = 0;

    // Features for GNN
    float features [PG_NODE_FEATURE_DIM] {};
    float embedding[PG_NODE_FEATURE_DIM] {};

    // Temporal tracking
    std::uint64_t first_seen_ns = 0;
    std::uint64_t last_seen_ns  = 0;
    std::uint32_t event_count   = 0;

    // Anomaly scores
    float anomaly_score = 0.0f;
    float causal_score  = 0.0f;

    // Flags
    std::uint8_t is_suspicious : 1 {0};
    std::uint8_t is_critical   : 1 {0};
    std::uint8_t is_external   : 1 {0};
    std::uint8_t is_root       : 1 {0};
    std::uint8_t _reserved     : 4 {0};
};

// ============================================================================
// Edge Structure
// ============================================================================

struct EdgeIoDetails {
    std::uint64_t bytes_read = 0;
    std::uint32_t flags      = 0;
};

struct EdgeExecDetails {
    char target_path[256] {};
    char args[512]        {};
};

struct EdgeNetworkDetails {
    std::uint64_t bytes_sent = 0;
    std::uint64_t bytes_recv = 0;
};

union EdgeDetailsUnion {
    EdgeIoDetails      io;
    EdgeExecDetails    exec;
    EdgeNetworkDetails network;

    EdgeDetailsUnion() noexcept : io{} {}
};

struct ProvenanceEdge {
    std::uint64_t id       = 0;
    std::uint64_t src_node = 0;
    std::uint64_t dst_node = 0;
    EdgeType      type     = EdgeType::UNKNOWN;

    std::uint64_t timestamp_ns = 0;
    std::uint64_t duration_ns  = 0;

    EdgeDetailsUnion details {};

    float features[PG_EDGE_FEATURE_DIM] {};
    float attention_score = 0.0f;

    float causal_weight = 0.0f;
    bool  is_causal     = false;

    std::uint8_t is_suspicious : 1 {0};
    std::uint8_t is_rare       : 1 {0};
    std::uint8_t _reserved     : 6 {0};
};

// ============================================================================
// Causal Chain (used by causal_inference.hpp)
// ============================================================================

enum class APTPhaseLegacy : std::uint8_t {
    RECONNAISSANCE = 0,
    WEAPONIZATION,
    DELIVERY,
    EXPLOITATION,
    INSTALLATION,
    C2,
    EXFILTRATION,
    UNKNOWN,
};

struct CausalChain {
    std::uint64_t chain_id = 0;
    std::uint64_t node_path[256] {};
    std::uint64_t edge_path[256] {};
    std::size_t   path_length = 0;

    std::uint64_t start_time_ns = 0;
    std::uint64_t end_time_ns   = 0;

    float anomaly_score = 0.0f;
    float causal_score  = 0.0f;
    float apt_likelihood = 0.0f;

    APTPhaseLegacy apt_phase = APTPhaseLegacy::UNKNOWN;

    char description[512] {};
};

// ============================================================================
// Provenance Graph
// ============================================================================

struct ProvenanceGraphStats {
    std::uint64_t total_events      = 0;
    std::uint64_t suspicious_events = 0;
    std::uint64_t causal_chains     = 0;
    double avg_node_degree          = 0.0;
    double graph_density            = 0.0;
};

class ProvenanceGraph {
public:
    ProvenanceGraph(std::size_t max_nodes, std::size_t max_edges);
    ~ProvenanceGraph() = default;

    ProvenanceGraph(const ProvenanceGraph&)            = delete;
    ProvenanceGraph& operator=(const ProvenanceGraph&) = delete;
    ProvenanceGraph(ProvenanceGraph&&)                 = delete;
    ProvenanceGraph& operator=(ProvenanceGraph&&)      = delete;

    void clear();

    // ----- Node operations -----
    // Returns the new node id, or std::nullopt if the graph is full.
    std::optional<std::uint64_t> add_node(NodeType type, const void* metadata = nullptr);
    [[nodiscard]] ProvenanceNode* get_node(std::uint64_t node_id);
    [[nodiscard]] ProvenanceNode* find_node_by_pid(std::uint32_t pid);
    [[nodiscard]] ProvenanceNode* find_node_by_path(std::string_view path);

    // ----- Edge operations -----
    std::optional<std::uint64_t> add_edge(std::uint64_t src,
                                          std::uint64_t dst,
                                          EdgeType type,
                                          std::uint64_t timestamp_ns = 0);
    [[nodiscard]] ProvenanceEdge* get_edge(std::uint64_t edge_id);

    // ----- Graph queries -----
    void get_neighbors    (std::uint64_t node_id, std::uint64_t* out_neighbors, std::size_t* out_count);
    void get_in_neighbors (std::uint64_t node_id, std::uint64_t* out_neighbors, std::size_t* out_count);
    void get_out_neighbors(std::uint64_t node_id, std::uint64_t* out_neighbors, std::size_t* out_count);

    // ----- Temporal operations -----
    void advance_window(std::uint64_t new_end_ns);
    void prune_old_nodes(std::uint64_t cutoff_ns);

    // ----- Causal analysis -----
    void extract_causal_chains(CausalChain* out_chains,
                               std::size_t max_chains,
                               std::size_t* out_count);
    [[nodiscard]] bool is_causal_edge(std::uint64_t edge_id);

    // ----- Statistics -----
    void compute_stats();
    void print_stats() const;

    // ----- Visualization/Export -----
    void export_dot (const char* filename) const;
    void export_json(const char* filename) const;

    // ----- Accessors -----
    [[nodiscard]] std::size_t num_nodes() const noexcept { return num_nodes_; }
    [[nodiscard]] std::size_t num_edges() const noexcept { return num_edges_; }
    [[nodiscard]] std::size_t max_nodes() const noexcept { return max_nodes_; }
    [[nodiscard]] std::size_t max_edges() const noexcept { return max_edges_; }

    [[nodiscard]] std::uint64_t window_start_ns() const noexcept { return window_start_ns_; }
    [[nodiscard]] std::uint64_t window_end_ns()   const noexcept { return window_end_ns_; }

    [[nodiscard]] const ProvenanceGraphStats& stats() const noexcept { return stats_; }

    // Raw storage access (needed by GNN code that walks the dense arrays).
    // Use with the graph lock held externally if multi-threading; current
    // GNN code is single-threaded against the graph during forward passes.
    [[nodiscard]] ProvenanceNode*       nodes_data()       noexcept { return nodes_.data(); }
    [[nodiscard]] const ProvenanceNode* nodes_data() const noexcept { return nodes_.data(); }
    [[nodiscard]] ProvenanceEdge*       edges_data()       noexcept { return edges_.data(); }
    [[nodiscard]] const ProvenanceEdge* edges_data() const noexcept { return edges_.data(); }
    [[nodiscard]] const std::uint64_t*  node_ids_data() const noexcept { return node_ids_.data(); }

private:
    static constexpr std::uint64_t kEmptySlot = static_cast<std::uint64_t>(-1);

    [[nodiscard]] static std::uint64_t hash_node_id(std::uint64_t id) noexcept;

    std::vector<ProvenanceNode> nodes_;
    std::vector<std::uint64_t>  node_ids_;
    std::size_t                 num_nodes_ = 0;
    std::size_t                 max_nodes_ = 0;

    std::vector<ProvenanceEdge> edges_;
    std::size_t                 num_edges_ = 0;
    std::size_t                 max_edges_ = 0;

    std::uint64_t window_start_ns_ = 0;
    std::uint64_t window_end_ns_   = 0;

    ProvenanceGraphStats stats_ {};

    mutable std::shared_mutex lock_;
};

// ============================================================================
// Free functions for feature extraction (used by the GNN layer).
// ============================================================================

void pg_extract_node_features(const ProvenanceNode& node, float* out_features);
void pg_extract_edge_features(const ProvenanceEdge& edge, float* out_features);

}  // namespace flowshield
