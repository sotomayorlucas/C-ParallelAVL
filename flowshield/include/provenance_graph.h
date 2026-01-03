/**
 * Provenance Graph for APT Detection
 *
 * Represents system behavior as a directed graph where:
 *   - Nodes = system entities (processes, files, sockets, registry, users)
 *   - Edges = syscalls/operations (fork, exec, read, write, connect, etc.)
 *
 * Designed for scalability (millions of nodes) and temporal analysis.
 */

#ifndef FLOWSHIELD_PROVENANCE_GRAPH_H
#define FLOWSHIELD_PROVENANCE_GRAPH_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Configuration
 * ============================================================================ */

#define PG_MAX_NODES            1000000     /* Max entities in graph */
#define PG_MAX_EDGES            5000000     /* Max syscalls/operations */
#define PG_NODE_FEATURE_DIM     64          /* Node feature vector size */
#define PG_EDGE_FEATURE_DIM     32          /* Edge feature vector size */
#define PG_TEMPORAL_WINDOW      3600        /* Temporal window (seconds) */
#define PG_MAX_NEIGHBORS        256         /* Max neighbors per node */

/* ============================================================================
 * Node Types (System Entities)
 * ============================================================================ */

typedef enum {
    NODE_PROCESS = 0,       /* Running process */
    NODE_FILE,              /* File (regular, device, pipe) */
    NODE_SOCKET,            /* Network socket */
    NODE_REGISTRY,          /* Windows registry key */
    NODE_USER,              /* User/principal */
    NODE_MEMORY,            /* Memory region */
    NODE_KERNEL_MODULE,     /* Kernel module/driver */
    NODE_UNKNOWN
} NodeType;

/* ============================================================================
 * Edge Types (System Operations)
 * ============================================================================ */

typedef enum {
    EDGE_FORK = 0,          /* Process creation */
    EDGE_EXEC,              /* Execute binary */
    EDGE_READ,              /* Read from file/socket */
    EDGE_WRITE,             /* Write to file/socket */
    EDGE_CONNECT,           /* Network connection */
    EDGE_BIND,              /* Bind to port */
    EDGE_SEND,              /* Send data */
    EDGE_RECV,              /* Receive data */
    EDGE_OPEN,              /* Open file */
    EDGE_CLOSE,             /* Close file descriptor */
    EDGE_DELETE,            /* Delete file */
    EDGE_RENAME,            /* Rename file */
    EDGE_CHMOD,             /* Change permissions */
    EDGE_CLONE,             /* Clone/fork */
    EDGE_KILL,              /* Signal/kill process */
    EDGE_MMAP,              /* Memory map */
    EDGE_MPROTECT,          /* Change memory protection */
    EDGE_LOAD_MODULE,       /* Load kernel module */
    EDGE_SETUID,            /* Change user ID */
    EDGE_SUDO,              /* Privilege escalation */
    EDGE_DNS_QUERY,         /* DNS lookup */
    EDGE_HTTP_REQUEST,      /* HTTP request */
    EDGE_UNKNOWN
} EdgeType;

/* ============================================================================
 * Node Structure
 * ============================================================================ */

typedef struct {
    uint64_t id;                        /* Unique node ID */
    NodeType type;                      /* Entity type */

    /* Entity metadata */
    union {
        struct {
            uint32_t pid;               /* Process ID */
            uint32_t ppid;              /* Parent PID */
            char cmdline[256];          /* Command line */
            char exe_path[256];         /* Executable path */
            uint32_t uid;               /* User ID */
            uint32_t gid;               /* Group ID */
            uint64_t start_time;        /* Process start time */
        } process;

        struct {
            char path[512];             /* File path */
            uint32_t inode;             /* Inode number */
            uint16_t mode;              /* Permissions */
            uint64_t size;              /* File size */
            uint64_t mtime;             /* Modification time */
        } file;

        struct {
            uint32_t local_ip;          /* Local IP */
            uint32_t remote_ip;         /* Remote IP */
            uint16_t local_port;        /* Local port */
            uint16_t remote_port;       /* Remote port */
            uint8_t protocol;           /* TCP/UDP */
        } socket;

        struct {
            char key_path[512];         /* Registry key path */
            char value_name[256];       /* Value name */
        } registry;

        struct {
            uint32_t uid;               /* User ID */
            char username[128];         /* Username */
        } user;
    } meta;

    /* Graph structure */
    uint64_t in_edges[PG_MAX_NEIGHBORS];    /* Incoming edge IDs */
    uint64_t out_edges[PG_MAX_NEIGHBORS];   /* Outgoing edge IDs */
    uint16_t in_degree;                     /* Number of in-edges */
    uint16_t out_degree;                    /* Number of out-edges */

    /* Features for GNN */
    float features[PG_NODE_FEATURE_DIM];    /* Node feature vector */
    float embedding[PG_NODE_FEATURE_DIM];   /* Learned embedding (output) */

    /* Temporal tracking */
    uint64_t first_seen_ns;                 /* First observation */
    uint64_t last_seen_ns;                  /* Last observation */
    uint32_t event_count;                   /* Number of events */

    /* Anomaly scores */
    float anomaly_score;                    /* Node-level anomaly score */
    float causal_score;                     /* Causal importance score */

    /* Flags */
    uint8_t is_suspicious:1;                /* Flagged as suspicious */
    uint8_t is_critical:1;                  /* Critical system entity */
    uint8_t is_external:1;                  /* External (e.g., internet IP) */
    uint8_t is_root:1;                      /* Root/admin privilege */
    uint8_t _reserved:4;
} ProvenanceNode;

/* ============================================================================
 * Edge Structure
 * ============================================================================ */

typedef struct {
    uint64_t id;                        /* Unique edge ID */
    uint64_t src_node;                  /* Source node ID */
    uint64_t dst_node;                  /* Destination node ID */
    EdgeType type;                      /* Operation type */

    /* Temporal info */
    uint64_t timestamp_ns;              /* When operation occurred */
    uint64_t duration_ns;               /* Operation duration */

    /* Operation details */
    union {
        struct {
            uint64_t bytes_read;        /* Bytes transferred */
            uint32_t flags;             /* Syscall flags */
        } io;

        struct {
            char target_path[256];      /* Exec target */
            char args[512];             /* Arguments */
        } exec;

        struct {
            uint64_t bytes_sent;
            uint64_t bytes_recv;
        } network;
    } details;

    /* Features for GNN */
    float features[PG_EDGE_FEATURE_DIM];    /* Edge feature vector */
    float attention_score;                  /* GAT attention weight */

    /* Causal analysis */
    float causal_weight;                    /* Causal strength */
    bool is_causal;                         /* True causal edge (not just correlation) */

    /* Flags */
    uint8_t is_suspicious:1;
    uint8_t is_rare:1;                      /* Rarely seen operation */
    uint8_t _reserved:6;
} ProvenanceEdge;

/* ============================================================================
 * Provenance Graph
 * ============================================================================ */

typedef struct ProvenanceGraph {
    /* Node storage (hash table indexed by entity ID) */
    ProvenanceNode* nodes;              /* Dense array of nodes */
    uint64_t* node_ids;                 /* ID -> array index mapping */
    size_t num_nodes;
    size_t max_nodes;

    /* Edge storage */
    ProvenanceEdge* edges;
    size_t num_edges;
    size_t max_edges;

    /* Temporal tracking */
    uint64_t window_start_ns;           /* Current time window start */
    uint64_t window_end_ns;             /* Current time window end */

    /* Graph statistics */
    struct {
        uint64_t total_events;          /* Total syscalls observed */
        uint64_t suspicious_events;     /* Flagged events */
        uint64_t causal_chains;         /* Detected causal chains */
        double avg_node_degree;         /* Average node degree */
        double graph_density;           /* Edge density */
    } stats;

    /* Thread safety */
    pthread_rwlock_t lock;

    /* Memory pool for efficiency */
    void* node_pool;
    void* edge_pool;
} ProvenanceGraph;

/* ============================================================================
 * Causal Chain (for APT detection)
 * ============================================================================ */

typedef struct {
    uint64_t chain_id;                  /* Unique chain ID */
    uint64_t node_path[256];            /* Sequence of nodes */
    uint64_t edge_path[256];            /* Sequence of edges */
    size_t path_length;

    /* Temporal span */
    uint64_t start_time_ns;
    uint64_t end_time_ns;

    /* Scoring */
    float anomaly_score;                /* How anomalous is this chain */
    float causal_score;                 /* Causal strength */
    float apt_likelihood;               /* Likelihood of APT */

    /* Classification */
    enum {
        APT_PHASE_RECONNAISSANCE,
        APT_PHASE_WEAPONIZATION,
        APT_PHASE_DELIVERY,
        APT_PHASE_EXPLOITATION,
        APT_PHASE_INSTALLATION,
        APT_PHASE_C2,
        APT_PHASE_EXFILTRATION,
        APT_PHASE_UNKNOWN
    } apt_phase;

    /* Description */
    char description[512];              /* Human-readable description */
} CausalChain;

/* ============================================================================
 * API Functions
 * ============================================================================ */

/* Lifecycle */
ProvenanceGraph* pg_create(size_t max_nodes, size_t max_edges);
void pg_destroy(ProvenanceGraph* graph);
void pg_clear(ProvenanceGraph* graph);

/* Node operations */
uint64_t pg_add_node(ProvenanceGraph* graph, NodeType type, const void* metadata);
ProvenanceNode* pg_get_node(ProvenanceGraph* graph, uint64_t node_id);
ProvenanceNode* pg_find_node_by_pid(ProvenanceGraph* graph, uint32_t pid);
ProvenanceNode* pg_find_node_by_path(ProvenanceGraph* graph, const char* path);

/* Edge operations */
uint64_t pg_add_edge(ProvenanceGraph* graph, uint64_t src, uint64_t dst,
                     EdgeType type, uint64_t timestamp_ns);
ProvenanceEdge* pg_get_edge(ProvenanceGraph* graph, uint64_t edge_id);

/* Graph queries */
void pg_get_neighbors(ProvenanceGraph* graph, uint64_t node_id,
                      uint64_t* out_neighbors, size_t* out_count);
void pg_get_in_neighbors(ProvenanceGraph* graph, uint64_t node_id,
                         uint64_t* out_neighbors, size_t* out_count);
void pg_get_out_neighbors(ProvenanceGraph* graph, uint64_t node_id,
                          uint64_t* out_neighbors, size_t* out_count);

/* Temporal operations */
void pg_advance_window(ProvenanceGraph* graph, uint64_t new_end_ns);
void pg_prune_old_nodes(ProvenanceGraph* graph, uint64_t cutoff_ns);

/* Causal analysis */
void pg_extract_causal_chains(ProvenanceGraph* graph,
                              CausalChain* out_chains,
                              size_t max_chains,
                              size_t* out_count);
bool pg_is_causal_edge(ProvenanceGraph* graph, uint64_t edge_id);

/* Feature extraction */
void pg_extract_node_features(ProvenanceNode* node, float* out_features);
void pg_extract_edge_features(ProvenanceEdge* edge, float* out_features);

/* Statistics */
void pg_compute_stats(ProvenanceGraph* graph);
void pg_print_stats(const ProvenanceGraph* graph);

/* Visualization/Export */
void pg_export_dot(const ProvenanceGraph* graph, const char* filename);
void pg_export_json(const ProvenanceGraph* graph, const char* filename);

#ifdef __cplusplus
}
#endif

#endif /* FLOWSHIELD_PROVENANCE_GRAPH_H */
