/**
 * Provenance Graph Implementation
 *
 * Scalable implementation for million-node graphs using:
 *   - Hash table for O(1) node lookups
 *   - Sparse adjacency storage
 *   - Memory pooling for efficiency
 */

#define _GNU_SOURCE
#include "../include/provenance_graph.h"
#include "../../include/parallel_avl.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <time.h>

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

static uint64_t hash_node_id(uint64_t id) {
    /* MurmurHash3 finalizer */
    id ^= id >> 33;
    id *= 0xff51afd7ed558ccdULL;
    id ^= id >> 33;
    id *= 0xc4ceb9fe1a85ec53ULL;
    id ^= id >> 33;
    return id;
}

static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

ProvenanceGraph* pg_create(size_t max_nodes, size_t max_edges) {
    ProvenanceGraph* graph = calloc(1, sizeof(ProvenanceGraph));
    if (!graph) return NULL;

    /* Allocate node storage */
    graph->nodes = calloc(max_nodes, sizeof(ProvenanceNode));
    graph->node_ids = calloc(max_nodes, sizeof(uint64_t));
    graph->max_nodes = max_nodes;
    graph->num_nodes = 0;

    if (!graph->nodes || !graph->node_ids) {
        pg_destroy(graph);
        return NULL;
    }

    /* Allocate edge storage */
    graph->edges = calloc(max_edges, sizeof(ProvenanceEdge));
    graph->max_edges = max_edges;
    graph->num_edges = 0;

    if (!graph->edges) {
        pg_destroy(graph);
        return NULL;
    }

    /* Initialize temporal window */
    graph->window_start_ns = get_time_ns();
    graph->window_end_ns = graph->window_start_ns + (PG_TEMPORAL_WINDOW * 1000000000ULL);

    /* Initialize lock */
    pthread_rwlock_init(&graph->lock, NULL);

    /* Initialize node ID mapping (using -1 for empty slots) */
    for (size_t i = 0; i < max_nodes; i++) {
        graph->node_ids[i] = UINT64_MAX;
    }

    printf("[ProvenanceGraph] Created with capacity: %zu nodes, %zu edges\n",
           max_nodes, max_edges);

    return graph;
}

void pg_destroy(ProvenanceGraph* graph) {
    if (!graph) return;

    free(graph->nodes);
    free(graph->node_ids);
    free(graph->edges);
    pthread_rwlock_destroy(&graph->lock);
    free(graph);
}

void pg_clear(ProvenanceGraph* graph) {
    if (!graph) return;

    pthread_rwlock_wrlock(&graph->lock);

    graph->num_nodes = 0;
    graph->num_edges = 0;

    for (size_t i = 0; i < graph->max_nodes; i++) {
        graph->node_ids[i] = UINT64_MAX;
    }

    memset(&graph->stats, 0, sizeof(graph->stats));

    pthread_rwlock_unlock(&graph->lock);
}

/* ============================================================================
 * Node Operations
 * ============================================================================ */

uint64_t pg_add_node(ProvenanceGraph* graph, NodeType type, const void* metadata) {
    if (!graph || graph->num_nodes >= graph->max_nodes) {
        return UINT64_MAX;
    }

    pthread_rwlock_wrlock(&graph->lock);

    /* Generate unique node ID */
    uint64_t node_id = graph->num_nodes;

    /* Find insertion slot using linear probing */
    uint64_t hash = hash_node_id(node_id);
    size_t slot = hash % graph->max_nodes;

    while (graph->node_ids[slot] != UINT64_MAX) {
        slot = (slot + 1) % graph->max_nodes;
    }

    /* Initialize node */
    ProvenanceNode* node = &graph->nodes[slot];
    memset(node, 0, sizeof(ProvenanceNode));

    node->id = node_id;
    node->type = type;
    node->first_seen_ns = get_time_ns();
    node->last_seen_ns = node->first_seen_ns;

    /* Copy metadata based on type */
    if (metadata) {
        switch (type) {
            case NODE_PROCESS:
                memcpy(&node->meta.process, metadata, sizeof(node->meta.process));
                node->is_root = (node->meta.process.uid == 0);
                break;
            case NODE_FILE:
                memcpy(&node->meta.file, metadata, sizeof(node->meta.file));
                break;
            case NODE_SOCKET:
                memcpy(&node->meta.socket, metadata, sizeof(node->meta.socket));
                /* Check if external IP */
                uint32_t ip = node->meta.socket.remote_ip;
                node->is_external = !((ip >> 24) == 10 ||           /* 10.0.0.0/8 */
                                     ((ip >> 24) == 172 && ((ip >> 16) & 0xF0) == 16) ||  /* 172.16.0.0/12 */
                                     ((ip >> 24) == 192 && (ip >> 16) == 168));  /* 192.168.0.0/16 */
                break;
            case NODE_REGISTRY:
                memcpy(&node->meta.registry, metadata, sizeof(node->meta.registry));
                break;
            case NODE_USER:
                memcpy(&node->meta.user, metadata, sizeof(node->meta.user));
                break;
            default:
                break;
        }
    }

    /* Store node ID mapping */
    graph->node_ids[slot] = node_id;
    graph->num_nodes++;

    pthread_rwlock_unlock(&graph->lock);

    return node_id;
}

ProvenanceNode* pg_get_node(ProvenanceGraph* graph, uint64_t node_id) {
    if (!graph) return NULL;

    pthread_rwlock_rdlock(&graph->lock);

    /* Hash lookup with linear probing */
    uint64_t hash = hash_node_id(node_id);
    size_t slot = hash % graph->max_nodes;

    for (size_t i = 0; i < graph->max_nodes; i++) {
        if (graph->node_ids[slot] == node_id) {
            ProvenanceNode* node = &graph->nodes[slot];
            pthread_rwlock_unlock(&graph->lock);
            return node;
        }
        if (graph->node_ids[slot] == UINT64_MAX) {
            break;  /* Not found */
        }
        slot = (slot + 1) % graph->max_nodes;
    }

    pthread_rwlock_unlock(&graph->lock);
    return NULL;
}

ProvenanceNode* pg_find_node_by_pid(ProvenanceGraph* graph, uint32_t pid) {
    if (!graph) return NULL;

    pthread_rwlock_rdlock(&graph->lock);

    for (size_t i = 0; i < graph->max_nodes; i++) {
        if (graph->node_ids[i] != UINT64_MAX) {
            ProvenanceNode* node = &graph->nodes[i];
            if (node->type == NODE_PROCESS && node->meta.process.pid == pid) {
                pthread_rwlock_unlock(&graph->lock);
                return node;
            }
        }
    }

    pthread_rwlock_unlock(&graph->lock);
    return NULL;
}

ProvenanceNode* pg_find_node_by_path(ProvenanceGraph* graph, const char* path) {
    if (!graph || !path) return NULL;

    pthread_rwlock_rdlock(&graph->lock);

    for (size_t i = 0; i < graph->max_nodes; i++) {
        if (graph->node_ids[i] != UINT64_MAX) {
            ProvenanceNode* node = &graph->nodes[i];
            if (node->type == NODE_FILE) {
                if (strcmp(node->meta.file.path, path) == 0) {
                    pthread_rwlock_unlock(&graph->lock);
                    return node;
                }
            } else if (node->type == NODE_PROCESS) {
                if (strcmp(node->meta.process.exe_path, path) == 0) {
                    pthread_rwlock_unlock(&graph->lock);
                    return node;
                }
            }
        }
    }

    pthread_rwlock_unlock(&graph->lock);
    return NULL;
}

/* ============================================================================
 * Edge Operations
 * ============================================================================ */

uint64_t pg_add_edge(ProvenanceGraph* graph, uint64_t src, uint64_t dst,
                     EdgeType type, uint64_t timestamp_ns) {
    if (!graph || graph->num_edges >= graph->max_edges) {
        return UINT64_MAX;
    }

    pthread_rwlock_wrlock(&graph->lock);

    /* Allocate edge */
    uint64_t edge_id = graph->num_edges;
    ProvenanceEdge* edge = &graph->edges[edge_id];

    memset(edge, 0, sizeof(ProvenanceEdge));
    edge->id = edge_id;
    edge->src_node = src;
    edge->dst_node = dst;
    edge->type = type;
    edge->timestamp_ns = timestamp_ns ? timestamp_ns : get_time_ns();

    /* Update node adjacency lists */
    ProvenanceNode* src_node = pg_get_node(graph, src);
    ProvenanceNode* dst_node = pg_get_node(graph, dst);

    if (src_node && src_node->out_degree < PG_MAX_NEIGHBORS) {
        src_node->out_edges[src_node->out_degree++] = edge_id;
        src_node->last_seen_ns = edge->timestamp_ns;
        src_node->event_count++;
    }

    if (dst_node && dst_node->in_degree < PG_MAX_NEIGHBORS) {
        dst_node->in_edges[dst_node->in_degree++] = edge_id;
        dst_node->last_seen_ns = edge->timestamp_ns;
        dst_node->event_count++;
    }

    graph->num_edges++;
    graph->stats.total_events++;

    pthread_rwlock_unlock(&graph->lock);

    return edge_id;
}

ProvenanceEdge* pg_get_edge(ProvenanceGraph* graph, uint64_t edge_id) {
    if (!graph || edge_id >= graph->num_edges) {
        return NULL;
    }

    return &graph->edges[edge_id];
}

/* ============================================================================
 * Graph Queries
 * ============================================================================ */

void pg_get_neighbors(ProvenanceGraph* graph, uint64_t node_id,
                      uint64_t* out_neighbors, size_t* out_count) {
    if (!graph || !out_neighbors || !out_count) return;

    pthread_rwlock_rdlock(&graph->lock);

    ProvenanceNode* node = pg_get_node(graph, node_id);
    if (!node) {
        *out_count = 0;
        pthread_rwlock_unlock(&graph->lock);
        return;
    }

    size_t count = 0;

    /* Add out-neighbors */
    for (size_t i = 0; i < node->out_degree; i++) {
        ProvenanceEdge* edge = pg_get_edge(graph, node->out_edges[i]);
        if (edge) {
            out_neighbors[count++] = edge->dst_node;
        }
    }

    /* Add in-neighbors */
    for (size_t i = 0; i < node->in_degree; i++) {
        ProvenanceEdge* edge = pg_get_edge(graph, node->in_edges[i]);
        if (edge) {
            out_neighbors[count++] = edge->src_node;
        }
    }

    *out_count = count;
    pthread_rwlock_unlock(&graph->lock);
}

void pg_get_out_neighbors(ProvenanceGraph* graph, uint64_t node_id,
                          uint64_t* out_neighbors, size_t* out_count) {
    if (!graph || !out_neighbors || !out_count) return;

    pthread_rwlock_rdlock(&graph->lock);

    ProvenanceNode* node = pg_get_node(graph, node_id);
    if (!node) {
        *out_count = 0;
        pthread_rwlock_unlock(&graph->lock);
        return;
    }

    size_t count = 0;
    for (size_t i = 0; i < node->out_degree; i++) {
        ProvenanceEdge* edge = pg_get_edge(graph, node->out_edges[i]);
        if (edge) {
            out_neighbors[count++] = edge->dst_node;
        }
    }

    *out_count = count;
    pthread_rwlock_unlock(&graph->lock);
}

/* ============================================================================
 * Temporal Operations
 * ============================================================================ */

void pg_advance_window(ProvenanceGraph* graph, uint64_t new_end_ns) {
    if (!graph) return;

    pthread_rwlock_wrlock(&graph->lock);
    graph->window_end_ns = new_end_ns;
    graph->window_start_ns = new_end_ns - (PG_TEMPORAL_WINDOW * 1000000000ULL);
    pthread_rwlock_unlock(&graph->lock);
}

void pg_prune_old_nodes(ProvenanceGraph* graph, uint64_t cutoff_ns) {
    if (!graph) return;

    pthread_rwlock_wrlock(&graph->lock);

    /* Mark old nodes for removal */
    size_t removed = 0;
    for (size_t i = 0; i < graph->max_nodes; i++) {
        if (graph->node_ids[i] != UINT64_MAX) {
            ProvenanceNode* node = &graph->nodes[i];
            if (node->last_seen_ns < cutoff_ns && !node->is_critical) {
                graph->node_ids[i] = UINT64_MAX;
                removed++;
            }
        }
    }

    if (removed > 0) {
        printf("[ProvenanceGraph] Pruned %zu old nodes\n", removed);
    }

    pthread_rwlock_unlock(&graph->lock);
}

/* ============================================================================
 * Feature Extraction
 * ============================================================================ */

void pg_extract_node_features(ProvenanceNode* node, float* out_features) {
    if (!node || !out_features) return;

    memset(out_features, 0, PG_NODE_FEATURE_DIM * sizeof(float));

    /* Type one-hot encoding [0-7] */
    out_features[node->type] = 1.0f;

    /* Degree features [8-11] */
    out_features[8] = (float)node->in_degree / PG_MAX_NEIGHBORS;
    out_features[9] = (float)node->out_degree / PG_MAX_NEIGHBORS;
    out_features[10] = (float)(node->in_degree + node->out_degree) / (2.0f * PG_MAX_NEIGHBORS);

    /* Temporal features [12-15] */
    uint64_t age_ns = get_time_ns() - node->first_seen_ns;
    out_features[12] = fminf((float)age_ns / 3600e9f, 1.0f);  /* Age in hours */
    out_features[13] = fminf((float)node->event_count / 1000.0f, 1.0f);

    /* Flags [16-19] */
    out_features[16] = node->is_suspicious ? 1.0f : 0.0f;
    out_features[17] = node->is_critical ? 1.0f : 0.0f;
    out_features[18] = node->is_external ? 1.0f : 0.0f;
    out_features[19] = node->is_root ? 1.0f : 0.0f;

    /* Anomaly scores [20-22] */
    out_features[20] = node->anomaly_score;
    out_features[21] = node->causal_score;

    /* Node-specific features [23+] */
    if (node->type == NODE_PROCESS) {
        out_features[23] = (float)node->meta.process.uid / 65535.0f;
        out_features[24] = (node->meta.process.ppid > 0) ? 1.0f : 0.0f;
    } else if (node->type == NODE_SOCKET) {
        out_features[25] = (float)node->meta.socket.local_port / 65535.0f;
        out_features[26] = (float)node->meta.socket.remote_port / 65535.0f;
        out_features[27] = (node->meta.socket.protocol == 6) ? 1.0f : 0.0f;  /* TCP */
    }
}

void pg_extract_edge_features(ProvenanceEdge* edge, float* out_features) {
    if (!edge || !out_features) return;

    memset(out_features, 0, PG_EDGE_FEATURE_DIM * sizeof(float));

    /* Type one-hot encoding [0-23] */
    if (edge->type < 24) {
        out_features[edge->type] = 1.0f;
    }

    /* Temporal features [24-26] */
    uint64_t age_ns = get_time_ns() - edge->timestamp_ns;
    out_features[24] = fminf((float)age_ns / 3600e9f, 1.0f);
    out_features[25] = fminf((float)edge->duration_ns / 1e9f, 1.0f);

    /* Flags [26-28] */
    out_features[26] = edge->is_suspicious ? 1.0f : 0.0f;
    out_features[27] = edge->is_rare ? 1.0f : 0.0f;
    out_features[28] = edge->is_causal ? 1.0f : 0.0f;

    /* Causal analysis [29-31] */
    out_features[29] = edge->causal_weight;
    out_features[30] = edge->attention_score;
}

/* ============================================================================
 * Statistics
 * ============================================================================ */

void pg_compute_stats(ProvenanceGraph* graph) {
    if (!graph) return;

    pthread_rwlock_rdlock(&graph->lock);

    /* Compute average degree */
    uint64_t total_degree = 0;
    for (size_t i = 0; i < graph->max_nodes; i++) {
        if (graph->node_ids[i] != UINT64_MAX) {
            ProvenanceNode* node = &graph->nodes[i];
            total_degree += node->in_degree + node->out_degree;
        }
    }
    graph->stats.avg_node_degree = (double)total_degree / (graph->num_nodes + 1);

    /* Compute density */
    uint64_t max_edges = (uint64_t)graph->num_nodes * (graph->num_nodes - 1);
    graph->stats.graph_density = (double)graph->num_edges / (max_edges + 1);

    pthread_rwlock_unlock(&graph->lock);
}

void pg_print_stats(const ProvenanceGraph* graph) {
    if (!graph) return;

    printf("\n=== Provenance Graph Statistics ===\n");
    printf("Nodes:      %zu / %zu (%.1f%% full)\n",
           graph->num_nodes, graph->max_nodes,
           100.0 * graph->num_nodes / graph->max_nodes);
    printf("Edges:      %zu / %zu (%.1f%% full)\n",
           graph->num_edges, graph->max_edges,
           100.0 * graph->num_edges / graph->max_edges);
    printf("Avg Degree: %.2f\n", graph->stats.avg_node_degree);
    printf("Density:    %.6f\n", graph->stats.graph_density);
    printf("Events:     %lu total, %lu suspicious\n",
           graph->stats.total_events, graph->stats.suspicious_events);
    printf("===================================\n\n");
}

/* ============================================================================
 * Causal Analysis (Simplified)
 * ============================================================================ */

void pg_extract_causal_chains(ProvenanceGraph* graph,
                              CausalChain* out_chains,
                              size_t max_chains,
                              size_t* out_count) {
    if (!graph || !out_chains || !out_count) return;

    pthread_rwlock_rdlock(&graph->lock);

    /* TODO: Implement full causal chain extraction with SCM
     * For now, simple DFS-based path extraction */

    *out_count = 0;

    pthread_rwlock_unlock(&graph->lock);
}

bool pg_is_causal_edge(ProvenanceGraph* graph, uint64_t edge_id) {
    if (!graph) return false;

    ProvenanceEdge* edge = pg_get_edge(graph, edge_id);
    return edge ? edge->is_causal : false;
}
