/**
 * Unified Detector Implementation
 *
 * Integrates network-level (FlowShield) and host-level (APT Detector)
 * threat detection with alert correlation and incident management.
 */

#define _GNU_SOURCE
#include "../include/unified_detector.h"
#include "../include/anomaly_detector.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <math.h>

/* ============================================================================
 * Internal Helpers
 * ============================================================================ */

static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static uint64_t generate_id(void) {
    static uint64_t counter = 0;
    return __atomic_fetch_add(&counter, 1, __ATOMIC_SEQ_CST);
}

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

UnifiedDetector* unified_detector_create(
    const DetectionConfig* network_config,
    size_t max_nodes,
    size_t max_edges
) {
    UnifiedDetector* detector = calloc(1, sizeof(UnifiedDetector));
    if (!detector) return NULL;

    /* Create FlowShield (network detector) */
    detector->flowshield = flowshield_create(network_config);
    if (!detector->flowshield) {
        unified_detector_destroy(detector);
        return NULL;
    }

    /* Create APT Detector (host detector) */
    detector->apt_detector = apt_detector_create(max_nodes, max_edges, NULL);
    if (!detector->apt_detector) {
        unified_detector_destroy(detector);
        return NULL;
    }

    /* Allocate alert storage */
    detector->max_alerts = 1000;
    detector->alerts = calloc(detector->max_alerts, sizeof(UnifiedAlert));
    if (!detector->alerts) {
        unified_detector_destroy(detector);
        return NULL;
    }
    pthread_mutex_init(&detector->alert_lock, NULL);

    /* Allocate incident storage */
    detector->max_incidents = UNIFIED_MAX_INCIDENTS;
    detector->incidents = calloc(detector->max_incidents, sizeof(SecurityIncident));
    if (!detector->incidents) {
        unified_detector_destroy(detector);
        return NULL;
    }
    pthread_mutex_init(&detector->incident_lock, NULL);

    /* Configuration */
    detector->config.enable_network_detection = true;
    detector->config.enable_host_detection = true;
    detector->config.enable_correlation = true;
    detector->config.correlation_window_ns = UNIFIED_CORRELATION_WINDOW * 1000000000ULL;
    detector->config.correlation_threshold = 0.5f;

    printf("[UnifiedDetector] Created with network + host detection\n");
    printf("  FlowShield:   Network-level anomaly detection\n");
    printf("  APT Detector: Host-level APT detection (GNN/GAT)\n");
    printf("  Correlation:  Enabled (window=%d sec)\n", UNIFIED_CORRELATION_WINDOW);

    return detector;
}

void unified_detector_destroy(UnifiedDetector* detector) {
    if (!detector) return;

    unified_detector_stop(detector);

    flowshield_destroy(detector->flowshield);
    apt_detector_destroy(detector->apt_detector);

    pthread_mutex_destroy(&detector->alert_lock);
    pthread_mutex_destroy(&detector->incident_lock);

    free(detector->alerts);
    free(detector->incidents);
    free(detector);
}

bool unified_detector_start(UnifiedDetector* detector) {
    if (!detector) return false;

    /* Start FlowShield */
    if (detector->config.enable_network_detection) {
        if (!flowshield_start(detector->flowshield)) {
            fprintf(stderr, "[UnifiedDetector] Failed to start FlowShield\n");
            return false;
        }
    }

    /* Start APT Detector */
    if (detector->config.enable_host_detection) {
        if (!apt_detector_start(detector->apt_detector)) {
            fprintf(stderr, "[UnifiedDetector] Failed to start APT Detector\n");
            return false;
        }
    }

    detector->is_running = true;

    printf("[UnifiedDetector] Started successfully\n");
    return true;
}

void unified_detector_stop(UnifiedDetector* detector) {
    if (!detector || !detector->is_running) return;

    detector->is_running = false;

    if (detector->flowshield) {
        flowshield_stop(detector->flowshield);
    }

    if (detector->apt_detector) {
        apt_detector_stop(detector->apt_detector);
    }

    printf("[UnifiedDetector] Stopped\n");
}

/* ============================================================================
 * Event Ingestion
 * ============================================================================ */

void unified_ingest_packet(
    UnifiedDetector* detector,
    const uint8_t* packet,
    size_t packet_len,
    uint64_t timestamp_ns
) {
    if (!detector || !packet || !detector->config.enable_network_detection) {
        return;
    }

    /* Forward to FlowShield */
    flowshield_process_packet(detector->flowshield, packet, packet_len);

    /* Also create provenance graph node for network event (optional) */
    /* This creates bidirectional flow: network → host layer */
    if (detector->config.enable_host_detection) {
        /* Extract flow key from packet and create socket node in provenance graph */
        /* TODO: Parse packet headers and create NODE_SOCKET in APT detector */
    }
}

void unified_ingest_flow(
    UnifiedDetector* detector,
    const FlowKey* flow_key,
    const FlowStats* flow_stats
) {
    if (!detector || !flow_key || !flow_stats) return;

    /* Process in FlowShield */
    if (detector->config.enable_network_detection) {
        /* FlowShield internally tracks flows */
    }

    /* Cross-layer enrichment: create socket node in provenance graph */
    if (detector->config.enable_host_detection && detector->apt_detector) {
        ProvenanceGraph* graph = detector->apt_detector->graph;

        /* Create socket node metadata */
        struct {
            uint32_t local_ip;
            uint32_t remote_ip;
            uint16_t local_port;
            uint16_t remote_port;
            uint8_t protocol;
        } socket_meta = {
            .local_ip = flow_key->src_ip,
            .remote_ip = flow_key->dst_ip,
            .local_port = flow_key->src_port,
            .remote_port = flow_key->dst_port,
            .protocol = flow_key->protocol
        };

        pg_add_node(graph, NODE_SOCKET, &socket_meta);
    }
}

void unified_ingest_syscall(
    UnifiedDetector* detector,
    const void* src_entity,
    NodeType src_type,
    const void* dst_entity,
    NodeType dst_type,
    EdgeType operation,
    uint64_t timestamp_ns
) {
    if (!detector || !detector->config.enable_host_detection) {
        return;
    }

    /* Forward to APT Detector */
    apt_ingest_event(
        detector->apt_detector,
        src_entity, src_type,
        dst_entity, dst_type,
        operation,
        timestamp_ns,
        NULL
    );

    /* Cross-layer: if this is a network syscall, update FlowShield */
    if (operation == EDGE_CONNECT || operation == EDGE_SEND || operation == EDGE_RECV) {
        /* Extract network flow info and track in FlowShield */
        /* This creates bidirectional flow: host → network layer */
    }
}

/* ============================================================================
 * Alert Correlation
 * ============================================================================ */

/**
 * Compute correlation score between network and host alerts.
 */
bool unified_correlate_alerts(
    UnifiedDetector* detector,
    const FlowAlert* network_alert,
    const APTAlert* host_alert,
    float* out_correlation
) {
    if (!detector || !network_alert || !host_alert || !out_correlation) {
        return false;
    }

    float correlation = 0.0f;

    /* 1. Temporal proximity */
    int64_t time_diff_ns = (int64_t)network_alert->timestamp_ns -
                           (int64_t)host_alert->timestamp_ns;
    if (time_diff_ns < 0) time_diff_ns = -time_diff_ns;

    float time_score = 0.0f;
    if (time_diff_ns < 60 * 1000000000ULL) {  /* Within 60 seconds */
        time_score = 1.0f - (float)time_diff_ns / (60.0f * 1e9f);
    }
    correlation += time_score * 0.4f;  /* 40% weight */

    /* 2. IP address overlap */
    float ip_score = 0.0f;

    /* Check if network flow IPs match host alert affected nodes */
    for (size_t i = 0; i < host_alert->num_affected_nodes; i++) {
        uint64_t node_id = host_alert->affected_nodes[i];
        ProvenanceNode* node = pg_get_node(detector->apt_detector->graph, node_id);

        if (node && node->type == NODE_SOCKET) {
            if (node->meta.socket.remote_ip == network_alert->flow.dst_ip ||
                node->meta.socket.remote_ip == network_alert->flow.src_ip) {
                ip_score = 1.0f;
                break;
            }
        }
    }
    correlation += ip_score * 0.3f;  /* 30% weight */

    /* 3. Attack type similarity */
    float attack_score = 0.0f;

    /* Map network attack types to APT phases */
    bool attack_related = false;

    if ((network_alert->attack_type & ATTACK_PORT_SCAN) &&
        (host_alert->detected_phases & APT_PHASE_RECONNAISSANCE)) {
        attack_related = true;
    }

    if ((network_alert->attack_type & (ATTACK_SYN_FLOOD | ATTACK_UDP_AMPLIFY)) &&
        (host_alert->detected_phases & APT_PHASE_C2)) {
        attack_related = true;
    }

    if (attack_related) {
        attack_score = 0.8f;
    }
    correlation += attack_score * 0.3f;  /* 30% weight */

    *out_correlation = correlation;

    /* Consider correlated if score > threshold */
    return correlation >= detector->config.correlation_threshold;
}

void unified_find_related_alerts(
    const UnifiedDetector* detector,
    const UnifiedAlert* reference_alert,
    uint64_t time_window_ns,
    UnifiedAlert* out_related,
    size_t max_related,
    size_t* out_count
) {
    if (!detector || !reference_alert || !out_related || !out_count) {
        if (out_count) *out_count = 0;
        return;
    }

    *out_count = 0;

    pthread_mutex_lock((pthread_mutex_t*)&detector->alert_lock);

    for (size_t i = 0; i < detector->num_alerts && *out_count < max_related; i++) {
        UnifiedAlert* alert = &detector->alerts[i];

        /* Check time window */
        int64_t time_diff = (int64_t)alert->timestamp_ns -
                           (int64_t)reference_alert->timestamp_ns;
        if (time_diff < 0) time_diff = -time_diff;

        if ((uint64_t)time_diff <= time_window_ns) {
            memcpy(&out_related[*out_count], alert, sizeof(UnifiedAlert));
            (*out_count)++;
        }
    }

    pthread_mutex_unlock((pthread_mutex_t*)&detector->alert_lock);
}

/* ============================================================================
 * Alert Retrieval
 * ============================================================================ */

void unified_get_alerts(
    const UnifiedDetector* detector,
    UnifiedAlert* out_alerts,
    size_t max_alerts,
    size_t* out_count
) {
    if (!detector || !out_alerts || !out_count) {
        if (out_count) *out_count = 0;
        return;
    }

    pthread_mutex_lock((pthread_mutex_t*)&detector->alert_lock);

    *out_count = (detector->num_alerts < max_alerts) ?
                 detector->num_alerts : max_alerts;

    memcpy(out_alerts, detector->alerts, *out_count * sizeof(UnifiedAlert));

    pthread_mutex_unlock((pthread_mutex_t*)&detector->alert_lock);
}

void unified_get_incidents(
    const UnifiedDetector* detector,
    SecurityIncident* out_incidents,
    size_t max_incidents,
    size_t* out_count
) {
    if (!detector || !out_incidents || !out_count) {
        if (out_count) *out_count = 0;
        return;
    }

    pthread_mutex_lock((pthread_mutex_t*)&detector->incident_lock);

    *out_count = (detector->num_incidents < max_incidents) ?
                 detector->num_incidents : max_incidents;

    memcpy(out_incidents, detector->incidents, *out_count * sizeof(SecurityIncident));

    pthread_mutex_unlock((pthread_mutex_t*)&detector->incident_lock);
}

SecurityIncident* unified_get_incident(
    const UnifiedDetector* detector,
    uint64_t incident_id
) {
    if (!detector) return NULL;

    pthread_mutex_lock((pthread_mutex_t*)&detector->incident_lock);

    for (size_t i = 0; i < detector->num_incidents; i++) {
        if (detector->incidents[i].incident_id == incident_id) {
            SecurityIncident* incident = &detector->incidents[i];
            pthread_mutex_unlock((pthread_mutex_t*)&detector->incident_lock);
            return incident;
        }
    }

    pthread_mutex_unlock((pthread_mutex_t*)&detector->incident_lock);
    return NULL;
}

/* ============================================================================
 * Context Enrichment
 * ============================================================================ */

void unified_enrich_network_alert(
    UnifiedDetector* detector,
    FlowAlert* network_alert
) {
    if (!detector || !network_alert || !detector->apt_detector) {
        return;
    }

    /* Find processes associated with this network flow */
    ProvenanceGraph* graph = detector->apt_detector->graph;

    /* Search for socket nodes matching this flow */
    for (size_t i = 0; i < graph->max_nodes; i++) {
        if (graph->node_ids[i] == UINT64_MAX) continue;

        ProvenanceNode* node = &graph->nodes[i];
        if (node->type == NODE_SOCKET) {
            if (node->meta.socket.remote_ip == network_alert->flow.dst_ip &&
                node->meta.socket.remote_port == network_alert->flow.dst_port) {

                /* Found matching socket - add process context to description */
                char enrichment[256];
                snprintf(enrichment, sizeof(enrichment),
                        " [Host Context: Socket node %lu, suspicious=%d]",
                        node->id, node->is_suspicious);

                strncat(network_alert->description, enrichment,
                       sizeof(network_alert->description) - strlen(network_alert->description) - 1);
                break;
            }
        }
    }
}

void unified_enrich_apt_alert(
    UnifiedDetector* detector,
    APTAlert* apt_alert
) {
    if (!detector || !apt_alert || !detector->flowshield) {
        return;
    }

    /* Find network flows associated with processes in the causal chain */
    /* Add network context to APT alert */

    char enrichment[256];
    snprintf(enrichment, sizeof(enrichment),
            " [Network Context: Active flows monitored by FlowShield]");

    strncat(apt_alert->description, enrichment,
           sizeof(apt_alert->description) - strlen(apt_alert->description) - 1);
}

void unified_build_timeline(
    const UnifiedDetector* detector,
    const SecurityIncident* incident,
    char* out_timeline,
    size_t timeline_size
) {
    if (!detector || !incident || !out_timeline) return;

    char* pos = out_timeline;
    size_t remaining = timeline_size;

    int written = snprintf(pos, remaining,
                          "=== Incident Timeline ===\n"
                          "Incident ID: %lu\n"
                          "Duration: %.2f seconds\n"
                          "Alerts: %zu\n\n",
                          incident->incident_id,
                          (incident->last_update_ns - incident->start_time_ns) / 1e9,
                          incident->num_alerts);

    pos += written;
    remaining -= written;

    /* List alerts chronologically */
    for (size_t i = 0; i < incident->num_alerts && remaining > 100; i++) {
        UnifiedAlert* alert = incident->alerts[i];
        if (!alert) continue;

        float time_offset = (alert->timestamp_ns - incident->start_time_ns) / 1e9f;

        written = snprintf(pos, remaining,
                          "[+%.2fs] %s (%s)\n",
                          time_offset,
                          alert->title,
                          alert->source == ALERT_SOURCE_NETWORK ? "Network" :
                          alert->source == ALERT_SOURCE_HOST ? "Host" : "Correlated");

        pos += written;
        remaining -= written;
    }
}

/* ============================================================================
 * Incident Management
 * ============================================================================ */

uint64_t unified_create_incident(
    UnifiedDetector* detector,
    const UnifiedAlert* alert
) {
    if (!detector || !alert) return 0;

    pthread_mutex_lock(&detector->incident_lock);

    if (detector->num_incidents >= detector->max_incidents) {
        pthread_mutex_unlock(&detector->incident_lock);
        return 0;
    }

    SecurityIncident* incident = &detector->incidents[detector->num_incidents++];
    memset(incident, 0, sizeof(SecurityIncident));

    incident->incident_id = generate_id();
    incident->start_time_ns = alert->timestamp_ns;
    incident->last_update_ns = alert->timestamp_ns;
    incident->status = INCIDENT_ACTIVE;

    /* Add initial alert */
    incident->alerts[0] = (UnifiedAlert*)alert;  /* Copy pointer */
    incident->num_alerts = 1;

    /* Classify incident based on alert */
    if (alert->host.has_host_info) {
        APTPhase phase = alert->host.apt_phase;
        if (phase & APT_PHASE_RECONNAISSANCE) {
            incident->classification = INCIDENT_RECON;
        } else if (phase & (APT_PHASE_EXPLOITATION | APT_PHASE_INSTALLATION)) {
            incident->classification = INCIDENT_INITIAL_COMPROMISE;
        } else if (phase & APT_PHASE_LATERAL_MOVEMENT) {
            incident->classification = INCIDENT_LATERAL_MOVEMENT;
        } else if (phase & APT_PHASE_EXFILTRATION) {
            incident->classification = INCIDENT_DATA_EXFILTRATION;
        }
    } else if (alert->network.has_network_info) {
        if (alert->network.attack_type & (ATTACK_SYN_FLOOD | ATTACK_UDP_AMPLIFY)) {
            incident->classification = INCIDENT_DDOS;
        } else if (alert->network.attack_type & ATTACK_PORT_SCAN) {
            incident->classification = INCIDENT_RECON;
        }
    }

    /* Set severity */
    if (alert->combined_severity > 0.8f) {
        incident->severity = SEVERITY_CRITICAL;
    } else if (alert->combined_severity > 0.6f) {
        incident->severity = SEVERITY_HIGH;
    } else if (alert->combined_severity > 0.4f) {
        incident->severity = SEVERITY_MEDIUM;
    } else {
        incident->severity = SEVERITY_LOW;
    }

    detector->stats.total_incidents++;
    detector->stats.active_incidents++;

    pthread_mutex_unlock(&detector->incident_lock);

    printf("[UnifiedDetector] Created incident %lu (severity=%d, type=%d)\n",
           incident->incident_id, incident->severity, incident->classification);

    return incident->incident_id;
}

void unified_add_alert_to_incident(
    UnifiedDetector* detector,
    uint64_t incident_id,
    const UnifiedAlert* alert
) {
    if (!detector || !alert) return;

    SecurityIncident* incident = unified_get_incident(detector, incident_id);
    if (!incident) return;

    pthread_mutex_lock(&detector->incident_lock);

    if (incident->num_alerts < UNIFIED_MAX_ALERTS_PER_INC) {
        incident->alerts[incident->num_alerts++] = (UnifiedAlert*)alert;
        incident->last_update_ns = alert->timestamp_ns;
    }

    pthread_mutex_unlock(&detector->incident_lock);
}

void unified_close_incident(
    UnifiedDetector* detector,
    uint64_t incident_id
) {
    if (!detector) return;

    SecurityIncident* incident = unified_get_incident(detector, incident_id);
    if (!incident) return;

    pthread_mutex_lock(&detector->incident_lock);

    incident->status = INCIDENT_CLOSED;
    detector->stats.active_incidents--;

    pthread_mutex_unlock(&detector->incident_lock);

    printf("[UnifiedDetector] Closed incident %lu\n", incident_id);
}

/* ============================================================================
 * Statistics
 * ============================================================================ */

void unified_print_stats(const UnifiedDetector* detector) {
    if (!detector) return;

    printf("\n=== Unified Detector Statistics ===\n");
    printf("Total Alerts:      %lu\n", detector->stats.total_alerts);
    printf("  Network:         %lu\n", detector->stats.network_alerts);
    printf("  Host:            %lu\n", detector->stats.host_alerts);
    printf("  Correlated:      %lu\n", detector->stats.correlated_alerts);
    printf("Incidents:         %lu total, %lu active\n",
           detector->stats.total_incidents, detector->stats.active_incidents);
    printf("Correlation time:  %.2f ms avg\n", detector->stats.avg_correlation_time_ms);
    printf("=====================================\n\n");

    /* Print component stats */
    printf("FlowShield (Network Layer):\n");
    flowshield_print_stats(detector->flowshield);

    printf("APT Detector (Host Layer):\n");
    apt_print_stats(detector->apt_detector);
}

/* ============================================================================
 * Response Actions
 * ============================================================================ */

bool unified_execute_response(
    UnifiedDetector* detector,
    const UnifiedAlert* alert
) {
    if (!detector || !alert) return false;

    switch (alert->recommended_response) {
        case RESPONSE_MONITOR:
            printf("[Response] Monitoring alert: %s\n", alert->title);
            return true;

        case RESPONSE_BLOCK_IP:
            if (alert->network.has_network_info) {
                unified_block_ip(detector, alert->network.flow.dst_ip, 0);
                return true;
            }
            break;

        case RESPONSE_KILL_PROCESS:
            if (alert->host.has_host_info) {
                /* Extract PID from causal chain and kill */
                printf("[Response] Would kill malicious processes\n");
                return true;
            }
            break;

        case RESPONSE_ISOLATE_HOST:
            printf("[Response] Would isolate host from network\n");
            return true;

        case RESPONSE_EMERGENCY:
            printf("[Response] EMERGENCY - Immediate action required!\n");
            return true;

        default:
            break;
    }

    return false;
}

void unified_block_ip(
    UnifiedDetector* detector,
    uint32_t ip_address,
    uint64_t duration_sec
) {
    if (!detector) return;

    printf("[Response] Blocking IP %u.%u.%u.%u for %lu seconds\n",
           (ip_address >> 24) & 0xFF,
           (ip_address >> 16) & 0xFF,
           (ip_address >> 8) & 0xFF,
           ip_address & 0xFF,
           duration_sec);

    /* TODO: Implement actual firewall rule injection */
}

void unified_kill_process(
    UnifiedDetector* detector,
    uint32_t pid
) {
    if (!detector) return;

    printf("[Response] Terminating malicious process PID=%u\n", pid);

    /* TODO: Implement process termination */
}
