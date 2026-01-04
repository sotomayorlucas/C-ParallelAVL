/**
 * Unified Detection Engine
 *
 * Integrates FlowShield (network-level) with GNN/GAT APT Detector (host-level)
 * for comprehensive multi-layer threat detection.
 *
 * Architecture:
 *   Network Layer (FlowShield) → DDoS, volumetric attacks, flow anomalies
 *   Host Layer (APT Detector)  → Process chains, lateral movement, persistence
 *   Integration Layer          → Alert correlation, context enrichment
 *
 * Key capabilities:
 *   - Bidirectional event flow (network ↔ host)
 *   - Alert correlation (link related network and host events)
 *   - Context enrichment (add network context to APT alerts, vice versa)
 *   - Unified incident timeline
 *   - Multi-stage attack detection
 */

#ifndef FLOWSHIELD_UNIFIED_DETECTOR_H
#define FLOWSHIELD_UNIFIED_DETECTOR_H

#include "flowshield.h"
#include "apt_detector.h"
#include "flow_types.h"
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Configuration
 * ============================================================================ */

#define UNIFIED_MAX_INCIDENTS       256     /* Max concurrent incidents */
#define UNIFIED_CORRELATION_WINDOW  300     /* Correlation window (seconds) */
#define UNIFIED_MAX_ALERTS_PER_INC  64      /* Max alerts per incident */

/* ============================================================================
 * Unified Alert
 * ============================================================================ */

/**
 * Unified alert combining network and host-level detections.
 */
typedef struct {
    uint64_t alert_id;                      /* Unique alert ID */
    uint64_t timestamp_ns;                  /* Alert timestamp */

    /* Source of detection */
    enum {
        ALERT_SOURCE_NETWORK,               /* FlowShield network detection */
        ALERT_SOURCE_HOST,                  /* APT detector host detection */
        ALERT_SOURCE_CORRELATED             /* Correlated from both layers */
    } source;

    /* Network-level information (if available) */
    struct {
        bool has_network_info;
        FlowAlert network_alert;            /* FlowShield alert */
        FlowKey flow;                       /* Network flow 5-tuple */
        FlowStats stats;                    /* Flow statistics */
        AttackType attack_type;             /* Network attack type */
    } network;

    /* Host-level information (if available) */
    struct {
        bool has_host_info;
        APTAlert apt_alert;                 /* APT detector alert */
        CausalChain causal_chain;           /* Causal event chain */
        APTPhase apt_phase;                 /* APT kill chain phase */
    } host;

    /* Unified assessment */
    float combined_severity;                /* Combined severity [0-1] */
    float correlation_score;                /* How related are network and host events */

    /* Incident association */
    uint64_t incident_id;                   /* Associated incident ID */

    /* MITRE ATT&CK mapping */
    char mitre_tactics[8][64];
    char mitre_techniques[16][64];
    size_t num_tactics;
    size_t num_techniques;

    /* Description */
    char title[256];
    char description[1024];

    /* Recommended response */
    enum {
        RESPONSE_MONITOR,
        RESPONSE_INVESTIGATE,
        RESPONSE_ISOLATE_NETWORK,           /* Block network traffic */
        RESPONSE_ISOLATE_HOST,              /* Quarantine host */
        RESPONSE_KILL_PROCESS,              /* Terminate malicious process */
        RESPONSE_BLOCK_IP,                  /* Block external IP */
        RESPONSE_EMERGENCY                  /* Immediate action required */
    } recommended_response;
} UnifiedAlert;

/* ============================================================================
 * Security Incident
 * ============================================================================ */

/**
 * Security incident aggregating multiple related alerts.
 */
typedef struct {
    uint64_t incident_id;                   /* Unique incident ID */
    uint64_t start_time_ns;                 /* Incident start time */
    uint64_t last_update_ns;                /* Last alert time */

    /* Associated alerts */
    UnifiedAlert* alerts[UNIFIED_MAX_ALERTS_PER_INC];
    size_t num_alerts;

    /* Incident classification */
    enum {
        INCIDENT_RECON,                     /* Reconnaissance */
        INCIDENT_INITIAL_COMPROMISE,        /* Initial access */
        INCIDENT_LATERAL_MOVEMENT,          /* Lateral movement */
        INCIDENT_DATA_EXFILTRATION,         /* Data theft */
        INCIDENT_DDOS,                      /* DDoS attack */
        INCIDENT_MULTI_STAGE_APT,           /* Complex APT campaign */
        INCIDENT_UNKNOWN
    } classification;

    /* Severity */
    enum {
        SEVERITY_LOW,
        SEVERITY_MEDIUM,
        SEVERITY_HIGH,
        SEVERITY_CRITICAL
    } severity;

    /* Affected assets */
    struct {
        uint32_t affected_ips[32];          /* Affected IP addresses */
        uint32_t affected_pids[32];         /* Affected process IDs */
        char affected_users[16][128];       /* Affected usernames */
        size_t num_ips;
        size_t num_pids;
        size_t num_users;
    } assets;

    /* Status */
    enum {
        INCIDENT_ACTIVE,
        INCIDENT_INVESTIGATING,
        INCIDENT_MITIGATED,
        INCIDENT_CLOSED
    } status;

    /* Timeline */
    char timeline[2048];                    /* Human-readable timeline */
} SecurityIncident;

/* ============================================================================
 * Unified Detector Engine
 * ============================================================================ */

/**
 * Unified detection engine combining network and host-level detection.
 */
typedef struct {
    /* Component detectors */
    FlowShield* flowshield;                 /* Network-level detector */
    APTDetector* apt_detector;              /* Host-level detector */

    /* Alert queues */
    UnifiedAlert* alerts;
    size_t num_alerts;
    size_t max_alerts;
    pthread_mutex_t alert_lock;

    /* Incidents */
    SecurityIncident* incidents;
    size_t num_incidents;
    size_t max_incidents;
    pthread_mutex_t incident_lock;

    /* Configuration */
    struct {
        bool enable_network_detection;      /* Enable FlowShield */
        bool enable_host_detection;         /* Enable APT detector */
        bool enable_correlation;            /* Enable alert correlation */
        uint64_t correlation_window_ns;     /* Time window for correlation */
        float correlation_threshold;        /* Min correlation score */
    } config;

    /* Statistics */
    struct {
        uint64_t total_alerts;
        uint64_t network_alerts;
        uint64_t host_alerts;
        uint64_t correlated_alerts;
        uint64_t total_incidents;
        uint64_t active_incidents;
        double avg_correlation_time_ms;
    } stats;

    /* Background processing */
    pthread_t correlation_thread;
    pthread_t incident_thread;
    bool is_running;
} UnifiedDetector;

/* ============================================================================
 * API - Lifecycle
 * ============================================================================ */

/**
 * Create unified detector.
 *
 * @param network_config        FlowShield configuration
 * @param host_config           APT detector configuration
 * @return                      Unified detector instance
 */
UnifiedDetector* unified_detector_create(
    const DetectionConfig* network_config,
    size_t max_nodes,
    size_t max_edges
);

void unified_detector_destroy(UnifiedDetector* detector);

/**
 * Start detection engines and background threads.
 */
bool unified_detector_start(UnifiedDetector* detector);

/**
 * Stop detection engines.
 */
void unified_detector_stop(UnifiedDetector* detector);

/* ============================================================================
 * API - Event Ingestion
 * ============================================================================ */

/**
 * Ingest network packet (FlowShield path).
 *
 * @param detector              Unified detector
 * @param packet                Packet data
 * @param packet_len            Packet length
 * @param timestamp_ns          Packet timestamp
 */
void unified_ingest_packet(
    UnifiedDetector* detector,
    const uint8_t* packet,
    size_t packet_len,
    uint64_t timestamp_ns
);

/**
 * Ingest network flow (FlowShield path).
 *
 * @param detector              Unified detector
 * @param flow_key              Flow 5-tuple
 * @param flow_stats            Flow statistics
 */
void unified_ingest_flow(
    UnifiedDetector* detector,
    const FlowKey* flow_key,
    const FlowStats* flow_stats
);

/**
 * Ingest system event (APT detector path).
 *
 * @param detector              Unified detector
 * @param src_entity            Source entity
 * @param src_type              Source type
 * @param dst_entity            Destination entity
 * @param dst_type              Destination type
 * @param operation             Operation type
 * @param timestamp_ns          Event timestamp
 */
void unified_ingest_syscall(
    UnifiedDetector* detector,
    const void* src_entity,
    NodeType src_type,
    const void* dst_entity,
    NodeType dst_type,
    EdgeType operation,
    uint64_t timestamp_ns
);

/* ============================================================================
 * API - Detection
 * ============================================================================ */

/**
 * Get current alerts.
 *
 * @param detector              Unified detector
 * @param out_alerts            Output alerts
 * @param max_alerts            Maximum alerts to return
 * @param out_count             Number of alerts returned
 */
void unified_get_alerts(
    const UnifiedDetector* detector,
    UnifiedAlert* out_alerts,
    size_t max_alerts,
    size_t* out_count
);

/**
 * Get active incidents.
 *
 * @param detector              Unified detector
 * @param out_incidents         Output incidents
 * @param max_incidents         Maximum incidents to return
 * @param out_count             Number of incidents returned
 */
void unified_get_incidents(
    const UnifiedDetector* detector,
    SecurityIncident* out_incidents,
    size_t max_incidents,
    size_t* out_count
);

/**
 * Get incident by ID.
 */
SecurityIncident* unified_get_incident(
    const UnifiedDetector* detector,
    uint64_t incident_id
);

/* ============================================================================
 * API - Alert Correlation
 * ============================================================================ */

/**
 * Correlate network and host alerts.
 *
 * @param detector              Unified detector
 * @param network_alert         Network alert
 * @param host_alert            Host alert
 * @param out_correlation       Correlation score [0, 1]
 * @return                      true if alerts are correlated
 */
bool unified_correlate_alerts(
    UnifiedDetector* detector,
    const FlowAlert* network_alert,
    const APTAlert* host_alert,
    float* out_correlation
);

/**
 * Find related alerts within time window.
 *
 * @param detector              Unified detector
 * @param reference_alert       Reference alert
 * @param time_window_ns        Time window
 * @param out_related           Output related alerts
 * @param max_related           Maximum related alerts
 * @param out_count             Number of related alerts found
 */
void unified_find_related_alerts(
    const UnifiedDetector* detector,
    const UnifiedAlert* reference_alert,
    uint64_t time_window_ns,
    UnifiedAlert* out_related,
    size_t max_related,
    size_t* out_count
);

/* ============================================================================
 * API - Context Enrichment
 * ============================================================================ */

/**
 * Enrich network alert with host context.
 *
 * @param detector              Unified detector
 * @param network_alert         Network alert (input/output)
 */
void unified_enrich_network_alert(
    UnifiedDetector* detector,
    FlowAlert* network_alert
);

/**
 * Enrich APT alert with network context.
 *
 * @param detector              Unified detector
 * @param apt_alert             APT alert (input/output)
 */
void unified_enrich_apt_alert(
    UnifiedDetector* detector,
    APTAlert* apt_alert
);

/**
 * Build complete attack timeline.
 *
 * @param detector              Unified detector
 * @param incident              Security incident
 * @param out_timeline          Output timeline string
 * @param timeline_size         Timeline buffer size
 */
void unified_build_timeline(
    const UnifiedDetector* detector,
    const SecurityIncident* incident,
    char* out_timeline,
    size_t timeline_size
);

/* ============================================================================
 * API - Incident Management
 * ============================================================================ */

/**
 * Create new incident from alert.
 *
 * @param detector              Unified detector
 * @param alert                 Triggering alert
 * @return                      New incident ID
 */
uint64_t unified_create_incident(
    UnifiedDetector* detector,
    const UnifiedAlert* alert
);

/**
 * Add alert to existing incident.
 *
 * @param detector              Unified detector
 * @param incident_id           Incident ID
 * @param alert                 Alert to add
 */
void unified_add_alert_to_incident(
    UnifiedDetector* detector,
    uint64_t incident_id,
    const UnifiedAlert* alert
);

/**
 * Close incident.
 *
 * @param detector              Unified detector
 * @param incident_id           Incident ID
 */
void unified_close_incident(
    UnifiedDetector* detector,
    uint64_t incident_id
);

/* ============================================================================
 * API - Response Actions
 * ============================================================================ */

/**
 * Execute recommended response action.
 *
 * @param detector              Unified detector
 * @param alert                 Alert with recommended action
 * @return                      true if action executed successfully
 */
bool unified_execute_response(
    UnifiedDetector* detector,
    const UnifiedAlert* alert
);

/**
 * Block IP address (network-level mitigation).
 *
 * @param detector              Unified detector
 * @param ip_address            IP to block
 * @param duration_sec          Block duration (0 = permanent)
 */
void unified_block_ip(
    UnifiedDetector* detector,
    uint32_t ip_address,
    uint64_t duration_sec
);

/**
 * Isolate host (host-level mitigation).
 *
 * @param detector              Unified detector
 * @param hostname              Host to isolate
 */
void unified_isolate_host(
    UnifiedDetector* detector,
    const char* hostname
);

/**
 * Kill malicious process.
 *
 * @param detector              Unified detector
 * @param pid                   Process ID to terminate
 */
void unified_kill_process(
    UnifiedDetector* detector,
    uint32_t pid
);

/* ============================================================================
 * API - Statistics & Reporting
 * ============================================================================ */

/**
 * Get detector statistics.
 */
void unified_get_stats(
    const UnifiedDetector* detector,
    void* out_stats
);

/**
 * Print statistics.
 */
void unified_print_stats(const UnifiedDetector* detector);

/**
 * Generate security report.
 *
 * @param detector              Unified detector
 * @param start_time_ns         Report start time
 * @param end_time_ns           Report end time
 * @param out_report            Output report
 * @param report_size           Report buffer size
 */
void unified_generate_report(
    const UnifiedDetector* detector,
    uint64_t start_time_ns,
    uint64_t end_time_ns,
    char* out_report,
    size_t report_size
);

/**
 * Export incident to JSON.
 */
void unified_export_incident_json(
    const SecurityIncident* incident,
    const char* filename
);

/* ============================================================================
 * Utilities
 * ============================================================================ */

/**
 * Convert unified alert to string.
 */
void unified_alert_to_string(
    const UnifiedAlert* alert,
    char* out_str,
    size_t str_size
);

/**
 * Convert incident to string.
 */
void unified_incident_to_string(
    const SecurityIncident* incident,
    char* out_str,
    size_t str_size
);

#ifdef __cplusplus
}
#endif

#endif /* FLOWSHIELD_UNIFIED_DETECTOR_H */
