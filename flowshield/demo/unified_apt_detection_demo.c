/**
 * Unified APT Detection Demo
 *
 * Demonstrates multi-layer threat detection combining:
 *   - Network-level detection (FlowShield)
 *   - Host-level APT detection (GNN/GAT)
 *   - Alert correlation and incident management
 *
 * Simulates a multi-stage APT attack:
 *   1. Network reconnaissance (port scanning)
 *   2. Initial compromise (exploit delivery)
 *   3. Process execution (malware)
 *   4. C2 beaconing (periodic network activity)
 *   5. Lateral movement (process spawning)
 *   6. Data exfiltration (slow network transfer)
 */

#include "../include/unified_detector.h"
#include "../include/temporal_gnn.h"
#include "../include/causal_inference.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ============================================================================
 * Simulation Helpers
 * ============================================================================ */

static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void simulate_network_scan(UnifiedDetector* detector) {
    printf("\n[ATTACK] Phase 1: Network Reconnaissance\n");
    printf("  Attacker: 192.168.1.100 → Target: 10.0.0.50 (ports 22-1000)\n\n");

    /* Simulate port scan - many connections to different ports */
    for (uint16_t port = 22; port < 1000; port += 100) {
        FlowKey flow = {
            .src_ip = (192 << 24) | (168 << 16) | (1 << 8) | 100,
            .dst_ip = (10 << 24) | (0 << 16) | (0 << 8) | 50,
            .src_port = 50000 + port,
            .dst_port = port,
            .protocol = PROTO_TCP
        };

        FlowStats stats = {
            .packet_count = 1,
            .byte_count = 64,
            .syn_count = 1,
            .ack_count = 0,
            .first_seen_ns = get_time_ns(),
            .last_seen_ns = get_time_ns()
        };

        unified_ingest_flow(detector, &flow, &stats);
        usleep(1000);  /* 1ms between scans */
    }

    printf("  → FlowShield should detect port scanning pattern\n");
}

static void simulate_exploit_delivery(UnifiedDetector* detector) {
    printf("\n[ATTACK] Phase 2: Exploit Delivery\n");
    printf("  Malicious HTTP request delivering exploit\n\n");

    FlowKey flow = {
        .src_ip = (192 << 24) | (168 << 16) | (1 << 8) | 100,
        .dst_ip = (10 << 24) | (0 << 16) | (0 << 8) | 50,
        .src_port = 51234,
        .dst_port = 80,
        .protocol = PROTO_TCP
    };

    FlowStats stats = {
        .packet_count = 50,
        .byte_count = 8192,  /* Large request */
        .syn_count = 1,
        .ack_count = 10,
        .first_seen_ns = get_time_ns(),
        .last_seen_ns = get_time_ns() + 500000000ULL  /* 500ms */
    };

    unified_ingest_flow(detector, &flow, &stats);

    printf("  → Suspicious HTTP flow detected\n");
}

static void simulate_malware_execution(UnifiedDetector* detector) {
    printf("\n[ATTACK] Phase 3: Malware Execution\n");
    printf("  webserver (PID 1000) → fork → malware.exe (PID 1337)\n\n");

    /* Process creation chain */
    struct {
        uint32_t pid;
        uint32_t ppid;
        char cmdline[256];
        char exe_path[256];
        uint32_t uid;
    } webserver = {
        .pid = 1000,
        .ppid = 1,
        .uid = 33,  /* www-data */
    };
    strcpy(webserver.cmdline, "/usr/bin/apache2");
    strcpy(webserver.exe_path, "/usr/bin/apache2");

    struct {
        uint32_t pid;
        uint32_t ppid;
        char cmdline[256];
        char exe_path[256];
        uint32_t uid;
    } malware = {
        .pid = 1337,
        .ppid = 1000,
        .uid = 33,
    };
    strcpy(malware.cmdline, "/tmp/malware.exe");
    strcpy(malware.exe_path, "/tmp/malware.exe");

    /* Ingest syscalls */
    unified_ingest_syscall(
        detector,
        &webserver, NODE_PROCESS,
        &malware, NODE_PROCESS,
        EDGE_FORK,
        get_time_ns()
    );

    unified_ingest_syscall(
        detector,
        &malware, NODE_PROCESS,
        &malware, NODE_PROCESS,
        EDGE_EXEC,
        get_time_ns()
    );

    printf("  → APT Detector should detect suspicious process chain\n");
    printf("  → Causal chain: webserver --fork--> malware\n");
}

static void simulate_c2_beaconing(UnifiedDetector* detector) {
    printf("\n[ATTACK] Phase 4: C2 Beaconing\n");
    printf("  malware.exe → C2 server (192.168.1.100:443) every 60 seconds\n\n");

    /* Periodic beaconing */
    for (int i = 0; i < 5; i++) {
        FlowKey flow = {
            .src_ip = (10 << 24) | (0 << 16) | (0 << 8) | 50,
            .dst_ip = (192 << 24) | (168 << 16) | (1 << 8) | 100,
            .src_port = 55000 + i,
            .dst_port = 443,
            .protocol = PROTO_TCP
        };

        FlowStats stats = {
            .packet_count = 10,
            .byte_count = 512,  /* Small beacon */
            .syn_count = 1,
            .ack_count = 5,
            .first_seen_ns = get_time_ns() + i * 60ULL * 1000000000ULL,
            .last_seen_ns = get_time_ns() + i * 60ULL * 1000000000ULL + 100000000ULL
        };

        unified_ingest_flow(detector, &flow, &stats);

        printf("  Beacon %d at T+%d seconds\n", i + 1, i * 60);

        /* Also create syscall event */
        struct {
            uint32_t pid;
            char exe_path[256];
        } malware = {.pid = 1337};
        strcpy(malware.exe_path, "/tmp/malware.exe");

        struct {
            uint32_t local_ip;
            uint32_t remote_ip;
            uint16_t local_port;
            uint16_t remote_port;
            uint8_t protocol;
        } socket = {
            .local_ip = flow.src_ip,
            .remote_ip = flow.dst_ip,
            .local_port = flow.src_port,
            .remote_port = flow.dst_port,
            .protocol = flow.protocol
        };

        unified_ingest_syscall(
            detector,
            &malware, NODE_PROCESS,
            &socket, NODE_SOCKET,
            EDGE_CONNECT,
            get_time_ns() + i * 60ULL * 1000000000ULL
        );
    }

    printf("\n  → Temporal GNN should detect periodicity (60s period)\n");
    printf("  → FlowShield + APT correlation should link network and host events\n");
}

static void simulate_data_exfiltration(UnifiedDetector* detector) {
    printf("\n[ATTACK] Phase 5: Data Exfiltration\n");
    printf("  Slow transfer to 192.168.1.100:8080 (avoiding detection)\n\n");

    FlowKey flow = {
        .src_ip = (10 << 24) | (0 << 16) | (0 << 8) | 50,
        .dst_ip = (192 << 24) | (168 << 16) | (1 << 8) | 100,
        .src_port = 56789,
        .dst_port = 8080,
        .protocol = PROTO_TCP
    };

    FlowStats stats = {
        .packet_count = 1000,
        .byte_count = 5 * 1024 * 1024,  /* 5 MB over time */
        .syn_count = 1,
        .ack_count = 500,
        .first_seen_ns = get_time_ns(),
        .last_seen_ns = get_time_ns() + 300ULL * 1000000000ULL  /* 5 minutes */
    };

    unified_ingest_flow(detector, &flow, &stats);

    printf("  → Temporal GNN should detect slow exfiltration pattern\n");
    printf("  → Rate: ~17 KB/s (low and slow to evade detection)\n");
}

/* ============================================================================
 * Main Demo
 * ============================================================================ */

int main(void) {
    printf("=======================================================\n");
    printf("  Unified APT Detection Demo\n");
    printf("  Multi-layer threat detection with GNN/GAT\n");
    printf("=======================================================\n\n");

    /* Create unified detector */
    DetectionConfig network_config = detection_config_default();
    network_config.max_pps_per_flow = 1000;
    network_config.syn_per_second_thresh = 100;

    UnifiedDetector* detector = unified_detector_create(
        &network_config,
        100000,   /* max nodes in provenance graph */
        500000    /* max edges */
    );

    if (!detector) {
        fprintf(stderr, "Failed to create unified detector\n");
        return 1;
    }

    /* Start detection */
    if (!unified_detector_start(detector)) {
        fprintf(stderr, "Failed to start unified detector\n");
        unified_detector_destroy(detector);
        return 1;
    }

    printf("\n✓ Unified detector started successfully\n");
    printf("  - Network layer: FlowShield\n");
    printf("  - Host layer: GNN/GAT APT Detector\n");
    printf("  - Correlation enabled\n\n");

    /* Simulate multi-stage APT attack */
    printf("=========================================\n");
    printf("  SIMULATING MULTI-STAGE APT ATTACK\n");
    printf("=========================================\n");

    simulate_network_scan(detector);
    sleep(2);

    simulate_exploit_delivery(detector);
    sleep(2);

    simulate_malware_execution(detector);
    sleep(2);

    simulate_c2_beaconing(detector);
    sleep(2);

    simulate_data_exfiltration(detector);
    sleep(2);

    /* Check for alerts */
    printf("\n=========================================\n");
    printf("  DETECTION RESULTS\n");
    printf("=========================================\n\n");

    UnifiedAlert alerts[100];
    size_t num_alerts;
    unified_get_alerts(detector, alerts, 100, &num_alerts);

    printf("Total alerts detected: %zu\n\n", num_alerts);

    for (size_t i = 0; i < num_alerts; i++) {
        printf("Alert %zu:\n", i + 1);
        printf("  Title:    %s\n", alerts[i].title);
        printf("  Source:   %s\n",
               alerts[i].source == ALERT_SOURCE_NETWORK ? "Network (FlowShield)" :
               alerts[i].source == ALERT_SOURCE_HOST ? "Host (APT Detector)" :
               "Correlated (Both layers)");
        printf("  Severity: %.2f\n", alerts[i].combined_severity);
        printf("  Response: %d\n", alerts[i].recommended_response);
        printf("\n");
    }

    /* Check for incidents */
    SecurityIncident incidents[100];
    size_t num_incidents;
    unified_get_incidents(detector, incidents, 100, &num_incidents);

    printf("Security incidents: %zu\n\n", num_incidents);

    for (size_t i = 0; i < num_incidents; i++) {
        printf("Incident %zu (ID=%lu):\n", i + 1, incidents[i].incident_id);
        printf("  Classification: %d\n", incidents[i].classification);
        printf("  Severity:       %d\n", incidents[i].severity);
        printf("  Status:         %d\n", incidents[i].status);
        printf("  Alerts:         %zu\n", incidents[i].num_alerts);
        printf("  Duration:       %.2f seconds\n",
               (incidents[i].last_update_ns - incidents[i].start_time_ns) / 1e9);

        /* Build timeline */
        char timeline[4096];
        unified_build_timeline(detector, &incidents[i], timeline, sizeof(timeline));
        printf("\n%s\n", timeline);
    }

    /* Print statistics */
    printf("=========================================\n");
    printf("  STATISTICS\n");
    printf("=========================================\n");
    unified_print_stats(detector);

    /* Cleanup */
    unified_detector_stop(detector);
    unified_detector_destroy(detector);

    printf("\n✓ Demo completed successfully\n\n");
    return 0;
}
