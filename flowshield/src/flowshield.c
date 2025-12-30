/**
 * FlowShield - Main Engine Implementation
 *
 * Combines flow tracking and anomaly detection into a unified engine.
 */

#include "../include/flowshield.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

/* ============================================================================
 * Engine Structure
 * ============================================================================ */

struct FlowShield {
    FlowTracker*     tracker;
    AnomalyDetector* detector;
    FlowShieldConfig config;

    /* RNG state for simulations */
    uint64_t rng_state;
};

/* Simple xorshift64 RNG */
static uint64_t xorshift64(uint64_t* state) {
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

static uint32_t random_ip(uint64_t* rng) {
    return (uint32_t)xorshift64(rng);
}

static uint16_t random_port(uint64_t* rng) {
    return (uint16_t)(xorshift64(rng) % 65535) + 1;
}

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

FlowShield* flowshield_create(const FlowShieldConfig* config) {
    FlowShield* engine = calloc(1, sizeof(FlowShield));
    if (!engine) return NULL;

    engine->config = config ? *config : flowshield_config_default();

    engine->tracker = flow_tracker_create(
        engine->config.num_shards,
        engine->config.routing
    );
    if (!engine->tracker) {
        free(engine);
        return NULL;
    }

    engine->detector = anomaly_detector_create(
        engine->tracker,
        &engine->config.detection
    );
    if (!engine->detector) {
        flow_tracker_destroy(engine->tracker);
        free(engine);
        return NULL;
    }

    /* Initialize RNG */
    engine->rng_state = time_now_ns() ^ 0xDEADBEEF;

    /* Start learning if configured */
    if (engine->config.enable_learning) {
        anomaly_detector_start_learning(
            engine->detector,
            engine->config.learning_duration_sec
        );
    }

    return engine;
}

void flowshield_destroy(FlowShield* engine) {
    if (!engine) return;

    anomaly_detector_destroy(engine->detector);
    flow_tracker_destroy(engine->tracker);
    free(engine);
}

/* ============================================================================
 * Packet Processing
 * ============================================================================ */

bool flowshield_process_packet(
    FlowShield* engine,
    uint32_t src_ip,
    uint32_t dst_ip,
    uint16_t src_port,
    uint16_t dst_port,
    uint8_t protocol,
    uint32_t packet_size,
    uint8_t tcp_flags
) {
    FlowKey key = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = protocol
    };
    return flowshield_process_flow_packet(engine, &key, packet_size, tcp_flags);
}

bool flowshield_process_flow_packet(
    FlowShield* engine,
    const FlowKey* key,
    uint32_t packet_size,
    uint8_t tcp_flags
) {
    if (!engine || !key) return false;

    FlowStats* stats = flow_tracker_record_packet(
        engine->tracker, key, packet_size, tcp_flags);

    if (!stats) return false;

    /* Quick inline check for obvious attacks */
    FlowAlert alert;
    if (anomaly_detector_check_flow(engine->detector, key, stats, &alert)) {
        flow_tracker_flag_flow(engine->tracker, key, alert.attack_type);
        return true;
    }

    return false;
}

/* ============================================================================
 * Analysis
 * ============================================================================ */

size_t flowshield_analyze(FlowShield* engine) {
    if (!engine) return 0;
    return anomaly_detector_analyze(engine->detector);
}

size_t flowshield_get_alerts(
    FlowShield* engine,
    FlowAlert* out_alerts,
    size_t max_alerts
) {
    if (!engine) return 0;
    return anomaly_detector_get_alerts(engine->detector, out_alerts, max_alerts);
}

void flowshield_clear_alerts(FlowShield* engine) {
    if (engine) {
        anomaly_detector_clear_alerts(engine->detector);
    }
}

/* ============================================================================
 * Metrics
 * ============================================================================ */

void flowshield_get_metrics(FlowShield* engine, FlowMetrics* out_metrics) {
    if (engine) {
        flow_tracker_get_metrics(engine->tracker, out_metrics);
    }
}

void flowshield_get_entropy(FlowShield* engine, EntropyAnalysis* out_entropy) {
    if (engine) {
        anomaly_detector_calc_entropy(engine->detector, out_entropy);
    }
}

void flowshield_get_detector_stats(FlowShield* engine, DetectorStats* out_stats) {
    if (engine) {
        anomaly_detector_get_stats(engine->detector, out_stats);
    }
}

/* ============================================================================
 * Accessors
 * ============================================================================ */

FlowTracker* flowshield_get_tracker(FlowShield* engine) {
    return engine ? engine->tracker : NULL;
}

AnomalyDetector* flowshield_get_detector(FlowShield* engine) {
    return engine ? engine->detector : NULL;
}

/* ============================================================================
 * Traffic Simulation
 * ============================================================================ */

void flowshield_simulate_normal_traffic(
    FlowShield* engine,
    size_t num_packets,
    size_t num_sources,
    size_t num_dests
) {
    if (!engine || num_packets == 0) return;

    /* Generate pool of IPs */
    uint32_t* src_ips = malloc(num_sources * sizeof(uint32_t));
    uint32_t* dst_ips = malloc(num_dests * sizeof(uint32_t));

    for (size_t i = 0; i < num_sources; i++) {
        src_ips[i] = random_ip(&engine->rng_state);
    }
    for (size_t i = 0; i < num_dests; i++) {
        dst_ips[i] = random_ip(&engine->rng_state);
    }

    /* Generate packets */
    for (size_t i = 0; i < num_packets; i++) {
        uint32_t src_ip = src_ips[xorshift64(&engine->rng_state) % num_sources];
        uint32_t dst_ip = dst_ips[xorshift64(&engine->rng_state) % num_dests];
        uint16_t src_port = random_port(&engine->rng_state);
        uint16_t dst_port = (xorshift64(&engine->rng_state) % 100 < 80)
            ? 80 : random_port(&engine->rng_state);  /* 80% to port 80 */
        uint8_t protocol = (xorshift64(&engine->rng_state) % 100 < 70)
            ? PROTO_TCP : PROTO_UDP;  /* 70% TCP */
        uint32_t size = 64 + (xorshift64(&engine->rng_state) % 1400);

        /* Normal TCP: SYN, then SYN+ACK, then data */
        uint8_t flags = 0x10;  /* ACK - normal data */
        if (xorshift64(&engine->rng_state) % 100 < 5) {
            flags = 0x02;  /* SYN - new connection */
        }

        flowshield_process_packet(engine,
            src_ip, dst_ip, src_port, dst_port,
            protocol, size, flags);
    }

    free(src_ips);
    free(dst_ips);
}

void flowshield_simulate_syn_flood(
    FlowShield* engine,
    uint32_t target_ip,
    uint16_t target_port,
    size_t num_packets,
    size_t num_sources
) {
    if (!engine || num_packets == 0) return;

    for (size_t i = 0; i < num_packets; i++) {
        /* Spoofed source IPs (or single source if num_sources == 1) */
        uint32_t src_ip;
        if (num_sources == 1) {
            src_ip = 0x0A000001;  /* 10.0.0.1 - single attacker */
        } else {
            src_ip = random_ip(&engine->rng_state);
        }

        uint16_t src_port = random_port(&engine->rng_state);

        /* SYN packet - no ACK */
        flowshield_process_packet(engine,
            src_ip, target_ip, src_port, target_port,
            PROTO_TCP, 64, 0x02);  /* SYN flag */
    }
}

void flowshield_simulate_udp_amplification(
    FlowShield* engine,
    uint32_t victim_ip,
    uint16_t amplifier_port,
    size_t num_packets,
    double amplification
) {
    if (!engine || num_packets == 0) return;

    /* Simulate responses from "amplifiers" to victim */
    for (size_t i = 0; i < num_packets; i++) {
        uint32_t amplifier_ip = random_ip(&engine->rng_state);
        uint16_t victim_port = random_port(&engine->rng_state);

        /* Large response packets (amplified) */
        uint32_t size = (uint32_t)(64 * amplification);
        if (size > 65535) size = 65535;

        flowshield_process_packet(engine,
            amplifier_ip, victim_ip,
            amplifier_port, victim_port,
            PROTO_UDP, size, 0);
    }
}

void flowshield_simulate_hotspot_attack(
    FlowShield* engine,
    size_t target_shard,
    size_t num_packets
) {
    if (!engine || num_packets == 0) return;

    size_t num_shards = flow_tracker_num_shards(engine->tracker);
    if (target_shard >= num_shards) target_shard = 0;

    /*
     * Generate keys that all hash to the same shard.
     * This is an algorithmic complexity attack!
     *
     * With STATIC_HASH routing, all these will serialize on one shard.
     * With LOAD_AWARE routing, they'll be distributed across shards.
     */
    for (size_t i = 0; i < num_packets; i++) {
        /* Find a key that hashes to target shard */
        FlowKey key;
        do {
            key.src_ip = random_ip(&engine->rng_state);
            key.dst_ip = random_ip(&engine->rng_state);
            key.src_port = random_port(&engine->rng_state);
            key.dst_port = random_port(&engine->rng_state);
            key.protocol = PROTO_TCP;

            int64_t hash = flow_key_hash(&key);
            /* Check if this would go to target shard with static routing */
            if ((size_t)(hash % (int64_t)num_shards) == target_shard) {
                break;
            }
        } while (1);

        flowshield_process_packet(engine,
            key.src_ip, key.dst_ip,
            key.src_port, key.dst_port,
            key.protocol, 128, 0x02);
    }
}

/* ============================================================================
 * Output Formatting
 * ============================================================================ */

size_t flowshield_alert_to_json(
    const FlowAlert* alert,
    char* buf,
    size_t buf_size
) {
    if (!alert || !buf || buf_size == 0) return 0;

    char src_ip[16], dst_ip[16];
    ip_to_str(alert->flow.src_ip, src_ip, sizeof(src_ip));
    ip_to_str(alert->flow.dst_ip, dst_ip, sizeof(dst_ip));

    const char* attack_name;
    switch (alert->attack_type) {
        case ATTACK_SYN_FLOOD:      attack_name = "syn_flood"; break;
        case ATTACK_UDP_AMPLIFY:    attack_name = "udp_amplification"; break;
        case ATTACK_DNS_AMPLIFY:    attack_name = "dns_amplification"; break;
        case ATTACK_NTP_AMPLIFY:    attack_name = "ntp_amplification"; break;
        case ATTACK_VOLUMETRIC:     attack_name = "volumetric"; break;
        case ATTACK_CARPET_BOMB:    attack_name = "carpet_bombing"; break;
        default:                    attack_name = "unknown"; break;
    }

    const char* severity_name;
    switch (alert->severity) {
        case SEVERITY_LOW:      severity_name = "low"; break;
        case SEVERITY_MEDIUM:   severity_name = "medium"; break;
        case SEVERITY_HIGH:     severity_name = "high"; break;
        case SEVERITY_CRITICAL: severity_name = "critical"; break;
        default:                severity_name = "info"; break;
    }

    return snprintf(buf, buf_size,
        "{"
        "\"timestamp\":%lu,"
        "\"attack_type\":\"%s\","
        "\"severity\":\"%s\","
        "\"confidence\":%.2f,"
        "\"flow\":{"
            "\"src_ip\":\"%s\","
            "\"dst_ip\":\"%s\","
            "\"src_port\":%u,"
            "\"dst_port\":%u,"
            "\"protocol\":%u"
        "},"
        "\"stats\":{"
            "\"packets\":%lu,"
            "\"bytes\":%lu,"
            "\"syn_count\":%u,"
            "\"ack_count\":%u"
        "},"
        "\"description\":\"%s\""
        "}",
        (unsigned long)(alert->timestamp_ns / 1000000),  /* ms */
        attack_name,
        severity_name,
        alert->confidence,
        src_ip, dst_ip,
        alert->flow.src_port, alert->flow.dst_port,
        alert->flow.protocol,
        (unsigned long)alert->stats.packet_count,
        (unsigned long)alert->stats.byte_count,
        alert->stats.syn_count,
        alert->stats.ack_count,
        alert->description
    );
}

size_t flowshield_metrics_to_prometheus(
    const FlowMetrics* metrics,
    char* buf,
    size_t buf_size
) {
    if (!metrics || !buf || buf_size == 0) return 0;

    return snprintf(buf, buf_size,
        "# HELP flowshield_packets_total Total packets processed\n"
        "# TYPE flowshield_packets_total counter\n"
        "flowshield_packets_total %lu\n"
        "# HELP flowshield_bytes_total Total bytes processed\n"
        "# TYPE flowshield_bytes_total counter\n"
        "flowshield_bytes_total %lu\n"
        "# HELP flowshield_flows_active Number of active flows\n"
        "# TYPE flowshield_flows_active gauge\n"
        "flowshield_flows_active %lu\n"
        "# HELP flowshield_flows_suspicious Number of suspicious flows\n"
        "# TYPE flowshield_flows_suspicious gauge\n"
        "flowshield_flows_suspicious %lu\n"
        "# HELP flowshield_shard_balance Load balance score (0-1)\n"
        "# TYPE flowshield_shard_balance gauge\n"
        "flowshield_shard_balance %.4f\n"
        "# HELP flowshield_alerts_active Number of active alerts\n"
        "# TYPE flowshield_alerts_active gauge\n"
        "flowshield_alerts_active %u\n",
        (unsigned long)metrics->total_packets,
        (unsigned long)metrics->total_bytes,
        (unsigned long)metrics->unique_flows,
        (unsigned long)metrics->suspicious_flows,
        metrics->shard_balance,
        metrics->active_alerts
    );
}

/* ============================================================================
 * Console Output
 * ============================================================================ */

void flowshield_print_summary(FlowShield* engine) {
    if (!engine) return;

    FlowMetrics metrics;
    flowshield_get_metrics(engine, &metrics);

    DetectorStats stats;
    flowshield_get_detector_stats(engine, &stats);

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                    FLOWSHIELD SUMMARY                        ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Flows:     %-10lu  │  Packets:    %-15lu    ║\n",
           (unsigned long)metrics.unique_flows,
           (unsigned long)metrics.total_packets);
    printf("║ Flagged:   %-10lu  │  Bytes:      %-15lu    ║\n",
           (unsigned long)metrics.suspicious_flows,
           (unsigned long)metrics.total_bytes);
    printf("║ Shards:    %-10lu  │  Balance:    %-6.1f%%            ║\n",
           (unsigned long)flow_tracker_num_shards(engine->tracker),
           metrics.shard_balance * 100);
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ DETECTION STATS                                              ║\n");
    printf("║ Analyses:  %-10lu  │  Alerts:     %-10lu         ║\n",
           (unsigned long)stats.total_analyses,
           (unsigned long)stats.total_alerts);
    printf("║ Avg Time:  %-6.2f ms   │  Flows/Run:  %-10lu         ║\n",
           stats.avg_analysis_time_ms,
           (unsigned long)stats.flows_analyzed);
    printf("╚══════════════════════════════════════════════════════════════╝\n");
}

void flowshield_print_dashboard(FlowShield* engine, bool clear_screen) {
    if (!engine) return;

    if (clear_screen) {
        printf("\033[2J\033[H");  /* ANSI clear screen */
    }

    FlowMetrics metrics;
    flowshield_get_metrics(engine, &metrics);

    EntropyAnalysis entropy;
    flowshield_get_entropy(engine, &entropy);

    size_t num_shards = flow_tracker_num_shards(engine->tracker);

    /* Header */
    printf("┌────────────────────────────────────────────────────────────────┐\n");
    printf("│  🛡️  FLOWSHIELD - Real-Time DDoS Detection                      │\n");
    printf("│  Routing: %-10s  │  Shards: %-3lu                         │\n",
           engine->config.routing == ROUTER_LOAD_AWARE ? "LOAD_AWARE" :
           engine->config.routing == ROUTER_STATIC_HASH ? "STATIC" : "OTHER",
           (unsigned long)num_shards);
    printf("├────────────────────────────────────────────────────────────────┤\n");

    /* Traffic stats */
    printf("│  TRAFFIC                                                       │\n");
    printf("│  Packets: %-12lu    Bytes: %-12lu               │\n",
           (unsigned long)metrics.total_packets,
           (unsigned long)metrics.total_bytes);
    printf("│  Flows:   %-12lu    Flagged: %-10lu                 │\n",
           (unsigned long)metrics.unique_flows,
           (unsigned long)metrics.suspicious_flows);

    /* Balance visualization */
    printf("├────────────────────────────────────────────────────────────────┤\n");
    printf("│  SHARD BALANCE: ");

    int bar_width = 40;
    int filled = (int)(metrics.shard_balance * bar_width);
    printf("[");
    for (int i = 0; i < bar_width; i++) {
        if (i < filled) {
            if (metrics.shard_balance > 0.8) printf("\033[32m█\033[0m");      /* Green */
            else if (metrics.shard_balance > 0.5) printf("\033[33m█\033[0m"); /* Yellow */
            else printf("\033[31m█\033[0m");                                    /* Red */
        } else {
            printf("░");
        }
    }
    printf("] %5.1f%%    │\n", metrics.shard_balance * 100);

    /* Entropy */
    printf("├────────────────────────────────────────────────────────────────┤\n");
    printf("│  ENTROPY ANALYSIS                                              │\n");
    printf("│  Source IPs:  %.2f bits  (unique: %-6lu)                     │\n",
           entropy.src_ip_entropy, (unsigned long)entropy.unique_src_ips);
    printf("│  Dest IPs:    %.2f bits  (unique: %-6lu)                     │\n",
           entropy.dst_ip_entropy, (unsigned long)entropy.unique_dst_ips);

    /* Alerts */
    size_t alert_count = anomaly_detector_alert_count(engine->detector);
    printf("├────────────────────────────────────────────────────────────────┤\n");
    printf("│  ALERTS: %-3lu                                                  │\n",
           (unsigned long)alert_count);

    if (alert_count > 0) {
        FlowAlert alerts[5];
        size_t shown = anomaly_detector_get_alerts(engine->detector, alerts, 5);
        for (size_t i = 0; i < shown; i++) {
            const char* icon;
            switch (alerts[i].severity) {
                case SEVERITY_CRITICAL: icon = "🔴"; break;
                case SEVERITY_HIGH:     icon = "🟠"; break;
                case SEVERITY_MEDIUM:   icon = "🟡"; break;
                default:                icon = "🟢"; break;
            }
            printf("│  %s %.50s │\n", icon, alerts[i].description);
        }
    }

    printf("└────────────────────────────────────────────────────────────────┘\n");
}
