/**
 * FlowShield - DDoS/Anomaly Detection Engine
 *
 * Core type definitions for network flow tracking and analysis.
 * Built on ParallelAVL for high-performance concurrent operations.
 */

#ifndef FLOWSHIELD_FLOW_TYPES_H
#define FLOWSHIELD_FLOW_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ============================================================================ */

#define FLOW_HISTORY_SIZE      16    /* Rolling window for rate calculation */
#define MAX_FLOWS_PER_QUERY   256    /* Max flows returned in range query */
#define DEFAULT_FLOW_TIMEOUT   60    /* Seconds before flow expires */

/* Protocol identifiers */
typedef enum {
    PROTO_UNKNOWN = 0,
    PROTO_ICMP    = 1,
    PROTO_TCP     = 6,
    PROTO_UDP     = 17
} FlowProtocol;

/* Attack types detected */
typedef enum {
    ATTACK_NONE           = 0,
    ATTACK_SYN_FLOOD      = 1 << 0,
    ATTACK_UDP_AMPLIFY    = 1 << 1,
    ATTACK_ICMP_FLOOD     = 1 << 2,
    ATTACK_HTTP_FLOOD     = 1 << 3,
    ATTACK_SLOWLORIS      = 1 << 4,
    ATTACK_DNS_AMPLIFY    = 1 << 5,
    ATTACK_NTP_AMPLIFY    = 1 << 6,
    ATTACK_CARPET_BOMB    = 1 << 7,
    ATTACK_PORT_SCAN      = 1 << 8,
    ATTACK_VOLUMETRIC     = 1 << 9
} AttackType;

/* Severity levels for alerts */
typedef enum {
    SEVERITY_INFO    = 0,
    SEVERITY_LOW     = 1,
    SEVERITY_MEDIUM  = 2,
    SEVERITY_HIGH    = 3,
    SEVERITY_CRITICAL= 4
} AlertSeverity;

/* ============================================================================
 * Flow Identification (5-tuple)
 * ============================================================================ */

typedef struct {
    uint32_t src_ip;        /* Source IP (network byte order) */
    uint32_t dst_ip;        /* Destination IP (network byte order) */
    uint16_t src_port;      /* Source port */
    uint16_t dst_port;      /* Destination port */
    uint8_t  protocol;      /* IP protocol number */
    uint8_t  _pad[3];       /* Alignment padding */
} FlowKey;

/* ============================================================================
 * Flow Statistics
 * ============================================================================ */

typedef struct {
    /* Counters */
    uint64_t packet_count;      /* Total packets in flow */
    uint64_t byte_count;        /* Total bytes in flow */

    /* TCP flags (for SYN flood detection) */
    uint32_t syn_count;         /* SYN packets seen */
    uint32_t ack_count;         /* ACK packets seen */
    uint32_t fin_count;         /* FIN packets seen */
    uint32_t rst_count;         /* RST packets seen */

    /* Timestamps */
    uint64_t first_seen_ns;     /* First packet timestamp (nanoseconds) */
    uint64_t last_seen_ns;      /* Last packet timestamp (nanoseconds) */

    /* Rate history (circular buffer for rolling averages) */
    uint32_t pps_history[FLOW_HISTORY_SIZE];   /* Packets per second */
    uint32_t bps_history[FLOW_HISTORY_SIZE];   /* Bytes per second (in KB) */
    uint8_t  history_idx;       /* Current position in circular buffer */
    uint8_t  history_count;     /* Number of valid entries */

    /* Flags */
    uint8_t  is_flagged;        /* Marked as suspicious */
    uint8_t  attack_types;      /* Bitmask of AttackType */
} FlowStats;

/* ============================================================================
 * Alert Structure
 * ============================================================================ */

typedef struct {
    FlowKey      flow;              /* Flow that triggered alert */
    FlowStats    stats;             /* Flow statistics at alert time */
    AttackType   attack_type;       /* Type of attack detected */
    AlertSeverity severity;         /* Alert severity */
    uint64_t     timestamp_ns;      /* When alert was generated */
    double       confidence;        /* Detection confidence (0.0 - 1.0) */
    char         description[256];  /* Human-readable description */
} FlowAlert;

/* ============================================================================
 * Aggregated Metrics (per time window)
 * ============================================================================ */

typedef struct {
    uint64_t timestamp_ns;          /* Start of time window */
    uint64_t window_duration_ns;    /* Duration of window */

    /* Global counters */
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t unique_flows;
    uint64_t new_flows;
    uint64_t expired_flows;

    /* Per-protocol breakdown */
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;

    /* Attack metrics */
    uint64_t syn_packets;
    uint64_t suspicious_flows;
    uint32_t active_alerts;

    /* Performance metrics */
    double   avg_pps;               /* Average packets per second */
    double   peak_pps;              /* Peak packets per second */
    double   shard_balance;         /* Load balance score (0.0 - 1.0) */
    uint64_t processing_latency_ns; /* Average processing latency */
} FlowMetrics;

/* ============================================================================
 * Detection Thresholds (configurable)
 * ============================================================================ */

typedef struct {
    /* Volumetric thresholds */
    uint64_t max_pps_per_flow;      /* Max packets/sec before flagging */
    uint64_t max_bps_per_flow;      /* Max bytes/sec before flagging */
    uint64_t max_total_pps;         /* Global packets/sec threshold */

    /* SYN flood detection */
    double   syn_ack_ratio_thresh;  /* SYN/ACK ratio threshold */
    uint32_t syn_per_second_thresh; /* SYN packets/sec threshold */

    /* Rate spike detection */
    double   rate_spike_sigma;      /* Standard deviations for spike */

    /* Entropy thresholds */
    double   min_src_entropy;       /* Minimum source IP entropy */
    double   min_dst_entropy;       /* Minimum destination entropy */

    /* Amplification detection */
    double   amplification_ratio;   /* Response/request size ratio */

    /* Timing */
    uint32_t flow_timeout_sec;      /* Seconds before flow expires */
    uint32_t analysis_interval_ms;  /* How often to run detection */
} DetectionConfig;

/* Default configuration */
static inline DetectionConfig detection_config_default(void) {
    return (DetectionConfig) {
        .max_pps_per_flow      = 10000,
        .max_bps_per_flow      = 100 * 1024 * 1024, /* 100 MB/s */
        .max_total_pps         = 1000000,
        .syn_ack_ratio_thresh  = 3.0,
        .syn_per_second_thresh = 1000,
        .rate_spike_sigma      = 3.0,
        .min_src_entropy       = 2.0,
        .min_dst_entropy       = 2.0,
        .amplification_ratio   = 10.0,
        .flow_timeout_sec      = 60,
        .analysis_interval_ms  = 1000
    };
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/* Generate 64-bit flow key for ParallelAVL */
static inline int64_t flow_key_hash(const FlowKey* key) {
    /* Murmur3-inspired hash combining all fields */
    uint64_t h = 0;
    h ^= (uint64_t)key->src_ip * 0xcc9e2d51;
    h ^= (uint64_t)key->dst_ip * 0x1b873593;
    h ^= (uint64_t)key->src_port << 32 | key->dst_port;
    h ^= (uint64_t)key->protocol * 0x85ebca6b;
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccd;
    h ^= h >> 33;
    return (int64_t)(h & 0x7FFFFFFFFFFFFFFF); /* Ensure positive */
}

/* Get current time in nanoseconds */
static inline uint64_t time_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* Convert IP to string (thread-safe) */
static inline void ip_to_str(uint32_t ip, char* buf, size_t len) {
    snprintf(buf, len, "%u.%u.%u.%u",
             (ip >> 24) & 0xFF,
             (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF,
             ip & 0xFF);
}

/* String to IP */
static inline uint32_t str_to_ip(const char* str) {
    uint32_t a, b, c, d;
    if (sscanf(str, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
        return (a << 24) | (b << 16) | (c << 8) | d;
    }
    return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* FLOWSHIELD_FLOW_TYPES_H */
