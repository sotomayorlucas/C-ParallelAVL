/**
 * FlowShield Live Capture Tool
 *
 * Real-time network traffic analysis using libpcap.
 * Demonstrates FlowShield on actual network traffic.
 *
 * Usage:
 *   sudo ./flowshield_live eth0              # Capture on interface
 *   sudo ./flowshield_live any               # Capture on all interfaces
 *   sudo ./flowshield_live -f capture.pcap   # Replay pcap file
 *   sudo ./flowshield_live -h                # Help
 */

#define _GNU_SOURCE
#include "../include/flowshield.h"
#include "../include/pcap_capture.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

/* ============================================================================
 * Configuration
 * ============================================================================ */

#define DEFAULT_SHARDS     8
#define ANALYSIS_INTERVAL  1  /* seconds */
#define DASHBOARD_REFRESH  1  /* seconds */

/* Global for signal handler */
static volatile int g_running = 1;
static FlowShield* g_engine = NULL;
static PcapCapture* g_capture = NULL;

/* ============================================================================
 * Signal Handler
 * ============================================================================ */

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
    printf("\n\n🛑 Shutting down...\n");

    if (g_capture) {
        pcap_capture_stop(g_capture);
    }
}

/* ============================================================================
 * Alert Callback
 * ============================================================================ */

static void alert_callback(const FlowAlert* alert, void* user_data) {
    (void)user_data;

    char src_ip[16], dst_ip[16];
    ip_to_str(alert->flow.src_ip, src_ip, sizeof(src_ip));
    ip_to_str(alert->flow.dst_ip, dst_ip, sizeof(dst_ip));

    const char* severity_icon;
    switch (alert->severity) {
        case SEVERITY_CRITICAL: severity_icon = "🔴"; break;
        case SEVERITY_HIGH:     severity_icon = "🟠"; break;
        case SEVERITY_MEDIUM:   severity_icon = "🟡"; break;
        default:                severity_icon = "🟢"; break;
    }

    printf("\n%s ALERT: %s\n", severity_icon, alert->description);
    printf("   Flow: %s:%u → %s:%u\n",
           src_ip, alert->flow.src_port,
           dst_ip, alert->flow.dst_port);
}

/* ============================================================================
 * Usage
 * ============================================================================ */

static void print_usage(const char* prog) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║            FlowShield Live Capture Tool                      ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("Usage: %s [OPTIONS] <interface|file>\n", prog);
    printf("\n");
    printf("Options:\n");
    printf("  -f <file>       Read from pcap file instead of live capture\n");
    printf("  -s <shards>     Number of AVL shards (default: %d)\n", DEFAULT_SHARDS);
    printf("  -b <filter>     BPF filter (e.g., 'tcp port 80')\n");
    printf("  -q              Quiet mode (no dashboard, only alerts)\n");
    printf("  -h              Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  sudo %s eth0                    # Capture on eth0\n", prog);
    printf("  sudo %s any                     # Capture on all interfaces\n", prog);
    printf("  sudo %s -b 'tcp port 80' eth0   # HTTP traffic only\n", prog);
    printf("  %s -f capture.pcap              # Replay pcap file\n", prog);
    printf("\n");
    printf("Note: Live capture requires root privileges.\n");
    printf("\n");
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(int argc, char* argv[]) {
    const char* interface = NULL;
    const char* pcap_file = NULL;
    const char* bpf_filter = NULL;
    int num_shards = DEFAULT_SHARDS;
    int quiet_mode = 0;

    /* Parse arguments */
    int opt;
    while ((opt = getopt(argc, argv, "f:s:b:qh")) != -1) {
        switch (opt) {
            case 'f':
                pcap_file = optarg;
                break;
            case 's':
                num_shards = atoi(optarg);
                if (num_shards < 1 || num_shards > 64) {
                    fprintf(stderr, "Error: shards must be 1-64\n");
                    return 1;
                }
                break;
            case 'b':
                bpf_filter = optarg;
                break;
            case 'q':
                quiet_mode = 1;
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return 0;
        }
    }

    /* Get interface from remaining args */
    if (optind < argc) {
        interface = argv[optind];
    }

    /* Validate input */
    if (!interface && !pcap_file) {
        fprintf(stderr, "Error: specify interface or -f <file>\n");
        print_usage(argv[0]);
        return 1;
    }

#ifndef HAVE_PCAP
    fprintf(stderr, "Error: FlowShield was compiled without libpcap support.\n");
    fprintf(stderr, "Rebuild with: make pcap\n");
    return 1;
#endif

    /* Setup signal handler */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Create FlowShield engine */
    printf("\n🛡️  FlowShield Live Capture\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    FlowShieldConfig config = flowshield_config_default();
    config.num_shards = num_shards;
    config.routing = ROUTER_LOAD_AWARE;

    g_engine = flowshield_create(&config);
    if (!g_engine) {
        fprintf(stderr, "Error: Failed to create FlowShield engine\n");
        return 1;
    }

    /* Set alert callback */
    anomaly_detector_set_callback(
        flowshield_get_detector(g_engine),
        alert_callback,
        NULL
    );

    printf("✓ Engine created with %d shards (LOAD_AWARE routing)\n", num_shards);

    /* Create capture */
#ifdef HAVE_PCAP
    if (pcap_file) {
        printf("✓ Opening pcap file: %s\n", pcap_file);
        g_capture = pcap_capture_from_file(g_engine, pcap_file);
    } else {
        printf("✓ Opening interface: %s\n", interface);
        if (bpf_filter) {
            printf("✓ BPF filter: %s\n", bpf_filter);
        }
        g_capture = pcap_capture_create(g_engine, interface, bpf_filter, 96);
    }

    if (!g_capture) {
        fprintf(stderr, "Error: Failed to create capture: %s\n",
                pcap_capture_get_error(g_capture));
        flowshield_destroy(g_engine);
        return 1;
    }

    printf("✓ Capture ready\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

    if (pcap_file) {
        /* Process file */
        printf("📄 Processing pcap file...\n\n");

        size_t processed = pcap_capture_process(g_capture, 0);
        flowshield_analyze(g_engine);

        printf("\n📊 Processing complete: %zu packets\n", processed);
        flowshield_print_summary(g_engine);
    } else {
        /* Live capture */
        printf("📡 Starting live capture (Ctrl+C to stop)...\n\n");

        if (!pcap_capture_start(g_capture)) {
            fprintf(stderr, "Error: Failed to start capture\n");
            pcap_capture_destroy(g_capture);
            flowshield_destroy(g_engine);
            return 1;
        }

        /* Main loop */
        time_t last_analysis = 0;
        time_t last_display = 0;

        while (g_running && pcap_capture_is_running(g_capture)) {
            time_t now = time(NULL);

            /* Run analysis periodically */
            if (now - last_analysis >= ANALYSIS_INTERVAL) {
                flowshield_analyze(g_engine);
                last_analysis = now;
            }

            /* Update display */
            if (!quiet_mode && now - last_display >= DASHBOARD_REFRESH) {
                flowshield_print_dashboard(g_engine, true);
                last_display = now;
            }

            usleep(100000);  /* 100ms */
        }

        pcap_capture_stop(g_capture);
    }

    /* Print final stats */
    printf("\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    CaptureStats cap_stats;
    pcap_capture_get_stats(g_capture, &cap_stats);

    printf("📊 Capture Statistics:\n");
    printf("   Packets received:   %lu\n", (unsigned long)cap_stats.packets_received);
    printf("   Packets processed:  %lu\n", (unsigned long)cap_stats.packets_processed);
    printf("   Packets dropped:    %lu\n", (unsigned long)cap_stats.packets_dropped);
    printf("   Bytes received:     %lu\n", (unsigned long)cap_stats.bytes_received);
    printf("   Avg capture rate:   %.1f pps\n", cap_stats.capture_rate_pps);

    flowshield_print_summary(g_engine);

    /* Cleanup */
    pcap_capture_destroy(g_capture);
#endif

    flowshield_destroy(g_engine);

    printf("\n✅ FlowShield shutdown complete\n\n");
    return 0;
}
