/**
 * FlowShield - libpcap Integration
 *
 * Real network traffic capture and analysis.
 * Requires libpcap-dev: apt-get install libpcap-dev
 */

#ifndef FLOWSHIELD_PCAP_CAPTURE_H
#define FLOWSHIELD_PCAP_CAPTURE_H

#include "flowshield.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Capture Handle
 * ============================================================================ */

typedef struct PcapCapture PcapCapture;

/* Capture statistics */
typedef struct {
    uint64_t packets_received;
    uint64_t packets_processed;
    uint64_t packets_dropped;
    uint64_t bytes_received;
    double   capture_rate_pps;
    double   processing_rate_pps;
} CaptureStats;

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

/**
 * Create capture instance.
 *
 * @param engine        FlowShield engine to feed packets into
 * @param interface     Network interface (e.g., "eth0", "any")
 * @param filter        BPF filter (e.g., "tcp port 80", NULL for all)
 * @param snaplen       Bytes to capture per packet (0 = default 96)
 * @return              Capture handle or NULL on error
 */
PcapCapture* pcap_capture_create(
    FlowShield* engine,
    const char* interface,
    const char* filter,
    int snaplen
);

/**
 * Create capture from pcap file (for replay/testing).
 *
 * @param engine        FlowShield engine
 * @param pcap_file     Path to .pcap or .pcapng file
 * @return              Capture handle or NULL on error
 */
PcapCapture* pcap_capture_from_file(
    FlowShield* engine,
    const char* pcap_file
);

/**
 * Destroy capture instance.
 */
void pcap_capture_destroy(PcapCapture* capture);

/* ============================================================================
 * Capture Control
 * ============================================================================ */

/**
 * Start capturing in a background thread.
 *
 * @param capture       Capture instance
 * @return              true if started successfully
 */
bool pcap_capture_start(PcapCapture* capture);

/**
 * Stop capturing.
 */
void pcap_capture_stop(PcapCapture* capture);

/**
 * Check if capture is running.
 */
bool pcap_capture_is_running(const PcapCapture* capture);

/**
 * Process packets in current thread (blocking).
 * Useful for single-threaded applications.
 *
 * @param capture       Capture instance
 * @param max_packets   Maximum packets to process (0 = unlimited)
 * @return              Number of packets processed
 */
size_t pcap_capture_process(PcapCapture* capture, size_t max_packets);

/* ============================================================================
 * Statistics
 * ============================================================================ */

/**
 * Get capture statistics.
 */
void pcap_capture_get_stats(const PcapCapture* capture, CaptureStats* out_stats);

/**
 * Get last error message.
 */
const char* pcap_capture_get_error(const PcapCapture* capture);

/* ============================================================================
 * Utility
 * ============================================================================ */

/**
 * List available network interfaces.
 *
 * @param out_names     Array to store interface names
 * @param max_names     Maximum number of names to store
 * @return              Number of interfaces found
 */
size_t pcap_capture_list_interfaces(char** out_names, size_t max_names);

/**
 * Free interface list.
 */
void pcap_capture_free_interfaces(char** names, size_t count);

#ifdef __cplusplus
}
#endif

#endif /* FLOWSHIELD_PCAP_CAPTURE_H */
