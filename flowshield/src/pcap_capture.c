/**
 * FlowShield - libpcap Integration Implementation
 *
 * Real network traffic capture using libpcap.
 */

#define _GNU_SOURCE
#include "../include/pcap_capture.h"

#ifdef HAVE_PCAP
#include <pcap.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

/* ============================================================================
 * Internal Structures
 * ============================================================================ */

struct PcapCapture {
    FlowShield* engine;

#ifdef HAVE_PCAP
    pcap_t* handle;
    struct bpf_program filter;
    bool filter_compiled;
#endif

    /* Capture thread */
    pthread_t thread;
    volatile bool running;
    volatile bool should_stop;

    /* Statistics */
    _Atomic uint64_t packets_received;
    _Atomic uint64_t packets_processed;
    _Atomic uint64_t bytes_received;
    uint64_t start_time_ns;

    /* Error buffer */
    char error_buf[256];
};

/* ============================================================================
 * Packet Parsing
 * ============================================================================ */

/* Ethernet header (14 bytes) */
#define ETHER_HEADER_LEN 14

/* Parse packet and feed to FlowShield */
static void process_packet(
    PcapCapture* capture,
    const uint8_t* packet,
    uint32_t len
) {
    if (len < ETHER_HEADER_LEN + 20) return;  /* Min: Ethernet + IP header */

    atomic_fetch_add(&capture->packets_received, 1);
    atomic_fetch_add(&capture->bytes_received, len);

    /* Skip Ethernet header */
    const uint8_t* ip_data = packet + ETHER_HEADER_LEN;
    uint32_t ip_len = len - ETHER_HEADER_LEN;

    /* Parse IP header */
    uint8_t version = (ip_data[0] >> 4) & 0x0F;
    if (version != 4) return;  /* Only IPv4 for now */

    uint8_t ihl = (ip_data[0] & 0x0F) * 4;
    if (ihl < 20 || ip_len < ihl) return;

    uint8_t protocol = ip_data[9];
    uint32_t src_ip = ntohl(*(uint32_t*)(ip_data + 12));
    uint32_t dst_ip = ntohl(*(uint32_t*)(ip_data + 16));

    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t tcp_flags = 0;

    const uint8_t* transport = ip_data + ihl;
    uint32_t transport_len = ip_len - ihl;

    if (protocol == IPPROTO_TCP && transport_len >= 20) {
        src_port = ntohs(*(uint16_t*)(transport));
        dst_port = ntohs(*(uint16_t*)(transport + 2));
        tcp_flags = transport[13];
    } else if (protocol == IPPROTO_UDP && transport_len >= 8) {
        src_port = ntohs(*(uint16_t*)(transport));
        dst_port = ntohs(*(uint16_t*)(transport + 2));
    } else if (protocol == IPPROTO_ICMP) {
        /* ICMP - no ports */
    }

    /* Feed to FlowShield */
    flowshield_process_packet(
        capture->engine,
        src_ip, dst_ip,
        src_port, dst_port,
        protocol,
        len,
        tcp_flags
    );

    atomic_fetch_add(&capture->packets_processed, 1);
}

/* ============================================================================
 * Capture Thread
 * ============================================================================ */

#ifdef HAVE_PCAP
static void pcap_callback(
    u_char* user,
    const struct pcap_pkthdr* header,
    const u_char* packet
) {
    PcapCapture* capture = (PcapCapture*)user;

    if (capture->should_stop) {
        pcap_breakloop(capture->handle);
        return;
    }

    process_packet(capture, packet, header->caplen);
}

static void* capture_thread(void* arg) {
    PcapCapture* capture = (PcapCapture*)arg;

    capture->running = true;
    capture->start_time_ns = time_now_ns();

    pcap_loop(capture->handle, 0, pcap_callback, (u_char*)capture);

    capture->running = false;
    return NULL;
}
#endif

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

PcapCapture* pcap_capture_create(
    FlowShield* engine,
    const char* interface,
    const char* filter,
    int snaplen
) {
#ifndef HAVE_PCAP
    (void)engine;
    (void)interface;
    (void)filter;
    (void)snaplen;
    return NULL;
#else
    if (!engine || !interface) return NULL;

    PcapCapture* capture = calloc(1, sizeof(PcapCapture));
    if (!capture) return NULL;

    capture->engine = engine;

    /* Open capture */
    char errbuf[PCAP_ERRBUF_SIZE];
    capture->handle = pcap_open_live(
        interface,
        snaplen > 0 ? snaplen : 96,  /* Capture IP + TCP/UDP headers */
        1,                            /* Promiscuous mode */
        100,                          /* Timeout ms */
        errbuf
    );

    if (!capture->handle) {
        snprintf(capture->error_buf, sizeof(capture->error_buf),
                 "pcap_open_live failed: %s", errbuf);
        free(capture);
        return NULL;
    }

    /* Compile and set filter if provided */
    if (filter && strlen(filter) > 0) {
        if (pcap_compile(capture->handle, &capture->filter, filter, 1, PCAP_NETMASK_UNKNOWN) == 0) {
            if (pcap_setfilter(capture->handle, &capture->filter) == 0) {
                capture->filter_compiled = true;
            }
        }
    }

    return capture;
#endif
}

PcapCapture* pcap_capture_from_file(FlowShield* engine, const char* pcap_file) {
#ifndef HAVE_PCAP
    (void)engine;
    (void)pcap_file;
    return NULL;
#else
    if (!engine || !pcap_file) return NULL;

    PcapCapture* capture = calloc(1, sizeof(PcapCapture));
    if (!capture) return NULL;

    capture->engine = engine;

    char errbuf[PCAP_ERRBUF_SIZE];
    capture->handle = pcap_open_offline(pcap_file, errbuf);

    if (!capture->handle) {
        snprintf(capture->error_buf, sizeof(capture->error_buf),
                 "pcap_open_offline failed: %s", errbuf);
        free(capture);
        return NULL;
    }

    return capture;
#endif
}

void pcap_capture_destroy(PcapCapture* capture) {
    if (!capture) return;

    pcap_capture_stop(capture);

#ifdef HAVE_PCAP
    if (capture->filter_compiled) {
        pcap_freecode(&capture->filter);
    }
    if (capture->handle) {
        pcap_close(capture->handle);
    }
#endif

    free(capture);
}

/* ============================================================================
 * Capture Control
 * ============================================================================ */

bool pcap_capture_start(PcapCapture* capture) {
#ifndef HAVE_PCAP
    (void)capture;
    return false;
#else
    if (!capture || capture->running) return false;

    capture->should_stop = false;

    if (pthread_create(&capture->thread, NULL, capture_thread, capture) != 0) {
        return false;
    }

    return true;
#endif
}

void pcap_capture_stop(PcapCapture* capture) {
    if (!capture || !capture->running) return;

    capture->should_stop = true;

#ifdef HAVE_PCAP
    if (capture->handle) {
        pcap_breakloop(capture->handle);
    }
#endif

    pthread_join(capture->thread, NULL);
}

bool pcap_capture_is_running(const PcapCapture* capture) {
    return capture && capture->running;
}

size_t pcap_capture_process(PcapCapture* capture, size_t max_packets) {
#ifndef HAVE_PCAP
    (void)capture;
    (void)max_packets;
    return 0;
#else
    if (!capture || !capture->handle) return 0;

    capture->start_time_ns = time_now_ns();

    int count = (max_packets > 0) ? (int)max_packets : -1;
    int result = pcap_dispatch(capture->handle, count, pcap_callback, (u_char*)capture);

    return (result >= 0) ? (size_t)result : 0;
#endif
}

/* ============================================================================
 * Statistics
 * ============================================================================ */

void pcap_capture_get_stats(const PcapCapture* capture, CaptureStats* out_stats) {
    if (!capture || !out_stats) return;

    memset(out_stats, 0, sizeof(CaptureStats));

    out_stats->packets_received = atomic_load(&capture->packets_received);
    out_stats->packets_processed = atomic_load(&capture->packets_processed);
    out_stats->bytes_received = atomic_load(&capture->bytes_received);

#ifdef HAVE_PCAP
    if (capture->handle) {
        struct pcap_stat ps;
        if (pcap_stats(capture->handle, &ps) == 0) {
            out_stats->packets_dropped = ps.ps_drop;
        }
    }
#endif

    /* Calculate rates */
    uint64_t elapsed_ns = time_now_ns() - capture->start_time_ns;
    if (elapsed_ns > 0) {
        double elapsed_sec = elapsed_ns / 1e9;
        out_stats->capture_rate_pps = out_stats->packets_received / elapsed_sec;
        out_stats->processing_rate_pps = out_stats->packets_processed / elapsed_sec;
    }
}

const char* pcap_capture_get_error(const PcapCapture* capture) {
    if (!capture) return "NULL capture";
    if (capture->error_buf[0]) return capture->error_buf;

#ifdef HAVE_PCAP
    if (capture->handle) {
        return pcap_geterr(capture->handle);
    }
#endif

    return "Unknown error";
}

/* ============================================================================
 * Utility
 * ============================================================================ */

size_t pcap_capture_list_interfaces(char** out_names, size_t max_names) {
#ifndef HAVE_PCAP
    (void)out_names;
    (void)max_names;
    return 0;
#else
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return 0;
    }

    size_t count = 0;
    for (pcap_if_t* d = alldevs; d && count < max_names; d = d->next) {
        out_names[count] = strdup(d->name);
        count++;
    }

    pcap_freealldevs(alldevs);
    return count;
#endif
}

void pcap_capture_free_interfaces(char** names, size_t count) {
    for (size_t i = 0; i < count; i++) {
        free(names[i]);
    }
}
