/**
 * FlowShield Live Capture Tool (C++23)
 *
 * Real-time network traffic analysis using libpcap. Demonstrates FlowShield on
 * actual network traffic. The libpcap-dependent body is guarded by HAVE_PCAP;
 * without it the file still compiles and main() prints a helpful message.
 *
 * Usage:
 *   sudo ./flowshield_live eth0              # Capture on interface
 *   sudo ./flowshield_live any               # Capture on all interfaces
 *   sudo ./flowshield_live -f capture.pcap   # Replay pcap file
 *   sudo ./flowshield_live -h                # Help
 */

#include "../include/flowshield.hpp"
#ifdef HAVE_PCAP
#include "../include/pcap_capture.hpp"
#endif

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <format>
#include <iostream>
#include <string>
#include <string_view>
#include <thread>

#include <unistd.h>  // getopt

namespace {

// ============================================================================
// Configuration
// ============================================================================

constexpr int kDefaultShards     = 8;
constexpr int kAnalysisInterval  = 1;   // seconds
constexpr int kDashboardRefresh  = 1;   // seconds

#ifdef HAVE_PCAP
// Globals for signal handler
std::atomic<bool> g_running{true};
flowshield::pcap_capture* g_capture = nullptr;

void signal_handler(int /*sig*/) {
    g_running.store(false, std::memory_order_release);
    std::cout << "\n\n[!] Shutting down...\n";
    if (g_capture) g_capture->stop();
}
#endif

// ============================================================================
// Usage
// ============================================================================

void print_usage(const char* prog) {
    std::cout << "\n";
    std::cout << "+==============================================================+\n";
    std::cout << "|            FlowShield Live Capture Tool                      |\n";
    std::cout << "+==============================================================+\n";
    std::cout << "\n";
    std::cout << std::format("Usage: {} [OPTIONS] <interface|file>\n", prog);
    std::cout << "\n";
    std::cout << "Options:\n";
    std::cout << "  -f <file>       Read from pcap file instead of live capture\n";
    std::cout << std::format("  -s <shards>     Number of AVL shards (default: {})\n", kDefaultShards);
    std::cout << "  -b <filter>     BPF filter (e.g., 'tcp port 80')\n";
    std::cout << "  -q              Quiet mode (no dashboard, only alerts)\n";
    std::cout << "  -h              Show this help\n";
    std::cout << "\n";
    std::cout << "Examples:\n";
    std::cout << std::format("  sudo {} eth0                    # Capture on eth0\n", prog);
    std::cout << std::format("  sudo {} any                     # Capture on all interfaces\n", prog);
    std::cout << std::format("  sudo {} -b 'tcp port 80' eth0   # HTTP traffic only\n", prog);
    std::cout << std::format("  {} -f capture.pcap              # Replay pcap file\n", prog);
    std::cout << "\n";
    std::cout << "Note: Live capture requires root privileges.\n";
    std::cout << "\n";
}

}  // namespace

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    const char* interface  = nullptr;
    const char* pcap_file  = nullptr;
    const char* bpf_filter = nullptr;
    int  num_shards = kDefaultShards;
    bool quiet_mode = false;

    int opt;
    while ((opt = ::getopt(argc, argv, "f:s:b:qh")) != -1) {
        switch (opt) {
            case 'f': pcap_file  = optarg; break;
            case 's':
                num_shards = std::atoi(optarg);
                if (num_shards < 1 || num_shards > 64) {
                    std::cerr << "Error: shards must be 1-64\n";
                    return 1;
                }
                break;
            case 'b': bpf_filter = optarg; break;
            case 'q': quiet_mode = true;   break;
            case 'h':
            default:
                print_usage(argv[0]);
                return 0;
        }
    }

    if (optind < argc) interface = argv[optind];

    if (!interface && !pcap_file) {
        std::cerr << "Error: specify interface or -f <file>\n";
        print_usage(argv[0]);
        return 1;
    }

#ifndef HAVE_PCAP
    (void)num_shards;
    (void)quiet_mode;
    (void)bpf_filter;
    std::cerr << "Error: FlowShield was compiled without libpcap support.\n";
    std::cerr << "Rebuild with HAVE_PCAP defined and link against -lpcap.\n";
    return 1;
#else
    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);

    std::cout << "\n[S] FlowShield Live Capture\n";
    std::cout << "==================================================================\n";

    flowshield::config cfg = flowshield::config_default();
    cfg.num_shards = static_cast<std::size_t>(num_shards);
    cfg.routing    = pavl::router_strategy::load_aware;

    flowshield::engine engine(cfg);

    // Hook up an alert callback on the underlying detector.
    engine.detector().set_callback([](const flowshield::flow_alert& alert) {
        std::string_view icon;
        switch (alert.severity) {
            case flowshield::alert_severity::critical: icon = "[!]"; break;
            case flowshield::alert_severity::high:     icon = "[H]"; break;
            case flowshield::alert_severity::medium:   icon = "[M]"; break;
            default:                                   icon = "[ ]"; break;
        }
        std::cout << "\n" << icon << " ALERT: " << alert.description << "\n";
        std::cout << std::format("   Flow: {}:{} -> {}:{}\n",
                                 flowshield::ip_to_str(alert.flow.src_ip), alert.flow.src_port,
                                 flowshield::ip_to_str(alert.flow.dst_ip), alert.flow.dst_port);
    });

    std::cout << std::format("OK Engine created with {} shards (LOAD_AWARE routing)\n", num_shards);

    std::unique_ptr<flowshield::pcap_capture> capture;
    if (pcap_file) {
        std::cout << "OK Opening pcap file: " << pcap_file << "\n";
        capture = std::make_unique<flowshield::pcap_capture>(engine, pcap_file);
    } else {
        std::cout << "OK Opening interface: " << interface << "\n";
        if (bpf_filter) std::cout << "OK BPF filter: " << bpf_filter << "\n";
        capture = std::make_unique<flowshield::pcap_capture>(
            engine, interface, bpf_filter ? bpf_filter : "", 96);
    }
    g_capture = capture.get();

    if (!capture->valid()) {
        std::cerr << "Error: Failed to create capture: " << capture->get_error() << "\n";
        return 1;
    }

    std::cout << "OK Capture ready\n";
    std::cout << "==================================================================\n\n";

    if (pcap_file) {
        std::cout << "[*] Processing pcap file...\n\n";
        const std::size_t processed = capture->process(0);
        engine.analyze();
        std::cout << std::format("\n[*] Processing complete: {} packets\n", processed);
        engine.print_summary();
    } else {
        std::cout << "[*] Starting live capture (Ctrl+C to stop)...\n\n";

        if (!capture->start()) {
            std::cerr << "Error: Failed to start capture\n";
            return 1;
        }

        using clock = std::chrono::steady_clock;
        auto last_analysis = clock::now() - std::chrono::seconds(kAnalysisInterval);
        auto last_display  = clock::now() - std::chrono::seconds(kDashboardRefresh);

        while (g_running.load(std::memory_order_acquire) && capture->is_running()) {
            const auto now = clock::now();

            if (now - last_analysis >= std::chrono::seconds(kAnalysisInterval)) {
                engine.analyze();
                last_analysis = now;
            }

            if (!quiet_mode && now - last_display >= std::chrono::seconds(kDashboardRefresh)) {
                engine.print_dashboard(true);
                last_display = now;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        capture->stop();
    }

    std::cout << "\n";
    std::cout << "==================================================================\n";

    const auto cap_stats = capture->get_stats();
    std::cout << "[*] Capture Statistics:\n";
    std::cout << std::format("   Packets received:   {}\n",   cap_stats.packets_received);
    std::cout << std::format("   Packets processed:  {}\n",   cap_stats.packets_processed);
    std::cout << std::format("   Packets dropped:    {}\n",   cap_stats.packets_dropped);
    std::cout << std::format("   Bytes received:     {}\n",   cap_stats.bytes_received);
    std::cout << std::format("   Avg capture rate:   {:.1f} pps\n", cap_stats.capture_rate_pps);

    engine.print_summary();

    g_capture = nullptr;
    std::cout << "\nOK FlowShield shutdown complete\n\n";
    return 0;
#endif
}
