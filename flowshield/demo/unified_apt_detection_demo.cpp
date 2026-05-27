/**
 * Unified APT Detection Demo (C++23)
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

#include "../include/causal_inference.hpp"
#include "../include/temporal_gnn.hpp"
#include "../include/unified_detector.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <format>
#include <iostream>
#include <string>
#include <thread>

namespace {

// ============================================================================
// Helpers
// ============================================================================

std::uint64_t get_time_ns() {
    using clock = std::chrono::steady_clock;
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               clock::now().time_since_epoch())
        .count();
}

// Minimal POD descriptors for syscall ingestion (engine treats these as
// opaque `const void*`).
struct ProcessEntity {
    std::uint32_t pid       = 0;
    std::uint32_t ppid      = 0;
    char          cmdline[256]  = {};
    char          exe_path[256] = {};
    std::uint32_t uid       = 0;
};

struct SocketEntity {
    std::uint32_t local_ip    = 0;
    std::uint32_t remote_ip   = 0;
    std::uint16_t local_port  = 0;
    std::uint16_t remote_port = 0;
    std::uint8_t  protocol    = 0;
};

// ============================================================================
// Simulated attack phases
// ============================================================================

void simulate_network_scan(flowshield::UnifiedDetector& detector) {
    std::cout << "\n[ATTACK] Phase 1: Network Reconnaissance\n";
    std::cout << "  Attacker: 192.168.1.100 -> Target: 10.0.0.50 (ports 22-1000)\n\n";

    for (std::uint16_t port = 22; port < 1000; port += 100) {
        flowshield::flow_key flow{};
        flow.src_ip   = (192u << 24) | (168u << 16) | (1u << 8) | 100u;
        flow.dst_ip   = (10u << 24)  | (0u << 16)   | (0u << 8) | 50u;
        flow.src_port = static_cast<std::uint16_t>(50'000 + port);
        flow.dst_port = port;
        flow.protocol = static_cast<std::uint8_t>(flowshield::flow_protocol::tcp);

        flowshield::flow_stats stats{};
        stats.packet_count  = 1;
        stats.byte_count    = 64;
        stats.syn_count     = 1;
        stats.ack_count     = 0;
        stats.first_seen_ns = get_time_ns();
        stats.last_seen_ns  = stats.first_seen_ns;

        detector.ingest_flow(flow, stats);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    std::cout << "  -> FlowShield should detect port scanning pattern\n";
}

void simulate_exploit_delivery(flowshield::UnifiedDetector& detector) {
    std::cout << "\n[ATTACK] Phase 2: Exploit Delivery\n";
    std::cout << "  Malicious HTTP request delivering exploit\n\n";

    flowshield::flow_key flow{};
    flow.src_ip   = (192u << 24) | (168u << 16) | (1u << 8) | 100u;
    flow.dst_ip   = (10u  << 24) | (0u   << 16) | (0u << 8) | 50u;
    flow.src_port = 51234;
    flow.dst_port = 80;
    flow.protocol = static_cast<std::uint8_t>(flowshield::flow_protocol::tcp);

    flowshield::flow_stats stats{};
    stats.packet_count  = 50;
    stats.byte_count    = 8192;
    stats.syn_count     = 1;
    stats.ack_count     = 10;
    stats.first_seen_ns = get_time_ns();
    stats.last_seen_ns  = stats.first_seen_ns + 500'000'000ULL;

    detector.ingest_flow(flow, stats);
    std::cout << "  -> Suspicious HTTP flow detected\n";
}

void simulate_malware_execution(flowshield::UnifiedDetector& detector) {
    std::cout << "\n[ATTACK] Phase 3: Malware Execution\n";
    std::cout << "  webserver (PID 1000) -> fork -> malware.exe (PID 1337)\n\n";

    ProcessEntity webserver{};
    webserver.pid = 1000;
    webserver.ppid = 1;
    webserver.uid  = 33;
    std::strcpy(webserver.cmdline,  "/usr/bin/apache2");
    std::strcpy(webserver.exe_path, "/usr/bin/apache2");

    ProcessEntity malware{};
    malware.pid  = 1337;
    malware.ppid = 1000;
    malware.uid  = 33;
    std::strcpy(malware.cmdline,  "/tmp/malware.exe");
    std::strcpy(malware.exe_path, "/tmp/malware.exe");

    detector.ingest_syscall(&webserver, flowshield::NodeType::PROCESS,
                            &malware,   flowshield::NodeType::PROCESS,
                            flowshield::EdgeType::FORK,
                            get_time_ns());

    detector.ingest_syscall(&malware, flowshield::NodeType::PROCESS,
                            &malware, flowshield::NodeType::PROCESS,
                            flowshield::EdgeType::EXEC,
                            get_time_ns());

    std::cout << "  -> APT Detector should detect suspicious process chain\n";
    std::cout << "  -> Causal chain: webserver --fork--> malware\n";
}

void simulate_c2_beaconing(flowshield::UnifiedDetector& detector) {
    std::cout << "\n[ATTACK] Phase 4: C2 Beaconing\n";
    std::cout << "  malware.exe -> C2 server (192.168.1.100:443) every 60 seconds\n\n";

    for (int i = 0; i < 5; ++i) {
        flowshield::flow_key flow{};
        flow.src_ip   = (10u  << 24) | (0u   << 16) | (0u << 8) | 50u;
        flow.dst_ip   = (192u << 24) | (168u << 16) | (1u << 8) | 100u;
        flow.src_port = static_cast<std::uint16_t>(55'000 + i);
        flow.dst_port = 443;
        flow.protocol = static_cast<std::uint8_t>(flowshield::flow_protocol::tcp);

        flowshield::flow_stats stats{};
        stats.packet_count  = 10;
        stats.byte_count    = 512;
        stats.syn_count     = 1;
        stats.ack_count     = 5;
        stats.first_seen_ns = get_time_ns() + static_cast<std::uint64_t>(i) * 60'000'000'000ULL;
        stats.last_seen_ns  = stats.first_seen_ns + 100'000'000ULL;

        detector.ingest_flow(flow, stats);

        std::cout << std::format("  Beacon {} at T+{} seconds\n", i + 1, i * 60);

        ProcessEntity malware{};
        malware.pid = 1337;
        std::strcpy(malware.exe_path, "/tmp/malware.exe");

        SocketEntity sock{};
        sock.local_ip    = flow.src_ip;
        sock.remote_ip   = flow.dst_ip;
        sock.local_port  = flow.src_port;
        sock.remote_port = flow.dst_port;
        sock.protocol    = flow.protocol;

        detector.ingest_syscall(&malware, flowshield::NodeType::PROCESS,
                                &sock,    flowshield::NodeType::SOCKET,
                                flowshield::EdgeType::CONNECT,
                                stats.first_seen_ns);
    }

    std::cout << "\n  -> Temporal GNN should detect periodicity (60s period)\n";
    std::cout << "  -> FlowShield + APT correlation should link network and host events\n";
}

void simulate_data_exfiltration(flowshield::UnifiedDetector& detector) {
    std::cout << "\n[ATTACK] Phase 5: Data Exfiltration\n";
    std::cout << "  Slow transfer to 192.168.1.100:8080 (avoiding detection)\n\n";

    flowshield::flow_key flow{};
    flow.src_ip   = (10u  << 24) | (0u   << 16) | (0u << 8) | 50u;
    flow.dst_ip   = (192u << 24) | (168u << 16) | (1u << 8) | 100u;
    flow.src_port = 56789;
    flow.dst_port = 8080;
    flow.protocol = static_cast<std::uint8_t>(flowshield::flow_protocol::tcp);

    flowshield::flow_stats stats{};
    stats.packet_count  = 1000;
    stats.byte_count    = 5ULL * 1024ULL * 1024ULL;
    stats.syn_count     = 1;
    stats.ack_count     = 500;
    stats.first_seen_ns = get_time_ns();
    stats.last_seen_ns  = stats.first_seen_ns + 300ULL * 1'000'000'000ULL;

    detector.ingest_flow(flow, stats);

    std::cout << "  -> Temporal GNN should detect slow exfiltration pattern\n";
    std::cout << "  -> Rate: ~17 KB/s (low and slow to evade detection)\n";
}

const char* alert_source_str(flowshield::AlertSource src) noexcept {
    switch (src) {
        case flowshield::AlertSource::Network:    return "Network (FlowShield)";
        case flowshield::AlertSource::Host:       return "Host (APT Detector)";
        case flowshield::AlertSource::Correlated: return "Correlated (Both layers)";
    }
    return "unknown";
}

}  // namespace

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "=======================================================\n";
    std::cout << "  Unified APT Detection Demo\n";
    std::cout << "  Multi-layer threat detection with GNN/GAT\n";
    std::cout << "=======================================================\n\n";

    flowshield::config network_config = flowshield::config_default();
    network_config.detection.max_pps_per_flow      = 1000;
    network_config.detection.syn_per_second_thresh = 100;

    flowshield::UnifiedDetector detector(network_config,
                                         100'000,    // max nodes
                                         500'000);   // max edges

    if (!detector.start()) {
        std::cerr << "Failed to start unified detector\n";
        return 1;
    }

    std::cout << "\nOK Unified detector started successfully\n";
    std::cout << "  - Network layer: FlowShield\n";
    std::cout << "  - Host layer: GNN/GAT APT Detector\n";
    std::cout << "  - Correlation enabled\n\n";

    std::cout << "=========================================\n";
    std::cout << "  SIMULATING MULTI-STAGE APT ATTACK\n";
    std::cout << "=========================================\n";

    simulate_network_scan(detector);
    std::this_thread::sleep_for(std::chrono::seconds(2));

    simulate_exploit_delivery(detector);
    std::this_thread::sleep_for(std::chrono::seconds(2));

    simulate_malware_execution(detector);
    std::this_thread::sleep_for(std::chrono::seconds(2));

    simulate_c2_beaconing(detector);
    std::this_thread::sleep_for(std::chrono::seconds(2));

    simulate_data_exfiltration(detector);
    std::this_thread::sleep_for(std::chrono::seconds(2));

    std::cout << "\n=========================================\n";
    std::cout << "  DETECTION RESULTS\n";
    std::cout << "=========================================\n\n";

    const auto alerts = detector.get_alerts(100);
    std::cout << std::format("Total alerts detected: {}\n\n", alerts.size());

    for (std::size_t i = 0; i < alerts.size(); ++i) {
        const auto& a = alerts[i];
        std::cout << std::format("Alert {}:\n", i + 1);
        std::cout << "  Title:    " << a.title.data() << "\n";
        std::cout << "  Source:   " << alert_source_str(a.source) << "\n";
        std::cout << std::format("  Severity: {:.2f}\n", a.combined_severity);
        std::cout << std::format("  Response: {}\n",
                                 static_cast<int>(a.recommended_response));
        std::cout << "\n";
    }

    const auto incidents = detector.get_incidents(100);
    std::cout << std::format("Security incidents: {}\n\n", incidents.size());

    for (std::size_t i = 0; i < incidents.size(); ++i) {
        const auto& inc = incidents[i];
        std::cout << std::format("Incident {} (ID={}):\n", i + 1, inc.incident_id);
        std::cout << std::format("  Classification: {}\n", static_cast<int>(inc.classification));
        std::cout << std::format("  Severity:       {}\n", static_cast<int>(inc.severity));
        std::cout << std::format("  Status:         {}\n", static_cast<int>(inc.status));
        std::cout << std::format("  Alerts:         {}\n", inc.num_alerts);
        std::cout << std::format("  Duration:       {:.2f} seconds\n",
                                 (inc.last_update_ns - inc.start_time_ns) / 1e9);

        const std::string timeline = detector.build_timeline(inc);
        std::cout << "\n" << timeline << "\n";
    }

    std::cout << "=========================================\n";
    std::cout << "  STATISTICS\n";
    std::cout << "=========================================\n";
    detector.print_stats();

    detector.stop();

    std::cout << "\nOK Demo completed successfully\n\n";
    return 0;
}
