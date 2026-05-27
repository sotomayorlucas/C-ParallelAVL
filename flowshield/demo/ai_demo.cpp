/**
 * FlowShield AI Demo (C++23)
 *
 * Demonstrates ML-based anomaly detection using:
 *  - Hailo-8L accelerator on Raspberry Pi 5 (if available)
 *  - CPU fallback with lightweight autoencoder
 */

#include "../include/ai_inference.hpp"
#include "../include/flowshield.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <format>
#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <string_view>

namespace {

// ============================================================================
// Demo Configuration
// ============================================================================

constexpr int kNormalSamples = 1000;
constexpr int kAttackSamples = 200;

// ============================================================================
// ANSI colors
// ============================================================================

constexpr std::string_view kRed     = "\033[31m";
constexpr std::string_view kGreen   = "\033[32m";
constexpr std::string_view kYellow  = "\033[33m";
constexpr std::string_view kBlue    = "\033[34m";
constexpr std::string_view kMagenta = "\033[35m";
constexpr std::string_view kCyan    = "\033[36m";
constexpr std::string_view kReset   = "\033[0m";
constexpr std::string_view kBold    = "\033[1m";

// ============================================================================
// Utilities
// ============================================================================

double get_time_ms() {
    using clock = std::chrono::steady_clock;
    static const auto start = clock::now();
    return std::chrono::duration<double, std::milli>(clock::now() - start).count();
}

void print_header(std::string_view title) {
    std::cout << "\n" << kBold << kMagenta;
    std::cout << "+==================================================================+\n";
    std::cout << std::format("|  {:<64}  |\n", title);
    std::cout << "+==================================================================+\n";
    std::cout << kReset;
}

void print_section(std::string_view title) {
    std::cout << "\n" << kBold << kCyan << "> " << title << kReset << "\n";
    std::cout << "--------------------------------------------------------------------\n";
}

// ============================================================================
// Demo: Platform Detection
// ============================================================================

void demo_platform_detection() {
    print_header("FlowShield AI - Platform Detection");

    print_section("Hardware Detection");

    // Platform model
    {
        std::ifstream f("/proc/device-tree/model");
        if (f.is_open()) {
            std::string model;
            std::getline(f, model);
            std::cout << "  Platform:     " << model << "\n";
        } else {
            std::cout << "  Platform:     Generic Linux\n";
        }
    }

    const bool has_hailo = flowshield::ai_engine::has_hailo();
    std::cout << "  Hailo-8L:     "
              << (has_hailo ? std::format("{}Available OK{}", kGreen, kReset)
                            : std::format("{}Not found (CPU mode){}", kYellow, kReset))
              << "\n";

    // CPU info
    {
        std::ifstream f("/proc/cpuinfo");
        std::string line;
        while (std::getline(f, line)) {
            if (line.starts_with("model name")) {
                auto pos = line.find(':');
                if (pos != std::string::npos) {
                    std::cout << "  CPU:          " << line.substr(pos + 2) << "\n";
                    break;
                }
            }
        }
    }

    // Memory
    {
        std::ifstream f("/proc/meminfo");
        std::string line;
        if (std::getline(f, line)) {
            unsigned long mem_kb = 0;
            if (std::sscanf(line.c_str(), "MemTotal: %lu kB", &mem_kb) == 1) {
                std::cout << std::format("  Memory:       {:.1f} GB\n", mem_kb / 1024.0 / 1024.0);
            }
        }
    }

    print_section("AI Engine Configuration");

    std::cout << std::format("  Feature dim:  {}\n", flowshield::ai_feature_dim);
    std::cout << std::format("  Latent dim:   {}\n", flowshield::ai_latent_dim);
    std::cout << std::format("  Classes:      {}\n", flowshield::ai_num_attack_classes);
    std::cout << std::format("  Batch size:   {}\n", flowshield::ai_batch_size);
    std::cout << std::format("  Threshold:    {:.2f}\n", flowshield::ai_anomaly_threshold);
}

// ============================================================================
// Demo: Feature Extraction
// ============================================================================

void demo_feature_extraction() {
    print_header("FlowShield AI - Feature Extraction");

    print_section("Sample Flow Features");

    flowshield::flow_key normal_key{};
    normal_key.src_ip   = 0xC0A80001;
    normal_key.dst_ip   = 0x08080808;
    normal_key.src_port = 54321;
    normal_key.dst_port = 443;
    normal_key.protocol = static_cast<std::uint8_t>(flowshield::flow_protocol::tcp);

    flowshield::flow_stats normal_stats{};
    normal_stats.packet_count  = 100;
    normal_stats.byte_count    = 50'000;
    normal_stats.syn_count     = 1;
    normal_stats.ack_count     = 98;
    normal_stats.fin_count     = 1;
    normal_stats.rst_count     = 0;
    normal_stats.first_seen_ns = 0;
    normal_stats.last_seen_ns  = 5'000'000'000ULL;

    flowshield::flow_key attack_key{};
    attack_key.src_ip   = 0x0A000001;
    attack_key.dst_ip   = 0xC0A80001;
    attack_key.src_port = 12345;
    attack_key.dst_port = 80;
    attack_key.protocol = static_cast<std::uint8_t>(flowshield::flow_protocol::tcp);

    flowshield::flow_stats attack_stats{};
    attack_stats.packet_count  = 10'000;
    attack_stats.byte_count    = 640'000;
    attack_stats.syn_count     = 9'900;
    attack_stats.ack_count     = 100;
    attack_stats.first_seen_ns = 0;
    attack_stats.last_seen_ns  = 1'000'000'000ULL;

    flowshield::ai_feature_vector normal_features{};
    flowshield::ai_feature_vector attack_features{};
    flowshield::ai_extract_features(normal_key, normal_stats, normal_features);
    flowshield::ai_extract_features(attack_key, attack_stats, attack_features);

    std::cout << "\n  " << kGreen << "Normal HTTPS traffic:" << kReset << "\n";
    std::cout << std::format("    PPS:        {:.3f} (normalized)\n", normal_features.packets_per_sec);
    std::cout << std::format("    BPS:        {:.3f} (normalized)\n", normal_features.bytes_per_sec);
    std::cout << std::format("    SYN ratio:  {:.3f}\n", normal_features.syn_ratio);
    std::cout << std::format("    ACK ratio:  {:.3f}\n", normal_features.ack_ratio);
    std::cout << std::format("    TCP:        {}  UDP: {}\n",
                             normal_features.is_tcp, normal_features.is_udp);

    std::cout << "\n  " << kRed << "SYN Flood attack:" << kReset << "\n";
    std::cout << std::format("    PPS:        {:.3f} (normalized) <- {}High!{}\n",
                             attack_features.packets_per_sec, kRed, kReset);
    std::cout << std::format("    BPS:        {:.3f} (normalized)\n", attack_features.bytes_per_sec);
    std::cout << std::format("    SYN ratio:  {:.3f} <- {}Suspicious!{}\n",
                             attack_features.syn_ratio, kRed, kReset);
    std::cout << std::format("    ACK ratio:  {:.3f} <- {}Low!{}\n",
                             attack_features.ack_ratio, kRed, kReset);
    std::cout << std::format("    SYN/ACK:    {:.3f} <- {}Very high!{}\n",
                             attack_features.syn_ack_ratio, kRed, kReset);
}

// ============================================================================
// Demo: Anomaly Detection
// ============================================================================

void demo_anomaly_detection() {
    print_header("FlowShield AI - Autoencoder Anomaly Detection");

    flowshield::ai_engine engine(flowshield::ai_backend::automatic);

    flowshield::ai_engine_stats stats{};
    engine.get_stats(stats);

    print_section("AI Engine Status");
    std::cout << "  Backend:      " << (stats.hailo_available ? "Hailo-8L" : "CPU") << "\n";
    if (stats.hailo_available) {
        std::cout << "  Device:       " << stats.hailo_device << "\n";
    }

    print_section("Training Phase (Learning Normal Baseline)");

    std::cout << std::format("  Training on {} normal traffic samples...\n", kNormalSamples);

    std::mt19937_64 rng{12345ULL};
    std::uniform_int_distribution<int> d100(0, 99);
    std::uniform_int_distribution<int> d15(0, 14);
    std::uniform_int_distribution<int> d5(0, 4);
    std::uniform_int_distribution<int> d1000(0, 999);
    std::uniform_int_distribution<int> d65535(0, 65534);

    const double train_start = get_time_ms();

    for (int i = 0; i < kNormalSamples; ++i) {
        flowshield::ai_feature_vector features{};
        features.packets_per_sec = 0.01f + d100(rng) / 10000.0f;
        features.bytes_per_sec   = 0.001f + d100(rng) / 100000.0f;
        features.is_tcp          = (d100(rng) < 80) ? 1.0f : 0.0f;
        features.is_udp          = (d100(rng) < 80) ? 0.0f : 1.0f;
        features.syn_ratio       = 0.01f + d5(rng) / 100.0f;
        features.ack_ratio       = 0.80f + d15(rng) / 100.0f;
        features.dst_port_norm   = (d1000(rng) < 800)
                                       ? 443.0f / 65535
                                       : d65535(rng) / 65535.0f;

        engine.update_model(features, flowshield::attack_type::none, false);
    }

    const double train_time = get_time_ms() - train_start;
    std::cout << std::format("  Baseline learned in {:.1f} ms\n", train_time);

    print_section("Detection Phase");

    std::size_t true_positives  = 0;
    std::size_t false_positives = 0;
    std::size_t true_negatives  = 0;
    std::size_t false_negatives = 0;

    std::cout << "\n  Testing detection accuracy...\n\n";

    // Normal samples
    for (int i = 0; i < 100; ++i) {
        flowshield::ai_feature_vector features{};
        features.packets_per_sec = 0.01f + d100(rng) / 10000.0f;
        features.bytes_per_sec   = 0.001f + d100(rng) / 100000.0f;
        features.is_tcp          = 1.0f;
        features.syn_ratio       = 0.02f;
        features.ack_ratio       = 0.85f;

        flowshield::ai_anomaly_result result{};
        engine.detect_anomaly(features, result);
        if (result.is_anomaly) ++false_positives;
        else                   ++true_negatives;
    }

    // Attack samples
    for (int i = 0; i < kAttackSamples; ++i) {
        flowshield::ai_feature_vector features{};
        switch (i % 4) {
            case 0:  // SYN Flood
                features.packets_per_sec = 0.9f;
                features.syn_ratio       = 0.95f;
                features.ack_ratio       = 0.01f;
                features.is_tcp          = 1.0f;
                break;
            case 1:  // UDP Amplification
                features.bytes_per_sec   = 0.95f;
                features.is_udp          = 1.0f;
                features.is_dns_port     = 1.0f;
                features.avg_packet_size = 0.9f;
                break;
            case 2:  // Port Scan
                features.dst_port_entropy = 0.95f;
                features.packets_per_sec  = 0.3f;
                features.syn_ratio        = 0.9f;
                break;
            case 3:  // Volumetric
                features.packets_per_sec = 0.99f;
                features.bytes_per_sec   = 0.99f;
                break;
        }

        flowshield::ai_anomaly_result result{};
        engine.detect_anomaly(features, result);
        if (result.is_anomaly) ++true_positives;
        else                   ++false_negatives;
    }

    const double precision = (true_positives + false_positives > 0)
        ? static_cast<double>(true_positives) / (true_positives + false_positives) : 0;
    const double recall = (true_positives + false_negatives > 0)
        ? static_cast<double>(true_positives) / (true_positives + false_negatives) : 0;
    const double f1 = (precision + recall > 0)
        ? 2 * precision * recall / (precision + recall) : 0;
    const double accuracy = static_cast<double>(true_positives + true_negatives) /
        (true_positives + true_negatives + false_positives + false_negatives);

    std::cout << "                    Predicted\n";
    std::cout << "                 Normal  Attack\n";
    std::cout << std::format("  Actual Normal   {:>4}    {:>4}\n", true_negatives, false_positives);
    std::cout << std::format("  Actual Attack   {:>4}    {:>4}\n", false_negatives, true_positives);
    std::cout << "\n";
    std::cout << std::format("  Accuracy:   {}{:.1f}%{}\n", kGreen, accuracy * 100, kReset);
    std::cout << std::format("  Precision:  {}{:.1f}%{}\n", kGreen, precision * 100, kReset);
    std::cout << std::format("  Recall:     {}{:.1f}%{}\n", kGreen, recall * 100, kReset);
    std::cout << std::format("  F1 Score:   {}{:.2f}{}\n",   kGreen, f1, kReset);

    print_section("Attack Classification");

    flowshield::ai_feature_vector syn_flood{};
    syn_flood.packets_per_sec = 0.95f;
    syn_flood.syn_ratio       = 0.98f;
    syn_flood.ack_ratio       = 0.01f;
    syn_flood.is_tcp          = 1.0f;
    syn_flood.dst_port_norm   = 80.0f / 65535;

    flowshield::ai_inference_result result{};
    engine.infer(syn_flood, result);

    std::cout << "\n  Sample: High SYN ratio TCP traffic\n";
    std::cout << std::format("  Anomaly:        {} (score: {:.2f})\n",
                             result.anomaly.is_anomaly
                                 ? std::format("{}YES{}", kRed, kReset)
                                 : "no",
                             result.anomaly.anomaly_score);
    std::cout << std::format("  Classification: {} ({:.1f}% confidence)\n",
                             flowshield::ai_attack_type_str(result.classification.predicted_class),
                             result.classification.confidence * 100);
    std::cout << std::format("  Inference time: {:.2f} ms\n", result.inference_time_ms);

    print_section("Performance Benchmark");

    const int num_iterations = 1000;
    flowshield::ai_feature_vector bench_features{};
    bench_features.packets_per_sec = 0.5f;

    const double start = get_time_ms();
    for (int i = 0; i < num_iterations; ++i) {
        flowshield::ai_anomaly_result bench_result{};
        engine.detect_anomaly(bench_features, bench_result);
    }
    const double total_time = get_time_ms() - start;

    std::cout << std::format("\n  Single inference:   {:.3f} ms\n", total_time / num_iterations);
    std::cout << std::format("  Throughput:         {:.0f} inferences/sec\n",
                             num_iterations / (total_time / 1000.0));

    engine.get_stats(stats);
    std::cout << std::format("  Total inferences:   {}\n", stats.total_inferences);
    std::cout << std::format("  Anomalies detected: {}\n", stats.anomalies_detected);
    std::cout << std::format("  Avg inference time: {:.3f} ms\n", stats.avg_inference_time_ms);
}

// ============================================================================
// Demo: Integration with FlowShield
// ============================================================================

void demo_integration() {
    print_header("FlowShield AI - Full Integration Demo");

    print_section("Creating AI-Enabled FlowShield Engine");

    flowshield::config cfg = flowshield::config_default();
    cfg.num_shards = 4;
    cfg.routing    = pavl::router_strategy::load_aware;

    flowshield::engine engine(cfg);

    std::cout << std::format("  Engine created with {} shards\n", cfg.num_shards);

    print_section("Simulating Mixed Traffic");

    std::cout << "  1. Normal traffic (baseline)...\n";
    engine.simulate_normal_traffic(5'000, 100, 20);

    std::cout << "  2. SYN Flood attack...\n";
    engine.simulate_syn_flood(0xC0A80001, 80, 2'000, 50);

    std::cout << "  3. More normal traffic...\n";
    engine.simulate_normal_traffic(3'000, 100, 20);

    print_section("Analysis Results");

    engine.analyze();
    const auto metrics = engine.get_metrics();

    std::cout << std::format("  Total flows:    {}\n", metrics.unique_flows);
    std::cout << std::format("  Suspicious:     {}\n", metrics.suspicious_flows);
    std::cout << std::format("  Shard balance:  {:.1f}%\n", metrics.shard_balance * 100);

    const auto alerts = engine.get_alerts(10);
    std::cout << std::format("  Alerts:         {}\n", alerts.size());

    if (!alerts.empty()) {
        std::cout << "\n  Recent alerts:\n";
        for (std::size_t i = 0; i < alerts.size() && i < 3; ++i) {
            const std::string_view icon =
                alerts[i].severity >= flowshield::alert_severity::high ? "[!]" : "[M]";
            std::cout << std::format("    {} - {}\n", icon, alerts[i].description);
        }
    }

    std::cout << "\n  " << kGreen << "OK Integration demo complete" << kReset << "\n";
}

}  // namespace

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    std::cout << kBold << kCyan;
    std::cout << "\n";
    std::cout << "  +===============================================================+\n";
    std::cout << "  |     FlowShield AI - ML-Based Network Anomaly Detection        |\n";
    std::cout << "  |                                                               |\n";
    std::cout << "  |     For Raspberry Pi 5 with Hailo-8L Accelerator              |\n";
    std::cout << "  +===============================================================+\n";
    std::cout << kReset << "\n";

    bool run_all = (argc == 1);

    for (int i = 1; i < argc; ++i) {
        std::string_view arg{argv[i]};
        if (arg == "-h" || arg == "--help") {
            std::cout << std::format("Usage: {} [demo_name]\n\n", argv[0]);
            std::cout << "Demos:\n";
            std::cout << "  platform    - Platform and hardware detection\n";
            std::cout << "  features    - Feature extraction from flows\n";
            std::cout << "  anomaly     - Autoencoder anomaly detection\n";
            std::cout << "  integration - Full FlowShield integration\n";
            std::cout << "  all         - Run all demos (default)\n";
            return 0;
        }
        if (arg == "platform")    { demo_platform_detection(); run_all = false; }
        if (arg == "features")    { demo_feature_extraction(); run_all = false; }
        if (arg == "anomaly")     { demo_anomaly_detection();  run_all = false; }
        if (arg == "integration") { demo_integration();        run_all = false; }
        if (arg == "all")         { run_all = true; break; }
    }

    if (run_all) {
        demo_platform_detection();
        demo_feature_extraction();
        demo_anomaly_detection();
        demo_integration();
    }

    print_header("AI Demo Complete");

    std::cout << "\n  Key Takeaways:\n";
    std::cout << "  " << kGreen << "OK" << kReset << " Autoencoder learns normal traffic patterns\n";
    std::cout << "  " << kGreen << "OK" << kReset << " Anomalies detected by reconstruction error\n";
    std::cout << "  " << kGreen << "OK" << kReset << " Attack classification from latent space\n";
    std::cout << "  " << kGreen << "OK" << kReset << " Hailo-8L acceleration when available\n";
    std::cout << "  " << kGreen << "OK" << kReset << " CPU fallback for any platform\n";

    std::cout << "\n  " << kCyan << "AI + ParallelAVL = Smart Edge Security" << kReset << "\n\n";
    return 0;
}
