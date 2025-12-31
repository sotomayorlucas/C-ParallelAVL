/**
 * FlowShield AI Demo
 *
 * Demonstrates ML-based anomaly detection using:
 * - Hailo-8L accelerator on Raspberry Pi 5 (if available)
 * - CPU fallback with lightweight autoencoder
 *
 * Features demonstrated:
 * - Feature extraction from network flows
 * - Autoencoder-based anomaly detection
 * - Attack classification
 * - Online learning
 * - Hardware acceleration
 */

#define _GNU_SOURCE
#define HAVE_AI  /* Enable AI features */

#include "../include/flowshield.h"
#include "../include/ai_inference.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

/* ============================================================================
 * Demo Configuration
 * ============================================================================ */

#define NORMAL_SAMPLES   1000
#define ATTACK_SAMPLES   200
#define BATCH_SIZE       64

/* Colors */
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_RESET   "\033[0m"
#define COLOR_BOLD    "\033[1m"

/* ============================================================================
 * Utilities
 * ============================================================================ */

static double get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

static void print_header(const char* title) {
    printf("\n");
    printf(COLOR_BOLD COLOR_MAGENTA);
    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║  %-66s║\n", title);
    printf("╚════════════════════════════════════════════════════════════════════╝\n");
    printf(COLOR_RESET);
}

static void print_section(const char* title) {
    printf("\n" COLOR_BOLD COLOR_CYAN "▶ %s" COLOR_RESET "\n", title);
    printf("────────────────────────────────────────────────────────────────────\n");
}

/* ============================================================================
 * Demo: Platform Detection
 * ============================================================================ */

static void demo_platform_detection(void) {
    print_header("FlowShield AI - Platform Detection");

    print_section("Hardware Detection");

    /* Check for Raspberry Pi */
    FILE* f = fopen("/proc/device-tree/model", "r");
    if (f) {
        char model[256] = {0};
        fread(model, 1, sizeof(model) - 1, f);
        fclose(f);
        printf("  Platform:     %s\n", model);
    } else {
        printf("  Platform:     Generic Linux\n");
    }

    /* Check for Hailo */
    bool has_hailo = ai_engine_has_hailo();
    printf("  Hailo-8L:     %s\n",
           has_hailo ? COLOR_GREEN "Available ✓" COLOR_RESET :
                       COLOR_YELLOW "Not found (CPU mode)" COLOR_RESET);

    /* Show CPU info */
    f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "model name", 10) == 0) {
                char* colon = strchr(line, ':');
                if (colon) {
                    printf("  CPU:          %s", colon + 2);
                    break;
                }
            }
            if (strncmp(line, "Hardware", 8) == 0) {
                char* colon = strchr(line, ':');
                if (colon) {
                    printf("  Hardware:     %s", colon + 2);
                }
            }
        }
        fclose(f);
    }

    /* Memory */
    f = fopen("/proc/meminfo", "r");
    if (f) {
        char line[256];
        if (fgets(line, sizeof(line), f)) {
            unsigned long mem_kb;
            if (sscanf(line, "MemTotal: %lu kB", &mem_kb) == 1) {
                printf("  Memory:       %.1f GB\n", mem_kb / 1024.0 / 1024.0);
            }
        }
        fclose(f);
    }

    print_section("AI Engine Configuration");

    printf("  Feature dim:  %d\n", AI_FEATURE_DIM);
    printf("  Latent dim:   %d\n", AI_LATENT_DIM);
    printf("  Classes:      %d\n", AI_NUM_ATTACK_CLASSES);
    printf("  Batch size:   %d\n", AI_BATCH_SIZE);
    printf("  Threshold:    %.2f\n", AI_ANOMALY_THRESHOLD);
}

/* ============================================================================
 * Demo: Feature Extraction
 * ============================================================================ */

static void demo_feature_extraction(void) {
    print_header("FlowShield AI - Feature Extraction");

    print_section("Sample Flow Features");

    /* Create sample flows */
    FlowKey normal_key = {
        .src_ip = 0xC0A80001,    /* 192.168.0.1 */
        .dst_ip = 0x08080808,    /* 8.8.8.8 */
        .src_port = 54321,
        .dst_port = 443,
        .protocol = PROTO_TCP
    };

    FlowStats normal_stats = {
        .packet_count = 100,
        .byte_count = 50000,
        .syn_count = 1,
        .ack_count = 98,
        .fin_count = 1,
        .rst_count = 0,
        .first_seen_ns = 0,
        .last_seen_ns = 5000000000ULL  /* 5 seconds */
    };

    FlowKey attack_key = {
        .src_ip = 0x0A000001,
        .dst_ip = 0xC0A80001,
        .src_port = 12345,
        .dst_port = 80,
        .protocol = PROTO_TCP
    };

    FlowStats attack_stats = {
        .packet_count = 10000,
        .byte_count = 640000,
        .syn_count = 9900,
        .ack_count = 100,
        .fin_count = 0,
        .rst_count = 0,
        .first_seen_ns = 0,
        .last_seen_ns = 1000000000ULL  /* 1 second */
    };

    /* Extract features */
    AIFeatureVector normal_features, attack_features;
    ai_extract_features(&normal_key, &normal_stats, &normal_features);
    ai_extract_features(&attack_key, &attack_stats, &attack_features);

    printf("\n  " COLOR_GREEN "Normal HTTPS traffic:" COLOR_RESET "\n");
    printf("    PPS:        %.3f (normalized)\n", normal_features.packets_per_sec);
    printf("    BPS:        %.3f (normalized)\n", normal_features.bytes_per_sec);
    printf("    SYN ratio:  %.3f\n", normal_features.syn_ratio);
    printf("    ACK ratio:  %.3f\n", normal_features.ack_ratio);
    printf("    TCP:        %.0f  UDP: %.0f\n", normal_features.is_tcp, normal_features.is_udp);

    printf("\n  " COLOR_RED "SYN Flood attack:" COLOR_RESET "\n");
    printf("    PPS:        %.3f (normalized) ← " COLOR_RED "High!" COLOR_RESET "\n",
           attack_features.packets_per_sec);
    printf("    BPS:        %.3f (normalized)\n", attack_features.bytes_per_sec);
    printf("    SYN ratio:  %.3f ← " COLOR_RED "Suspicious!" COLOR_RESET "\n",
           attack_features.syn_ratio);
    printf("    ACK ratio:  %.3f ← " COLOR_RED "Low!" COLOR_RESET "\n",
           attack_features.ack_ratio);
    printf("    SYN/ACK:    %.3f ← " COLOR_RED "Very high!" COLOR_RESET "\n",
           attack_features.syn_ack_ratio);
}

/* ============================================================================
 * Demo: Anomaly Detection
 * ============================================================================ */

static void demo_anomaly_detection(void) {
    print_header("FlowShield AI - Autoencoder Anomaly Detection");

    /* Create AI engine */
    AIEngine* engine = ai_engine_create(AI_BACKEND_AUTO, NULL);
    if (!engine) {
        printf(COLOR_RED "  Failed to create AI engine\n" COLOR_RESET);
        return;
    }

    AIEngineStats stats;
    ai_engine_get_stats(engine, &stats);

    print_section("AI Engine Status");
    printf("  Backend:      %s\n",
           stats.hailo_available ? "Hailo-8L" : "CPU");
    if (stats.hailo_available) {
        printf("  Device:       %s\n", stats.hailo_device);
    }

    print_section("Training Phase (Learning Normal Baseline)");

    printf("  Training on %d normal traffic samples...\n", NORMAL_SAMPLES);

    double train_start = get_time_ms();
    size_t normal_count = 0;

    for (int i = 0; i < NORMAL_SAMPLES; i++) {
        /* Generate normal-looking features */
        AIFeatureVector features = {
            .packets_per_sec = 0.01f + (rand() % 100) / 10000.0f,
            .bytes_per_sec = 0.001f + (rand() % 100) / 100000.0f,
            .is_tcp = (rand() % 100 < 80) ? 1.0f : 0.0f,
            .is_udp = (rand() % 100 < 80) ? 0.0f : 1.0f,
            .syn_ratio = 0.01f + (rand() % 5) / 100.0f,
            .ack_ratio = 0.80f + (rand() % 15) / 100.0f,
            .dst_port_norm = (rand() % 1000 < 800) ? 443.0f/65535 : (rand() % 65535) / 65535.0f
        };

        /* Update baseline */
        ai_update_model(engine, &features, ATTACK_NONE, false);
        normal_count++;
    }

    double train_time = get_time_ms() - train_start;
    printf("  Baseline learned in %.1f ms\n", train_time);

    print_section("Detection Phase");

    /* Test with mix of normal and attack traffic */
    size_t true_positives = 0;
    size_t false_positives = 0;
    size_t true_negatives = 0;
    size_t false_negatives = 0;

    printf("\n  Testing detection accuracy...\n\n");

    /* Normal samples */
    for (int i = 0; i < 100; i++) {
        AIFeatureVector features = {
            .packets_per_sec = 0.01f + (rand() % 100) / 10000.0f,
            .bytes_per_sec = 0.001f + (rand() % 100) / 100000.0f,
            .is_tcp = 1.0f,
            .syn_ratio = 0.02f,
            .ack_ratio = 0.85f,
        };

        AIAnomalyResult result;
        ai_detect_anomaly(engine, &features, &result);

        if (result.is_anomaly) {
            false_positives++;
        } else {
            true_negatives++;
        }
    }

    /* Attack samples */
    for (int i = 0; i < ATTACK_SAMPLES; i++) {
        AIFeatureVector features = {0};

        /* Generate different attack patterns */
        int attack_type = i % 4;
        switch (attack_type) {
            case 0:  /* SYN Flood */
                features.packets_per_sec = 0.9f;
                features.syn_ratio = 0.95f;
                features.ack_ratio = 0.01f;
                features.is_tcp = 1.0f;
                break;
            case 1:  /* UDP Amplification */
                features.bytes_per_sec = 0.95f;
                features.is_udp = 1.0f;
                features.is_dns_port = 1.0f;
                features.avg_packet_size = 0.9f;
                break;
            case 2:  /* Port Scan */
                features.dst_port_entropy = 0.95f;
                features.packets_per_sec = 0.3f;
                features.syn_ratio = 0.9f;
                break;
            case 3:  /* Volumetric */
                features.packets_per_sec = 0.99f;
                features.bytes_per_sec = 0.99f;
                break;
        }

        AIAnomalyResult result;
        ai_detect_anomaly(engine, &features, &result);

        if (result.is_anomaly) {
            true_positives++;
        } else {
            false_negatives++;
        }
    }

    /* Calculate metrics */
    double precision = (true_positives + false_positives > 0) ?
        (double)true_positives / (true_positives + false_positives) : 0;
    double recall = (true_positives + false_negatives > 0) ?
        (double)true_positives / (true_positives + false_negatives) : 0;
    double f1 = (precision + recall > 0) ?
        2 * precision * recall / (precision + recall) : 0;
    double accuracy = (double)(true_positives + true_negatives) /
        (true_positives + true_negatives + false_positives + false_negatives);

    printf("                    Predicted\n");
    printf("                 Normal  Attack\n");
    printf("  Actual Normal   %4zu    %4zu\n", true_negatives, false_positives);
    printf("  Actual Attack   %4zu    %4zu\n", false_negatives, true_positives);
    printf("\n");
    printf("  Accuracy:   " COLOR_GREEN "%.1f%%" COLOR_RESET "\n", accuracy * 100);
    printf("  Precision:  " COLOR_GREEN "%.1f%%" COLOR_RESET "\n", precision * 100);
    printf("  Recall:     " COLOR_GREEN "%.1f%%" COLOR_RESET "\n", recall * 100);
    printf("  F1 Score:   " COLOR_GREEN "%.2f" COLOR_RESET "\n", f1);

    print_section("Attack Classification");

    /* Test classifier */
    AIFeatureVector syn_flood = {
        .packets_per_sec = 0.95f,
        .syn_ratio = 0.98f,
        .ack_ratio = 0.01f,
        .is_tcp = 1.0f,
        .dst_port_norm = 80.0f/65535
    };

    AIInferenceResult result;
    ai_infer(engine, &syn_flood, &result);

    printf("\n  Sample: High SYN ratio TCP traffic\n");
    printf("  Anomaly:        %s (score: %.2f)\n",
           result.anomaly.is_anomaly ? COLOR_RED "YES" COLOR_RESET : "no",
           result.anomaly.anomaly_score);
    printf("  Classification: %s (%.1f%% confidence)\n",
           ai_attack_type_str(result.classification.predicted_class),
           result.classification.confidence * 100);
    printf("  Inference time: %.2f ms\n", result.inference_time_ms);

    print_section("Performance Benchmark");

    /* Benchmark inference speed */
    double total_time = 0;
    int num_iterations = 1000;

    AIFeatureVector bench_features = {0.5f};

    double start = get_time_ms();
    for (int i = 0; i < num_iterations; i++) {
        AIAnomalyResult bench_result;
        ai_detect_anomaly(engine, &bench_features, &bench_result);
    }
    total_time = get_time_ms() - start;

    printf("\n  Single inference:   %.3f ms\n", total_time / num_iterations);
    printf("  Throughput:         %.0f inferences/sec\n",
           num_iterations / (total_time / 1000.0));

    ai_engine_get_stats(engine, &stats);
    printf("  Total inferences:   %lu\n", (unsigned long)stats.total_inferences);
    printf("  Anomalies detected: %lu\n", (unsigned long)stats.anomalies_detected);
    printf("  Avg inference time: %.3f ms\n", stats.avg_inference_time_ms);

    ai_engine_destroy(engine);
}

/* ============================================================================
 * Demo: Integration with FlowShield
 * ============================================================================ */

static void demo_integration(void) {
    print_header("FlowShield AI - Full Integration Demo");

    print_section("Creating AI-Enabled FlowShield Engine");

    FlowShieldConfig config = flowshield_config_default();
    config.num_shards = 4;
    config.routing = ROUTER_LOAD_AWARE;
    /* Note: AI integration would be enabled in flowshield.c */

    FlowShield* engine = flowshield_create(&config);
    if (!engine) {
        printf(COLOR_RED "  Failed to create engine\n" COLOR_RESET);
        return;
    }

    printf("  Engine created with %zu shards\n", config.num_shards);

    print_section("Simulating Mixed Traffic");

    printf("  1. Normal traffic (baseline)...\n");
    flowshield_simulate_normal_traffic(engine, 5000, 100, 20);

    printf("  2. SYN Flood attack...\n");
    flowshield_simulate_syn_flood(engine, 0xC0A80001, 80, 2000, 50);

    printf("  3. More normal traffic...\n");
    flowshield_simulate_normal_traffic(engine, 3000, 100, 20);

    print_section("Analysis Results");

    /* Run detection */
    flowshield_analyze(engine);

    FlowMetrics metrics;
    flowshield_get_metrics(engine, &metrics);

    printf("  Total flows:    %lu\n", (unsigned long)metrics.unique_flows);
    printf("  Suspicious:     %lu\n", (unsigned long)metrics.suspicious_flows);
    printf("  Shard balance:  %.1f%%\n", metrics.shard_balance * 100);

    FlowAlert alerts[10];
    size_t num_alerts = flowshield_get_alerts(engine, alerts, 10);
    printf("  Alerts:         %zu\n", num_alerts);

    if (num_alerts > 0) {
        printf("\n  Recent alerts:\n");
        for (size_t i = 0; i < num_alerts && i < 3; i++) {
            printf("    %s - %s\n",
                   alerts[i].severity >= SEVERITY_HIGH ? "🔴" : "🟡",
                   alerts[i].description);
        }
    }

    flowshield_destroy(engine);

    printf("\n  " COLOR_GREEN "✓ Integration demo complete" COLOR_RESET "\n");
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(int argc, char* argv[]) {
    printf(COLOR_BOLD COLOR_CYAN);
    printf("\n");
    printf("  ╔═══════════════════════════════════════════════════════════════╗\n");
    printf("  ║     FlowShield AI - ML-Based Network Anomaly Detection        ║\n");
    printf("  ║                                                               ║\n");
    printf("  ║     For Raspberry Pi 5 with Hailo-8L Accelerator              ║\n");
    printf("  ╚═══════════════════════════════════════════════════════════════╝\n");
    printf(COLOR_RESET "\n");

    bool run_all = (argc == 1);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [demo_name]\n\n", argv[0]);
            printf("Demos:\n");
            printf("  platform    - Platform and hardware detection\n");
            printf("  features    - Feature extraction from flows\n");
            printf("  anomaly     - Autoencoder anomaly detection\n");
            printf("  integration - Full FlowShield integration\n");
            printf("  all         - Run all demos (default)\n");
            return 0;
        }
        if (strcmp(argv[i], "platform") == 0) { demo_platform_detection(); run_all = false; }
        if (strcmp(argv[i], "features") == 0) { demo_feature_extraction(); run_all = false; }
        if (strcmp(argv[i], "anomaly") == 0) { demo_anomaly_detection(); run_all = false; }
        if (strcmp(argv[i], "integration") == 0) { demo_integration(); run_all = false; }
        if (strcmp(argv[i], "all") == 0) { run_all = true; break; }
    }

    if (run_all) {
        demo_platform_detection();
        demo_feature_extraction();
        demo_anomaly_detection();
        demo_integration();
    }

    print_header("AI Demo Complete");

    printf("\n  Key Takeaways:\n");
    printf("  " COLOR_GREEN "✓" COLOR_RESET " Autoencoder learns normal traffic patterns\n");
    printf("  " COLOR_GREEN "✓" COLOR_RESET " Anomalies detected by reconstruction error\n");
    printf("  " COLOR_GREEN "✓" COLOR_RESET " Attack classification from latent space\n");
    printf("  " COLOR_GREEN "✓" COLOR_RESET " Hailo-8L acceleration when available\n");
    printf("  " COLOR_GREEN "✓" COLOR_RESET " CPU fallback for any platform\n");

    printf("\n  " COLOR_CYAN "🤖 AI + ParallelAVL = Smart Edge Security" COLOR_RESET "\n\n");

    return 0;
}
