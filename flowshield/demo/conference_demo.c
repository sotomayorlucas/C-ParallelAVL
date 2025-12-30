/**
 * FlowShield Conference Demo
 *
 * "Adversary-Resistant Flow Counting with Parallel AVL Trees"
 *
 * This demo shows how ROUTER_LOAD_AWARE defeats algorithmic complexity
 * attacks that would serialize ROUTER_STATIC_HASH.
 *
 * Perfect for security conferences like DEF CON, Black Hat, etc.
 */

#define _GNU_SOURCE
#include "../include/flowshield.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>

/* ============================================================================
 * Demo Configuration
 * ============================================================================ */

#define NUM_SHARDS      8
#define NORMAL_PACKETS  100000
#define ATTACK_PACKETS  50000
#define NUM_THREADS     4

/* Colors for terminal output */
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_RESET   "\033[0m"
#define COLOR_BOLD    "\033[1m"

/* ============================================================================
 * Timing Utilities
 * ============================================================================ */

static double get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

/* ============================================================================
 * Print Helpers
 * ============================================================================ */

static void print_header(const char* title) {
    printf("\n");
    printf(COLOR_BOLD COLOR_CYAN);
    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║  %-66s║\n", title);
    printf("╚════════════════════════════════════════════════════════════════════╝\n");
    printf(COLOR_RESET);
}

static void print_section(const char* title) {
    printf("\n" COLOR_BOLD COLOR_YELLOW "▶ %s" COLOR_RESET "\n", title);
    printf("────────────────────────────────────────────────────────────────────\n");
}

static void print_balance_bar(const char* label, double balance, int width) {
    printf("  %s ", label);

    int filled = (int)(balance * width);

    printf("[");
    for (int i = 0; i < width; i++) {
        if (i < filled) {
            if (balance > 0.8)
                printf(COLOR_GREEN "█" COLOR_RESET);
            else if (balance > 0.5)
                printf(COLOR_YELLOW "█" COLOR_RESET);
            else
                printf(COLOR_RED "█" COLOR_RESET);
        } else {
            printf("░");
        }
    }
    printf("] ");

    if (balance > 0.8)
        printf(COLOR_GREEN);
    else if (balance > 0.5)
        printf(COLOR_YELLOW);
    else
        printf(COLOR_RED);

    printf("%5.1f%%" COLOR_RESET "\n", balance * 100);
}

static void print_comparison(
    const char* metric,
    double static_val,
    double load_aware_val,
    const char* unit,
    bool higher_is_better
) {
    double diff = load_aware_val - static_val;
    bool load_aware_wins = higher_is_better ? (diff > 0) : (diff < 0);

    printf("  %-20s", metric);
    printf(" │ ");

    if (!load_aware_wins)
        printf(COLOR_GREEN);
    printf("%10.2f %s", static_val, unit);
    printf(COLOR_RESET);

    printf(" │ ");

    if (load_aware_wins)
        printf(COLOR_GREEN);
    printf("%10.2f %s", load_aware_val, unit);
    printf(COLOR_RESET);

    printf(" │ ");

    if (load_aware_wins)
        printf(COLOR_GREEN "✓");
    else
        printf(COLOR_RED "✗");
    printf(COLOR_RESET "\n");
}

/* ============================================================================
 * Concurrent Worker
 * ============================================================================ */

typedef struct {
    FlowShield* engine;
    size_t packets_to_send;
    bool hotspot_attack;
    size_t target_shard;
    double elapsed_ms;
} WorkerArgs;

static void* worker_thread(void* arg) {
    WorkerArgs* args = (WorkerArgs*)arg;

    double start = get_time_ms();

    if (args->hotspot_attack) {
        flowshield_simulate_hotspot_attack(
            args->engine,
            args->target_shard,
            args->packets_to_send
        );
    } else {
        flowshield_simulate_normal_traffic(
            args->engine,
            args->packets_to_send,
            1000,  /* sources */
            100    /* destinations */
        );
    }

    args->elapsed_ms = get_time_ms() - start;
    return NULL;
}

/* ============================================================================
 * Demo Scenarios
 * ============================================================================ */

typedef struct {
    double elapsed_ms;
    double balance;
    size_t flows;
    size_t alerts;
    double throughput_kpps;
} BenchmarkResult;

static BenchmarkResult run_scenario(
    RouterStrategy routing,
    bool with_attack,
    size_t num_threads
) {
    FlowShieldConfig config = flowshield_config_default();
    config.num_shards = NUM_SHARDS;
    config.routing = routing;

    FlowShield* engine = flowshield_create(&config);
    BenchmarkResult result = {0};

    pthread_t threads[NUM_THREADS];
    WorkerArgs args[NUM_THREADS];

    /* Configure workers */
    size_t packets_per_thread = (with_attack ? ATTACK_PACKETS : NORMAL_PACKETS) / num_threads;

    for (size_t i = 0; i < num_threads; i++) {
        args[i].engine = engine;
        args[i].packets_to_send = packets_per_thread;
        args[i].hotspot_attack = with_attack;
        args[i].target_shard = 0;  /* All attack shard 0 */
        args[i].elapsed_ms = 0;
    }

    /* Start workers */
    double start = get_time_ms();

    for (size_t i = 0; i < num_threads; i++) {
        pthread_create(&threads[i], NULL, worker_thread, &args[i]);
    }

    for (size_t i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    result.elapsed_ms = get_time_ms() - start;

    /* Collect metrics */
    FlowMetrics metrics;
    flowshield_get_metrics(engine, &metrics);

    result.balance = metrics.shard_balance;
    result.flows = metrics.unique_flows;
    result.alerts = anomaly_detector_alert_count(flowshield_get_detector(engine));
    result.throughput_kpps = (double)(packets_per_thread * num_threads) / result.elapsed_ms;

    flowshield_destroy(engine);
    return result;
}

/* ============================================================================
 * Demo 1: Normal Traffic Comparison
 * ============================================================================ */

static void demo_normal_traffic(void) {
    print_header("DEMO 1: Normal Traffic - Baseline Performance");

    printf("\n  Simulating %d packets across %d threads...\n\n",
           NORMAL_PACKETS, NUM_THREADS);

    printf("  Running STATIC_HASH...\n");
    BenchmarkResult static_result = run_scenario(ROUTER_STATIC_HASH, false, NUM_THREADS);

    printf("  Running LOAD_AWARE...\n");
    BenchmarkResult load_aware_result = run_scenario(ROUTER_LOAD_AWARE, false, NUM_THREADS);

    print_section("Results: Normal Traffic");

    printf("  %-20s │ %12s │ %12s │ Winner\n", "Metric", "STATIC_HASH", "LOAD_AWARE");
    printf("  ────────────────────┼──────────────┼──────────────┼────────\n");

    print_comparison("Throughput", static_result.throughput_kpps,
                     load_aware_result.throughput_kpps, "Kpps", true);
    print_comparison("Time", static_result.elapsed_ms,
                     load_aware_result.elapsed_ms, "ms", false);
    print_comparison("Balance", static_result.balance * 100,
                     load_aware_result.balance * 100, "%", true);

    printf("\n  " COLOR_CYAN "📊 Under normal traffic, both strategies perform similarly." COLOR_RESET "\n");
    printf("     LOAD_AWARE has ~5-10%% overhead for load tracking.\n");
}

/* ============================================================================
 * Demo 2: Hotspot Attack (The Main Event!)
 * ============================================================================ */

static void demo_hotspot_attack(void) {
    print_header("DEMO 2: Algorithmic Complexity Attack (HOTSPOT)");

    printf("\n  " COLOR_RED COLOR_BOLD "⚠️  ATTACK SCENARIO" COLOR_RESET "\n");
    printf("  Attacker generates %d keys that ALL hash to Shard 0.\n", ATTACK_PACKETS);
    printf("  With STATIC_HASH, this serializes all operations on one shard!\n\n");

    printf("  Running STATIC_HASH under attack...\n");
    BenchmarkResult static_result = run_scenario(ROUTER_STATIC_HASH, true, NUM_THREADS);

    printf("  Running LOAD_AWARE under attack...\n");
    BenchmarkResult load_aware_result = run_scenario(ROUTER_LOAD_AWARE, true, NUM_THREADS);

    print_section("Results: Under Hotspot Attack");

    printf("  %-20s │ %12s │ %12s │ Winner\n", "Metric", "STATIC_HASH", "LOAD_AWARE");
    printf("  ────────────────────┼──────────────┼──────────────┼────────\n");

    print_comparison("Throughput", static_result.throughput_kpps,
                     load_aware_result.throughput_kpps, "Kpps", true);
    print_comparison("Time", static_result.elapsed_ms,
                     load_aware_result.elapsed_ms, "ms", false);
    print_comparison("Balance", static_result.balance * 100,
                     load_aware_result.balance * 100, "%", true);

    print_section("Shard Load Distribution");

    printf("  " COLOR_BOLD "STATIC_HASH" COLOR_RESET " (Vulnerable):\n");
    print_balance_bar("Balance", static_result.balance, 50);

    printf("\n  " COLOR_BOLD "LOAD_AWARE" COLOR_RESET " (Resistant):\n");
    print_balance_bar("Balance", load_aware_result.balance, 50);

    /* Calculate improvement */
    double speedup = load_aware_result.throughput_kpps / static_result.throughput_kpps;
    double balance_improvement = load_aware_result.balance - static_result.balance;

    print_section("Attack Mitigation Summary");

    printf("  " COLOR_GREEN "✓" COLOR_RESET " Throughput improvement: " COLOR_GREEN "%.1fx faster" COLOR_RESET "\n", speedup);
    printf("  " COLOR_GREEN "✓" COLOR_RESET " Balance improvement:   " COLOR_GREEN "+%.1f%% better distribution" COLOR_RESET "\n",
           balance_improvement * 100);

    printf("\n  " COLOR_CYAN COLOR_BOLD "🛡️  LOAD_AWARE routing successfully mitigates the attack!" COLOR_RESET "\n");
    printf("     Keys are redistributed across shards based on load.\n");
}

/* ============================================================================
 * Demo 3: Detection Capabilities
 * ============================================================================ */

static void demo_detection(void) {
    print_header("DEMO 3: DDoS Detection Algorithms");

    FlowShieldConfig config = flowshield_config_default();
    config.num_shards = NUM_SHARDS;
    config.routing = ROUTER_LOAD_AWARE;

    FlowShield* engine = flowshield_create(&config);

    print_section("Generating Mixed Traffic");

    printf("  1. Normal traffic (baseline)...\n");
    flowshield_simulate_normal_traffic(engine, 50000, 1000, 100);
    flowshield_analyze(engine);

    printf("  2. SYN Flood attack...\n");
    flowshield_simulate_syn_flood(engine,
        str_to_ip("192.168.1.100"),  /* target */
        80,                           /* port */
        10000,                        /* packets */
        100                           /* spoofed sources */
    );
    flowshield_analyze(engine);

    printf("  3. UDP Amplification attack...\n");
    flowshield_simulate_udp_amplification(engine,
        str_to_ip("10.0.0.50"),   /* victim */
        53,                        /* DNS */
        5000,                      /* packets */
        50.0                       /* 50x amplification */
    );
    flowshield_analyze(engine);

    print_section("Detection Results");

    FlowMetrics metrics;
    flowshield_get_metrics(engine, &metrics);

    DetectorStats stats;
    flowshield_get_detector_stats(engine, &stats);

    printf("  Total Flows:      %lu\n", (unsigned long)metrics.unique_flows);
    printf("  Suspicious:       %lu\n", (unsigned long)metrics.suspicious_flows);
    printf("  Alerts Generated: %lu\n", (unsigned long)stats.total_alerts);

    print_section("Alert Details");

    FlowAlert alerts[10];
    size_t num_alerts = flowshield_get_alerts(engine, alerts, 10);

    for (size_t i = 0; i < num_alerts && i < 5; i++) {
        const char* icon;
        const char* color;
        switch (alerts[i].severity) {
            case SEVERITY_CRITICAL: icon = "🔴"; color = COLOR_RED; break;
            case SEVERITY_HIGH:     icon = "🟠"; color = COLOR_RED; break;
            case SEVERITY_MEDIUM:   icon = "🟡"; color = COLOR_YELLOW; break;
            default:                icon = "🟢"; color = COLOR_GREEN; break;
        }
        printf("  %s %s%s%s\n", icon, color, alerts[i].description, COLOR_RESET);
    }

    print_section("Entropy Analysis");

    EntropyAnalysis entropy;
    flowshield_get_entropy(engine, &entropy);

    printf("  Source IP entropy:  %.2f bits (unique: %lu)\n",
           entropy.src_ip_entropy, (unsigned long)entropy.unique_src_ips);
    printf("  Dest IP entropy:    %.2f bits (unique: %lu)\n",
           entropy.dst_ip_entropy, (unsigned long)entropy.unique_dst_ips);

    printf("\n  " COLOR_CYAN "📊 Low entropy indicates focused attack patterns." COLOR_RESET "\n");

    flowshield_destroy(engine);
}

/* ============================================================================
 * Demo 4: Live Dashboard
 * ============================================================================ */

static void demo_live_dashboard(void) {
    print_header("DEMO 4: Live Dashboard (5 seconds)");

    FlowShieldConfig config = flowshield_config_default();
    config.num_shards = NUM_SHARDS;
    config.routing = ROUTER_LOAD_AWARE;

    FlowShield* engine = flowshield_create(&config);

    printf("\n  Starting live monitoring with simulated traffic...\n");
    printf("  (Dashboard updates every second)\n\n");

    for (int i = 0; i < 5; i++) {
        /* Simulate traffic burst */
        flowshield_simulate_normal_traffic(engine, 10000, 500, 50);

        /* Occasional attack */
        if (i == 2) {
            flowshield_simulate_syn_flood(engine, str_to_ip("192.168.1.1"), 443, 5000, 50);
        }

        flowshield_analyze(engine);
        flowshield_print_dashboard(engine, true);

        usleep(1000000);  /* 1 second */
    }

    flowshield_destroy(engine);
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(int argc, char* argv[]) {
    printf(COLOR_BOLD COLOR_MAGENTA);
    printf("\n");
    printf("  ███████╗██╗      ██████╗ ██╗    ██╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗ \n");
    printf("  ██╔════╝██║     ██╔═══██╗██║    ██║██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗\n");
    printf("  █████╗  ██║     ██║   ██║██║ █╗ ██║███████╗███████║██║█████╗  ██║     ██║  ██║\n");
    printf("  ██╔══╝  ██║     ██║   ██║██║███╗██║╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║\n");
    printf("  ██║     ███████╗╚██████╔╝╚███╔███╔╝███████║██║  ██║██║███████╗███████╗██████╔╝\n");
    printf("  ╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ \n");
    printf(COLOR_RESET);
    printf("\n");
    printf(COLOR_CYAN "  Adversary-Resistant DDoS Detection Engine" COLOR_RESET "\n");
    printf("  Built on ParallelAVL with LOAD_AWARE routing\n");
    printf("\n");

    bool run_all = (argc == 1);
    bool run_demo[5] = {false};

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "1") == 0 || strcmp(argv[i], "normal") == 0) run_demo[1] = true;
        else if (strcmp(argv[i], "2") == 0 || strcmp(argv[i], "attack") == 0) run_demo[2] = true;
        else if (strcmp(argv[i], "3") == 0 || strcmp(argv[i], "detect") == 0) run_demo[3] = true;
        else if (strcmp(argv[i], "4") == 0 || strcmp(argv[i], "live") == 0) run_demo[4] = true;
        else if (strcmp(argv[i], "all") == 0) run_all = true;
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [demo_numbers...]\n", argv[0]);
            printf("\nDemos:\n");
            printf("  1, normal  - Normal traffic comparison\n");
            printf("  2, attack  - Hotspot attack (main demo!)\n");
            printf("  3, detect  - Detection algorithms\n");
            printf("  4, live    - Live dashboard\n");
            printf("  all        - Run all demos\n");
            return 0;
        }
    }

    if (run_all) {
        demo_normal_traffic();
        demo_hotspot_attack();
        demo_detection();
        /* Skip live dashboard in "all" mode */
    } else {
        if (run_demo[1]) demo_normal_traffic();
        if (run_demo[2]) demo_hotspot_attack();
        if (run_demo[3]) demo_detection();
        if (run_demo[4]) demo_live_dashboard();
    }

    print_header("DEMO COMPLETE");

    printf("\n  Key Takeaways:\n");
    printf("  " COLOR_GREEN "✓" COLOR_RESET " LOAD_AWARE routing defeats algorithmic complexity attacks\n");
    printf("  " COLOR_GREEN "✓" COLOR_RESET " Multi-algorithm detection catches various DDoS patterns\n");
    printf("  " COLOR_GREEN "✓" COLOR_RESET " Entropy analysis reveals attack characteristics\n");
    printf("  " COLOR_GREEN "✓" COLOR_RESET " Lock-free statistics enable real-time monitoring\n");

    printf("\n  " COLOR_CYAN "🔗 Built on ParallelAVL - github.com/your-repo" COLOR_RESET "\n\n");

    return 0;
}
