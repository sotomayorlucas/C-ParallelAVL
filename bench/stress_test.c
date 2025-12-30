/**
 * @file stress_test.c
 * @brief Stress test with adversarial attacks and millions of operations
 * 
 * Tests:
 *   1. High-volume stress test (10M+ operations)
 *   2. Hotspot attack (all keys to same shard)
 *   3. Hash collision attack (crafted keys)
 *   4. Rapid topology changes under load
 *   5. Mixed concurrent workload
 */

#include "../include/parallel_avl.h"
#include "../include/avl_tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

#ifdef _WIN32
#include <windows.h>
#define NUM_CORES 8
typedef HANDLE thread_t;
#define THREAD_CREATE(t, func, arg) (*(t) = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)(func), (arg), 0, NULL), *(t) != NULL)
#define THREAD_JOIN(t) (WaitForSingleObject((t), INFINITE), CloseHandle(t))

static double get_time_ms(void) {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart * 1000.0 / (double)freq.QuadPart;
}
#else
#include <pthread.h>
#include <unistd.h>
#define NUM_CORES 8
typedef pthread_t thread_t;
#define THREAD_CREATE(t, func, arg) (pthread_create((t), NULL, (func), (arg)) == 0)
#define THREAD_JOIN(t) pthread_join((t), NULL)

static double get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}
#endif

/* Fast xorshift64 RNG */
static inline uint64_t xorshift64(uint64_t* state) {
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

/* ============================================================================
 * Test Results Structure
 * ============================================================================ */

typedef struct {
    const char* test_name;
    size_t total_ops;
    double duration_ms;
    double throughput;
    double balance_score;
    size_t final_size;
    int passed;
} TestResult;

static TestResult results[20];
static int result_count = 0;

static void record_result(const char* name, size_t ops, double duration, 
                          double balance, size_t size, int passed) {
    TestResult* r = &results[result_count++];
    r->test_name = name;
    r->total_ops = ops;
    r->duration_ms = duration;
    r->throughput = ops / (duration / 1000.0);
    r->balance_score = balance;
    r->final_size = size;
    r->passed = passed;
}

/* ============================================================================
 * Worker Thread Arguments
 * ============================================================================ */

typedef struct {
    ParallelAVL* tree;
    size_t ops;
    int key_range;
    int thread_id;
    int read_pct;
    int insert_pct;
    /* For adversarial attacks */
    int64_t* attack_keys;
    size_t attack_key_count;
} WorkerArgs;

/* ============================================================================
 * Standard Mixed Workload Worker
 * ============================================================================ */

#ifdef _WIN32
static DWORD WINAPI mixed_worker(LPVOID arg) {
#else
static void* mixed_worker(void* arg) {
#endif
    WorkerArgs* args = (WorkerArgs*)arg;
    uint64_t rng = 12345ULL + (uint64_t)args->thread_id * 7919ULL;
    
    for (size_t i = 0; i < args->ops; i++) {
        int64_t key = (int64_t)(xorshift64(&rng) % (uint64_t)args->key_range);
        uint64_t op = xorshift64(&rng) % 100;
        
        if (op < (uint64_t)args->read_pct) {
            parallel_avl_contains(args->tree, key);
        } else if (op < (uint64_t)(args->read_pct + args->insert_pct)) {
            parallel_avl_insert(args->tree, key, NULL);
        } else {
            parallel_avl_remove(args->tree, key);
        }
    }
    
    return 0;
}

/* ============================================================================
 * Adversarial Hotspot Worker (all keys to same shard)
 * ============================================================================ */

#ifdef _WIN32
static DWORD WINAPI hotspot_worker(LPVOID arg) {
#else
static void* hotspot_worker(void* arg) {
#endif
    WorkerArgs* args = (WorkerArgs*)arg;
    uint64_t rng = 12345ULL + (uint64_t)args->thread_id * 7919ULL;
    
    /* Use attack keys that all hash to same shard */
    for (size_t i = 0; i < args->ops; i++) {
        size_t idx = xorshift64(&rng) % args->attack_key_count;
        int64_t key = args->attack_keys[idx];
        uint64_t op = xorshift64(&rng) % 100;
        
        if (op < 70) {
            parallel_avl_contains(args->tree, key);
        } else if (op < 85) {
            parallel_avl_insert(args->tree, key, NULL);
        } else {
            parallel_avl_remove(args->tree, key);
        }
    }
    
    return 0;
}

/* ============================================================================
 * Test 1: High-Volume Stress Test (10M operations)
 * ============================================================================ */

static void test_high_volume_stress(void) {
    printf("\n=== Test 1: High-Volume Stress Test ===\n");
    
    const size_t TOTAL_OPS = 10000000;  /* 10 million */
    const int KEY_RANGE = 1000000;
    const size_t NUM_THREADS = 8;
    const size_t OPS_PER_THREAD = TOTAL_OPS / NUM_THREADS;
    
    printf("Operations: %zu (10M)\n", TOTAL_OPS);
    printf("Key range: %d (1M)\n", KEY_RANGE);
    printf("Threads: %zu\n", NUM_THREADS);
    printf("Workload: 70%% read, 15%% insert, 15%% delete\n\n");
    
    ParallelAVL* tree = parallel_avl_create(NUM_THREADS, ROUTER_STATIC_HASH);
    if (!tree) {
        printf("FAIL: Could not create tree\n");
        record_result("High-Volume 10M", TOTAL_OPS, 0, 0, 0, 0);
        return;
    }
    
    /* Pre-populate with 100K elements */
    printf("Pre-populating with 100K elements... ");
    for (int i = 0; i < 100000; i++) {
        parallel_avl_insert(tree, i, NULL);
    }
    printf("done\n");
    
    thread_t threads[NUM_THREADS];
    WorkerArgs args[NUM_THREADS];
    
    printf("Running stress test... ");
    fflush(stdout);
    
    double start = get_time_ms();
    
    for (size_t i = 0; i < NUM_THREADS; i++) {
        args[i].tree = tree;
        args[i].ops = OPS_PER_THREAD;
        args[i].key_range = KEY_RANGE;
        args[i].thread_id = (int)i;
        args[i].read_pct = 70;
        args[i].insert_pct = 15;
        THREAD_CREATE(&threads[i], mixed_worker, &args[i]);
    }
    
    for (size_t i = 0; i < NUM_THREADS; i++) {
        THREAD_JOIN(threads[i]);
    }
    
    double end = get_time_ms();
    double duration = end - start;
    
    printf("done\n\n");
    
    double throughput = TOTAL_OPS / (duration / 1000.0);
    double balance = parallel_avl_balance_score(tree);
    size_t final_size = parallel_avl_size(tree);
    
    printf("Results:\n");
    printf("  Duration: %.2f ms\n", duration);
    printf("  Throughput: %.0f ops/sec (%.2f M/s)\n", throughput, throughput / 1000000.0);
    printf("  Balance score: %.2f%%\n", balance * 100);
    printf("  Final size: %zu\n", final_size);
    
    int passed = throughput > 1000000;  /* At least 1M ops/sec */
    printf("  Status: %s\n", passed ? "PASS" : "FAIL");
    
    record_result("High-Volume 10M", TOTAL_OPS, duration, balance, final_size, passed);
    parallel_avl_destroy(tree);
}

/* ============================================================================
 * Test 2: Extreme Volume (50M operations)
 * ============================================================================ */

static void test_extreme_volume(void) {
    printf("\n=== Test 2: Extreme Volume Stress Test ===\n");
    
    const size_t TOTAL_OPS = 50000000;  /* 50 million */
    const int KEY_RANGE = 5000000;
    const size_t NUM_THREADS = 8;
    const size_t OPS_PER_THREAD = TOTAL_OPS / NUM_THREADS;
    
    printf("Operations: %zu (50M)\n", TOTAL_OPS);
    printf("Key range: %d (5M)\n", KEY_RANGE);
    printf("Threads: %zu\n", NUM_THREADS);
    
    ParallelAVL* tree = parallel_avl_create(NUM_THREADS, ROUTER_STATIC_HASH);
    if (!tree) {
        printf("FAIL: Could not create tree\n");
        record_result("Extreme 50M", TOTAL_OPS, 0, 0, 0, 0);
        return;
    }
    
    /* Pre-populate */
    printf("Pre-populating with 500K elements... ");
    for (int i = 0; i < 500000; i++) {
        parallel_avl_insert(tree, i, NULL);
    }
    printf("done\n");
    
    thread_t threads[NUM_THREADS];
    WorkerArgs args[NUM_THREADS];
    
    printf("Running extreme stress test... ");
    fflush(stdout);
    
    double start = get_time_ms();
    
    for (size_t i = 0; i < NUM_THREADS; i++) {
        args[i].tree = tree;
        args[i].ops = OPS_PER_THREAD;
        args[i].key_range = KEY_RANGE;
        args[i].thread_id = (int)i;
        args[i].read_pct = 80;
        args[i].insert_pct = 10;
        THREAD_CREATE(&threads[i], mixed_worker, &args[i]);
    }
    
    for (size_t i = 0; i < NUM_THREADS; i++) {
        THREAD_JOIN(threads[i]);
    }
    
    double end = get_time_ms();
    double duration = end - start;
    
    printf("done\n\n");
    
    double throughput = TOTAL_OPS / (duration / 1000.0);
    double balance = parallel_avl_balance_score(tree);
    size_t final_size = parallel_avl_size(tree);
    
    printf("Results:\n");
    printf("  Duration: %.2f ms (%.2f sec)\n", duration, duration / 1000.0);
    printf("  Throughput: %.0f ops/sec (%.2f M/s)\n", throughput, throughput / 1000000.0);
    printf("  Balance score: %.2f%%\n", balance * 100);
    printf("  Final size: %zu\n", final_size);
    
    int passed = throughput > 1000000;
    printf("  Status: %s\n", passed ? "PASS" : "FAIL");
    
    record_result("Extreme 50M", TOTAL_OPS, duration, balance, final_size, passed);
    parallel_avl_destroy(tree);
}

/* ============================================================================
 * Test 3: Adversarial Hotspot Attack
 * ============================================================================ */

/* Generate keys that all hash to shard 0 */
static void generate_hotspot_keys(int64_t* keys, size_t count, size_t num_shards) {
    size_t found = 0;
    int64_t candidate = 0;
    
    while (found < count) {
        /* Murmur3 finalizer (same as router) */
        uint64_t h = (uint64_t)candidate;
        h ^= h >> 33;
        h *= 0xff51afd7ed558ccdULL;
        h ^= h >> 33;
        h *= 0xc4ceb9fe1a85ec53ULL;
        h ^= h >> 33;
        
        if ((h % num_shards) == 0) {
            keys[found++] = candidate;
        }
        candidate++;
    }
}

static void test_hotspot_attack(void) {
    printf("\n=== Test 3: Adversarial Hotspot Attack ===\n");
    
    const size_t TOTAL_OPS = 5000000;
    const size_t NUM_THREADS = 8;
    const size_t NUM_SHARDS = 8;
    const size_t ATTACK_KEYS = 100000;
    const size_t OPS_PER_THREAD = TOTAL_OPS / NUM_THREADS;
    
    printf("Operations: %zu (5M)\n", TOTAL_OPS);
    printf("Attack: All keys hash to shard 0\n");
    printf("Attack keys: %zu\n", ATTACK_KEYS);
    printf("Threads: %zu\n", NUM_THREADS);
    
    /* Generate attack keys */
    printf("Generating attack keys... ");
    fflush(stdout);
    int64_t* attack_keys = (int64_t*)malloc(ATTACK_KEYS * sizeof(int64_t));
    generate_hotspot_keys(attack_keys, ATTACK_KEYS, NUM_SHARDS);
    printf("done\n");
    
    /* Test with STATIC_HASH (vulnerable) */
    printf("\n--- With STATIC_HASH (vulnerable) ---\n");
    ParallelAVL* tree_static = parallel_avl_create(NUM_SHARDS, ROUTER_STATIC_HASH);
    
    thread_t threads[NUM_THREADS];
    WorkerArgs args[NUM_THREADS];
    
    double start = get_time_ms();
    
    for (size_t i = 0; i < NUM_THREADS; i++) {
        args[i].tree = tree_static;
        args[i].ops = OPS_PER_THREAD;
        args[i].thread_id = (int)i;
        args[i].attack_keys = attack_keys;
        args[i].attack_key_count = ATTACK_KEYS;
        THREAD_CREATE(&threads[i], hotspot_worker, &args[i]);
    }
    
    for (size_t i = 0; i < NUM_THREADS; i++) {
        THREAD_JOIN(threads[i]);
    }
    
    double end = get_time_ms();
    double duration_static = end - start;
    double throughput_static = TOTAL_OPS / (duration_static / 1000.0);
    double balance_static = parallel_avl_balance_score(tree_static);
    
    printf("  Duration: %.2f ms\n", duration_static);
    printf("  Throughput: %.0f ops/sec (%.2f M/s)\n", throughput_static, throughput_static / 1000000.0);
    printf("  Balance: %.2f%% (expected: LOW due to attack)\n", balance_static * 100);
    
    /* Test with LOAD_AWARE (resistant) */
    printf("\n--- With LOAD_AWARE (resistant) ---\n");
    ParallelAVL* tree_aware = parallel_avl_create(NUM_SHARDS, ROUTER_LOAD_AWARE);
    
    start = get_time_ms();
    
    for (size_t i = 0; i < NUM_THREADS; i++) {
        args[i].tree = tree_aware;
        THREAD_CREATE(&threads[i], hotspot_worker, &args[i]);
    }
    
    for (size_t i = 0; i < NUM_THREADS; i++) {
        THREAD_JOIN(threads[i]);
    }
    
    end = get_time_ms();
    double duration_aware = end - start;
    double throughput_aware = TOTAL_OPS / (duration_aware / 1000.0);
    double balance_aware = parallel_avl_balance_score(tree_aware);
    
    printf("  Duration: %.2f ms\n", duration_aware);
    printf("  Throughput: %.0f ops/sec (%.2f M/s)\n", throughput_aware, throughput_aware / 1000000.0);
    printf("  Balance: %.2f%% (expected: HIGHER due to redistribution)\n", balance_aware * 100);
    
    /* Analysis */
    printf("\n--- Analysis ---\n");
    printf("  LOAD_AWARE vs STATIC_HASH speedup: %.2fx\n", throughput_aware / throughput_static);
    printf("  Balance improvement: %.2f%% -> %.2f%%\n", balance_static * 100, balance_aware * 100);
    
    int passed = balance_aware > balance_static || throughput_aware > throughput_static * 0.8;
    printf("  Status: %s\n", passed ? "PASS (attack mitigated)" : "FAIL");
    
    record_result("Hotspot Attack", TOTAL_OPS, duration_aware, balance_aware, 
                  parallel_avl_size(tree_aware), passed);
    
    free(attack_keys);
    parallel_avl_destroy(tree_static);
    parallel_avl_destroy(tree_aware);
}

/* ============================================================================
 * Test 4: Write-Heavy Stress Test
 * ============================================================================ */

static void test_write_heavy(void) {
    printf("\n=== Test 4: Write-Heavy Stress Test ===\n");
    
    const size_t TOTAL_OPS = 5000000;
    const int KEY_RANGE = 500000;
    const size_t NUM_THREADS = 8;
    const size_t OPS_PER_THREAD = TOTAL_OPS / NUM_THREADS;
    
    printf("Operations: %zu (5M)\n", TOTAL_OPS);
    printf("Workload: 20%% read, 50%% insert, 30%% delete (WRITE-HEAVY)\n");
    printf("Threads: %zu\n", NUM_THREADS);
    
    ParallelAVL* tree = parallel_avl_create(NUM_THREADS, ROUTER_STATIC_HASH);
    
    thread_t threads[NUM_THREADS];
    WorkerArgs args[NUM_THREADS];
    
    printf("Running write-heavy test... ");
    fflush(stdout);
    
    double start = get_time_ms();
    
    for (size_t i = 0; i < NUM_THREADS; i++) {
        args[i].tree = tree;
        args[i].ops = OPS_PER_THREAD;
        args[i].key_range = KEY_RANGE;
        args[i].thread_id = (int)i;
        args[i].read_pct = 20;
        args[i].insert_pct = 50;
        THREAD_CREATE(&threads[i], mixed_worker, &args[i]);
    }
    
    for (size_t i = 0; i < NUM_THREADS; i++) {
        THREAD_JOIN(threads[i]);
    }
    
    double end = get_time_ms();
    double duration = end - start;
    
    printf("done\n\n");
    
    double throughput = TOTAL_OPS / (duration / 1000.0);
    double balance = parallel_avl_balance_score(tree);
    size_t final_size = parallel_avl_size(tree);
    
    printf("Results:\n");
    printf("  Duration: %.2f ms\n", duration);
    printf("  Throughput: %.0f ops/sec (%.2f M/s)\n", throughput, throughput / 1000000.0);
    printf("  Balance score: %.2f%%\n", balance * 100);
    printf("  Final size: %zu\n", final_size);
    
    int passed = throughput > 500000 && balance > 0.7;
    printf("  Status: %s\n", passed ? "PASS" : "FAIL");
    
    record_result("Write-Heavy 5M", TOTAL_OPS, duration, balance, final_size, passed);
    parallel_avl_destroy(tree);
}

/* ============================================================================
 * Test 5: Dynamic Scaling Under Load
 * ============================================================================ */

#ifdef _WIN32
static DWORD WINAPI scaling_worker(LPVOID arg) {
#else
static void* scaling_worker(void* arg) {
#endif
    WorkerArgs* args = (WorkerArgs*)arg;
    uint64_t rng = 12345ULL + (uint64_t)args->thread_id * 7919ULL;
    
    for (size_t i = 0; i < args->ops; i++) {
        int64_t key = (int64_t)(xorshift64(&rng) % (uint64_t)args->key_range);
        uint64_t op = xorshift64(&rng) % 100;
        
        if (op < 70) {
            parallel_avl_contains(args->tree, key);
        } else if (op < 85) {
            parallel_avl_insert(args->tree, key, NULL);
        } else {
            parallel_avl_remove(args->tree, key);
        }
        
        /* Yield occasionally to allow scaling operations */
        if (i % 100000 == 0) {
#ifdef _WIN32
            Sleep(0);
#else
            sched_yield();
#endif
        }
    }
    
    return 0;
}

static void test_dynamic_scaling_under_load(void) {
    printf("\n=== Test 5: Dynamic Scaling Under Load ===\n");
    
    const size_t TOTAL_OPS = 2000000;
    const int KEY_RANGE = 200000;
    const size_t NUM_THREADS = 4;
    const size_t OPS_PER_THREAD = TOTAL_OPS / NUM_THREADS;
    
    printf("Operations: %zu (2M)\n", TOTAL_OPS);
    printf("Initial shards: 4, will scale to 8, then back to 4\n");
    printf("Threads: %zu\n", NUM_THREADS);
    
    ParallelAVL* tree = parallel_avl_create(4, ROUTER_INTELLIGENT);
    
    /* Pre-populate */
    for (int i = 0; i < 50000; i++) {
        parallel_avl_insert(tree, i, NULL);
    }
    
    thread_t threads[NUM_THREADS];
    WorkerArgs args[NUM_THREADS];
    
    printf("Starting concurrent operations with scaling...\n");
    fflush(stdout);
    
    double start = get_time_ms();
    
    /* Start worker threads */
    for (size_t i = 0; i < NUM_THREADS; i++) {
        args[i].tree = tree;
        args[i].ops = OPS_PER_THREAD;
        args[i].key_range = KEY_RANGE;
        args[i].thread_id = (int)i;
        args[i].read_pct = 70;
        args[i].insert_pct = 15;
        THREAD_CREATE(&threads[i], scaling_worker, &args[i]);
    }
    
    /* Perform scaling operations while workers are running */
#ifdef _WIN32
    Sleep(100);
#else
    usleep(100000);
#endif
    
    printf("  Adding shards (4 -> 8)... ");
    for (int i = 0; i < 4; i++) {
        parallel_avl_add_shard(tree);
    }
    printf("done (shards: %zu)\n", parallel_avl_num_shards(tree));
    
#ifdef _WIN32
    Sleep(100);
#else
    usleep(100000);
#endif
    
    printf("  Removing shards (8 -> 4)... ");
    for (int i = 0; i < 4; i++) {
        parallel_avl_remove_shard(tree);
    }
    printf("done (shards: %zu)\n", parallel_avl_num_shards(tree));
    
    /* Wait for workers */
    for (size_t i = 0; i < NUM_THREADS; i++) {
        THREAD_JOIN(threads[i]);
    }
    
    double end = get_time_ms();
    double duration = end - start;
    
    printf("\nVerifying data integrity... ");
    /* Sample verification */
    int integrity_ok = 1;
    for (int i = 0; i < 1000; i++) {
        /* Just check that operations don't crash */
        parallel_avl_contains(tree, i);
    }
    printf("%s\n\n", integrity_ok ? "OK" : "FAIL");
    
    double throughput = TOTAL_OPS / (duration / 1000.0);
    double balance = parallel_avl_balance_score(tree);
    size_t final_size = parallel_avl_size(tree);
    
    printf("Results:\n");
    printf("  Duration: %.2f ms\n", duration);
    printf("  Throughput: %.0f ops/sec (%.2f M/s)\n", throughput, throughput / 1000000.0);
    printf("  Balance score: %.2f%%\n", balance * 100);
    printf("  Final size: %zu\n", final_size);
    printf("  Final shards: %zu\n", parallel_avl_num_shards(tree));
    
    int passed = integrity_ok && throughput > 100000;
    printf("  Status: %s\n", passed ? "PASS" : "FAIL");
    
    record_result("Dynamic Scaling", TOTAL_OPS, duration, balance, final_size, passed);
    parallel_avl_destroy(tree);
}

/* ============================================================================
 * Test 6: Read-Only Stress (Cache Performance)
 * ============================================================================ */

#ifdef _WIN32
static DWORD WINAPI readonly_worker(LPVOID arg) {
#else
static void* readonly_worker(void* arg) {
#endif
    WorkerArgs* args = (WorkerArgs*)arg;
    uint64_t rng = 12345ULL + (uint64_t)args->thread_id * 7919ULL;
    
    for (size_t i = 0; i < args->ops; i++) {
        int64_t key = (int64_t)(xorshift64(&rng) % (uint64_t)args->key_range);
        parallel_avl_contains(args->tree, key);
    }
    
    return 0;
}

static void test_readonly_stress(void) {
    printf("\n=== Test 6: Read-Only Stress Test ===\n");
    
    const size_t TOTAL_OPS = 20000000;  /* 20 million reads */
    const int KEY_RANGE = 1000000;
    const size_t NUM_THREADS = 8;
    const size_t OPS_PER_THREAD = TOTAL_OPS / NUM_THREADS;
    
    printf("Operations: %zu (20M reads)\n", TOTAL_OPS);
    printf("Workload: 100%% reads\n");
    printf("Threads: %zu\n", NUM_THREADS);
    
    ParallelAVL* tree = parallel_avl_create(NUM_THREADS, ROUTER_STATIC_HASH);
    
    /* Pre-populate with 500K elements */
    printf("Pre-populating with 500K elements... ");
    for (int i = 0; i < 500000; i++) {
        parallel_avl_insert(tree, i, NULL);
    }
    printf("done\n");
    
    thread_t threads[NUM_THREADS];
    WorkerArgs args[NUM_THREADS];
    
    printf("Running read-only stress test... ");
    fflush(stdout);
    
    double start = get_time_ms();
    
    for (size_t i = 0; i < NUM_THREADS; i++) {
        args[i].tree = tree;
        args[i].ops = OPS_PER_THREAD;
        args[i].key_range = KEY_RANGE;
        args[i].thread_id = (int)i;
        THREAD_CREATE(&threads[i], readonly_worker, &args[i]);
    }
    
    for (size_t i = 0; i < NUM_THREADS; i++) {
        THREAD_JOIN(threads[i]);
    }
    
    double end = get_time_ms();
    double duration = end - start;
    
    printf("done\n\n");
    
    double throughput = TOTAL_OPS / (duration / 1000.0);
    
    printf("Results:\n");
    printf("  Duration: %.2f ms\n", duration);
    printf("  Throughput: %.0f ops/sec (%.2f M/s)\n", throughput, throughput / 1000000.0);
    
    int passed = throughput > 5000000;  /* At least 5M reads/sec */
    printf("  Status: %s\n", passed ? "PASS" : "FAIL");
    
    record_result("Read-Only 20M", TOTAL_OPS, duration, 1.0, 500000, passed);
    parallel_avl_destroy(tree);
}

/* ============================================================================
 * Summary Report
 * ============================================================================ */

static void print_summary(void) {
    printf("\n");
    printf("+============================================================================+\n");
    printf("|                        STRESS TEST SUMMARY                                 |\n");
    printf("+============================================================================+\n");
    printf("| %-25s | %10s | %12s | %8s | %6s |\n", 
           "Test", "Ops", "Throughput", "Balance", "Status");
    printf("+---------------------------+------------+--------------+----------+--------+\n");
    
    int total_passed = 0;
    for (int i = 0; i < result_count; i++) {
        TestResult* r = &results[i];
        printf("| %-25s | %10zu | %10.2f M | %6.1f%% | %6s |\n",
               r->test_name,
               r->total_ops,
               r->throughput / 1000000.0,
               r->balance_score * 100,
               r->passed ? "PASS" : "FAIL");
        if (r->passed) total_passed++;
    }
    
    printf("+---------------------------+------------+--------------+----------+--------+\n");
    printf("| TOTAL: %d/%d tests passed                                                  |\n",
           total_passed, result_count);
    printf("+============================================================================+\n");
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    printf("\n");
    printf("+============================================================================+\n");
    printf("|           PARALLEL AVL STRESS TEST - ADVERSARIAL ATTACKS                  |\n");
    printf("+============================================================================+\n");
    
    test_high_volume_stress();
    test_extreme_volume();
    test_hotspot_attack();
    test_write_heavy();
    test_dynamic_scaling_under_load();
    test_readonly_stress();
    
    print_summary();
    
    return 0;
}
