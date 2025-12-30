/**
 * @file benchmark_parallel.c
 * @brief High-performance benchmark for Parallel AVL Tree
 */

#include "../include/parallel_avl.h"
#include "../include/avl_tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#define NUM_CORES 8
typedef HANDLE thread_t;
typedef DWORD (WINAPI *thread_func_t)(LPVOID);
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
typedef void* (*thread_func_t)(void*);
#define THREAD_CREATE(t, func, arg) (pthread_create((t), NULL, (func), (arg)) == 0)
#define THREAD_JOIN(t) pthread_join((t), NULL)

static double get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}
#endif

/* Fast xorshift64 RNG - much faster than rand() */
static inline uint64_t xorshift64(uint64_t* state) {
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

/* ============================================================================
 * Single-threaded AVL benchmark (baseline)
 * ============================================================================ */

static double benchmark_single_avl(size_t ops, int key_range) {
    AVLTree* tree = avl_tree_create(NULL);
    if (!tree) return 0;
    
    /* Pre-populate */
    for (int i = 0; i < 1000; i++) {
        avl_tree_insert(tree, i, NULL);
    }
    
    uint64_t rng = 12345;
    
    double start = get_time_ms();
    
    for (size_t i = 0; i < ops; i++) {
        int64_t key = (int64_t)(xorshift64(&rng) % (uint64_t)key_range);
        uint64_t op = xorshift64(&rng) % 100;
        
        if (op < 70) {  /* 70% reads */
            avl_tree_contains(tree, key);
        } else if (op < 85) {  /* 15% inserts */
            avl_tree_insert(tree, key, NULL);
        } else {  /* 15% deletes */
            avl_tree_remove(tree, key);
        }
    }
    
    double end = get_time_ms();
    avl_tree_destroy(tree);
    
    double seconds = (end - start) / 1000.0;
    if (seconds < 0.001) seconds = 0.001;
    return ops / seconds;
}

/* ============================================================================
 * Multi-threaded Parallel AVL benchmark
 * ============================================================================ */

typedef struct {
    ParallelAVL* tree;
    size_t ops;
    int key_range;
    int thread_id;
    double throughput;
} WorkerArgs;

#ifdef _WIN32
static DWORD WINAPI parallel_worker(LPVOID arg) {
#else
static void* parallel_worker(void* arg) {
#endif
    WorkerArgs* args = (WorkerArgs*)arg;
    
    uint64_t rng = 12345ULL + (uint64_t)args->thread_id * 1000ULL;
    
    double start = get_time_ms();
    
    for (size_t i = 0; i < args->ops; i++) {
        int64_t key = (int64_t)(xorshift64(&rng) % (uint64_t)args->key_range);
        uint64_t op = xorshift64(&rng) % 100;
        
        if (op < 70) {  /* 70% reads */
            parallel_avl_contains(args->tree, key);
        } else if (op < 85) {  /* 15% inserts */
            parallel_avl_insert(args->tree, key, NULL);
        } else {  /* 15% deletes */
            parallel_avl_remove(args->tree, key);
        }
    }
    
    double end = get_time_ms();
    double seconds = (end - start) / 1000.0;
    if (seconds < 0.001) seconds = 0.001;
    args->throughput = args->ops / seconds;
    
    return 0;
}

static double benchmark_parallel_avl(size_t num_threads, size_t ops_per_thread, 
                                      int key_range, RouterStrategy strategy) {
    ParallelAVL* tree = parallel_avl_create(num_threads, strategy);
    if (!tree) return 0;
    
    /* Pre-populate */
    for (int i = 0; i < 1000; i++) {
        parallel_avl_insert(tree, i, NULL);
    }
    
    thread_t* threads = (thread_t*)malloc(num_threads * sizeof(thread_t));
    WorkerArgs* args = (WorkerArgs*)malloc(num_threads * sizeof(WorkerArgs));
    
    if (!threads || !args) {
        free(threads);
        free(args);
        parallel_avl_destroy(tree);
        return 0;
    }
    
    double start = get_time_ms();
    
    /* Launch threads */
    for (size_t i = 0; i < num_threads; i++) {
        args[i].tree = tree;
        args[i].ops = ops_per_thread;
        args[i].key_range = key_range;
        args[i].thread_id = (int)i;
        args[i].throughput = 0;
        THREAD_CREATE(&threads[i], parallel_worker, &args[i]);
    }
    
    /* Wait for completion */
    for (size_t i = 0; i < num_threads; i++) {
        THREAD_JOIN(threads[i]);
    }
    
    double end = get_time_ms();
    
    free(threads);
    free(args);
    parallel_avl_destroy(tree);
    
    double seconds = (end - start) / 1000.0;
    if (seconds < 0.001) seconds = 0.001;
    return (num_threads * ops_per_thread) / seconds;
}

/* ============================================================================
 * Tests
 * ============================================================================ */

static void test_basic_operations(void) {
    printf("\n=== Basic Operations Test ===\n");
    
    ParallelAVL* tree = parallel_avl_create(4, ROUTER_STATIC_HASH);
    if (!tree) {
        printf("FAIL: Could not create tree\n");
        return;
    }
    
    /* Insert */
    printf("Inserting 1000 elements... ");
    for (int i = 0; i < 1000; i++) {
        parallel_avl_insert(tree, i, (void*)(intptr_t)(i * 2));
    }
    printf("OK\n");
    
    /* Verify size */
    size_t size = parallel_avl_size(tree);
    printf("Size check: %zu (expected 1000) %s\n", size, size == 1000 ? "OK" : "FAIL");
    
    /* Contains */
    printf("Contains check... ");
    int contains_ok = 1;
    for (int i = 0; i < 1000; i++) {
        if (!parallel_avl_contains(tree, i)) {
            contains_ok = 0;
            break;
        }
    }
    printf("%s\n", contains_ok ? "OK" : "FAIL");
    
    /* Get */
    printf("Get check... ");
    bool found;
    void* val = parallel_avl_get(tree, 42, &found);
    printf("key=42, value=%d, found=%d %s\n", 
           (int)(intptr_t)val, found, 
           (found && (intptr_t)val == 84) ? "OK" : "FAIL");
    
    /* Remove */
    printf("Remove check... ");
    bool removed = parallel_avl_remove(tree, 42);
    bool still_exists = parallel_avl_contains(tree, 42);
    printf("removed=%d, still_exists=%d %s\n", 
           removed, still_exists, 
           (removed && !still_exists) ? "OK" : "FAIL");
    
    parallel_avl_print_stats(tree);
    parallel_avl_destroy(tree);
}

static void test_dynamic_scaling(void) {
    printf("\n=== Dynamic Scaling Test ===\n");
    
    ParallelAVL* tree = parallel_avl_create(2, ROUTER_STATIC_HASH);
    if (!tree) {
        printf("FAIL: Could not create tree\n");
        return;
    }
    
    printf("Inserting 500 elements with 2 shards... ");
    for (int i = 0; i < 500; i++) {
        parallel_avl_insert(tree, i, NULL);
    }
    printf("OK (shards: %zu)\n", parallel_avl_num_shards(tree));
    
    printf("Adding shard... ");
    if (parallel_avl_add_shard(tree)) {
        printf("OK (shards: %zu)\n", parallel_avl_num_shards(tree));
    } else {
        printf("FAIL\n");
    }
    
    printf("Verifying data accessibility... ");
    int accessible = 1;
    for (int i = 0; i < 500; i++) {
        if (!parallel_avl_contains(tree, i)) {
            accessible = 0;
            printf("FAIL (key %d not found)\n", i);
            break;
        }
    }
    if (accessible) printf("OK\n");
    
    printf("Force rebalancing... ");
    parallel_avl_force_rebalance(tree);
    printf("OK\n");
    
    parallel_avl_print_stats(tree);
    parallel_avl_destroy(tree);
}

/* ============================================================================
 * Main
 * ============================================================================ */

static void print_header(const char* title) {
    printf("\n");
    printf("+------------------------------------------------------------+\n");
    printf("|  %-56s  |\n", title);
    printf("+------------------------------------------------------------+\n");
}

static void run_scalability_test(size_t num_threads, size_t ops_per_thread, int key_range) {
    char title[64];
    snprintf(title, sizeof(title), "%zu Threads - Scalability Test", num_threads);
    print_header(title);
    
    printf("Total operations: %zu\n", num_threads * ops_per_thread);
    printf("Operations per thread: %zu\n", ops_per_thread);
    printf("Key range: %d\n\n", key_range);
    
    /* Baseline single-threaded */
    printf("Baseline (single-threaded AVL):\n");
    double baseline = benchmark_single_avl(num_threads * ops_per_thread, key_range);
    printf("  Throughput: %.0f ops/sec\n", baseline);
    
    /* Parallel with STATIC_HASH (fastest) */
    printf("\nParallel AVL (STATIC_HASH, %zu shards):\n", num_threads);
    double parallel_static = benchmark_parallel_avl(num_threads, ops_per_thread, 
                                                     key_range, ROUTER_STATIC_HASH);
    printf("  Throughput: %.0f ops/sec\n", parallel_static);
    
    /* Parallel with INTELLIGENT */
    printf("\nParallel AVL (INTELLIGENT, %zu shards):\n", num_threads);
    double parallel_intel = benchmark_parallel_avl(num_threads, ops_per_thread, 
                                                    key_range, ROUTER_INTELLIGENT);
    printf("  Throughput: %.0f ops/sec\n", parallel_intel);
    
    /* Analysis */
    printf("\n--- Analysis ---\n");
    printf("STATIC_HASH speedup vs baseline: %.2fx %s\n", 
           parallel_static / baseline,
           parallel_static > baseline ? "[OK]" : "[SLOWER]");
    printf("INTELLIGENT speedup vs baseline: %.2fx %s\n", 
           parallel_intel / baseline,
           parallel_intel > baseline ? "[OK]" : "[SLOWER]");
    
    printf("\nSCALABILITY (STATIC_HASH):\n");
    printf("  Ideal speedup:   %.1fx\n", (double)num_threads);
    printf("  Actual speedup:  %.2fx\n", parallel_static / baseline);
    printf("  Efficiency:      %.1f%%\n", 
           (parallel_static / baseline) / (double)num_threads * 100);
}

static void run_large_scale_benchmark(void) {
    print_header("Large Scale Benchmark");
    
    const size_t TOTAL_OPS = 1000000;
    const int KEY_RANGE = 100000;
    
    printf("Total operations: %zu\n", TOTAL_OPS);
    printf("Key range: %d\n\n", KEY_RANGE);
    
    /* Baseline */
    printf("Baseline (single-threaded AVL):\n");
    double baseline = benchmark_single_avl(TOTAL_OPS, KEY_RANGE);
    printf("  Throughput: %.0f ops/sec\n\n", baseline);
    
    /* Test different thread counts */
    size_t thread_counts[] = {2, 4, 8};
    
    for (size_t i = 0; i < sizeof(thread_counts)/sizeof(thread_counts[0]); i++) {
        size_t threads = thread_counts[i];
        size_t ops_per_thread = TOTAL_OPS / threads;
        
        printf("Parallel AVL (%zu threads, %zu shards):\n", threads, threads);
        double throughput = benchmark_parallel_avl(threads, ops_per_thread, 
                                                    KEY_RANGE, ROUTER_STATIC_HASH);
        printf("  Throughput: %.0f ops/sec\n", throughput);
        printf("  Speedup:    %.2fx\n", throughput / baseline);
        printf("  Efficiency: %.1f%%\n\n", (throughput / baseline) / (double)threads * 100);
    }
}

int main(void) {
    print_header("Parallel AVL Tree - Pure C (Optimized)");
    
    printf("Features:\n");
    printf("  - Node pooling for fast allocation\n");
    printf("  - Robin Hood hashing in redirect index\n");
    printf("  - Atomic statistics (lock-free reads)\n");
    printf("  - Cache-line optimized data layout\n");
    printf("  - Inline hot path functions\n");
    printf("  - Spin-count on critical sections (Windows)\n");
    
    /* Run tests */
    test_basic_operations();
    test_dynamic_scaling();
    
    /* Scalability tests with different workloads */
    printf("\n");
    
    /* Small workload */
    for (size_t threads = 2; threads <= NUM_CORES; threads *= 2) {
        run_scalability_test(threads, 10000, 10000);
    }
    
    /* Large scale benchmark */
    run_large_scale_benchmark();
    
    print_header("Benchmark Complete");
    
    return 0;
}
