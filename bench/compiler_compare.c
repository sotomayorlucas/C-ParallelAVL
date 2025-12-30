/**
 * @file compiler_compare.c
 * @brief Compiler comparison benchmark (GCC vs Intel ICX)
 * 
 * Simple, reliable tests for compiler comparison.
 */

#include "../include/parallel_avl.h"
#include "../include/avl_tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
typedef HANDLE thread_t;
#define THREAD_CREATE(t, func, arg) (*(t) = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)(func), (arg), 0, NULL))
#define THREAD_JOIN(t) (WaitForSingleObject((t), INFINITE), CloseHandle(t))

static double get_time_ms(void) {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart * 1000.0 / (double)freq.QuadPart;
}
#else
#include <pthread.h>
typedef pthread_t thread_t;
#define THREAD_CREATE(t, func, arg) pthread_create((t), NULL, (func), (arg))
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
 * Benchmark 1: Single-threaded AVL performance
 * ============================================================================ */

static double bench_single_avl(size_t ops, int key_range) {
    AVLTree* tree = avl_tree_create(NULL);
    
    /* Pre-populate */
    for (int i = 0; i < 10000; i++) {
        avl_tree_insert(tree, i, NULL);
    }
    
    uint64_t rng = 12345;
    double start = get_time_ms();
    
    for (size_t i = 0; i < ops; i++) {
        int64_t key = (int64_t)(xorshift64(&rng) % (uint64_t)key_range);
        uint64_t op = xorshift64(&rng) % 100;
        
        if (op < 70) {
            avl_tree_contains(tree, key);
        } else if (op < 85) {
            avl_tree_insert(tree, key, NULL);
        } else {
            avl_tree_remove(tree, key);
        }
    }
    
    double end = get_time_ms();
    avl_tree_destroy(tree);
    
    return ops / ((end - start) / 1000.0);
}

/* ============================================================================
 * Benchmark 2: Parallel AVL performance
 * ============================================================================ */

typedef struct {
    ParallelAVL* tree;
    size_t ops;
    int key_range;
    int thread_id;
} WorkerArgs;

#ifdef _WIN32
static DWORD WINAPI parallel_worker(LPVOID arg) {
#else
static void* parallel_worker(void* arg) {
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
    }
    return 0;
}

static double bench_parallel_avl(size_t num_threads, size_t ops_per_thread, int key_range) {
    ParallelAVL* tree = parallel_avl_create(num_threads, ROUTER_STATIC_HASH);
    
    /* Pre-populate */
    for (int i = 0; i < 10000; i++) {
        parallel_avl_insert(tree, i, NULL);
    }
    
    thread_t* threads = (thread_t*)malloc(num_threads * sizeof(thread_t));
    WorkerArgs* args = (WorkerArgs*)malloc(num_threads * sizeof(WorkerArgs));
    
    double start = get_time_ms();
    
    for (size_t i = 0; i < num_threads; i++) {
        args[i].tree = tree;
        args[i].ops = ops_per_thread;
        args[i].key_range = key_range;
        args[i].thread_id = (int)i;
        THREAD_CREATE(&threads[i], parallel_worker, &args[i]);
    }
    
    for (size_t i = 0; i < num_threads; i++) {
        THREAD_JOIN(threads[i]);
    }
    
    double end = get_time_ms();
    
    free(threads);
    free(args);
    parallel_avl_destroy(tree);
    
    return (num_threads * ops_per_thread) / ((end - start) / 1000.0);
}

/* ============================================================================
 * Benchmark 3: Hash table performance
 * ============================================================================ */

#include "../include/hash_table.h"

static double bench_hash_table(size_t ops, int key_range) {
    HashTable* table = hash_table_create(1024);
    
    /* Pre-populate */
    for (int i = 0; i < 10000; i++) {
        hash_table_insert(table, i, (size_t)i);
    }
    
    uint64_t rng = 12345;
    double start = get_time_ms();
    
    for (size_t i = 0; i < ops; i++) {
        int64_t key = (int64_t)(xorshift64(&rng) % (uint64_t)key_range);
        uint64_t op = xorshift64(&rng) % 100;
        
        if (op < 70) {
            size_t val;
            hash_table_lookup(table, key, &val);
        } else if (op < 85) {
            hash_table_insert(table, key, (size_t)key);
        } else {
            hash_table_remove(table, key);
        }
    }
    
    double end = get_time_ms();
    hash_table_destroy(table);
    
    return ops / ((end - start) / 1000.0);
}

/* ============================================================================
 * Main - Run all benchmarks
 * ============================================================================ */

int main(void) {
    printf("\n");
    printf("+============================================================+\n");
    printf("|     COMPILER COMPARISON BENCHMARK - Parallel AVL Tree      |\n");
    printf("+============================================================+\n");
    
#ifdef __INTEL_COMPILER
    printf("| Compiler: Intel ICX                                        |\n");
#elif defined(__GNUC__)
    printf("| Compiler: GCC %d.%d.%d                                        |\n",
           __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#else
    printf("| Compiler: Unknown                                          |\n");
#endif
    printf("+============================================================+\n\n");
    
    /* Warm-up run */
    printf("Warm-up... ");
    fflush(stdout);
    bench_single_avl(100000, 10000);
    printf("done\n\n");
    
    /* Test 1: Single-threaded AVL */
    printf("=== Test 1: Single-threaded AVL (5M ops) ===\n");
    double t1 = bench_single_avl(5000000, 500000);
    printf("  Throughput: %.2f M ops/sec\n\n", t1 / 1000000.0);
    
    /* Test 2: Single-threaded AVL (10M ops) */
    printf("=== Test 2: Single-threaded AVL (10M ops) ===\n");
    double t2 = bench_single_avl(10000000, 1000000);
    printf("  Throughput: %.2f M ops/sec\n\n", t2 / 1000000.0);
    
    /* Test 3: Hash Table (10M ops) */
    printf("=== Test 3: Hash Table (10M ops) ===\n");
    double t3 = bench_hash_table(10000000, 1000000);
    printf("  Throughput: %.2f M ops/sec\n\n", t3 / 1000000.0);
    
    /* Test 4: Parallel AVL 2 threads (10M ops) */
    printf("=== Test 4: Parallel AVL 2 threads (10M ops) ===\n");
    double t4 = bench_parallel_avl(2, 5000000, 1000000);
    printf("  Throughput: %.2f M ops/sec\n\n", t4 / 1000000.0);
    
    /* Test 5: Parallel AVL 4 threads (10M ops) */
    printf("=== Test 5: Parallel AVL 4 threads (10M ops) ===\n");
    double t5 = bench_parallel_avl(4, 2500000, 1000000);
    printf("  Throughput: %.2f M ops/sec\n\n", t5 / 1000000.0);
    
    /* Test 6: Parallel AVL 8 threads (10M ops) */
    printf("=== Test 6: Parallel AVL 8 threads (10M ops) ===\n");
    double t6 = bench_parallel_avl(8, 1250000, 1000000);
    printf("  Throughput: %.2f M ops/sec\n\n", t6 / 1000000.0);
    
    /* Test 7: High-volume parallel (50M ops) */
    printf("=== Test 7: High-volume Parallel 8 threads (50M ops) ===\n");
    double t7 = bench_parallel_avl(8, 6250000, 5000000);
    printf("  Throughput: %.2f M ops/sec\n\n", t7 / 1000000.0);
    
    /* Summary */
    printf("+============================================================+\n");
    printf("|                      RESULTS SUMMARY                       |\n");
    printf("+============================================================+\n");
    printf("| Test                          | Throughput (M ops/sec)     |\n");
    printf("+-------------------------------+----------------------------+\n");
    printf("| Single AVL 5M                 | %26.2f |\n", t1 / 1000000.0);
    printf("| Single AVL 10M                | %26.2f |\n", t2 / 1000000.0);
    printf("| Hash Table 10M                | %26.2f |\n", t3 / 1000000.0);
    printf("| Parallel 2T 10M               | %26.2f |\n", t4 / 1000000.0);
    printf("| Parallel 4T 10M               | %26.2f |\n", t5 / 1000000.0);
    printf("| Parallel 8T 10M               | %26.2f |\n", t6 / 1000000.0);
    printf("| Parallel 8T 50M               | %26.2f |\n", t7 / 1000000.0);
    printf("+-------------------------------+----------------------------+\n");
    
    /* Output for easy parsing */
    printf("\n[CSV_OUTPUT]\n");
    printf("single_avl_5m,%.2f\n", t1 / 1000000.0);
    printf("single_avl_10m,%.2f\n", t2 / 1000000.0);
    printf("hash_table_10m,%.2f\n", t3 / 1000000.0);
    printf("parallel_2t_10m,%.2f\n", t4 / 1000000.0);
    printf("parallel_4t_10m,%.2f\n", t5 / 1000000.0);
    printf("parallel_8t_10m,%.2f\n", t6 / 1000000.0);
    printf("parallel_8t_50m,%.2f\n", t7 / 1000000.0);
    
    return 0;
}
