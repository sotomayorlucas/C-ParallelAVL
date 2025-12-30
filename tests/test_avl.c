/**
 * @file test_avl.c
 * @brief Unit tests for Parallel AVL Tree - Pure C Implementation
 */

#include "../include/parallel_avl.h"
#include "../include/avl_tree.h"
#include "../include/hash_table.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) static void test_##name(void)
#define RUN_TEST(name) do { \
    printf("  Testing %s... ", #name); \
    fflush(stdout); \
    test_##name(); \
    printf("PASS\n"); \
    tests_passed++; \
} while(0)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("FAIL at %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        tests_failed++; \
        return; \
    } \
} while(0)

/* ============================================================================
 * AVL Tree Tests
 * ============================================================================ */

TEST(avl_create_destroy) {
    AVLTree* tree = avl_tree_create(NULL);
    ASSERT(tree != NULL);
    ASSERT(avl_tree_size(tree) == 0);
    ASSERT(avl_tree_empty(tree));
    avl_tree_destroy(tree);
}

TEST(avl_insert_contains) {
    AVLTree* tree = avl_tree_create(NULL);
    
    avl_tree_insert(tree, 10, NULL);
    avl_tree_insert(tree, 5, NULL);
    avl_tree_insert(tree, 15, NULL);
    
    ASSERT(avl_tree_size(tree) == 3);
    ASSERT(avl_tree_contains(tree, 10));
    ASSERT(avl_tree_contains(tree, 5));
    ASSERT(avl_tree_contains(tree, 15));
    ASSERT(!avl_tree_contains(tree, 20));
    
    avl_tree_destroy(tree);
}

TEST(avl_remove) {
    AVLTree* tree = avl_tree_create(NULL);
    
    for (int i = 0; i < 100; i++) {
        avl_tree_insert(tree, i, NULL);
    }
    ASSERT(avl_tree_size(tree) == 100);
    
    ASSERT(avl_tree_remove(tree, 50));
    ASSERT(!avl_tree_contains(tree, 50));
    ASSERT(avl_tree_size(tree) == 99);
    
    ASSERT(!avl_tree_remove(tree, 50));
    ASSERT(!avl_tree_remove(tree, 200));
    
    avl_tree_destroy(tree);
}

TEST(avl_get) {
    AVLTree* tree = avl_tree_create(NULL);
    
    avl_tree_insert(tree, 42, (void*)123);
    
    bool found;
    void* val = avl_tree_get(tree, 42, &found);
    ASSERT(found);
    ASSERT((intptr_t)val == 123);
    
    val = avl_tree_get(tree, 99, &found);
    ASSERT(!found);
    
    avl_tree_destroy(tree);
}

TEST(avl_min_max) {
    AVLTree* tree = avl_tree_create(NULL);
    
    bool found;
    avl_tree_min_key(tree, &found);
    ASSERT(!found);
    
    avl_tree_insert(tree, 50, NULL);
    avl_tree_insert(tree, 25, NULL);
    avl_tree_insert(tree, 75, NULL);
    avl_tree_insert(tree, 10, NULL);
    avl_tree_insert(tree, 90, NULL);
    
    ASSERT(avl_tree_min_key(tree, &found) == 10);
    ASSERT(found);
    ASSERT(avl_tree_max_key(tree, &found) == 90);
    ASSERT(found);
    
    avl_tree_destroy(tree);
}

TEST(avl_balance) {
    AVLTree* tree = avl_tree_create(NULL);
    
    /* Insert in sorted order (worst case for BST) */
    for (int i = 0; i < 1000; i++) {
        avl_tree_insert(tree, i, NULL);
    }
    
    /* AVL should still be balanced */
    for (int i = 0; i < 1000; i++) {
        ASSERT(avl_tree_contains(tree, i));
    }
    
    avl_tree_destroy(tree);
}

TEST(avl_node_pool) {
    AVLTree* tree = avl_tree_create(NULL);
    
    /* Insert many elements to test node pooling */
    for (int i = 0; i < 10000; i++) {
        avl_tree_insert(tree, i, NULL);
    }
    ASSERT(avl_tree_size(tree) == 10000);
    
    /* Remove half */
    for (int i = 0; i < 5000; i++) {
        ASSERT(avl_tree_remove(tree, i));
    }
    ASSERT(avl_tree_size(tree) == 5000);
    
    /* Re-insert (should reuse pooled nodes) */
    for (int i = 0; i < 5000; i++) {
        avl_tree_insert(tree, i, NULL);
    }
    ASSERT(avl_tree_size(tree) == 10000);
    
    avl_tree_destroy(tree);
}

/* ============================================================================
 * Hash Table Tests
 * ============================================================================ */

TEST(hash_create_destroy) {
    HashTable* table = hash_table_create(16);
    ASSERT(table != NULL);
    ASSERT(hash_table_size(table) == 0);
    hash_table_destroy(table);
}

TEST(hash_insert_lookup) {
    HashTable* table = hash_table_create(16);
    
    ASSERT(hash_table_insert(table, 100, 42));
    ASSERT(hash_table_insert(table, 200, 84));
    ASSERT(hash_table_size(table) == 2);
    
    size_t value;
    ASSERT(hash_table_lookup(table, 100, &value));
    ASSERT(value == 42);
    
    ASSERT(hash_table_lookup(table, 200, &value));
    ASSERT(value == 84);
    
    ASSERT(!hash_table_lookup(table, 300, &value));
    
    hash_table_destroy(table);
}

TEST(hash_remove) {
    HashTable* table = hash_table_create(16);
    
    hash_table_insert(table, 100, 42);
    hash_table_insert(table, 200, 84);
    
    ASSERT(hash_table_remove(table, 100));
    ASSERT(!hash_table_lookup(table, 100, NULL));
    ASSERT(hash_table_size(table) == 1);
    
    ASSERT(!hash_table_remove(table, 100));
    
    hash_table_destroy(table);
}

TEST(hash_resize) {
    HashTable* table = hash_table_create(4);
    
    /* Insert many elements to trigger resize */
    for (int i = 0; i < 100; i++) {
        ASSERT(hash_table_insert(table, i, (size_t)(i * 10)));
    }
    ASSERT(hash_table_size(table) == 100);
    
    /* Verify all elements */
    for (int i = 0; i < 100; i++) {
        size_t value;
        ASSERT(hash_table_lookup(table, i, &value));
        ASSERT(value == (size_t)(i * 10));
    }
    
    hash_table_destroy(table);
}

TEST(hash_robin_hood) {
    HashTable* table = hash_table_create(16);
    
    /* Insert keys that might collide */
    for (int i = 0; i < 1000; i++) {
        ASSERT(hash_table_insert(table, i * 17, (size_t)i));
    }
    
    /* Verify all */
    for (int i = 0; i < 1000; i++) {
        size_t value;
        ASSERT(hash_table_lookup(table, i * 17, &value));
        ASSERT(value == (size_t)i);
    }
    
    /* Remove half and verify rest */
    for (int i = 0; i < 500; i++) {
        ASSERT(hash_table_remove(table, i * 17));
    }
    
    for (int i = 500; i < 1000; i++) {
        size_t value;
        ASSERT(hash_table_lookup(table, i * 17, &value));
        ASSERT(value == (size_t)i);
    }
    
    hash_table_destroy(table);
}

/* ============================================================================
 * Parallel AVL Tests
 * ============================================================================ */

TEST(parallel_create_destroy) {
    ParallelAVL* tree = parallel_avl_create(4, ROUTER_STATIC_HASH);
    ASSERT(tree != NULL);
    ASSERT(parallel_avl_size(tree) == 0);
    ASSERT(parallel_avl_num_shards(tree) == 4);
    parallel_avl_destroy(tree);
}

TEST(parallel_insert_contains) {
    ParallelAVL* tree = parallel_avl_create(4, ROUTER_STATIC_HASH);
    
    for (int i = 0; i < 100; i++) {
        parallel_avl_insert(tree, i, NULL);
    }
    
    ASSERT(parallel_avl_size(tree) == 100);
    
    for (int i = 0; i < 100; i++) {
        ASSERT(parallel_avl_contains(tree, i));
    }
    ASSERT(!parallel_avl_contains(tree, 999));
    
    parallel_avl_destroy(tree);
}

TEST(parallel_remove) {
    ParallelAVL* tree = parallel_avl_create(4, ROUTER_STATIC_HASH);
    
    for (int i = 0; i < 100; i++) {
        parallel_avl_insert(tree, i, NULL);
    }
    
    ASSERT(parallel_avl_remove(tree, 50));
    ASSERT(!parallel_avl_contains(tree, 50));
    ASSERT(parallel_avl_size(tree) == 99);
    
    ASSERT(!parallel_avl_remove(tree, 50));
    
    parallel_avl_destroy(tree);
}

TEST(parallel_get) {
    ParallelAVL* tree = parallel_avl_create(4, ROUTER_STATIC_HASH);
    
    parallel_avl_insert(tree, 42, (void*)123);
    
    bool found;
    void* val = parallel_avl_get(tree, 42, &found);
    ASSERT(found);
    ASSERT((intptr_t)val == 123);
    
    val = parallel_avl_get(tree, 99, &found);
    ASSERT(!found);
    
    parallel_avl_destroy(tree);
}

TEST(parallel_range_query) {
    ParallelAVL* tree = parallel_avl_create(4, ROUTER_STATIC_HASH);
    
    for (int i = 0; i < 100; i++) {
        parallel_avl_insert(tree, i, NULL);
    }
    
    AVLKeyValue results[50];
    size_t count;
    
    parallel_avl_range_query(tree, 20, 30, results, 50, &count);
    ASSERT(count == 11);
    
    /* Verify sorted */
    for (size_t i = 1; i < count; i++) {
        ASSERT(results[i].key > results[i-1].key);
    }
    
    parallel_avl_destroy(tree);
}

TEST(parallel_add_shard) {
    ParallelAVL* tree = parallel_avl_create(2, ROUTER_STATIC_HASH);
    
    for (int i = 0; i < 100; i++) {
        parallel_avl_insert(tree, i, NULL);
    }
    
    ASSERT(parallel_avl_num_shards(tree) == 2);
    
    ASSERT(parallel_avl_add_shard(tree));
    ASSERT(parallel_avl_num_shards(tree) == 3);
    
    /* All elements should still be accessible */
    for (int i = 0; i < 100; i++) {
        ASSERT(parallel_avl_contains(tree, i));
    }
    
    parallel_avl_destroy(tree);
}

TEST(parallel_remove_shard) {
    ParallelAVL* tree = parallel_avl_create(4, ROUTER_STATIC_HASH);
    
    for (int i = 0; i < 100; i++) {
        parallel_avl_insert(tree, i, NULL);
    }
    
    ASSERT(parallel_avl_remove_shard(tree));
    ASSERT(parallel_avl_num_shards(tree) == 3);
    ASSERT(parallel_avl_size(tree) == 100);
    
    for (int i = 0; i < 100; i++) {
        ASSERT(parallel_avl_contains(tree, i));
    }
    
    parallel_avl_destroy(tree);
}

TEST(parallel_force_rebalance) {
    ParallelAVL* tree = parallel_avl_create(4, ROUTER_LOAD_AWARE);
    
    for (int i = 0; i < 100; i++) {
        parallel_avl_insert(tree, i, NULL);
    }
    
    parallel_avl_force_rebalance(tree);
    
    for (int i = 0; i < 100; i++) {
        ASSERT(parallel_avl_contains(tree, i));
    }
    
    ASSERT(parallel_avl_balance_score(tree) > 0.8);
    
    parallel_avl_destroy(tree);
}

TEST(parallel_routing_strategies) {
    RouterStrategy strategies[] = {
        ROUTER_STATIC_HASH,
        ROUTER_LOAD_AWARE,
        ROUTER_CONSISTENT_HASH,
        ROUTER_INTELLIGENT
    };
    
    for (size_t s = 0; s < sizeof(strategies)/sizeof(strategies[0]); s++) {
        ParallelAVL* tree = parallel_avl_create(4, strategies[s]);
        
        for (int i = 0; i < 100; i++) {
            parallel_avl_insert(tree, i, NULL);
        }
        
        for (int i = 0; i < 100; i++) {
            ASSERT(parallel_avl_contains(tree, i));
        }
        
        parallel_avl_destroy(tree);
    }
}

TEST(parallel_large_scale) {
    ParallelAVL* tree = parallel_avl_create(8, ROUTER_STATIC_HASH);
    
    /* Insert 100K elements */
    for (int i = 0; i < 100000; i++) {
        parallel_avl_insert(tree, i, (void*)(intptr_t)i);
    }
    
    ASSERT(parallel_avl_size(tree) == 100000);
    
    /* Verify random sample */
    for (int i = 0; i < 100000; i += 1000) {
        bool found;
        void* val = parallel_avl_get(tree, i, &found);
        ASSERT(found);
        ASSERT((intptr_t)val == i);
    }
    
    parallel_avl_destroy(tree);
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    printf("\n=== AVL Tree Unit Tests ===\n");
    RUN_TEST(avl_create_destroy);
    RUN_TEST(avl_insert_contains);
    RUN_TEST(avl_remove);
    RUN_TEST(avl_get);
    RUN_TEST(avl_min_max);
    RUN_TEST(avl_balance);
    RUN_TEST(avl_node_pool);
    
    printf("\n=== Hash Table Unit Tests ===\n");
    RUN_TEST(hash_create_destroy);
    RUN_TEST(hash_insert_lookup);
    RUN_TEST(hash_remove);
    RUN_TEST(hash_resize);
    RUN_TEST(hash_robin_hood);
    
    printf("\n=== Parallel AVL Unit Tests ===\n");
    RUN_TEST(parallel_create_destroy);
    RUN_TEST(parallel_insert_contains);
    RUN_TEST(parallel_remove);
    RUN_TEST(parallel_get);
    RUN_TEST(parallel_range_query);
    RUN_TEST(parallel_add_shard);
    RUN_TEST(parallel_remove_shard);
    RUN_TEST(parallel_force_rebalance);
    RUN_TEST(parallel_routing_strategies);
    RUN_TEST(parallel_large_scale);
    
    printf("\n=== Results ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    
    return tests_failed > 0 ? 1 : 0;
}
