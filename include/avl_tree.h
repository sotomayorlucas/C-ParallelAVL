/**
 * @file avl_tree.h
 * @brief High-performance AVL Tree in pure C (C11)
 * 
 * Optimizations:
 *   - Inline critical path functions
 *   - Cache-friendly node layout
 *   - Minimal branching in hot paths
 *   - Node pooling for reduced allocations
 */

#ifndef AVL_TREE_H
#define AVL_TREE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Compiler hints for optimization */
#ifdef __GNUC__
#define AVL_LIKELY(x)   __builtin_expect(!!(x), 1)
#define AVL_UNLIKELY(x) __builtin_expect(!!(x), 0)
#define AVL_INLINE      static inline __attribute__((always_inline))
#define AVL_HOT         __attribute__((hot))
#define AVL_PREFETCH(x) __builtin_prefetch(x)
#else
#define AVL_LIKELY(x)   (x)
#define AVL_UNLIKELY(x) (x)
#define AVL_INLINE      static inline
#define AVL_HOT
#define AVL_PREFETCH(x)
#endif

/**
 * AVL Node - cache-line optimized layout (64 bytes on most systems)
 */
typedef struct AVLNode {
    int64_t key;                    /* 8 bytes */
    void* value;                    /* 8 bytes */
    struct AVLNode* left;           /* 8 bytes */
    struct AVLNode* right;          /* 8 bytes */
    struct AVLNode* parent;         /* 8 bytes */
    int32_t height;                 /* 4 bytes */
    int32_t _padding;               /* 4 bytes - alignment */
} AVLNode;  /* Total: 48 bytes, fits in cache line */

/**
 * Node pool for fast allocation
 */
#define AVL_POOL_BLOCK_SIZE 256

typedef struct AVLNodeBlock {
    AVLNode nodes[AVL_POOL_BLOCK_SIZE];
    struct AVLNodeBlock* next;
} AVLNodeBlock;

typedef struct AVLNodePool {
    AVLNodeBlock* blocks;
    AVLNode* free_list;
    size_t total_allocated;
} AVLNodePool;

/**
 * AVL Tree structure
 */
typedef struct AVLTree {
    AVLNode* root;
    size_t size;
    AVLNodePool pool;
    void (*value_destructor)(void*);
} AVLTree;

/**
 * Key-Value pair for extraction/range queries
 */
typedef struct AVLKeyValue {
    int64_t key;
    void* value;
} AVLKeyValue;

/* ============================================================================
 * Node Pool Functions (inlined for performance)
 * ============================================================================ */

AVL_INLINE void avl_pool_init(AVLNodePool* pool) {
    pool->blocks = NULL;
    pool->free_list = NULL;
    pool->total_allocated = 0;
}

AVL_INLINE AVLNode* avl_pool_alloc(AVLNodePool* pool) {
    if (AVL_LIKELY(pool->free_list != NULL)) {
        AVLNode* node = pool->free_list;
        pool->free_list = node->right;  /* Using right as next pointer in free list */
        return node;
    }
    
    /* Allocate new block */
    AVLNodeBlock* block = (AVLNodeBlock*)malloc(sizeof(AVLNodeBlock));
    if (!block) return NULL;
    
    block->next = pool->blocks;
    pool->blocks = block;
    
    /* Add all nodes except first to free list */
    for (size_t i = 1; i < AVL_POOL_BLOCK_SIZE - 1; i++) {
        block->nodes[i].right = &block->nodes[i + 1];
    }
    block->nodes[AVL_POOL_BLOCK_SIZE - 1].right = pool->free_list;
    pool->free_list = &block->nodes[1];
    
    pool->total_allocated += AVL_POOL_BLOCK_SIZE;
    return &block->nodes[0];
}

AVL_INLINE void avl_pool_free(AVLNodePool* pool, AVLNode* node) {
    node->right = pool->free_list;
    pool->free_list = node;
}

AVL_INLINE void avl_pool_destroy(AVLNodePool* pool) {
    AVLNodeBlock* block = pool->blocks;
    while (block) {
        AVLNodeBlock* next = block->next;
        free(block);
        block = next;
    }
    pool->blocks = NULL;
    pool->free_list = NULL;
}

/* ============================================================================
 * Core AVL Functions (inlined hot paths)
 * ============================================================================ */

AVL_INLINE int avl_height(const AVLNode* n) {
    return n ? n->height : 0;
}

AVL_INLINE int avl_max(int a, int b) {
    return a > b ? a : b;
}

AVL_INLINE void avl_update_height(AVLNode* n) {
    if (n) {
        n->height = 1 + avl_max(avl_height(n->left), avl_height(n->right));
    }
}

AVL_INLINE int avl_balance_factor(const AVLNode* n) {
    return avl_height(n->right) - avl_height(n->left);
}

/* ============================================================================
 * Public API
 * ============================================================================ */

AVLTree* avl_tree_create(void (*value_destructor)(void*));
void avl_tree_destroy(AVLTree* tree);
void avl_tree_insert(AVLTree* tree, int64_t key, void* value) AVL_HOT;
bool avl_tree_remove(AVLTree* tree, int64_t key);
bool avl_tree_contains(const AVLTree* tree, int64_t key) AVL_HOT;
void* avl_tree_get(const AVLTree* tree, int64_t key, bool* found) AVL_HOT;
size_t avl_tree_size(const AVLTree* tree);
bool avl_tree_empty(const AVLTree* tree);
int64_t avl_tree_min_key(const AVLTree* tree, bool* found);
int64_t avl_tree_max_key(const AVLTree* tree, bool* found);
void avl_tree_clear(AVLTree* tree);
AVLNode* avl_tree_get_root(const AVLTree* tree);
void avl_tree_extract_all(const AVLTree* tree, AVLKeyValue* out_array, size_t* out_count);

/* Range query with callback (avoids allocation) */
typedef bool (*AVLRangeCallback)(int64_t key, void* value, void* ctx);
void avl_tree_range_foreach(const AVLTree* tree, int64_t lo, int64_t hi,
                            AVLRangeCallback callback, void* ctx);

#ifdef __cplusplus
}
#endif

#endif /* AVL_TREE_H */
