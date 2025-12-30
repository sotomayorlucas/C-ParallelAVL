/**
 * @file avl_tree.c
 * @brief High-performance AVL Tree implementation
 */

#include "../include/avl_tree.h"

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

AVL_INLINE AVLNode* avl_node_create(AVLTree* tree, int64_t key, void* value) {
    AVLNode* node = avl_pool_alloc(&tree->pool);
    if (AVL_UNLIKELY(!node)) return NULL;
    
    node->key = key;
    node->value = value;
    node->left = NULL;
    node->right = NULL;
    node->parent = NULL;
    node->height = 1;
    
    return node;
}

AVL_INLINE AVLNode* avl_find_node(const AVLTree* tree, int64_t key) {
    AVLNode* current = tree->root;
    
    while (AVL_LIKELY(current != NULL)) {
        AVL_PREFETCH(current->left);
        AVL_PREFETCH(current->right);
        
        if (key < current->key) {
            current = current->left;
        } else if (key > current->key) {
            current = current->right;
        } else {
            return current;
        }
    }
    return NULL;
}

AVL_INLINE AVLNode* avl_find_min(AVLNode* node) {
    if (AVL_UNLIKELY(!node)) return NULL;
    while (node->left) {
        node = node->left;
    }
    return node;
}

AVL_INLINE AVLNode* avl_find_max(AVLNode* node) {
    if (AVL_UNLIKELY(!node)) return NULL;
    while (node->right) {
        node = node->right;
    }
    return node;
}

AVL_INLINE void avl_transplant(AVLTree* tree, AVLNode* u, AVLNode* v) {
    if (!u->parent) {
        tree->root = v;
    } else if (u == u->parent->left) {
        u->parent->left = v;
    } else {
        u->parent->right = v;
    }
    if (v) {
        v->parent = u->parent;
    }
}

AVL_INLINE AVLNode* avl_rotate_left(AVLTree* tree, AVLNode* x) {
    AVLNode* y = x->right;
    AVLNode* B = y->left;
    
    y->left = x;
    x->right = B;
    
    if (B) B->parent = x;
    
    y->parent = x->parent;
    if (!x->parent) {
        tree->root = y;
    } else if (x->parent->left == x) {
        x->parent->left = y;
    } else {
        x->parent->right = y;
    }
    x->parent = y;
    
    /* Update heights - inlined for performance */
    x->height = 1 + avl_max(avl_height(x->left), avl_height(x->right));
    y->height = 1 + avl_max(avl_height(y->left), avl_height(y->right));
    
    return y;
}

AVL_INLINE AVLNode* avl_rotate_right(AVLTree* tree, AVLNode* x) {
    AVLNode* y = x->left;
    AVLNode* B = y->right;
    
    y->right = x;
    x->left = B;
    
    if (B) B->parent = x;
    
    y->parent = x->parent;
    if (!x->parent) {
        tree->root = y;
    } else if (x->parent->left == x) {
        x->parent->left = y;
    } else {
        x->parent->right = y;
    }
    x->parent = y;
    
    x->height = 1 + avl_max(avl_height(x->left), avl_height(x->right));
    y->height = 1 + avl_max(avl_height(y->left), avl_height(y->right));
    
    return y;
}

AVL_INLINE AVLNode* avl_rebalance_node(AVLTree* tree, AVLNode* node) {
    avl_update_height(node);
    int bf = avl_balance_factor(node);
    
    if (bf == 2) {
        if (avl_balance_factor(node->right) < 0) {
            avl_rotate_right(tree, node->right);
        }
        return avl_rotate_left(tree, node);
    } else if (bf == -2) {
        if (avl_balance_factor(node->left) > 0) {
            avl_rotate_left(tree, node->left);
        }
        return avl_rotate_right(tree, node);
    }
    
    return node;
}

static void avl_rebalance(AVLTree* tree, AVLNode* start) {
    AVLNode* node = start;
    while (node) {
        node = avl_rebalance_node(tree, node);
        node = node->parent;
    }
}

static void avl_destroy_values_recursive(AVLTree* tree, AVLNode* node) {
    if (!node) return;
    
    avl_destroy_values_recursive(tree, node->left);
    avl_destroy_values_recursive(tree, node->right);
    
    if (tree->value_destructor && node->value) {
        tree->value_destructor(node->value);
    }
}

static void avl_extract_recursive(const AVLNode* node, AVLKeyValue* out_array, size_t* index) {
    if (!node) return;
    
    avl_extract_recursive(node->left, out_array, index);
    
    out_array[*index].key = node->key;
    out_array[*index].value = node->value;
    (*index)++;
    
    avl_extract_recursive(node->right, out_array, index);
}

static void avl_range_recursive(const AVLNode* node, int64_t lo, int64_t hi,
                                AVLRangeCallback callback, void* ctx, bool* stop) {
    if (!node || *stop) return;
    
    if (node->key > lo) {
        avl_range_recursive(node->left, lo, hi, callback, ctx, stop);
    }
    
    if (!*stop && node->key >= lo && node->key <= hi) {
        if (!callback(node->key, node->value, ctx)) {
            *stop = true;
            return;
        }
    }
    
    if (!*stop && node->key < hi) {
        avl_range_recursive(node->right, lo, hi, callback, ctx, stop);
    }
}

/* ============================================================================
 * Public API
 * ============================================================================ */

AVLTree* avl_tree_create(void (*value_destructor)(void*)) {
    AVLTree* tree = (AVLTree*)malloc(sizeof(AVLTree));
    if (AVL_UNLIKELY(!tree)) return NULL;
    
    tree->root = NULL;
    tree->size = 0;
    tree->value_destructor = value_destructor;
    avl_pool_init(&tree->pool);
    
    return tree;
}

void avl_tree_destroy(AVLTree* tree) {
    if (!tree) return;
    
    if (tree->value_destructor) {
        avl_destroy_values_recursive(tree, tree->root);
    }
    
    avl_pool_destroy(&tree->pool);
    free(tree);
}

void AVL_HOT avl_tree_insert(AVLTree* tree, int64_t key, void* value) {
    if (AVL_UNLIKELY(!tree)) return;
    
    AVLNode* parent = NULL;
    AVLNode* current = tree->root;
    
    /* Find insertion point */
    while (AVL_LIKELY(current != NULL)) {
        parent = current;
        if (key < current->key) {
            current = current->left;
        } else if (key > current->key) {
            current = current->right;
        } else {
            /* Key exists, update value */
            if (tree->value_destructor && current->value) {
                tree->value_destructor(current->value);
            }
            current->value = value;
            return;
        }
    }
    
    AVLNode* new_node = avl_node_create(tree, key, value);
    if (AVL_UNLIKELY(!new_node)) return;
    
    new_node->parent = parent;
    
    if (!parent) {
        tree->root = new_node;
    } else if (key < parent->key) {
        parent->left = new_node;
    } else {
        parent->right = new_node;
    }
    
    tree->size++;
    avl_rebalance(tree, new_node);
}

bool avl_tree_remove(AVLTree* tree, int64_t key) {
    if (AVL_UNLIKELY(!tree)) return false;
    
    AVLNode* node = avl_find_node(tree, key);
    if (!node) return false;
    
    AVLNode* rebalance_start = NULL;
    
    if (!node->left) {
        rebalance_start = node->parent;
        avl_transplant(tree, node, node->right);
    } else if (!node->right) {
        rebalance_start = node->parent;
        avl_transplant(tree, node, node->left);
    } else {
        AVLNode* successor = avl_find_min(node->right);
        rebalance_start = (successor->parent == node) ? successor : successor->parent;
        
        if (successor->parent != node) {
            avl_transplant(tree, successor, successor->right);
            successor->right = node->right;
            successor->right->parent = successor;
        }
        
        avl_transplant(tree, node, successor);
        successor->left = node->left;
        successor->left->parent = successor;
    }
    
    if (tree->value_destructor && node->value) {
        tree->value_destructor(node->value);
    }
    
    avl_pool_free(&tree->pool, node);
    tree->size--;
    
    if (rebalance_start) {
        avl_rebalance(tree, rebalance_start);
    }
    
    return true;
}

bool AVL_HOT avl_tree_contains(const AVLTree* tree, int64_t key) {
    if (AVL_UNLIKELY(!tree)) return false;
    return avl_find_node(tree, key) != NULL;
}

void* AVL_HOT avl_tree_get(const AVLTree* tree, int64_t key, bool* found) {
    if (found) *found = false;
    if (AVL_UNLIKELY(!tree)) return NULL;
    
    AVLNode* node = avl_find_node(tree, key);
    if (node) {
        if (found) *found = true;
        return node->value;
    }
    
    return NULL;
}

size_t avl_tree_size(const AVLTree* tree) {
    return tree ? tree->size : 0;
}

bool avl_tree_empty(const AVLTree* tree) {
    return !tree || tree->size == 0;
}

int64_t avl_tree_min_key(const AVLTree* tree, bool* found) {
    if (found) *found = false;
    if (!tree || !tree->root) return 0;
    
    AVLNode* node = avl_find_min(tree->root);
    if (node) {
        if (found) *found = true;
        return node->key;
    }
    
    return 0;
}

int64_t avl_tree_max_key(const AVLTree* tree, bool* found) {
    if (found) *found = false;
    if (!tree || !tree->root) return 0;
    
    AVLNode* node = avl_find_max(tree->root);
    if (node) {
        if (found) *found = true;
        return node->key;
    }
    
    return 0;
}

void avl_tree_clear(AVLTree* tree) {
    if (!tree) return;
    
    if (tree->value_destructor) {
        avl_destroy_values_recursive(tree, tree->root);
    }
    
    avl_pool_destroy(&tree->pool);
    avl_pool_init(&tree->pool);
    
    tree->root = NULL;
    tree->size = 0;
}

AVLNode* avl_tree_get_root(const AVLTree* tree) {
    return tree ? tree->root : NULL;
}

void avl_tree_extract_all(const AVLTree* tree, AVLKeyValue* out_array, size_t* out_count) {
    if (!tree || !out_array || !out_count) return;
    
    size_t index = 0;
    avl_extract_recursive(tree->root, out_array, &index);
    *out_count = index;
}

void avl_tree_range_foreach(const AVLTree* tree, int64_t lo, int64_t hi,
                            AVLRangeCallback callback, void* ctx) {
    if (!tree || !callback) return;
    
    bool stop = false;
    avl_range_recursive(tree->root, lo, hi, callback, ctx, &stop);
}
