#pragma once

#include "common.hpp"

#include <algorithm>
#include <cstdlib>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace pavl {

template <avl_key Key, avl_value Value>
class avl_tree {
public:
    using key_type = Key;
    using value_type = Value;
    struct key_value {
        Key key;
        Value value;
    };

    struct node {
        Key key;
        Value value;
        node* left;
        node* right;
        node* parent;
        std::int32_t height;
        std::int32_t _pad;
    };

private:
    static constexpr std::size_t pool_block_size = 256;

    struct node_block {
        union storage { node n; constexpr storage() noexcept {} ~storage() noexcept {} };
        storage slots[pool_block_size];
        node_block* next;
        node_block() noexcept : next{nullptr} {}
    };

    class node_pool {
    public:
        node_pool() noexcept = default;
        node_pool(const node_pool&) = delete;
        node_pool& operator=(const node_pool&) = delete;
        node_pool(node_pool&& other) noexcept
            : blocks_{std::exchange(other.blocks_, nullptr)},
              free_list_{std::exchange(other.free_list_, nullptr)},
              total_{std::exchange(other.total_, 0)} {}
        node_pool& operator=(node_pool&& other) noexcept {
            if (this != &other) {
                release_blocks();
                blocks_ = std::exchange(other.blocks_, nullptr);
                free_list_ = std::exchange(other.free_list_, nullptr);
                total_ = std::exchange(other.total_, 0);
            }
            return *this;
        }
        ~node_pool() noexcept { release_blocks(); }

        [[nodiscard]] PAVL_ALWAYS_INLINE node* acquire_raw() {
            if (free_list_) [[likely]] {
                node* n = free_list_;
                free_list_ = n->right;
                return n;
            }
            auto* block = new (std::nothrow) node_block{};
            if (!block) [[unlikely]] return nullptr;
            block->next = blocks_;
            blocks_ = block;
            for (std::size_t i = 1; i < pool_block_size - 1; ++i) {
                auto* nd = std::launder(reinterpret_cast<node*>(&block->slots[i]));
                auto* nx = std::launder(reinterpret_cast<node*>(&block->slots[i + 1]));
                nd->right = nx;
            }
            auto* last = std::launder(reinterpret_cast<node*>(&block->slots[pool_block_size - 1]));
            last->right = free_list_;
            free_list_ = std::launder(reinterpret_cast<node*>(&block->slots[1]));
            total_ += pool_block_size;
            return std::launder(reinterpret_cast<node*>(&block->slots[0]));
        }

        PAVL_ALWAYS_INLINE void release_raw(node* n) noexcept {
            n->right = free_list_;
            free_list_ = n;
        }

        void release_blocks() noexcept {
            auto* b = blocks_;
            while (b) {
                auto* next = b->next;
                delete b;
                b = next;
            }
            blocks_ = nullptr;
            free_list_ = nullptr;
            total_ = 0;
        }

        [[nodiscard]] std::size_t allocated() const noexcept { return total_; }

    private:
        node_block* blocks_{};
        node* free_list_{};
        std::size_t total_{};
    };

public:
    avl_tree() noexcept = default;
    avl_tree(const avl_tree&) = delete;
    avl_tree& operator=(const avl_tree&) = delete;
    avl_tree(avl_tree&& other) noexcept
        : root_{std::exchange(other.root_, nullptr)},
          size_{std::exchange(other.size_, 0)},
          pool_{std::move(other.pool_)} {}
    avl_tree& operator=(avl_tree&& other) noexcept {
        if (this != &other) {
            clear();
            root_ = std::exchange(other.root_, nullptr);
            size_ = std::exchange(other.size_, 0);
            pool_ = std::move(other.pool_);
        }
        return *this;
    }
    ~avl_tree() { destroy_subtree(root_); }

    [[nodiscard]] std::size_t size() const noexcept { return size_; }
    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }
    [[nodiscard]] const node* root() const noexcept { return root_; }

    void clear() noexcept(std::is_nothrow_destructible_v<Value>) {
        destroy_subtree(root_);
        pool_.release_blocks();
        root_ = nullptr;
        size_ = 0;
    }

    PAVL_HOT void insert(Key key, Value value) {
        node* parent = nullptr;
        node* current = root_;
        while (current) [[likely]] {
            parent = current;
            if (key < current->key) current = current->left;
            else if (current->key < key) current = current->right;
            else {
                current->value = std::move(value);
                return;
            }
        }
        node* nn = pool_.acquire_raw();
        if (!nn) [[unlikely]] return;
        std::construct_at(&nn->key, key);
        std::construct_at(&nn->value, std::move(value));
        nn->left = nullptr;
        nn->right = nullptr;
        nn->parent = parent;
        nn->height = 1;
        if (!parent) {
            root_ = nn;
        } else if (key < parent->key) {
            parent->left = nn;
        } else {
            parent->right = nn;
        }
        ++size_;
        rebalance_from(nn);
    }

    PAVL_HOT bool remove(const Key& key) {
        node* n = find_node(root_, key);
        if (!n) return false;
        node* rebalance_start = nullptr;
        if (!n->left) {
            rebalance_start = n->parent;
            transplant(n, n->right);
        } else if (!n->right) {
            rebalance_start = n->parent;
            transplant(n, n->left);
        } else {
            node* succ = leftmost(n->right);
            rebalance_start = (succ->parent == n) ? succ : succ->parent;
            if (succ->parent != n) {
                transplant(succ, succ->right);
                succ->right = n->right;
                succ->right->parent = succ;
            }
            transplant(n, succ);
            succ->left = n->left;
            succ->left->parent = succ;
        }
        std::destroy_at(&n->value);
        std::destroy_at(&n->key);
        pool_.release_raw(n);
        --size_;
        if (rebalance_start) rebalance_from(rebalance_start);
        return true;
    }

    [[nodiscard]] PAVL_HOT bool contains(const Key& key) const noexcept {
        return find_node(root_, key) != nullptr;
    }

    [[nodiscard]] PAVL_HOT Value* find(const Key& key) noexcept {
        node* n = find_node(root_, key);
        return n ? &n->value : nullptr;
    }

    [[nodiscard]] PAVL_HOT const Value* find(const Key& key) const noexcept {
        const node* n = find_node(root_, key);
        return n ? &n->value : nullptr;
    }

    [[nodiscard]] std::optional<Key> min_key() const noexcept {
        if (!root_) return std::nullopt;
        return leftmost(root_)->key;
    }

    [[nodiscard]] std::optional<Key> max_key() const noexcept {
        if (!root_) return std::nullopt;
        return rightmost(root_)->key;
    }

    template <std::invocable<const Key&, Value&> F>
    void range_for_each(const Key& lo, const Key& hi, F&& f) {
        bool stop = false;
        range_walk(root_, lo, hi, f, stop);
    }

    template <std::invocable<const Key&, const Value&> F>
    void range_for_each(const Key& lo, const Key& hi, F&& f) const {
        bool stop = false;
        range_walk_const(root_, lo, hi, f, stop);
    }

    [[nodiscard]] std::vector<key_value> extract_all() const {
        std::vector<key_value> out;
        out.reserve(size_);
        inorder_collect(root_, out);
        return out;
    }

private:
    [[nodiscard]] PAVL_ALWAYS_INLINE static std::int32_t height_of(const node* n) noexcept {
        return n ? n->height : 0;
    }

    PAVL_ALWAYS_INLINE static void update_height(node* n) noexcept {
        n->height = 1 + std::max(height_of(n->left), height_of(n->right));
    }

    [[nodiscard]] PAVL_ALWAYS_INLINE static std::int32_t balance_factor(const node* n) noexcept {
        return height_of(n->right) - height_of(n->left);
    }

    [[nodiscard]] PAVL_HOT static node* find_node(node* root, const Key& key) noexcept {
        node* cur = root;
        while (cur) [[likely]] {
            PAVL_PREFETCH(cur->left);
            PAVL_PREFETCH(cur->right);
            if (key < cur->key) cur = cur->left;
            else if (cur->key < key) cur = cur->right;
            else return cur;
        }
        return nullptr;
    }

    [[nodiscard]] PAVL_HOT static const node* find_node(const node* root, const Key& key) noexcept {
        const node* cur = root;
        while (cur) [[likely]] {
            if (key < cur->key) cur = cur->left;
            else if (cur->key < key) cur = cur->right;
            else return cur;
        }
        return nullptr;
    }

    [[nodiscard]] static node* leftmost(node* n) noexcept {
        while (n->left) n = n->left;
        return n;
    }

    [[nodiscard]] static const node* leftmost(const node* n) noexcept {
        while (n->left) n = n->left;
        return n;
    }

    [[nodiscard]] static node* rightmost(node* n) noexcept {
        while (n->right) n = n->right;
        return n;
    }

    [[nodiscard]] static const node* rightmost(const node* n) noexcept {
        while (n->right) n = n->right;
        return n;
    }

    void transplant(node* u, node* v) noexcept {
        if (!u->parent) root_ = v;
        else if (u == u->parent->left) u->parent->left = v;
        else u->parent->right = v;
        if (v) v->parent = u->parent;
    }

    PAVL_ALWAYS_INLINE node* rotate_left(node* x) noexcept {
        node* y = x->right;
        node* b = y->left;
        y->left = x;
        x->right = b;
        if (b) b->parent = x;
        y->parent = x->parent;
        if (!x->parent) root_ = y;
        else if (x->parent->left == x) x->parent->left = y;
        else x->parent->right = y;
        x->parent = y;
        update_height(x);
        update_height(y);
        return y;
    }

    PAVL_ALWAYS_INLINE node* rotate_right(node* x) noexcept {
        node* y = x->left;
        node* b = y->right;
        y->right = x;
        x->left = b;
        if (b) b->parent = x;
        y->parent = x->parent;
        if (!x->parent) root_ = y;
        else if (x->parent->left == x) x->parent->left = y;
        else x->parent->right = y;
        x->parent = y;
        update_height(x);
        update_height(y);
        return y;
    }

    PAVL_ALWAYS_INLINE node* rebalance_node(node* n) noexcept {
        update_height(n);
        auto bf = balance_factor(n);
        if (bf == 2) {
            if (balance_factor(n->right) < 0) rotate_right(n->right);
            return rotate_left(n);
        }
        if (bf == -2) {
            if (balance_factor(n->left) > 0) rotate_left(n->left);
            return rotate_right(n);
        }
        return n;
    }

    void rebalance_from(node* start) noexcept {
        node* n = start;
        while (n) {
            n = rebalance_node(n);
            n = n->parent;
        }
    }

    void destroy_subtree(node* n) noexcept(std::is_nothrow_destructible_v<Value>) {
        if (!n) return;
        destroy_subtree(n->left);
        destroy_subtree(n->right);
        std::destroy_at(&n->value);
        std::destroy_at(&n->key);
    }

    template <typename F>
    void range_walk(node* n, const Key& lo, const Key& hi, F& f, bool& stop) {
        if (!n || stop) return;
        if (lo < n->key) range_walk(n->left, lo, hi, f, stop);
        if (stop) return;
        if (!(n->key < lo) && !(hi < n->key)) {
            if constexpr (std::is_same_v<std::invoke_result_t<F&, const Key&, Value&>, bool>) {
                if (!f(n->key, n->value)) { stop = true; return; }
            } else {
                f(n->key, n->value);
            }
        }
        if (n->key < hi) range_walk(n->right, lo, hi, f, stop);
    }

    template <typename F>
    void range_walk_const(const node* n, const Key& lo, const Key& hi, F& f, bool& stop) const {
        if (!n || stop) return;
        if (lo < n->key) range_walk_const(n->left, lo, hi, f, stop);
        if (stop) return;
        if (!(n->key < lo) && !(hi < n->key)) {
            if constexpr (std::is_same_v<std::invoke_result_t<F&, const Key&, const Value&>, bool>) {
                if (!f(n->key, n->value)) { stop = true; return; }
            } else {
                f(n->key, n->value);
            }
        }
        if (n->key < hi) range_walk_const(n->right, lo, hi, f, stop);
    }

    void inorder_collect(const node* n, std::vector<key_value>& out) const {
        if (!n) return;
        inorder_collect(n->left, out);
        out.push_back({n->key, n->value});
        inorder_collect(n->right, out);
    }

    node* root_{};
    std::size_t size_{};
    node_pool pool_{};
};

}  // namespace pavl
