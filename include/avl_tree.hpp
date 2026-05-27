#pragma once

#include "common.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
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

    // Returned by try_insert / insert_or_assign / try_emplace.
    struct insert_result {
        Value* value_ptr;    // pointer to the stored value (existing or new)
        bool   inserted;     // true if a new node was created
    };

private:
    static constexpr std::size_t pool_block_size = 256;

    // The pool keeps a single linked list of free slots through raw bytes:
    // each freed slot's first sizeof(void*) bytes hold a pointer to the next
    // free slot. Slots are constructed (placement-new) on acquire and
    // destroyed (std::destroy_at) on release, so the byte-pointer trick only
    // ever runs over storage that is NOT alive as a `node`. This avoids the
    // lifetime UB of writing through a non-constructed union member.
    struct node_block {
        alignas(node) std::byte data[sizeof(node) * pool_block_size];
        node_block* next{nullptr};
    };

    static constexpr std::size_t slot_stride = sizeof(node);

    [[nodiscard]] static std::byte* slot_at(node_block* b, std::size_t i) noexcept {
        return b->data + i * slot_stride;
    }

    [[nodiscard]] static std::byte* free_list_link(std::byte* slot) noexcept {
        // The first sizeof(void*) bytes of a free slot store the next pointer.
        return slot;
    }

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

        // Returns raw storage for one node. The caller must construct
        // key/value/etc with std::construct_at (or assignment for trivial
        // types) before reading any field.
        [[nodiscard]] PAVL_ALWAYS_INLINE std::byte* acquire_raw_storage() {
            if (free_list_) [[likely]] {
                std::byte* slot = free_list_;
                std::byte* next;
                std::memcpy(&next, free_list_link(slot), sizeof(next));
                free_list_ = next;
                return slot;
            }
            auto* block = new (std::nothrow) node_block{};
            if (!block) [[unlikely]] return nullptr;
            block->next = blocks_;
            blocks_ = block;
            // Build the free list: slots [1..N-1] form the new free list,
            // slot 0 will be handed back to the caller. All writes go to
            // raw bytes — no node has begun its lifetime yet.
            for (std::size_t i = 1; i < pool_block_size - 1; ++i) {
                std::byte* cur  = slot_at(block, i);
                std::byte* next = slot_at(block, i + 1);
                std::memcpy(free_list_link(cur), &next, sizeof(next));
            }
            std::byte* last = slot_at(block, pool_block_size - 1);
            std::memcpy(free_list_link(last), &free_list_, sizeof(free_list_));
            free_list_ = slot_at(block, 1);
            total_ += pool_block_size;
            return slot_at(block, 0);
        }

        // Returns a previously-acquired (and now destroyed) slot to the
        // free list. The caller is responsible for std::destroy_at-ing the
        // node before calling this — after that the storage is raw bytes
        // and we can freely write the free-list link.
        PAVL_ALWAYS_INLINE void release_raw_storage(std::byte* slot) noexcept {
            std::memcpy(free_list_link(slot), &free_list_, sizeof(free_list_));
            free_list_ = slot;
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
        std::byte*  free_list_{};
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

    // insert(): always present after the call; overwrites if the key existed.
    PAVL_HOT void insert(Key key, Value value) {
        (void)insert_or_assign(std::move(key), std::move(value));
    }

    // insert_or_assign(): tells the caller whether it was a new insertion
    // or an overwrite. Returns a pointer to the stored value.
    insert_result insert_or_assign(Key key, Value value) {
        const auto loc = locate(key);
        if (loc.found) {
            loc.found->value = std::move(value);
            return {&loc.found->value, false};
        }
        node* nn = construct_node(std::move(key), std::move(value), loc.parent);
        if (!nn) [[unlikely]] return {nullptr, false};
        link_new(nn, loc.parent, loc.attach_to_left);
        return {&nn->value, true};
    }

    // try_insert(): no-op if the key already exists.
    insert_result try_insert(Key key, Value value) {
        const auto loc = locate(key);
        if (loc.found) {
            return {&loc.found->value, false};
        }
        node* nn = construct_node(std::move(key), std::move(value), loc.parent);
        if (!nn) [[unlikely]] return {nullptr, false};
        link_new(nn, loc.parent, loc.attach_to_left);
        return {&nn->value, true};
    }

    // try_emplace(): construct Value in place from args if key absent.
    template <typename... Args>
    insert_result try_emplace(Key key, Args&&... args) {
        const auto loc = locate(key);
        if (loc.found) {
            return {&loc.found->value, false};
        }
        node* nn = construct_node(std::move(key), std::forward<Args>(args)...);
        if (!nn) [[unlikely]] return {nullptr, false};
        nn->parent = loc.parent;
        link_new(nn, loc.parent, loc.attach_to_left);
        return {&nn->value, true};
    }

    // Heterogeneous remove: any K' that is order-comparable with Key.
    template <typename K>
        requires order_comparable_with<Key, K>
    PAVL_HOT bool remove(const K& key) {
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
        destroy_node(n);
        --size_;
        if (rebalance_start) rebalance_from(rebalance_start);
        return true;
    }

    template <typename K>
        requires order_comparable_with<Key, K>
    [[nodiscard]] PAVL_HOT bool contains(const K& key) const noexcept {
        return find_node(root_, key) != nullptr;
    }

    template <typename K>
        requires order_comparable_with<Key, K>
    [[nodiscard]] PAVL_HOT Value* find(const K& key) noexcept {
        node* n = find_node(root_, key);
        return n ? &n->value : nullptr;
    }

    template <typename K>
        requires order_comparable_with<Key, K>
    [[nodiscard]] PAVL_HOT const Value* find(const K& key) const noexcept {
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

    template <typename K>
        requires order_comparable_with<Key, K>
    [[nodiscard]] PAVL_HOT static node* find_node(node* root, const K& key) noexcept {
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

    template <typename K>
        requires order_comparable_with<Key, K>
    [[nodiscard]] PAVL_HOT static const node* find_node(const node* root, const K& key) noexcept {
        const node* cur = root;
        while (cur) [[likely]] {
            if (key < cur->key) cur = cur->left;
            else if (cur->key < key) cur = cur->right;
            else return cur;
        }
        return nullptr;
    }

    // Locate where a key would be inserted. If found, returns the existing
    // node and ignores attach_to_left. If not found, returns the parent
    // under which the new node should be linked, and which side.
    struct locate_result {
        node* found;           // nullptr if absent
        node* parent;          // parent of the slot where it would go
        bool  attach_to_left;  // valid only when found == nullptr
    };

    template <typename K>
        requires order_comparable_with<Key, K>
    [[nodiscard]] locate_result locate(const K& key) {
        node* parent = nullptr;
        node* cur = root_;
        bool left = false;
        while (cur) {
            if (key < cur->key) {
                parent = cur; cur = cur->left;  left = true;
            } else if (cur->key < key) {
                parent = cur; cur = cur->right; left = false;
            } else {
                return {cur, parent, false};
            }
        }
        return {nullptr, parent, left};
    }

    // Link a freshly-constructed node into the tree under `parent`,
    // rebalancing on the way up.
    void link_new(node* nn, node* parent, bool attach_to_left) noexcept {
        nn->parent = parent;
        if (!parent) {
            root_ = nn;
        } else if (attach_to_left) {
            parent->left = nn;
        } else {
            parent->right = nn;
        }
        ++size_;
        rebalance_from(nn);
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
        // Subtree destruction does NOT recycle slots back to the pool —
        // the caller (clear() / dtor) releases the whole block list right
        // after this returns. Destroying subobjects is enough to run user
        // destructors; the raw storage goes away with the block.
        std::destroy_at(&n->value);
        std::destroy_at(&n->key);
    }

    // Acquire raw storage from the pool and begin lifetimes of the node
    // subobjects. Returns nullptr if the pool can't grow.
    template <typename K, typename... ValueArgs>
    [[nodiscard]] node* construct_node(K&& k, ValueArgs&&... value_args)
        noexcept(std::is_nothrow_constructible_v<Key, K&&>
              && std::is_nothrow_constructible_v<Value, ValueArgs&&...>)
    {
        std::byte* storage = pool_.acquire_raw_storage();
        if (!storage) [[unlikely]] return nullptr;
        node* n = std::launder(reinterpret_cast<node*>(storage));
        std::construct_at(&n->key,   std::forward<K>(k));
        std::construct_at(&n->value, std::forward<ValueArgs>(value_args)...);
        n->left = nullptr;
        n->right = nullptr;
        n->parent = nullptr;
        n->height = 1;
        return n;
    }

    // Variant that also stores the parent pointer (avoids one extra write
    // at the caller). Used on the insert() hot path.
    template <typename K, typename V>
    [[nodiscard]] node* construct_node(K&& k, V&& v, node* parent)
        noexcept(std::is_nothrow_constructible_v<Key, K&&>
              && std::is_nothrow_constructible_v<Value, V&&>)
    {
        node* n = construct_node(std::forward<K>(k), std::forward<V>(v));
        if (n) n->parent = parent;
        return n;
    }

    // End lifetimes of the node subobjects and return the raw storage to
    // the pool. The slot becomes available for the next acquire.
    PAVL_ALWAYS_INLINE void destroy_node(node* n) noexcept {
        std::destroy_at(&n->value);
        std::destroy_at(&n->key);
        pool_.release_raw_storage(reinterpret_cast<std::byte*>(n));
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
