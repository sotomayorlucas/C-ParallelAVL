// concurrent_avl<K, V> — Fase 1a: concurrent BST with Bronson-style
// optimistic descent. NO balancing yet (that comes in Fase 1b). NO
// reclamation (Fase 3). NO remove (Fase 2). NO range queries (Fase 5).
//
// Goal of this file at this point: validate the changeOVL protocol
// (versioned, validating descent + parent-lock insert) on a real
// multi-threaded benchmark under ASan/UBSan/TSan. If this part is
// clean, adding rotations on top is straightforward (only changes the
// post-insert path).
//
// Reference: Bronson, Casper, Chafi, Olukotun. "A Practical Concurrent
// Binary Search Tree." PPoPP 2010.

#pragma once

#include "common.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <utility>

namespace pavl {

namespace detail::cavl {

// ---------------------------------------------------------------------
// changeOVL encoding
// ---------------------------------------------------------------------
//
// 64-bit field:
//   bit 63        : growing  — a child slot is being filled
//   bit 62        : shrinking — node is being rotated or unlinked
//   bit 61        : unlinked — node is no longer reachable from root
//   bits  0..60   : monotonic version counter
//
// "is changing" means growing OR shrinking. Readers that observe a
// changing version must wait for it to become stable (or retry).
inline constexpr std::uint64_t ovl_growing_bit   = 1ULL << 63;
inline constexpr std::uint64_t ovl_shrinking_bit = 1ULL << 62;
inline constexpr std::uint64_t ovl_unlinked_bit  = 1ULL << 61;
inline constexpr std::uint64_t ovl_state_mask    = ovl_growing_bit
                                                 | ovl_shrinking_bit
                                                 | ovl_unlinked_bit;
inline constexpr std::uint64_t ovl_version_mask  = ~ovl_state_mask;
inline constexpr std::uint64_t ovl_version_one   = 1ULL;  // increment step

[[nodiscard]] constexpr bool ovl_is_growing(std::uint64_t v)   noexcept { return (v & ovl_growing_bit)   != 0; }
[[nodiscard]] constexpr bool ovl_is_shrinking(std::uint64_t v) noexcept { return (v & ovl_shrinking_bit) != 0; }
[[nodiscard]] constexpr bool ovl_is_changing(std::uint64_t v)  noexcept {
    return (v & (ovl_growing_bit | ovl_shrinking_bit)) != 0;
}
[[nodiscard]] constexpr bool ovl_is_unlinked(std::uint64_t v)  noexcept { return (v & ovl_unlinked_bit) != 0; }

// ---------------------------------------------------------------------
// Direction tags for child selection
// ---------------------------------------------------------------------
enum class dir : std::uint8_t { left = 0, right = 1 };

[[nodiscard]] constexpr dir other(dir d) noexcept {
    return d == dir::left ? dir::right : dir::left;
}

}  // namespace detail::cavl

// =====================================================================
// concurrent_avl<K, V>
// =====================================================================
template <avl_key Key, avl_value Value>
    requires std::default_initializable<Key> && std::default_initializable<Value>
class concurrent_avl {
public:
    using key_type   = Key;
    using value_type = Value;

private:
    using ovl_t = std::uint64_t;
    using dir   = detail::cavl::dir;

    struct node {
        Key       key;
        Value     value;

        // Children read by readers without locks. Writers store under
        // the parent lock + growing/shrinking bits to make the change
        // visible-but-marked to in-flight readers.
        std::atomic<node*> left{nullptr};
        std::atomic<node*> right{nullptr};

        // Atomic because the rebalance ascent reads it without locks
        // (only writes parent under SELF's lock during rotation).
        std::atomic<node*> parent{nullptr};

        // AVL height. Read lock-free by rebalance, written under
        // SELF's lock.
        std::atomic<std::int32_t> height{1};

        // The protocol's heart. See cavl::ovl_* helpers.
        std::atomic<ovl_t> changeOVL{0};

        // Per-node writer lock. Held during insert's child publish,
        // and during rotation on every node whose pointers change.
        std::mutex lock;

        // Sentinel constructor used by holder_ only; key/value never
        // examined for the holder (its descent never compares against it).
        node() = default;

        template <typename K, typename V>
        node(K&& k, V&& v) : key{std::forward<K>(k)}, value{std::forward<V>(v)} {}

        [[nodiscard]] std::atomic<node*>& child(dir d) noexcept {
            return d == dir::left ? left : right;
        }
        [[nodiscard]] const std::atomic<node*>& child(dir d) const noexcept {
            return d == dir::left ? left : right;
        }
    };

    // Sentinel "root holder". holder_.right is the real root of the
    // tree. holder_.left is never used. The descent always starts here,
    // with dir::right, validated against holder_.changeOVL — this is
    // the Bronson trick that lets a reader detect when a root rotation
    // moved the actual root, since holder_.changeOVL bumps whenever the
    // root's identity changes (rotation that re-roots, first insert).
    //
    // holder_.key/value are never compared with user keys; the descent
    // always goes right at the holder regardless. We do require Key and
    // Value to be default-initialisable so the holder can construct.
    mutable node holder_{};

    // Approximate size: incremented inside the parent lock on a new
    // insertion, never decremented in Fase 1a. relaxed is fine — it's
    // for stats, not synchronisation.
    std::atomic<std::size_t> size_{0};

public:
    concurrent_avl() noexcept = default;
    concurrent_avl(const concurrent_avl&) = delete;
    concurrent_avl& operator=(const concurrent_avl&) = delete;
    concurrent_avl(concurrent_avl&&) = delete;
    concurrent_avl& operator=(concurrent_avl&&) = delete;

    ~concurrent_avl() {
        destroy_subtree(holder_.right.load(std::memory_order_relaxed));
    }

    [[nodiscard]] std::size_t size() const noexcept {
        return size_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] bool empty() const noexcept { return size() == 0; }

    // Debug helpers — only valid in a quiesced (single-threaded) state.
    [[nodiscard]] std::int32_t debug_root_height() const noexcept {
        node* r = holder_.right.load(std::memory_order_acquire);
        return r ? r->height.load(std::memory_order_acquire) : 0;
    }
    [[nodiscard]] bool debug_check_avl_invariants() const noexcept {
        return debug_check_avl(holder_.right.load(std::memory_order_acquire)) >= 0;
    }
private:
    [[nodiscard]] static std::int32_t debug_check_avl(const node* n) noexcept {
        if (!n) return 0;
        const auto hl = debug_check_avl(n->left.load(std::memory_order_acquire));
        const auto hr = debug_check_avl(n->right.load(std::memory_order_acquire));
        if (hl < 0 || hr < 0) return -1;
        if (std::abs(hl - hr) > 1) return -1;
        const auto computed = 1 + std::max(hl, hr);
        if (computed != n->height.load(std::memory_order_acquire)) return -1;
        return computed;
    }
public:

    // =================================================================
    // Lookup: validating descent. No locks.
    // =================================================================
    [[nodiscard]] bool contains(const Key& key) const {
        while (true) {
            const ovl_t holder_ovl = holder_.changeOVL.load(std::memory_order_acquire);
            // The descent's first "edge" is holder_.right; the parent
            // is the holder itself and its OVL is what we just captured.
            node* root = holder_.right.load(std::memory_order_acquire);
            const auto r = attempt_get(&holder_, holder_ovl, root, key);
            if (r == status::retry) continue;
            return r == status::found;
        }
    }

    // =================================================================
    // Insert (upsert): overwrites existing value with same key.
    //
    // Fase 1a returns void (full insert_outcome / try_insert etc. land
    // in Fase 4). This entry point currently has insert_or_assign
    // semantics — used both by callers and by the eventual try_insert
    // (which will simply skip the overwrite branch).
    // =================================================================
    void insert(Key key, Value value) {
        while (true) {
            const ovl_t holder_ovl = holder_.changeOVL.load(std::memory_order_acquire);
            node* root = holder_.right.load(std::memory_order_acquire);
            const auto r = attempt_insert(&holder_, holder_ovl, root, key, value);
            if (r == status::retry) continue;
            return;
        }
    }

private:
    // attempt_get / attempt_insert return one of these.
    //   found      — for contains: key present
    //   not_found  — for contains: key absent, descent ended at a null slot
    //   inserted   — for insert: a new node was created (or value overwritten)
    //   retry      — the descent observed inconsistency; restart from root
    enum class status : std::uint8_t { found, not_found, inserted, retry };

    // -----------------------------------------------------------------
    // Lookup descent (recursive — depth bounded by tree height, which
    // in Fase 1a is unbounded if keys arrive in order; in Fase 1b we
    // get back O(log n)).
    //
    // Parameters:
    //   parent : the parent we just came from (nullptr at root)
    //   pv     : the changeOVL of parent observed BEFORE following the
    //            child link to `n`. Used to detect "parent mutated
    //            between version read and child read" — Bronson's
    //            linearisation trick.
    //   n      : the node we are currently visiting
    //   key    : search key
    // -----------------------------------------------------------------
    // Iterative Bronson descent with parent-OVL validation.
    //
    // Invariant at the top of each iteration: we reached `n` by reading
    // parent.child(d) and parent's OVL was `pv` at that read. Before
    // doing anything with `n`, we re-read parent.OVL and check it's
    // still `pv`. If it changed, the path is no longer valid (parent
    // rotated, possibly moving `n` to a different subtree) — restart
    // from root.
    //
    // For the first call from contains(), parent is nullptr; the check
    // is skipped at the entry.
    [[nodiscard]] status attempt_get(node* parent, ovl_t pv, node* n, const Key& key) const {
        while (true) {
            // Validate the (parent -> n) edge before we touch n.
            if (parent && parent->changeOVL.load(std::memory_order_acquire) != pv) {
                return status::retry;
            }
            if (!n) {
                // Empty slot reached through a still-valid parent edge.
                return status::not_found;
            }

            const ovl_t nv = n->changeOVL.load(std::memory_order_acquire);
            if (detail::cavl::ovl_is_unlinked(nv)) return status::retry;
            if (detail::cavl::ovl_is_changing(nv)) {
                std::this_thread::yield();
                continue;  // re-validate parent edge and re-read n.OVL
            }

            if (!(key < n->key) && !(n->key < key)) {
                return status::found;
            }
            const dir d = (key < n->key) ? dir::left : dir::right;

            node* c = n->child(d).load(std::memory_order_acquire);
            // Validate n's OVL after reading its child.
            if (n->changeOVL.load(std::memory_order_acquire) != nv) {
                return status::retry;
            }

            // Descend: n becomes the new parent for the next iteration.
            parent = n;
            pv = nv;
            n = c;
        }
    }

    // -----------------------------------------------------------------
    // Insert descent.
    //
    // Reaches a null child slot, then takes the parent's lock, re-
    // validates that the slot is still null, then publishes the new
    // node. If the key matches mid-descent, overwrites the value
    // under that node's lock.
    // -----------------------------------------------------------------
    // Bronson insert descent. Mirrors attempt_get's parent-OVL
    // validation: every edge we follow is validated before we trust
    // the child. The publish step takes the parent's lock and
    // re-validates parent.OVL against the captured nv2 once more,
    // to catch a rotation that happened between the descent and the
    // lock acquisition.
    [[nodiscard]] status attempt_insert(node* parent, ovl_t pv, node* n,
                                        const Key& key, Value& value) {
        // The direction we descended from `parent` to reach `n`. For the
        // first call from insert() this is dir::right (the holder always
        // sends us right). For subsequent recursive levels it's recomputed
        // from key vs parent.key.
        dir current_dir = dir::right;
        while (true) {
            // Validate the edge that brought us to n.
            if (parent->changeOVL.load(std::memory_order_acquire) != pv) {
                return status::retry;
            }
            if (!n) {
                // Slot empty along a still-valid parent edge: publish.
                node* parent_of_fresh = nullptr;
                {
                    std::scoped_lock lk{parent->lock};
                    if (parent->changeOVL.load(std::memory_order_acquire) != pv) {
                        return status::retry;
                    }
                    if (parent->child(current_dir).load(std::memory_order_relaxed) != nullptr) {
                        return status::retry;
                    }

                    const ovl_t bumped = (pv & detail::cavl::ovl_version_mask)
                                       | detail::cavl::ovl_growing_bit;
                    parent->changeOVL.store(bumped, std::memory_order_release);

                    auto* fresh = new node{Key{key}, std::move(value)};
                    fresh->parent.store(parent, std::memory_order_release);
                    parent->child(current_dir).store(fresh, std::memory_order_release);

                    const ovl_t finished = (pv + detail::cavl::ovl_version_one)
                                         & detail::cavl::ovl_version_mask;
                    parent->changeOVL.store(finished, std::memory_order_release);

                    size_.fetch_add(1, std::memory_order_relaxed);
                    parent_of_fresh = parent;
                }  // <-- parent->lock released BEFORE ascent.

                fix_heights_and_rebalance_ascent(parent_of_fresh);
                return status::inserted;
            }

            const ovl_t nv = n->changeOVL.load(std::memory_order_acquire);
            if (detail::cavl::ovl_is_unlinked(nv)) return status::retry;
            if (detail::cavl::ovl_is_changing(nv)) {
                std::this_thread::yield();
                continue;
            }

            if (!(key < n->key) && !(n->key < key)) {
                // Key match — overwrite under n's lock. Validate n's
                // OVL after taking the lock.
                std::scoped_lock lk{n->lock};
                if (n->changeOVL.load(std::memory_order_acquire) != nv) {
                    return status::retry;
                }
                n->value = std::move(value);
                return status::inserted;
            }

            const dir d = (key < n->key) ? dir::left : dir::right;
            node* c = n->child(d).load(std::memory_order_acquire);
            if (n->changeOVL.load(std::memory_order_acquire) != nv) {
                return status::retry;
            }

            // Descend.
            parent = n;
            pv = nv;
            n = c;
            current_dir = d;
        }
    }

    // -----------------------------------------------------------------
    // Rebalance ascent with single + double rotations.
    //
    // For each node along the path from `start` to the root:
    //   1. Take SELF's lock briefly. Recompute height. Read balance.
    //      Release lock.
    //   2. If |balance| > 1, decide single vs double rotation.
    //      Acquire ALL needed locks atomically via std::lock (p, n,
    //      y, and z for double rotations), validate post-lock, then
    //      do the pointer surgery + height updates under those locks.
    //
    // Lock acquisition discipline:
    //   - All multi-lock acquisitions use std::lock, which is
    //     deadlock-free for any order.
    //   - We never hold n's lock while taking another lock outside of
    //     std::lock (avoids the cross-rotation deadlock we hit earlier).
    //   - Self-locking is impossible: we always release SELF's lock
    //     before the rotation tries to re-acquire it as part of the
    //     bigger std::lock chain.
    // -----------------------------------------------------------------
    // Pending-rebalance retry loop.
    //
    // A rotation can fail validation because some prerequisite (n's
    // parent, n's child y, y's child z) moved while we dropped n's
    // own lock to acquire the multi-lock chain. The "lazy rebalance"
    // policy from Bronson's paper handles this by enqueueing the
    // pending work for later processing; we use a tighter local form:
    // retry the same node up to MAX_RETRIES with a yield between
    // attempts. If after all retries it's still unbalanced we give up
    // on this node (some other ascent will pick it up — every insert
    // does a full ascent, so any persistent imbalance gets handled).
    void fix_heights_and_rebalance_ascent(node* start) {
        constexpr int max_retries = 8;
        node* n = start;
        while (n != nullptr && n != &holder_) {
            for (int attempt = 0; attempt < max_retries; ++attempt) {
                std::int32_t bf = 0;
                {
                    std::scoped_lock nl{n->lock};
                    if (detail::cavl::ovl_is_unlinked(n->changeOVL.load(std::memory_order_acquire))) {
                        return;
                    }
                    const auto hl = height_of(n->left.load(std::memory_order_acquire));
                    const auto hr = height_of(n->right.load(std::memory_order_acquire));
                    n->height.store(1 + std::max(hl, hr), std::memory_order_release);
                    bf = hr - hl;
                }

                if (bf <= 1 && bf >= -1) break;   // balanced; advance
                const bool rotated = (bf > 1) ? try_right_heavy_rotate(n)
                                              : try_left_heavy_rotate(n);
                if (rotated) break;               // success; advance
                // Validation failed; another ascent's heights moved
                // under us. Yield and re-evaluate this node.
                std::this_thread::yield();
            }
            n = n->parent.load(std::memory_order_acquire);
        }
    }

    [[nodiscard]] static std::int32_t height_of(const node* n) noexcept {
        return n ? n->height.load(std::memory_order_acquire) : 0;
    }

    // The "parent-side" lock to use when rotating n. If n.parent is
    // nullptr, n is the real root and we use root_lock_ to synchronise
    // the assignment to root_.
    // p is always non-null now because the holder sits above every
    // real node — if n is the actual root, n.parent == &holder_.
    [[nodiscard]] std::mutex& parent_side_lock(node* parent_of_n) noexcept {
        return parent_of_n->lock;
    }

    // Right-heavy rotation entry. n is right-heavy (bf > 1). Decides
    // between single rotate_left (RR case) and double rotate_right_then_left
    // (RL case) based on y = n.right's own balance.
    // Returns true if a rotation was applied, false if validation failed
    // (some prerequisite — y, z, parent relationship — moved while we
    // dropped n's lock).  On false, the ascent retries this node.
    [[nodiscard]] bool try_right_heavy_rotate(node* n) {
        node* y = n->right.load(std::memory_order_acquire);
        if (!y) return false;
        const auto y_hl = height_of(y->left.load(std::memory_order_acquire));
        const auto y_hr = height_of(y->right.load(std::memory_order_acquire));
        const bool double_case = (y_hr - y_hl) < 0;

        node* p = n->parent.load(std::memory_order_acquire);
        std::mutex& p_lock = parent_side_lock(p);

        if (double_case) {
            node* z = y->left.load(std::memory_order_acquire);
            if (!z) return false;
            std::lock(p_lock, n->lock, y->lock, z->lock);
            std::lock_guard<std::mutex> pl{p_lock, std::adopt_lock};
            std::lock_guard<std::mutex> nl{n->lock, std::adopt_lock};
            std::lock_guard<std::mutex> yl{y->lock, std::adopt_lock};
            std::lock_guard<std::mutex> zl{z->lock, std::adopt_lock};
            if (!validate_rotation(p, n, y, true)) return false;
            if (n->right.load(std::memory_order_acquire) != y) return false;
            if (y->left.load(std::memory_order_acquire) != z)  return false;
            do_rotate_right_under_locks(n, y, z);
            node* new_y = n->right.load(std::memory_order_acquire);
            do_rotate_left_under_locks(p, n, new_y);
            return true;
        }
        std::lock(p_lock, n->lock, y->lock);
        std::lock_guard<std::mutex> pl{p_lock, std::adopt_lock};
        std::lock_guard<std::mutex> nl{n->lock, std::adopt_lock};
        std::lock_guard<std::mutex> yl{y->lock, std::adopt_lock};
        if (!validate_rotation(p, n, y, true)) return false;
        do_rotate_left_under_locks(p, n, y);
        return true;
    }

    [[nodiscard]] bool try_left_heavy_rotate(node* n) {
        node* y = n->left.load(std::memory_order_acquire);
        if (!y) return false;
        const auto y_hl = height_of(y->left.load(std::memory_order_acquire));
        const auto y_hr = height_of(y->right.load(std::memory_order_acquire));
        const bool double_case = (y_hl - y_hr) < 0;

        node* p = n->parent.load(std::memory_order_acquire);
        std::mutex& p_lock = parent_side_lock(p);

        if (double_case) {
            node* z = y->right.load(std::memory_order_acquire);
            if (!z) return false;
            std::lock(p_lock, n->lock, y->lock, z->lock);
            std::lock_guard<std::mutex> pl{p_lock, std::adopt_lock};
            std::lock_guard<std::mutex> nl{n->lock, std::adopt_lock};
            std::lock_guard<std::mutex> yl{y->lock, std::adopt_lock};
            std::lock_guard<std::mutex> zl{z->lock, std::adopt_lock};
            if (!validate_rotation(p, n, y, false)) return false;
            if (n->left.load(std::memory_order_acquire) != y)   return false;
            if (y->right.load(std::memory_order_acquire) != z)  return false;
            do_rotate_left_under_locks(n, y, z);
            node* new_y = n->left.load(std::memory_order_acquire);
            do_rotate_right_under_locks(p, n, new_y);
            return true;
        }
        std::lock(p_lock, n->lock, y->lock);
        std::lock_guard<std::mutex> pl{p_lock, std::adopt_lock};
        std::lock_guard<std::mutex> nl{n->lock, std::adopt_lock};
        std::lock_guard<std::mutex> yl{y->lock, std::adopt_lock};
        if (!validate_rotation(p, n, y, false)) return false;
        do_rotate_right_under_locks(p, n, y);
        return true;
    }

    // Post-lock validation. The triple (p, n, y) must still match the
    // tree's actual state: p must still be n's parent, y must still be
    // n's appropriate child.
    [[nodiscard]] bool validate_rotation(node* p, node* n, node* y, bool right_heavy) const noexcept {
        if (detail::cavl::ovl_is_unlinked(n->changeOVL.load(std::memory_order_acquire))) return false;
        if (detail::cavl::ovl_is_unlinked(y->changeOVL.load(std::memory_order_acquire))) return false;
        if (n->parent.load(std::memory_order_acquire) != p) return false;
        const node* expected_child = right_heavy ? n->right.load(std::memory_order_acquire)
                                                 : n->left.load(std::memory_order_acquire);
        if (expected_child != y) return false;
        return true;
    }

    // Single rotate-left under all relevant locks held by caller.
    //
    //      n                y
    //     / \              / \
    //    A   y     ->     n   C
    //       / \          / \
    //      B   C        A   B
    void do_rotate_left_under_locks(node* p, node* n, node* y) {
        node* B = y->left.load(std::memory_order_acquire);

        // ALSO mark the parent as in-flux. p's child pointer is about
        // to change; any reader that captured p.OVL while looking at
        // its old child must retry. This is especially important when
        // p is the holder — that's how readers detect "root changed".
        set_shrinking(p);
        set_shrinking(n);
        set_shrinking(y);

        y->left.store(n, std::memory_order_release);
        n->right.store(B, std::memory_order_release);
        if (B) B->parent.store(n, std::memory_order_release);

        if (p->left.load(std::memory_order_acquire) == n) {
            p->left.store(y, std::memory_order_release);
        } else {
            p->right.store(y, std::memory_order_release);
        }
        y->parent.store(p, std::memory_order_release);
        n->parent.store(y, std::memory_order_release);

        n->height.store(1 + std::max(height_of(n->left.load(std::memory_order_acquire)),
                                     height_of(n->right.load(std::memory_order_acquire))),
                        std::memory_order_release);
        y->height.store(1 + std::max(height_of(y->left.load(std::memory_order_acquire)),
                                     height_of(y->right.load(std::memory_order_acquire))),
                        std::memory_order_release);

        clear_shrinking(n);
        clear_shrinking(y);
        clear_shrinking(p);
    }

    // Mirror of rotate_left.
    void do_rotate_right_under_locks(node* p, node* n, node* y) {
        node* B = y->right.load(std::memory_order_acquire);

        set_shrinking(p);
        set_shrinking(n);
        set_shrinking(y);

        y->right.store(n, std::memory_order_release);
        n->left.store(B, std::memory_order_release);
        if (B) B->parent.store(n, std::memory_order_release);

        if (p->left.load(std::memory_order_acquire) == n) {
            p->left.store(y, std::memory_order_release);
        } else {
            p->right.store(y, std::memory_order_release);
        }
        y->parent.store(p, std::memory_order_release);
        n->parent.store(y, std::memory_order_release);

        n->height.store(1 + std::max(height_of(n->left.load(std::memory_order_acquire)),
                                     height_of(n->right.load(std::memory_order_acquire))),
                        std::memory_order_release);
        y->height.store(1 + std::max(height_of(y->left.load(std::memory_order_acquire)),
                                     height_of(y->right.load(std::memory_order_acquire))),
                        std::memory_order_release);

        clear_shrinking(n);
        clear_shrinking(y);
        clear_shrinking(p);
    }

    static void set_shrinking(node* n) noexcept {
        const ovl_t cur = n->changeOVL.load(std::memory_order_acquire);
        n->changeOVL.store((cur & detail::cavl::ovl_version_mask)
                              | detail::cavl::ovl_shrinking_bit,
                           std::memory_order_release);
    }
    static void clear_shrinking(node* n) noexcept {
        const ovl_t cur = n->changeOVL.load(std::memory_order_acquire);
        n->changeOVL.store(((cur & detail::cavl::ovl_version_mask)
                            + detail::cavl::ovl_version_one)
                           & detail::cavl::ovl_version_mask,
                           std::memory_order_release);
    }

    // -----------------------------------------------------------------
    // First-insert path: root is null, install the new node as root.
    // Returns true if we won the race, false if we lost it (and the
    // caller should retry the regular insert path).
    // -----------------------------------------------------------------
    // try_install_root removed: the first insert publishes under
    // holder_ via the regular attempt_insert path.

    // -----------------------------------------------------------------
    // Destructor helper. Single-threaded post-conditions assumed.
    // -----------------------------------------------------------------
    void destroy_subtree(node* n) noexcept {
        if (!n) return;
        destroy_subtree(n->left.load(std::memory_order_relaxed));
        destroy_subtree(n->right.load(std::memory_order_relaxed));
        delete n;
    }
};

}  // namespace pavl
