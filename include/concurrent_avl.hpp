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
class concurrent_avl {
public:
    using key_type   = Key;
    using value_type = Value;

private:
    using ovl_t = std::uint64_t;
    using dir   = detail::cavl::dir;

    struct node {
        const Key key;
        Value     value;

        // Children read by readers without locks. Writers store under
        // the parent lock + growing/shrinking bits to make the change
        // visible-but-marked to in-flight readers.
        std::atomic<node*> left{nullptr};
        std::atomic<node*> right{nullptr};

        // Parent only used by writers (rotations, eventually). For
        // Fase 1a it's just informational — readers don't follow it.
        node* parent{nullptr};

        // Used by Fase 1b for AVL balance. Initialised to 1 (leaf).
        std::int32_t height{1};

        // The protocol's heart. See cavl::ovl_* helpers.
        std::atomic<ovl_t> changeOVL{0};

        // Per-node writer lock. Held only on the parent during insert,
        // and (in later phases) on the nodes involved in a rotation.
        std::mutex lock;

        template <typename K, typename V>
        node(K&& k, V&& v) : key{std::forward<K>(k)}, value{std::forward<V>(v)} {}

        [[nodiscard]] std::atomic<node*>& child(dir d) noexcept {
            return d == dir::left ? left : right;
        }
        [[nodiscard]] const std::atomic<node*>& child(dir d) const noexcept {
            return d == dir::left ? left : right;
        }
    };

    // Root pointer. Initially nullptr; on first insert the new node
    // becomes root atomically under root_lock_.
    std::atomic<node*> root_{nullptr};
    std::mutex         root_lock_;

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
        // Single-threaded teardown — caller is responsible for ensuring
        // no readers are still alive. EBR (Fase 3) will lift this.
        destroy_subtree(root_.load(std::memory_order_relaxed));
    }

    [[nodiscard]] std::size_t size() const noexcept {
        return size_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] bool empty() const noexcept { return size() == 0; }

    // =================================================================
    // Lookup: validating descent. No locks.
    // =================================================================
    [[nodiscard]] bool contains(const Key& key) const {
        while (true) {  // outer retry: root changes are rare but possible
            node* root = root_.load(std::memory_order_acquire);
            if (!root) return false;
            const auto r = attempt_get(nullptr, 0, root, key);
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
            node* root = root_.load(std::memory_order_acquire);
            if (!root) {
                if (try_install_root(std::move(key), std::move(value))) return;
                // Lost the race; retry from root.
                continue;
            }
            const auto r = attempt_insert(root, key, value);
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
    [[nodiscard]] status attempt_get(node* parent, ovl_t pv, node* n, const Key& key) const {
        while (true) {
            // 1. Read this node's version up-front. We'll re-check it
            //    later to validate the child we follow.
            const ovl_t nv = n->changeOVL.load(std::memory_order_acquire);
            if (detail::cavl::ovl_is_unlinked(nv)) {
                // Someone unlinked us mid-traversal. Bail to outer retry.
                return status::retry;
            }
            // If a write is in progress on n we don't know whether the
            // child slot we want is stable. Wait briefly and retry.
            if (detail::cavl::ovl_is_changing(nv)) {
                std::this_thread::yield();
                continue;
            }

            // 2. Compare and decide direction.
            if (!(key < n->key) && !(n->key < key)) {
                // Key match. The match itself doesn't depend on
                // pointer state — n->key is immutable after
                // construction — so we can return without rechecking
                // versions. (Validation of the value's presence
                // becomes relevant in Fase 2 for partially-external
                // routing nodes.)
                return status::found;
            }
            const dir d = (key < n->key) ? dir::left : dir::right;

            // 3. Follow the child link. Re-validate n's version after
            //    the load: if it changed, n was modified and the
            //    child we read may have been a transient value.
            node* c = n->child(d).load(std::memory_order_acquire);
            const ovl_t nv2 = n->changeOVL.load(std::memory_order_acquire);
            if (nv2 != nv) {
                // n changed underneath us — restart at n.
                continue;
            }

            // 4. If parent != null, also validate that parent hasn't
            //    rotated us away. We don't actually need to chase
            //    parents here in Fase 1a (no rotations), but the hook
            //    is in place so Fase 1b can use it.
            //    (For now `pv` is informational.)
            (void)parent; (void)pv;

            if (!c) {
                // Empty slot — key is absent. But if n's version had
                // any in-flight modification when we last looked, we
                // couldn't have gotten here (the changing check above
                // already deflected us). So this answer is stable.
                return status::not_found;
            }

            // 5. Recurse into c. (Tail call effectively.)
            n = c;
            parent = n;        // would be `n` from caller's frame, but
                               // attempt_get is iterative so we just
                               // advance and reuse the locals.
            pv = nv;
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
    [[nodiscard]] status attempt_insert(node* n, const Key& key, Value& value) {
        while (true) {
            const ovl_t nv = n->changeOVL.load(std::memory_order_acquire);
            if (detail::cavl::ovl_is_unlinked(nv)) return status::retry;
            if (detail::cavl::ovl_is_changing(nv)) {
                std::this_thread::yield();
                continue;
            }

            if (!(key < n->key) && !(n->key < key)) {
                // Key match — update value under n's lock.
                std::scoped_lock lk{n->lock};
                // Validate that n is still alive after taking the lock.
                if (detail::cavl::ovl_is_unlinked(n->changeOVL.load(std::memory_order_acquire))) {
                    return status::retry;
                }
                n->value = std::move(value);
                return status::inserted;
            }

            const dir d = (key < n->key) ? dir::left : dir::right;
            node* c = n->child(d).load(std::memory_order_acquire);
            const ovl_t nv2 = n->changeOVL.load(std::memory_order_acquire);
            if (nv2 != nv) continue;  // n moved underneath us, retry at n

            if (c) {
                n = c;
                continue;
            }

            // Slot is empty — try to install a new child here. Take
            // n's lock and re-check the slot.
            std::scoped_lock lk{n->lock};
            if (detail::cavl::ovl_is_unlinked(n->changeOVL.load(std::memory_order_acquire))) {
                return status::retry;
            }
            if (n->child(d).load(std::memory_order_relaxed) != nullptr) {
                // Someone else inserted into the same slot first. The
                // child must be re-descended into.
                continue;
            }

            // Mark n as growing so concurrent readers know to wait
            // before trusting the new child link.
            const ovl_t bumped = (nv2 & detail::cavl::ovl_version_mask)
                               | detail::cavl::ovl_growing_bit;
            n->changeOVL.store(bumped, std::memory_order_release);

            auto* fresh = new node{std::move(key), std::move(value)};
            fresh->parent = n;
            n->child(d).store(fresh, std::memory_order_release);

            // Clear growing, bump version. Readers that saw growing
            // will retry and now see the new child.
            const ovl_t finished = (nv2 + detail::cavl::ovl_version_one)
                                 & detail::cavl::ovl_version_mask;
            n->changeOVL.store(finished, std::memory_order_release);

            size_.fetch_add(1, std::memory_order_relaxed);
            return status::inserted;
        }
    }

    // -----------------------------------------------------------------
    // First-insert path: root is null, install the new node as root.
    // Returns true if we won the race, false if we lost it (and the
    // caller should retry the regular insert path).
    // -----------------------------------------------------------------
    [[nodiscard]] bool try_install_root(Key key, Value value) {
        std::scoped_lock lk{root_lock_};
        if (root_.load(std::memory_order_relaxed) != nullptr) return false;
        auto* fresh = new node{std::move(key), std::move(value)};
        root_.store(fresh, std::memory_order_release);
        size_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

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
