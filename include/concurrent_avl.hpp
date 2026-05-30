// concurrent_avl<K, V> — Bronson-style concurrent AVL.
//
// Optimistic, validating descent (changeOVL versioning). Per-node locks
// only for the writer path (insert publish + rotation surgery + remove
// mark / physical unlink). Readers are lock-free except for an in-lock
// value copy in get().
//
// Pieces:
//   Fase 1a — validating descent + per-node locked insert (no rotation)
//   Fase 1b — concurrent AVL rotations under std::lock chains
//   Fase 2a — logical remove via routing nodes
//   Fase 2b — physical unlink for 0/1-child routing nodes
//   Fase 3  — epoch-based reclamation (EBR) for unlinked nodes
//   Fase 4  — insert_or_assign / try_insert / try_emplace / get API
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
#include <vector>

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

namespace detail::cavl {

// =====================================================================
// Epoch-based reclamation (EBR)
// =====================================================================
//
// A single process-global domain shared by all concurrent_avl trees.
// Type-erased: retire() takes a pointer + a deleter, so the domain
// doesn't need to know the node type.
//
// Protocol (quiescent-state, 2-epoch grace period):
//
//   - global_epoch_ monotonically increases.
//   - Each thread that ever enters a critical section registers a
//     `participant` (lazily, via thread_local). Participants are
//     never unregistered — a bounded leak of one cache-line per
//     thread for the life of the process, which is the standard
//     simplification and avoids the thread-death teardown race.
//   - A `guard` announces the thread's local epoch on construction
//     (local_epoch = global_epoch) and clears it on destruction
//     (local_epoch = quiescent). While quiescent a thread holds no
//     references into the tree, so anything retired before it went
//     quiescent is safe to free w.r.t. that thread.
//   - retire(p, deleter) stamps p with the current global epoch and
//     puts it in a limbo list. Every so often we try to advance the
//     epoch: if every registered participant is either quiescent or
//     already at global_epoch, we bump global_epoch and free
//     everything stamped <= new_epoch - 2.
//
// Why 2 epochs: a node retired in epoch E might still be referenced
// by a thread that entered its critical section in epoch E. That
// thread will exit and re-enter; by the time global_epoch reaches
// E+2, every thread has gone quiescent at least once since E, so no
// live reference to the node can remain.
class ebr {
private:
    static constexpr std::uint64_t reclaim_interval = 64;

    struct retired {
        void* ptr;
        void (*deleter)(void*);
        std::uint64_t epoch;
    };

    struct alignas(cache_line_size) participant {
        std::atomic<std::uint64_t> local_epoch{0};  // 0 == quiescent
        std::uint64_t depth{0};               // guard nesting (thread-local)
        std::uint64_t retire_count{0};        // reclaim throttling
        std::vector<retired> limbo;
        participant* next{nullptr};
    };

    std::atomic<std::uint64_t> global_epoch_{1};
    std::atomic<participant*>  head_{nullptr};
    std::mutex                 registry_mutex_;

    ebr() = default;
    ~ebr() {
        participant* p = head_.load(std::memory_order_acquire);
        while (p) {
            for (auto& r : p->limbo) r.deleter(r.ptr);
            participant* next = p->next;
            delete p;
            p = next;
        }
    }
    ebr(const ebr&) = delete;
    ebr& operator=(const ebr&) = delete;

    [[nodiscard]] participant& local_participant() {
        thread_local participant* mine = register_participant();
        return *mine;
    }

    [[nodiscard]] participant* register_participant() {
        auto* p = new participant{};
        std::scoped_lock lk{registry_mutex_};
        p->next = head_.load(std::memory_order_relaxed);
        head_.store(p, std::memory_order_release);
        return p;
    }

    void try_advance_and_reclaim(participant& self) {
        const auto cur = global_epoch_.load(std::memory_order_acquire);
        bool can_advance = true;
        {
            std::scoped_lock lk{registry_mutex_};
            for (participant* p = head_.load(std::memory_order_acquire);
                 p != nullptr; p = p->next) {
                const auto e = p->local_epoch.load(std::memory_order_acquire);
                if (e != 0 && e != cur) { can_advance = false; break; }
            }
        }
        if (can_advance) {
            std::uint64_t expected = cur;
            global_epoch_.compare_exchange_strong(expected, cur + 1,
                                                   std::memory_order_acq_rel);
        }
        // Reclaim from THIS thread's limbo: anything stamped at epoch
        // <= global_epoch_ - 2 is safe (every thread has gone
        // quiescent at least once since then).
        const auto safe = global_epoch_.load(std::memory_order_acquire);
        auto& limbo = self.limbo;
        std::size_t kept = 0;
        for (std::size_t i = 0; i < limbo.size(); ++i) {
            if (limbo[i].epoch + 2 <= safe) {
                limbo[i].deleter(limbo[i].ptr);
            } else {
                limbo[kept++] = limbo[i];
            }
        }
        limbo.resize(kept);
    }

public:
    static constexpr std::uint64_t quiescent = 0;

    [[nodiscard]] static ebr& instance() {
        static ebr e;
        return e;
    }

    // RAII critical-section guard. Announces the thread's epoch on
    // entry, returns it to quiescent on exit. Re-entrant via a
    // per-thread depth counter.
    class guard {
    public:
        guard() : self_{instance().local_participant()} {
            if (self_.depth++ == 0) {
                self_.local_epoch.store(
                    instance().global_epoch_.load(std::memory_order_acquire),
                    std::memory_order_release);
                std::atomic_thread_fence(std::memory_order_seq_cst);
            }
        }
        ~guard() {
            if (--self_.depth == 0) {
                self_.local_epoch.store(quiescent, std::memory_order_release);
            }
        }
        guard(const guard&) = delete;
        guard& operator=(const guard&) = delete;
    private:
        participant& self_;
    };

    void retire(void* p, void (*deleter)(void*)) {
        auto& self = local_participant();
        const auto e = global_epoch_.load(std::memory_order_acquire);
        self.limbo.push_back({p, deleter, e});
        if (++self.retire_count % reclaim_interval == 0) {
            try_advance_and_reclaim(self);
        }
    }

    // Drain every limbo list NOW. Only safe when no thread is inside
    // a critical section (e.g. process teardown). Not used in the
    // normal path; kept for completeness / test harnesses.
    void drain_all() {
        std::scoped_lock lk{registry_mutex_};
        for (participant* p = head_.load(std::memory_order_acquire);
             p != nullptr; p = p->next) {
            for (auto& r : p->limbo) r.deleter(r.ptr);
            p->limbo.clear();
        }
    }
};

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

        // Pending-rebalance flag. Set by an ascent that detected an
        // imbalance on this node but couldn't apply the rotation
        // (validation lost the race with another ascent). Cleared by
        // the next operation that successfully rebalances this node.
        // Concurrent inserts pick up pendings on descent (see
        // attempt_insert) so off-path imbalances don't linger past
        // the next operation that traverses the area.
        std::atomic<bool> needs_rebalance{false};

        // Bronson's "partially-external" deletion mark. A node with
        // two children that's logically removed stays in the tree as
        // a routing-only node (key preserved for BST descent, value
        // absent). Lookups that land on a routing node return not
        // found; inserts that match a routing node's key REACTIVATE
        // it instead of allocating a new node.
        std::atomic<bool> is_routing{false};

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

    // EBR deleter for retired nodes (type-erased entry point for the
    // global epoch domain).
    static void reclaim_node(void* p) noexcept {
        delete static_cast<node*>(p);
    }

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
        detail::cavl::ebr::guard g;
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
    // Same as insert_or_assign — kept under both names for callers and
    // for std::map API parity.
    // =================================================================
    void insert(Key key, Value value) {
        (void)do_insert<insert_policy::overwrite>(std::move(key), std::move(value));
    }

    // Explicit std::map-style alias for the overwrite semantics.
    void insert_or_assign(Key key, Value value) {
        (void)do_insert<insert_policy::overwrite>(std::move(key), std::move(value));
    }

    // Insert only if absent. Returns true if a new live entry was
    // created (which includes reactivation of a routing node left
    // behind by a prior remove), false if the key was already present
    // with a live value (the supplied value is then discarded, not
    // assigned). Mirrors std::map::try_emplace's return convention.
    [[nodiscard]] bool try_insert(Key key, Value value) {
        return do_insert<insert_policy::only_if_absent>(std::move(key), std::move(value));
    }

    // try_emplace: construct Value in place from Args once, then
    // try_insert. If the key was already present, the constructed
    // value is moved-into the function and destroyed on return —
    // identical lifetime to passing Value(args...) directly to
    // try_insert. (We construct upfront rather than deferring to the
    // publish point because under concurrent retries a one-shot
    // factory is fragile; the cost of one extra construction on a
    // collision is the price for code that's clearly correct.)
    template <class... Args>
    [[nodiscard]] bool try_emplace(Key key, Args&&... args) {
        Value v(std::forward<Args>(args)...);
        return do_insert<insert_policy::only_if_absent>(std::move(key), std::move(v));
    }

    // Get a snapshot copy of the value associated with `key`.
    // Returns std::nullopt if the key is absent or maps to a routing
    // (logically removed) node. The copy is taken under the matched
    // node's lock to serialise against a concurrent overwrite of
    // n->value — without the lock the read could tear for non-trivial
    // Value types (e.g. std::string).
    [[nodiscard]] std::optional<Value> get(const Key& key) const {
        detail::cavl::ebr::guard g;
        while (true) {
            const ovl_t holder_ovl = holder_.changeOVL.load(std::memory_order_acquire);
            node* root = holder_.right.load(std::memory_order_acquire);
            std::optional<Value> out;
            const auto r = attempt_get_value(&holder_, holder_ovl, root, key, out);
            if (r == status::retry) continue;
            return out;
        }
    }

    // Logically remove `key` from the tree. Returns true if a live
    // node was found and turned into a routing node (or unlinked, in
    // the 0/1-child case once Fase 2b lands). Returns false if the
    // key was already absent or already routing.
    //
    // Fase 2a: marks the matched node as routing (is_routing = true)
    // and decrements size. The node stays in the BST structure so
    // future inserts of the same key can reactivate it cheaply.
    // Fase 2b will add the physical unlink path for nodes with 0/1
    // children, restoring O(log n) memory.
    bool remove(const Key& key) {
        detail::cavl::ebr::guard g;
        while (true) {
            const ovl_t holder_ovl = holder_.changeOVL.load(std::memory_order_acquire);
            node* root = holder_.right.load(std::memory_order_acquire);
            const auto r = attempt_remove(&holder_, holder_ovl, root, key);
            if (r == status::retry) continue;
            return r == status::removed;
        }
    }

private:
    // attempt_get / attempt_insert / attempt_remove return one of these.
    //   found        — for contains: key present
    //   not_found    — for contains: key absent, descent ended at a null slot
    //   inserted     — for insert: a new live entry was created (or assigned)
    //   not_inserted — for try_insert: key was already live, no change
    //   removed      — for remove: a live entry was demoted to routing
    //   retry        — the descent observed inconsistency; restart from root
    enum class status : std::uint8_t {
        found, not_found, inserted, not_inserted, removed, retry
    };

    // insert dispatch policy:
    //   overwrite      — assign on key match (insert / insert_or_assign)
    //   only_if_absent — leave value untouched on key match; only act if
    //                    the matched node is a routing node (reactivate)
    //                    or the descent reaches an empty slot
    enum class insert_policy : std::uint8_t { overwrite, only_if_absent };

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
                // Match on the node's key. If it has been logically
                // removed (routing node), the key is absent from the
                // tree's value-set even though the node is still in
                // the structure. is_routing is monotonic within a
                // node's life — once set, it stays set until an
                // insert reactivates it under n's lock — so an
                // acquire-load here pairs with the release-store in
                // remove() / the reactivation store in attempt_insert.
                if (n->is_routing.load(std::memory_order_acquire)) {
                    return status::not_found;
                }
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

    // attempt_get's twin for get(): same validating descent, but on
    // key match takes n's lock briefly to copy the value out before
    // returning. The lock guards against a concurrent overwrite of
    // n->value tearing a non-trivial type mid-read.
    [[nodiscard]] status attempt_get_value(node* parent, ovl_t pv, node* n,
                                            const Key& key,
                                            std::optional<Value>& out) const {
        while (true) {
            if (parent && parent->changeOVL.load(std::memory_order_acquire) != pv) {
                return status::retry;
            }
            if (!n) return status::not_found;

            const ovl_t nv = n->changeOVL.load(std::memory_order_acquire);
            if (detail::cavl::ovl_is_unlinked(nv)) return status::retry;
            if (detail::cavl::ovl_is_changing(nv)) {
                std::this_thread::yield();
                continue;
            }

            if (!(key < n->key) && !(n->key < key)) {
                std::scoped_lock lk{n->lock};
                if (n->changeOVL.load(std::memory_order_acquire) != nv) {
                    return status::retry;
                }
                if (n->is_routing.load(std::memory_order_acquire)) {
                    return status::not_found;
                }
                out.emplace(n->value);
                return status::found;
            }
            const dir d = (key < n->key) ? dir::left : dir::right;

            node* c = n->child(d).load(std::memory_order_acquire);
            if (n->changeOVL.load(std::memory_order_acquire) != nv) {
                return status::retry;
            }
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
    // Common entry point for all four insert flavours. Loops over
    // attempt_insert until a non-retry status is returned, then maps
    // it to "did we add a new live entry?" for the try_* callers.
    template <insert_policy Policy>
    bool do_insert(Key key, Value value) {
        detail::cavl::ebr::guard g;
        while (true) {
            const ovl_t holder_ovl = holder_.changeOVL.load(std::memory_order_acquire);
            node* root = holder_.right.load(std::memory_order_acquire);
            const auto r = attempt_insert<Policy>(&holder_, holder_ovl, root, key, value);
            if (r == status::retry) continue;
            return r == status::inserted;
        }
    }

    // Bronson insert descent. Mirrors attempt_get's parent-OVL
    // validation: every edge we follow is validated before we trust
    // the child. The publish step takes the parent's lock and
    // re-validates parent.OVL against the captured nv2 once more,
    // to catch a rotation that happened between the descent and the
    // lock acquisition.
    //
    // Policy controls the key-match branch: overwrite always assigns;
    // only_if_absent only acts when the matched node is routing
    // (reactivation counts as inserting a new live key).
    template <insert_policy Policy>
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
                // Key match. Two sub-cases:
                //   (a) n is a routing node (logically removed by a
                //       prior remove()): REACTIVATE it under both
                //       policies — the user is adding a key that's
                //       not in the live set.
                //   (b) n is live:
                //         overwrite     — assign value, size unchanged
                //         only_if_absent — leave alone, return not_inserted
                std::scoped_lock lk{n->lock};
                if (n->changeOVL.load(std::memory_order_acquire) != nv) {
                    return status::retry;
                }
                const bool routing = n->is_routing.load(std::memory_order_acquire);
                if (routing) {
                    n->value = std::move(value);
                    n->is_routing.store(false, std::memory_order_release);
                    size_.fetch_add(1, std::memory_order_relaxed);
                    return status::inserted;
                }
                if constexpr (Policy == insert_policy::overwrite) {
                    n->value = std::move(value);
                    return status::inserted;
                } else {
                    return status::not_inserted;
                }
            }

            const dir d = (key < n->key) ? dir::left : dir::right;
            node* c = n->child(d).load(std::memory_order_acquire);
            if (n->changeOVL.load(std::memory_order_acquire) != nv) {
                return status::retry;
            }

            // Opportunistic pending-rebalance pickup. If n has been
            // flagged by a prior ascent that couldn't finish its
            // rotation, process it before continuing the descent.
            // Only retry from root if the processing actually rotated
            // n (in which case our descent's `c` is stale). If the
            // flag was already stale or the rebalance couldn't
            // converge, continue the descent we already validated
            // above — retrying unconditionally would livelock pure
            // read/skip operations (e.g. try_insert hitting a live
            // key) that never run their own ascent to clear the flag.
            if (n->needs_rebalance.load(std::memory_order_acquire)) {
                if (process_pending_if_set(n) == pending_result::rotated) {
                    return status::retry;
                }
            }

            // Descend.
            parent = n;
            pv = nv;
            n = c;
            current_dir = d;
        }
    }

    // -----------------------------------------------------------------
    // Logical remove (Fase 2a).
    //
    // Same Bronson-style validating descent as attempt_get; when it
    // reaches the matching node, takes that node's lock and marks
    // it as routing (is_routing = true). If the node was already
    // routing or absent, returns not_found.
    //
    // Fase 2b will add the physical unlink path: when the routing
    // node has 0 or 1 children, it can be unlinked from the tree
    // (under parent + node + maybe-child locks) and recycled later
    // via EBR. For now everything stays in the tree; concurrent
    // re-insert of the same key reactivates the routing node
    // cheaply (see attempt_insert).
    // -----------------------------------------------------------------
    [[nodiscard]] status attempt_remove(node* parent, ovl_t pv, node* n,
                                        const Key& key) {
        while (true) {
            if (parent->changeOVL.load(std::memory_order_acquire) != pv) {
                return status::retry;
            }
            if (!n) return status::not_found;

            const ovl_t nv = n->changeOVL.load(std::memory_order_acquire);
            if (detail::cavl::ovl_is_unlinked(nv)) return status::retry;
            if (detail::cavl::ovl_is_changing(nv)) {
                std::this_thread::yield();
                continue;
            }

            if (!(key < n->key) && !(n->key < key)) {
                // Matched n's key.
                {
                    // Inner scope so n->lock is released before the
                    // physical-unlink chain (which re-acquires it
                    // under std::lock).
                    std::scoped_lock lk{n->lock};
                    if (n->changeOVL.load(std::memory_order_acquire) != nv) {
                        return status::retry;
                    }
                    if (n->is_routing.load(std::memory_order_relaxed)) {
                        return status::not_found;       // already removed
                    }
                    n->is_routing.store(true, std::memory_order_release);
                    size_.fetch_sub(1, std::memory_order_relaxed);
                }
                // Fase 2b: physical unlink for 0/1-child routing nodes.
                // Failure (e.g., the node now has 2 children because
                // of a concurrent insert into the empty slot) just
                // leaves it as a routing node — a later op collects.
                if (try_physical_unlink(n)) {
                    node* p_post = n->parent.load(std::memory_order_acquire);
                    if (p_post && p_post != &holder_) {
                        fix_heights_and_rebalance_ascent(p_post);
                    }
                    // n is now unreachable from the tree. Hand it to
                    // EBR — it stays alive until every thread that
                    // might hold a stale reference has gone quiescent
                    // (2 epochs), then gets delete'd. We're inside our
                    // own epoch guard here, so n won't be reclaimed
                    // before we return.
                    detail::cavl::ebr::instance().retire(n, &reclaim_node);
                }
                return status::removed;
            }

            const dir d = (key < n->key) ? dir::left : dir::right;
            node* c = n->child(d).load(std::memory_order_acquire);
            if (n->changeOVL.load(std::memory_order_acquire) != nv) {
                return status::retry;
            }
            parent = n;
            pv = nv;
            n = c;
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
        constexpr int max_passes = 4;
        for (int pass = 0; pass < max_passes; ++pass) {
            single_ascent_pass(start);
            if (path_is_avl_balanced(start)) return;
            // Some node on the path is still unbalanced — another
            // ascent racing with us mutated heights underneath. Yield
            // and try the whole ascent again. Capped at max_passes
            // so we don't livelock if the contention is sustained;
            // any remaining imbalance will be picked up by the next
            // insert (every insert does a full ascent).
            std::this_thread::yield();
        }
    }

    // One ascent pass: walk from start to the holder, updating
    // heights and triggering rotations where the local balance
    // factor exceeds 1. Per-node retry loop handles the "rotation
    // validation lost a race" case for that single node. If after
    // all retries the node is still unbalanced, set its
    // needs_rebalance flag so subsequent operations can pick it up.
    void single_ascent_pass(node* start) {
        constexpr int max_retries = 8;
        node* n = start;
        while (n != nullptr && n != &holder_) {
            bool converged = false;
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
                if (bf <= 1 && bf >= -1) { converged = true; break; }
                const bool rotated = (bf > 1) ? try_right_heavy_rotate(n)
                                              : try_left_heavy_rotate(n);
                if (rotated) { converged = true; break; }
                std::this_thread::yield();
            }
            if (converged) {
                n->needs_rebalance.store(false, std::memory_order_release);
            } else {
                n->needs_rebalance.store(true, std::memory_order_release);
            }
            n = n->parent.load(std::memory_order_acquire);
        }
    }

    // Result of an in-descent pending-rebalance pickup. Tells the
    // caller whether the tree structure under `n` actually changed
    // (descent context invalidated → caller must retry from root)
    // or not (safe to continue the current descent).
    enum class pending_result : std::uint8_t {
        unchanged,   // flag was stale OR rebalance attempts couldn't converge
        rotated,     // structure was modified; descent context is stale
    };

    // Inline helper used by attempt_insert's descent: if `n` has its
    // needs_rebalance flag set, attempt to rebalance n in place.
    //
    // Crucially, we do NOT force the caller to retry when the flag was
    // stale (already balanced) or when 8 attempts couldn't converge.
    // Without that distinction, an operation that doesn't mutate the
    // tree (e.g. try_insert hitting a live key) livelocks: every
    // descent through a flagged node would return retry, and because
    // no ascent runs to clear the flag the next descent hits the
    // same flag again. Returning `unchanged` lets the descent
    // continue — the flag eventually gets cleared by some op that
    // does run an ascent through here.
    [[nodiscard]] pending_result process_pending_if_set(node* n) {
        if (!n || !n->needs_rebalance.load(std::memory_order_acquire)) {
            return pending_result::unchanged;
        }
        constexpr int max_retries = 8;
        for (int attempt = 0; attempt < max_retries; ++attempt) {
            std::int32_t bf = 0;
            {
                std::scoped_lock nl{n->lock};
                if (detail::cavl::ovl_is_unlinked(n->changeOVL.load(std::memory_order_acquire))) {
                    return pending_result::unchanged;
                }
                const auto hl = height_of(n->left.load(std::memory_order_acquire));
                const auto hr = height_of(n->right.load(std::memory_order_acquire));
                n->height.store(1 + std::max(hl, hr), std::memory_order_release);
                bf = hr - hl;
            }
            if (bf <= 1 && bf >= -1) {
                n->needs_rebalance.store(false, std::memory_order_release);
                return pending_result::unchanged;
            }
            const bool rotated = (bf > 1) ? try_right_heavy_rotate(n)
                                          : try_left_heavy_rotate(n);
            if (rotated) {
                n->needs_rebalance.store(false, std::memory_order_release);
                return pending_result::rotated;
            }
            std::this_thread::yield();
        }
        // Couldn't converge — leave flag set for the next op.
        return pending_result::unchanged;
    }

    // Lock-free verification: scan from `start` to the holder and
    // return true iff every node currently satisfies |bf| <= 1.
    // Heights are atomic; the answer is a snapshot that may already
    // be stale by the time we return — but if it says "balanced", we
    // know there *was* a moment in our scan where the invariant held.
    // The outer ascent loop uses this as a heuristic for "should I
    // do another pass".
    [[nodiscard]] bool path_is_avl_balanced(node* start) const noexcept {
        node* n = start;
        while (n != nullptr && n != &holder_) {
            const auto hl = height_of(n->left.load(std::memory_order_acquire));
            const auto hr = height_of(n->right.load(std::memory_order_acquire));
            if (std::abs(hr - hl) > 1) return false;
            n = n->parent.load(std::memory_order_acquire);
        }
        return true;
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

    // Mark n as unlinked. Bumps the version too (so any in-flight
    // descenders that captured an older OVL retry instead of
    // chasing pointers that lead nowhere).
    static void set_unlinked(node* n) noexcept {
        const ovl_t cur = n->changeOVL.load(std::memory_order_acquire);
        n->changeOVL.store(((cur & detail::cavl::ovl_version_mask)
                            + detail::cavl::ovl_version_one)
                           | detail::cavl::ovl_unlinked_bit,
                           std::memory_order_release);
    }

    // Fase 2b: try to physically unlink a routing node with 0 or 1
    // children. Returns true if the node was unlinked from the tree
    // (its memory is intentionally NOT freed yet — EBR / Fase 3 will
    // handle reclamation; until then the node is a leak that's
    // bounded by the high-water-mark of distinct keys ever removed).
    //
    // Why only 0/1 children: a 2-child unlink would need to splice
    // in the in-order successor, which is another descent + rotation
    // cascade. Bronson keeps 2-child removed nodes as routing nodes
    // (Fase 2a behaviour) and only physically removes when collapse
    // is structurally trivial.
    //
    // Lock chain (deadlock-free via std::lock):
    //   parent(n), n, only_child (if present)
    [[nodiscard]] bool try_physical_unlink(node* n) {
        node* p = n->parent.load(std::memory_order_acquire);
        if (!p) return false;  // shouldn't happen (holder_ is always above)

        node* L = n->left.load(std::memory_order_acquire);
        node* R = n->right.load(std::memory_order_acquire);
        if (L && R) return false;  // 2 children → stays routing
        node* only_child = L ? L : R;

        auto do_unlink = [&]() {
            // Mark n as unlinked under p's lock so concurrent
            // descenders that took p.OVL pre-unlink will see the
            // bump and retry.
            set_shrinking(p);
            set_unlinked(n);
            if (p->left.load(std::memory_order_acquire) == n) {
                p->left.store(only_child, std::memory_order_release);
            } else {
                p->right.store(only_child, std::memory_order_release);
            }
            if (only_child) {
                only_child->parent.store(p, std::memory_order_release);
            }
            clear_shrinking(p);
        };

        if (only_child) {
            std::lock(p->lock, n->lock, only_child->lock);
            std::lock_guard<std::mutex> pl{p->lock,           std::adopt_lock};
            std::lock_guard<std::mutex> nl{n->lock,           std::adopt_lock};
            std::lock_guard<std::mutex> cl{only_child->lock,  std::adopt_lock};
            // Post-lock validation: nothing about (p, n, only_child)
            // may have changed since we read them above.
            if (n->parent.load(std::memory_order_acquire) != p) return false;
            if (!n->is_routing.load(std::memory_order_relaxed)) return false;
            if (detail::cavl::ovl_is_unlinked(n->changeOVL.load(std::memory_order_acquire)))
                return false;
            node* L2 = n->left.load(std::memory_order_acquire);
            node* R2 = n->right.load(std::memory_order_acquire);
            if (L2 && R2) return false;
            node* oc2 = L2 ? L2 : R2;
            if (oc2 != only_child) return false;
            do_unlink();
            return true;
        }

        // 0-child case: only need p + n locks.
        std::lock(p->lock, n->lock);
        std::lock_guard<std::mutex> pl{p->lock, std::adopt_lock};
        std::lock_guard<std::mutex> nl{n->lock, std::adopt_lock};
        if (n->parent.load(std::memory_order_acquire) != p) return false;
        if (!n->is_routing.load(std::memory_order_relaxed)) return false;
        if (detail::cavl::ovl_is_unlinked(n->changeOVL.load(std::memory_order_acquire)))
            return false;
        if (n->left.load(std::memory_order_acquire)  != nullptr) return false;
        if (n->right.load(std::memory_order_acquire) != nullptr) return false;
        do_unlink();
        return true;
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
