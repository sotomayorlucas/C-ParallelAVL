// concurrent_avl<K, V> — design notes (Fase 0)
//
// This header is the design document for the Bronson-style optimistic
// concurrent AVL that will replace the current sharded layer. At this
// point it intentionally contains NO executable implementation — only
// type sketches and protocol descriptions, so we can review the
// algorithm before writing the actual code.
//
// Reference:
//   Bronson, Casper, Chafi, Olukotun. "A Practical Concurrent Binary
//   Search Tree." PPoPP 2010. (Stanford CCAVL.)
//
// =====================================================================
// 0. Goals
// =====================================================================
//
//   - Single AVL tree (no sharding, no router, no redirect_index).
//   - Multiple threads operate on it concurrently.
//   - Readers never take node locks under contention-free descent.
//   - Writers take fine-grained locks only on the nodes involved in
//     a rotation, not on the whole tree.
//   - Strict AVL balance is preserved (every committed state has
//     |height(left) - height(right)| <= 1 for every node).
//   - Sanitisable: ASan + UBSan + TSan must stay clean under stress.
//
// Non-goals:
//   - Lock-free strict (we use locks on writers; that's "fine-grained",
//     not lock-free).
//   - Wait-freedom.
//
// =====================================================================
// 1. Node layout
// =====================================================================
//
//   struct node {
//       Key key;                            // immutable after construction
//       Value value;                        // mutated under node lock
//       std::atomic<node*> left;            // child pointers are atomic
//       std::atomic<node*> right;           //   (readers traverse without locks)
//       node* parent;                       // protected by node lock
//       std::int32_t height;                // protected by node lock
//       std::atomic<std::uint64_t> changeOVL; // version + state bits
//       std::mutex lock;                    // taken by writers only
//   };
//
// changeOVL encoding (the heart of Bronson):
//   bit 63    : "growing" — a child subtree is being inserted into
//   bit 62    : "shrinking" — this node is being rotated or unlinked
//   bit 61    : "unlinked"  — node has been removed from the tree
//   bits 0-60 : monotonic version counter, incremented on every state change
//
// Helpers:
//   is_changing(v)  ::= (v & (growing | shrinking)) != 0
//   is_unlinked(v)  ::= (v & unlinked) != 0
//   version(v)      ::= v & version_mask
//
// Invariant: changeOVL only ever increases. Even after wrap (~2^61 ops)
// the ABA risk is negligible at typical throughput (>700 years at 1G ops/s).
//
// =====================================================================
// 2. Hand-over-hand validating descent (the read path)
// =====================================================================
//
// Reader (contains / find / visit):
//
//   node* p = root;
//   uint64_t pv = p.changeOVL.load(acquire);
//   while (true) {
//       if (is_unlinked(pv))            -> restart from root
//       direction d = compare(key, p.key);
//       if (d == EQUAL)                 -> return p (validate before use)
//       node* c = p.children[d].load(acquire);
//       uint64_t pv2 = p.changeOVL.load(acquire);
//       if (pv != pv2)                  -> retry this step (p changed
//                                          between reading version and child)
//       if (c == nullptr)               -> key absent, but wait...
//                                          if (is_changing(pv))
//                                              -> wait for stable, retry
//                                          else
//                                              -> return absent
//       p = c; pv = c.changeOVL.load(acquire);
//   }
//
// The pre-/post-read of changeOVL around the child load is the key
// trick: it guarantees the reader either sees a consistent
// (parent, child) pair OR notices the inconsistency and retries.
//
// Critical: the reader DOES NOT take p.lock. It only reads atomics.
//
// =====================================================================
// 3. Insert
// =====================================================================
//
// Insert is similar to descent, but when the reader-style descent
// reaches a null leaf-slot, the writer:
//
//   1. Take parent.lock.
//   2. Re-validate: parent.changeOVL hasn't changed since the descent's
//      last read of it. If it changed, retry from root.
//   3. Re-check that parent.children[d] is still nullptr. If not,
//      retry from root.
//   4. Bump parent.changeOVL with growing bit set.
//   5. Allocate new node.
//   6. parent.children[d].store(new_node, release).
//   7. Clear growing bit, bump version.
//   8. Release parent.lock.
//   9. Walk up, rebalancing — see Section 5.
//
// If during descent we hit a key match, we either:
//   - insert (overwrite): take p.lock, validate p not unlinked, set
//     p.value, release. (No version bump needed for value update if
//     we don't promise structural snapshot for value reads.)
//   - try_insert: do nothing, return inserted=false.
//
// =====================================================================
// 4. Remove (partially-external)
// =====================================================================
//
// Bronson's trick to avoid most AVL deletion pain: nodes with two
// children are NOT physically removed. They become "routing nodes"
// (key still present, value cleared, marked as logically deleted).
// Only leaf nodes (or nodes with one child) are physically unlinked.
//
//   1. Descent locates target node t.
//   2. Take t.lock; validate not unlinked.
//   3. If t has 0 or 1 children:
//      - Take parent.lock (carefully — may need restart if parent
//        changed). Lock order: always parent before child.
//      - Bump t.changeOVL with shrinking bit.
//      - Re-parent (parent.children[d] := t's single child or null).
//      - Set t.changeOVL = unlinked.
//      - Release locks.
//      - Hand t to EBR for later reclamation (see Section 7).
//   4. If t has 2 children:
//      - Mark t as "value-deleted" (separate atomic bit, or sentinel
//        in Value). Tree structure unchanged.
//      - Rebalance not needed (no structural change).
//
// A subsequent insert with the same key reuses the routing node:
// flips it back to "value-present" and updates the Value.
//
// =====================================================================
// 5. Rotation (the dangerous part)
// =====================================================================
//
// AVL rotation involves three nodes: x (out-of-balance), y (the child
// to rotate up), and possibly z (y's child that becomes x's child).
// Plus x's parent p, which needs to be re-linked.
//
// Lock order to avoid deadlock:
//   1. p (x's parent)
//   2. x
//   3. y
//   4. z (if double rotation)
//
// All four locks are taken before any pointer mutation. Bump the
// changeOVL of x and y with shrinking bit. Mutate pointers in the
// fixed order [p->child, x->child, y->child]. Clear shrinking bits,
// bump versions. Release locks in reverse order.
//
// Rotations bubble up from the insertion/deletion point exactly like
// the sequential AVL — same balance factor logic, just under locks.
//
// =====================================================================
// 6. Range query — snapshot semantics
// =====================================================================
//
// The user chose snapshot semantics (option (a) from the plan): a
// range_query must return a coherent slice as of *some* serialised
// point in the tree's history, not a best-effort traversal.
//
// Two options, decision deferred to Fase 5:
//
//   (a) Global epoch lock. range_query takes a single global rwlock
//       in exclusive mode briefly to copy the relevant subrange.
//       Easy, correct, but writes pause during range_query. Acceptable
//       if range_query is rare.
//
//   (b) Snapshot via versioned descent. Reader observes a global
//       structural version S before starting. Descent retries any
//       sub-step whose parent's changeOVL is > S (it has a version
//       newer than our snapshot). Combined with EBR keeping unlinked
//       nodes alive long enough for in-flight range_queries.
//
// Both keep writes lock-free for the common path. (a) is ~50 LOC,
// (b) is ~150. We'll pick when Fase 5 arrives.
//
// =====================================================================
// 7. Memory reclamation (EBR — Fase 3)
// =====================================================================
//
// Removed nodes can't be deleted immediately: some reader may be
// holding a pointer obtained before the unlink completed. Three
// possibilities, ranked by simplicity:
//
//   (a) Quiescent-state EBR. A global epoch counter; each thread
//       publishes "currently in an operation" when it descends, and
//       advances the epoch on each public-API exit. A retired node
//       enters epoch N's retire list; it's freed when all threads
//       have observed epoch >= N+2.
//       LOC: ~150. Hot-path cost: 2 atomic ops per op (epoch enter/exit).
//
//   (b) Hazard pointers. Each thread publishes the node it's currently
//       holding. Retired nodes wait until no hazard pointer points
//       at them. Smoother under high load but more bookkeeping.
//       LOC: ~300. Hot path: 1 atomic store per pointer follow.
//
//   (c) std::hazard_pointer (C++26). Not in libstdc++ 13 — defer.
//
// We will start with (a) Quiescent-state EBR. The protocol fits the
// rest of the design (each operation has a clear "enter" and "exit",
// matching the existing read_guard pattern from parallel_avl).
//
// During Fases 1-2 we'll skip reclamation entirely (intentional leak)
// to validate the descent/insert/rotation protocol first. Fase 3
// adds EBR on top.
//
// =====================================================================
// 8. Memory ordering summary
// =====================================================================
//
//   changeOVL.load        acquire   (synchronises with the writer's
//                                    bump after a pointer mutation)
//   changeOVL.store/cas   release   (publishes the mutation)
//   children[d].load      acquire
//   children[d].store     release
//   parent (mutated only under lock, so plain access)
//   height (same)
//   value (under lock; reads under lock too)
//
// We do NOT need seq_cst anywhere in the descent: the changeOVL
// pre-/post-read provides the linearisation point. Writers
// synchronise with each other via std::mutex (which is already
// seq_cst on the lock boundary).
//
// =====================================================================
// 9. Linearisation points
// =====================================================================
//
// For each operation, the linearisation point is:
//
//   contains/find  : the post-read of changeOVL on the matching node
//                    (or on the parent if no match) that validated
//                    the descent's last step.
//   insert         : the parent.children[d].store(new_node) inside
//                    the parent lock.
//   remove (struct): the parent.children[d].store(null_or_child)
//                    inside the parent lock.
//   remove (value) : the value-deleted bit set inside the node lock.
//   visit          : the call to F(value) under the node lock.
//   range_query    : depends on which option we pick in Fase 5.
//
// =====================================================================
// 10. Invariants (checked by debug build / sanity test)
// =====================================================================
//
//   I1: For every reachable node n, n != n.left and n != n.right.
//   I2: For every reachable node n with key k_n: every key in
//       subtree(n.left) is < k_n, every key in subtree(n.right) is > k_n.
//   I3: For every reachable node n with both children present:
//       |height(n.left) - height(n.right)| <= 1.
//   I4: Routing nodes (value-deleted) still satisfy I2 (their key
//       remains in place; only the value is logically absent).
//   I5: A node with changeOVL.unlinked == 1 is unreachable from root.
//
// Invariants hold between operations. WITHIN an operation we can see
// them transiently broken (a rotation in progress) — the changeOVL
// flag tells readers to wait.
//
// =====================================================================
// 11. What this header will look like by end of Fase 6
// =====================================================================
//
//   namespace pavl {
//
//   template <avl_key Key, avl_value Value>
//   class concurrent_avl {
//   public:
//       using key_type = Key;
//       using value_type = Value;
//       struct key_value { Key key; Value value; };
//       struct insert_outcome { bool inserted; };
//
//       concurrent_avl() noexcept;
//       ~concurrent_avl();
//       // non-copy non-move (mutex members)
//
//       // Lookup
//       [[nodiscard]] bool contains(const Key&) const;
//       [[nodiscard]] std::optional<Value> get(const Key&) const
//           requires std::copyable<Value>;
//       template <std::invocable<Value&> F>
//       [[nodiscard]] bool visit(const Key&, F&&);
//
//       // Mutation
//       void insert(Key, Value);                                  // overwrite
//       insert_outcome try_insert(Key, Value);                    // no-op if present
//       insert_outcome insert_or_assign(Key, Value);              // explicit
//       template <typename... Args>
//       insert_outcome try_emplace(Key, Args&&...);               // construct V in-place
//       bool remove(const Key&);
//
//       // Snapshot range
//       template <std::invocable<const Key&, const Value&> F>
//       void range_for_each(const Key& lo, const Key& hi, F&&) const;
//       [[nodiscard]] std::vector<key_value> extract_all() const;
//
//       // Status
//       [[nodiscard]] std::size_t size() const noexcept;
//       [[nodiscard]] bool empty() const noexcept;
//   };
//
//   }  // namespace pavl
//
// All of this becomes real in Fases 1-5. This file ends here for now
// — Fase 1 will replace this block with the actual implementation.

#pragma once

#include "common.hpp"

// Forward declarations only (no implementation yet).
namespace pavl {
template <avl_key Key, avl_value Value> class concurrent_avl;
}  // namespace pavl
