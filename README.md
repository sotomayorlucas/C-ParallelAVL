# concurrent_avl&lt;K, V&gt; — Bronson optimistic AVL in C++23

Header-only template implementation of a practical lock-free-for-reads,
fine-grained-locking-for-writes concurrent AVL tree.

Based on the Bronson, Casper, Chafi, Olukotun algorithm
(*A Practical Concurrent Binary Search Tree*, PPoPP 2010), with the
standard pieces:

- **Optimistic, validating descent** — readers chase pointers without
  acquiring any lock, validating each (parent → child) edge against a
  per-node version counter (`changeOVL`) that is bumped whenever the
  node's structural state changes. A reader that loses a race with a
  concurrent rotation retries from the root.
- **Per-node `std::mutex` for writers** — `insert` only locks the
  parent of the publishing slot; `remove` only locks the matched node
  (then optionally also its parent + only-child for physical unlink).
- **Rotation under multi-lock chains** — single + double rotations
  acquire all the nodes they touch atomically via `std::lock(...)`, so
  the surgery is deadlock-free regardless of which direction the
  rotation runs.
- **Partially-external deletion** — a node with two children that is
  logically removed stays in the tree as a *routing node* (key
  preserved for BST descent, no value, `is_routing = true`). Future
  inserts of the same key reactivate it; a concurrent reader sees
  "not present" for routing keys. 0/1-child routing nodes are
  physically unlinked and handed to EBR for reclamation.
- **Epoch-based reclamation (EBR)** — every public operation installs
  a thread-local `ebr::guard`. Retired nodes wait two epochs before
  being `delete`d, so no thread can dereference a freed node.

## API

```cpp
#include "concurrent_avl.hpp"

pavl::concurrent_avl<int64_t, std::string> t;

// Writers — all thread-safe, no external locking needed.
t.insert(42, "hello");                     // overwrite if present
t.insert_or_assign(42, "world");           // std::map alias for the above
bool inserted = t.try_insert(7, "x");      // true if new live entry
bool emplaced = t.try_emplace(9, "y");     // construct V in place, try_insert
bool gone     = t.remove(42);              // logical remove + maybe-unlink

// Readers — lock-free except for get() / range_for_each which copy
// under the matched node's lock to serialise against a concurrent
// overwrite.
bool present  = t.contains(7);
std::optional<std::string> v = t.get(7);

// Best-effort snapshot iteration in ascending key order.
t.for_each([](const int64_t& k, const std::string& v) {
    std::cout << k << " -> " << v << "\n";
});
t.range_for_each(0, 100, [&](auto& k, auto& v) { /* ... */ });

// Size is approximate under concurrent ops; exact in a quiesced tree.
std::cout << t.size() << "\n";
```

`Key` must satisfy `std::totally_ordered + std::copyable`; `Value` must
be `std::movable`. Both must be `std::default_initializable` (the
sentinel root holder default-constructs them but never inspects the
values). `get` / `range_for_each` / `for_each` additionally require
`std::copyable<Value>` per call (the value is copied out under the
node's lock before the visitor sees it, so a long-running visitor
doesn't block writers).

## Concurrency semantics

- **`contains`, `get`** — linearisable. The successful descent's last
  read of the matched node's OVL (under its own lock for `get`)
  defines the linearisation point.
- **`insert`, `insert_or_assign`, `try_insert`, `try_emplace`,
  `remove`** — linearisable. The store that publishes the new node
  (or assigns the value, or sets `is_routing = true`) is the
  linearisation point.
- **`range_for_each`, `for_each`** — *best-effort snapshot*. Any key
  that is continuously live for the entire call is visited exactly
  once. A key that flickers (insert+remove during the call) may be
  visited 0 or 1 times. A node rotated through our recursion may be
  visited 0 or 2 times in the pathological case. Each emitted
  `(key, value)` pair was a real, live pair at *some* moment during
  the call — no torn reads, no values from routing or unlinked nodes.

The visitor for `range_for_each` and `for_each` runs **outside** any
node lock, so it can call back into the tree (`contains`, `get`,
`insert`, even another `range_for_each`) without self-deadlock.

## Build

```sh
make            # release: build benchmark + tests
make test       # build and run unit tests
make bench      # build and run throughput benchmark
make debug      # build tests with ASan + UBSan
make clean
```

Toolchain: GCC 13+ or Clang 17+ — needs `std::format`, `std::jthread`,
`std::scoped_lock`'s `std::lock` interaction, and concepts in the
constraint syntax.

## File layout

```
include/
  common.hpp          # cache_line_size + avl_key / avl_value concepts
  concurrent_avl.hpp  # the tree
bench/
  benchmark_concurrent_avl.cpp
tests/
  test_concurrent_avl.cpp
```

## Throughput

Measured on a 4-core x86_64 box, GCC 13.3, `-O3 -march=native -flto`,
via `bench/benchmark_concurrent_avl.cpp`. Numbers in operations / second.

| workload                  | 1 thread | 2 threads | 4 threads | 8 threads |
|---------------------------|---------:|----------:|----------:|----------:|
| Read-only (100% contains) | ~3.2 M   | ~7.4 M    | ~14 M     | ~13 M     |
| Mixed 70/15/15            | ~4.0 M   | ~5.6 M    | ~8.5 M    | ~7.5 M    |
| Write-heavy 20/40/40      | ~4.0 M   | ~3.5 M    | ~5.3 M    | ~4.4 M    |

Read-only scaling is the strongest case for the design — lock-free
descent + validating OVL means readers never block writers and don't
block each other. Throughput peaks around the core count (4) and
plateaus or dips at 8 threads on a 4-core box, where oversubscription
costs more than the extra parallelism buys.

## Known limitations

- A residual rebalance-retry livelock can be hit by the Fase 1a
  concurrent stress tests (`insert_visible_after_return`,
  `concurrent_insert_remove_mix`) under sustained high-contention
  scheduling. On a quiet 4-core box the suite passes cleanly; under
  rapid back-to-back runs it can hang in ~50% of cases. Single-
  threaded usage and the Fase 5 iteration path are not affected.

## License

Same as the repo at large.
