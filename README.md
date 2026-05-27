# Parallel AVL Tree — C++23

Header-only template implementation of a high-performance, sharded,
concurrent AVL tree. Templated on `<Key, Value>`, RAII, lock-free
statistics, with cherry-picks from C++26 gated on feature-test macros.

## Highlights

- **`template<Key, Value>`** — no `void*`, no manual destructors. Value
  lifetime is managed by the tree (works with `std::string`,
  `std::unique_ptr<T>`, etc.).
- **RAII throughout** — constructors/destructors replace `*_create/*_destroy`;
  `std::atomic / std::shared_mutex / std::scoped_lock / std::jthread`
  replace the cross-platform shims of the original C code.
- **`[[likely]]` / `[[unlikely]]`**, `alignas(64)`, `[[gnu::always_inline]]`
  on hot paths.
- **Heterogeneous lookup** — `tree.contains(42)` works with `Key=int64_t`
  and a `short` argument; `tree.contains("hi"sv)` works with `Key=string`.
- **`std::map`-style insert variants** — `try_insert`, `insert_or_assign`,
  `try_emplace` returning `{inserted}`.
- **Concurrent topology mutation is safe** — `add_shard`, `remove_shard`,
  `force_rebalance` serialize against in-flight ops via
  `std::shared_mutex`. The C original use-after-free'd here under load.
- **Verified clean** under AddressSanitizer, UBSan, and ThreadSanitizer.

## Toolchain

- GCC 13+ or Clang 17+ for solid C++23 library support (`std::expected`,
  `std::format`, `std::jthread`, `std::ranges`).
- C++26 features are opt-in via `__cpp_lib_*` feature-test macros; the
  code compiles cleanly on GCC 13 / libstdc++ 13.

## Build

```sh
make            # release: benchmark_parallel + test_avl
make test       # run unit tests
make benchmark  # run scalability benchmark
make stress     # run 6 stress tests including adversarial workloads
make compare    # compiler-vs-compiler comparison bench
make debug      # ASan + UBSan build
```

## File layout

```
include/
  common.hpp          # concepts, cache_line_size, key_hash, attributes
  avl_tree.hpp        # avl_tree<K, V> + node_pool
  hash_table.hpp      # hash_table<K, V> (Robin Hood, used by redirect_index)
  shard.hpp           # shard<K, V> = mutex + avl_tree + atomic stats
  router.hpp          # router (hash → shard, 4 strategies)
  redirect_index.hpp  # redirect_index<K> (shared_mutex RW lock)
  parallel_avl.hpp    # parallel_avl<K, V> — public API
tests/test_avl.cpp
bench/{benchmark_parallel,stress_test,compiler_compare}.cpp
```

## Usage

```cpp
#include "parallel_avl.hpp"

int main() {
    pavl::parallel_avl<std::int64_t, std::string> tree{
        8, pavl::router_strategy::intelligent};

    tree.insert(42, "hello");                       // overwrites if present
    auto r = tree.try_insert(42, "ignored");        // r.inserted == false
    tree.try_emplace(99, 5, 'x');                   // "xxxxx", in-place

    if (auto v = tree.get(42)) std::cout << *v;

    tree.visit(42, [](std::string& s) { s += " world"; });

    auto rows = tree.range_query(10, 50, /*max*/ 100);

    tree.add_shard();                               // thread-safe
    tree.force_rebalance();

    auto s = tree.snapshot();
}
```

## API reference

### `parallel_avl<K, V>` — operations

| Method                            | Returns                | Notes                                                            |
|-----------------------------------|------------------------|------------------------------------------------------------------|
| `insert(K, V)`                    | `void`                 | Overwrites if `K` exists.                                        |
| `try_insert(K, V)`                | `{bool inserted}`      | No-op if `K` exists.                                             |
| `insert_or_assign(K, V)`          | `{bool inserted}`      | Always present after call; reports new vs update.                |
| `try_emplace(K, Args...)`         | `{bool inserted}`      | Constructs `V` in place from args if `K` absent.                 |
| `contains(K)`                     | `bool`                 | Searches natural shard, falls back to redirect index/topology.   |
| `get(K)`                          | `optional<V>`          | Requires `copyable<V>`.                                          |
| `visit(K, F)`                     | `bool`                 | Invokes `F(V&)` under shard lock if present.                     |
| `remove(K)`                       | `bool`                 |                                                                  |
| `range_query(lo, hi, max)`        | `vector<key_value>`    | Sorted by key. Filters shards via `intersects_range`.            |
| `add_shard()` / `remove_shard()`  | `bool`                 | Serializes against in-flight ops.                                |
| `force_rebalance()`               | `void`                 | Redistributes all keys with `static_hash`. Clears redirects.     |
| `size()` / `num_shards()`         | `size_t`               | Snapshot under topology shared-lock.                             |
| `snapshot()`                      | `stats`                | Per-shard sizes, router balance, redirect stats.                 |

### Heterogeneous lookup (`avl_tree<K, V>` only)

`contains`, `find`, `remove` on the single-shard `avl_tree` accept any
type `K'` that is order-comparable with `Key` (concept
`pavl::order_comparable_with<Key, K'>`):

```cpp
pavl::avl_tree<std::string, int> t;
t.insert("hello", 1);

std::string_view sv = "hello";
t.contains(sv);     // no std::string allocation
t.find(sv);
t.remove(sv);
```

`parallel_avl` intentionally **doesn't** expose heterogeneous lookup at
its top level: routing hashes the key, and the hashes of `Key` and `K'`
must agree for the routing to find the right shard. Without that
guarantee the operation would silently miss. Use heterogeneous lookup
on a single `shard` or `avl_tree` if you need it.

## Complexity (n = total keys, S = shards)

| Operation                          | Average        | Worst       |
|------------------------------------|----------------|-------------|
| `insert / try_insert / contains / find / remove / visit / get` | O(log(n/S))    | O(log n)    |
| `range_query(lo, hi)`              | O(S + k log(n/S)) where k = matches | O(n)        |
| `size() / num_shards() / snapshot()` | O(S)         | O(S)        |
| `add_shard()`                      | O(1)           | O(1)        |
| `remove_shard()`                   | O(m + m log(n/S)) where m = size of removed shard | — |
| `force_rebalance()`                | O(n log(n/S))  | O(n log(n/S)) |

Worst-case `O(log n)` for the basic operations occurs only when topology
has changed and the redirect index plus exhaustive shard search both
miss — uncommon in practice and only inflates by a constant `S`.

## Concurrency model

### Lock hierarchy (acquired in this order)

```
topology gate       (parallel_avl, hand-rolled reader counter + scaling mutex)
  shard_mutex_      (one per shard, plain mutex)
    redirect_mutex_ (redirect_index, shared_mutex)
```

`parallel_avl` does NOT use `std::shared_mutex` for topology; instead it
uses a hand-rolled reader gate (`active_readers_` atomic counter +
`scaling_wanted_` flag + `scaling_mutex_`). Functionally equivalent to a
RW-mutex but avoids the libstdc++ `pthread_rwlock_t` machinery — ~15%
faster on the read-only stress test in our measurements.

Held by:

| Operation                          | topology gate | `shard_mutex_` | `redirect_mutex_` |
|------------------------------------|---------------|----------------|-------------------|
| `insert / contains / get / remove / visit / range_query` | **reader** | exclusive (one shard) | shared on lookup, exclusive on record |
| `add_shard / remove_shard / force_rebalance / clear`     | **writer** (drains readers) | — | exclusive at end |
| `size / num_shards / snapshot / balance_score`           | **reader** | — | shared |

### Memory order on atomic counters

The stats are deliberately approximate. The choices below reflect what
TSan accepts and what gives the cheapest correct ordering on x86_64 /
ARMv8.

| Atomic field                                  | Reads / writes | Order        |
|-----------------------------------------------|----------------|--------------|
| `shard::size_, insert_count_, lookup_count_, remove_count_` | counters | `relaxed`   |
| `shard::min_key_, max_key_`                   | bounds         | `relaxed`    |
| `shard::has_keys_`                            | publish flag   | `acquire/release` (gates min/max reads) |
| `parallel_avl::total_ops_, redirect_hits_`    | counters       | `relaxed`    |
| `parallel_avl::has_redirects_, topology_changed_` | hot-path flags | `acquire/release` |
| `router::shard_loads_[i]`                     | per-shard load | `relaxed`    |
| `router::cached_balance_score_` (`atomic<double>`) | approx metric | `relaxed`    |
| `router::cached_has_hotspot_`                 | adaptive cache | `relaxed`    |
| `router::ops_since_cache_, adaptive_interval_` | adaptive cache | `relaxed`   |

### Linearisability

The tree is linearisable for `insert / contains / get / remove / visit /
try_insert / insert_or_assign / try_emplace` under any mix of
concurrent calls, **provided** that the `redirect_index` keeps the
record of any non-natural placement. This is the role of the `has_redirects_`
+ `topology_changed_` two-flag scheme: lookups only consult the redirect
index when at least one flag is set.

`range_query` is **not** linearisable: it collects results from each
shard under that shard's lock, and an `insert` to an already-visited
shard concurrent with a `range_query` is not reflected. Use
`force_rebalance()` then `range_query` for a clean snapshot, or accept
the per-shard atomic semantics.

`snapshot()` returns per-shard counters that were each taken atomically
but not coherently across shards. Treat the totals as approximate
under load.

## Performance

Single-thread shard hot path (5M ops, gcc 13.3 `-O3 -march=native -flto`):

| Op       | C++23 port    | C original    |
|----------|---------------|---------------|
| insert   | 7.9 M ops/s   | 6.1 M ops/s   |
| contains | 10.6 M ops/s  | 9.7 M ops/s   |

Multi-thread sustained (8 threads, 4M ops, 70/15/15 read/insert/delete):
~2.7 M ops/s for both — within noise.

Topology safety overhead: the hand-rolled reader gate
(`active_readers_` + `scaling_wanted_`) measures ~15% faster on a
read-only microbench than `std::shared_mutex` would (4.3 vs 3.75 M
ops/s, 8 threads, 20M total ops). Versus an unsynchronised read it
still costs ~20%. That overhead buys correctness: the original C
version use-after-free'd under concurrent scaling, confirmed by
AddressSanitizer.

## License

MIT — same as the original project.
