# Parallel AVL Tree — C++23

Header-only template implementation of a high-performance, sharded, concurrent
AVL tree. Templated on `<Key, Value>`, RAII, lock-free statistics, with optional
cherry-picks from C++26 gated on feature-test macros.

## Highlights

- **`template<Key, Value>`** — no `void*`, no manual destructors. Value lifetime
  is managed by the tree (works with `std::string`, `std::unique_ptr<T>`, etc.).
- **RAII** — `pavl::parallel_avl<K, V>` is created and destroyed by scope.
- **`std::atomic` / `std::shared_mutex` / `std::scoped_lock` / `std::jthread`**
  replace the per-platform `atomics.h`, `pthread_*`, `SRWLOCK`, `CreateThread`
  abstractions of the original C code.
- **`std::expected`, `std::ranges`, `std::format`, `std::source_location`** used
  where they sharpen the API.
- **`[[likely]]` / `[[unlikely]]`**, `alignas(64)`, `[[gnu::always_inline]]` on
  hot paths — same micro-architectural tuning as the C version.
- **Concurrent topology mutation is safe**: `add_shard`, `remove_shard`,
  `force_rebalance` serialize against in-flight ops via a `std::shared_mutex`.
  (The C original use-after-free'd here under load; verified with ASan.)

## Toolchain

- GCC 13+ or Clang 17+ for solid C++23 library support (`std::expected`,
  `std::format`, `std::jthread`, `std::ranges`).
- C++26 features are opt-in via `__cpp_lib_*` feature-test macros; the code
  compiles cleanly on a current GCC 13 / libstdc++ 13 toolchain.

## Build

```sh
make            # release: benchmark_parallel + test_avl
make test       # run unit tests (24 tests)
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
    pavl::parallel_avl<std::int64_t, std::string> tree{8, pavl::router_strategy::intelligent};

    tree.insert(42, "hello");
    if (auto v = tree.get(42)) std::println("found: {}", *v);

    // Zero-copy visit
    tree.visit(42, [](std::string& s) { s += " world"; });

    // Range queries return std::vector<key_value>
    auto rows = tree.range_query(10, 50, /*max*/ 100);

    // Dynamic scaling (thread-safe, serializes vs in-flight ops)
    tree.add_shard();
    tree.force_rebalance();

    auto s = tree.snapshot();
    std::println("shards={} size={} balance={:.2f}", s.num_shards, s.total_size, s.balance_score);
}
```

## Routing strategies

| Enum | Behaviour |
|------|-----------|
| `router_strategy::static_hash` | Plain hash → shard. Fastest, fragile to adversarial keys. |
| `router_strategy::load_aware` | Detects hotspots, redirects to least loaded shard. |
| `router_strategy::consistent_hash` | Virtual nodes — stable under topology changes. |
| `router_strategy::intelligent` | Adaptive hybrid. **Default.** |

## Notes on performance

Single-thread shard hot path (5M ops, gcc 13.3 `-O3 -march=native -flto`):

| Op | C++23 port | C original |
|----|-----------|-----------|
| insert | 7.9 M ops/s | 6.1 M ops/s |
| contains | 10.6 M ops/s | 9.7 M ops/s |

Multi-thread sustained (8 threads, 4M ops, 70/15/15 read/insert/delete):
~2.7 M ops/s for both — within noise of each other.

The `shared_mutex` for topology safety costs ~30% on the pure-read stress
test versus an unsynchronized read. That overhead buys correctness:
the original C version use-after-free'd here, confirmed by AddressSanitizer.

## License

MIT — same as the original project.
