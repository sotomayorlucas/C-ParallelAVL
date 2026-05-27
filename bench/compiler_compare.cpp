// Compiler comparison benchmark (e.g. GCC vs Clang vs Intel ICX).

#include "avl_tree.hpp"
#include "hash_table.hpp"
#include "parallel_avl.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <format>
#include <iostream>
#include <thread>
#include <vector>

namespace {

using clock_t = std::chrono::steady_clock;

class xorshift64 {
public:
    explicit xorshift64(std::uint64_t seed) noexcept : state_{seed ? seed : 0xdeadbeefULL} {}
    [[gnu::always_inline]] std::uint64_t operator()() noexcept {
        auto x = state_; x ^= x << 13; x ^= x >> 7; x ^= x << 17; state_ = x; return x;
    }
private:
    std::uint64_t state_;
};

[[nodiscard]] double seconds_since(clock_t::time_point t) {
    return std::chrono::duration<double>(clock_t::now() - t).count();
}

double bench_single_avl(std::size_t ops, int key_range) {
    pavl::avl_tree<std::int64_t, void*> tree;
    for (int i = 0; i < 10000; ++i) tree.insert(i, nullptr);
    xorshift64 rng{12345};
    const auto t0 = clock_t::now();
    for (std::size_t i = 0; i < ops; ++i) {
        const auto key = static_cast<std::int64_t>(rng() % static_cast<std::uint64_t>(key_range));
        const auto op = rng() % 100;
        if (op < 70) (void)tree.contains(key);
        else if (op < 85) tree.insert(key, nullptr);
        else tree.remove(key);
    }
    return static_cast<double>(ops) / seconds_since(t0);
}

double bench_parallel_avl(std::size_t num_threads, std::size_t ops_per_thread, int key_range) {
    pavl::parallel_avl<std::int64_t, void*> tree{num_threads, pavl::router_strategy::static_hash};
    for (int i = 0; i < 10000; ++i) tree.insert(i, nullptr);
    std::vector<std::jthread> ws;
    ws.reserve(num_threads);
    const auto t0 = clock_t::now();
    for (std::size_t t = 0; t < num_threads; ++t) {
        ws.emplace_back([&, t]() {
            xorshift64 rng{12345ULL + t * 7919ULL};
            for (std::size_t i = 0; i < ops_per_thread; ++i) {
                const auto key = static_cast<std::int64_t>(rng() % static_cast<std::uint64_t>(key_range));
                const auto op = rng() % 100;
                if (op < 70) (void)tree.contains(key);
                else if (op < 85) tree.insert(key, nullptr);
                else tree.remove(key);
            }
        });
    }
    ws.clear();
    return static_cast<double>(num_threads * ops_per_thread) / seconds_since(t0);
}

double bench_hash_table(std::size_t ops, int key_range) {
    pavl::hash_table<std::int64_t, std::size_t> table{1024};
    for (int i = 0; i < 10000; ++i) table.insert(i, static_cast<std::size_t>(i));
    xorshift64 rng{12345};
    const auto t0 = clock_t::now();
    for (std::size_t i = 0; i < ops; ++i) {
        const auto key = static_cast<std::int64_t>(rng() % static_cast<std::uint64_t>(key_range));
        const auto op = rng() % 100;
        if (op < 70) (void)table.find(key);
        else if (op < 85) table.insert(key, static_cast<std::size_t>(key));
        else table.remove(key);
    }
    return static_cast<double>(ops) / seconds_since(t0);
}

}  // namespace

int main() {
    std::cout << "\n+============================================================+\n"
                 "|     COMPILER COMPARISON BENCHMARK - C++23 Parallel AVL     |\n"
                 "+============================================================+\n";
#ifdef __INTEL_LLVM_COMPILER
    std::cout << std::format("| Compiler: Intel ICX {}                              |\n", __INTEL_LLVM_COMPILER);
#elif defined(__clang__)
    std::cout << std::format("| Compiler: Clang {}.{}.{}                              |\n",
                             __clang_major__, __clang_minor__, __clang_patchlevel__);
#elif defined(__GNUC__)
    std::cout << std::format("| Compiler: GCC {}.{}.{}                                |\n",
                             __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#else
    std::cout << "| Compiler: Unknown                                          |\n";
#endif
    std::cout << "+============================================================+\n\n";

    std::cout << "Warm-up... " << std::flush;
    bench_single_avl(100000, 10000);
    std::cout << "done\n\n";

    std::cout << "=== Test 1: Single-threaded AVL (5M ops) ===\n";
    const auto t1 = bench_single_avl(5'000'000, 500'000);
    std::cout << std::format("  Throughput: {:.2f} M ops/sec\n\n", t1 / 1e6);

    std::cout << "=== Test 2: Single-threaded AVL (10M ops) ===\n";
    const auto t2 = bench_single_avl(10'000'000, 1'000'000);
    std::cout << std::format("  Throughput: {:.2f} M ops/sec\n\n", t2 / 1e6);

    std::cout << "=== Test 3: Hash Table (10M ops) ===\n";
    const auto t3 = bench_hash_table(10'000'000, 1'000'000);
    std::cout << std::format("  Throughput: {:.2f} M ops/sec\n\n", t3 / 1e6);

    std::cout << "=== Test 4: Parallel AVL 2 threads (10M ops) ===\n";
    const auto t4 = bench_parallel_avl(2, 5'000'000, 1'000'000);
    std::cout << std::format("  Throughput: {:.2f} M ops/sec\n\n", t4 / 1e6);

    std::cout << "=== Test 5: Parallel AVL 4 threads (10M ops) ===\n";
    const auto t5 = bench_parallel_avl(4, 2'500'000, 1'000'000);
    std::cout << std::format("  Throughput: {:.2f} M ops/sec\n\n", t5 / 1e6);

    std::cout << "=== Test 6: Parallel AVL 8 threads (10M ops) ===\n";
    const auto t6 = bench_parallel_avl(8, 1'250'000, 1'000'000);
    std::cout << std::format("  Throughput: {:.2f} M ops/sec\n\n", t6 / 1e6);

    std::cout << "=== Test 7: High-volume Parallel 8 threads (50M ops) ===\n";
    const auto t7 = bench_parallel_avl(8, 6'250'000, 5'000'000);
    std::cout << std::format("  Throughput: {:.2f} M ops/sec\n\n", t7 / 1e6);

    std::cout << "+============================================================+\n"
                 "|                      RESULTS SUMMARY                       |\n"
                 "+============================================================+\n"
                 "| Test                          | Throughput (M ops/sec)     |\n"
                 "+-------------------------------+----------------------------+\n";
    std::cout << std::format("| Single AVL 5M                 | {:26.2f} |\n", t1 / 1e6);
    std::cout << std::format("| Single AVL 10M                | {:26.2f} |\n", t2 / 1e6);
    std::cout << std::format("| Hash Table 10M                | {:26.2f} |\n", t3 / 1e6);
    std::cout << std::format("| Parallel 2T 10M               | {:26.2f} |\n", t4 / 1e6);
    std::cout << std::format("| Parallel 4T 10M               | {:26.2f} |\n", t5 / 1e6);
    std::cout << std::format("| Parallel 8T 10M               | {:26.2f} |\n", t6 / 1e6);
    std::cout << std::format("| Parallel 8T 50M               | {:26.2f} |\n", t7 / 1e6);
    std::cout << "+-------------------------------+----------------------------+\n";

    std::cout << "\n[CSV_OUTPUT]\n";
    std::cout << std::format("single_avl_5m,{:.2f}\n", t1 / 1e6);
    std::cout << std::format("single_avl_10m,{:.2f}\n", t2 / 1e6);
    std::cout << std::format("hash_table_10m,{:.2f}\n", t3 / 1e6);
    std::cout << std::format("parallel_2t_10m,{:.2f}\n", t4 / 1e6);
    std::cout << std::format("parallel_4t_10m,{:.2f}\n", t5 / 1e6);
    std::cout << std::format("parallel_8t_10m,{:.2f}\n", t6 / 1e6);
    std::cout << std::format("parallel_8t_50m,{:.2f}\n", t7 / 1e6);
    return 0;
}
