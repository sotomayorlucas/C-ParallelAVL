// Multi-threaded benchmark for the C++23 ParallelAVL port.

#include "avl_tree.hpp"
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

constexpr std::size_t num_cores = 8;

using clock_t = std::chrono::steady_clock;

class xorshift64 {
public:
    explicit xorshift64(std::uint64_t seed) noexcept : state_{seed ? seed : 0xdeadbeefULL} {}
    [[gnu::always_inline]] std::uint64_t operator()() noexcept {
        auto x = state_;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        state_ = x;
        return x;
    }
private:
    std::uint64_t state_;
};

[[nodiscard]] double seconds_since(clock_t::time_point start) {
    using namespace std::chrono;
    auto s = duration<double>(clock_t::now() - start).count();
    return s < 1e-9 ? 1e-9 : s;
}

// ============================================================================
// Single-threaded AVL baseline
// ============================================================================

double benchmark_single_avl(std::size_t ops, int key_range) {
    pavl::avl_tree<std::int64_t, void*> tree;
    for (int i = 0; i < 1000; ++i) tree.insert(i, nullptr);
    xorshift64 rng{12345};
    const auto start = clock_t::now();
    for (std::size_t i = 0; i < ops; ++i) {
        const auto key = static_cast<std::int64_t>(rng() % static_cast<std::uint64_t>(key_range));
        const auto op = rng() % 100;
        if (op < 70) (void)tree.contains(key);
        else if (op < 85) tree.insert(key, nullptr);
        else tree.remove(key);
    }
    return static_cast<double>(ops) / seconds_since(start);
}

// ============================================================================
// Parallel AVL — std::jthread workers
// ============================================================================

double benchmark_parallel_avl(std::size_t num_threads, std::size_t ops_per_thread,
                              int key_range, pavl::router_strategy strategy) {
    pavl::parallel_avl<std::int64_t, void*> tree{num_threads, strategy};
    for (int i = 0; i < 1000; ++i) tree.insert(i, nullptr);

    std::vector<std::jthread> workers;
    workers.reserve(num_threads);
    std::atomic<std::size_t> start_gate{num_threads};
    std::atomic<bool> go{false};

    const auto wall_start = clock_t::now();
    for (std::size_t tid = 0; tid < num_threads; ++tid) {
        workers.emplace_back([&, tid]() {
            xorshift64 rng{12345ULL + tid * 1000ULL};
            // Wait on the start gate so all workers begin together.
            if (start_gate.fetch_sub(1) == 1) go.store(true, std::memory_order_release);
            while (!go.load(std::memory_order_acquire)) {}
            for (std::size_t i = 0; i < ops_per_thread; ++i) {
                const auto key = static_cast<std::int64_t>(rng() % static_cast<std::uint64_t>(key_range));
                const auto op = rng() % 100;
                if (op < 70) (void)tree.contains(key);
                else if (op < 85) tree.insert(key, nullptr);
                else tree.remove(key);
            }
        });
    }
    // jthread joins on destruction
    workers.clear();
    return static_cast<double>(num_threads * ops_per_thread) / seconds_since(wall_start);
}

// ============================================================================
// Smoke tests
// ============================================================================

void test_basic_operations() {
    std::cout << "\n=== Basic Operations Test ===\n";
    pavl::parallel_avl<std::int64_t, std::int64_t> tree{4, pavl::router_strategy::static_hash};
    std::cout << "Inserting 1000 elements... ";
    for (int i = 0; i < 1000; ++i) tree.insert(i, i * 2);
    std::cout << "OK\n";
    std::cout << std::format("Size check: {} (expected 1000) {}\n",
                             tree.size(), tree.size() == 1000 ? "OK" : "FAIL");
    bool ok = true;
    for (int i = 0; i < 1000; ++i) if (!tree.contains(i)) { ok = false; break; }
    std::cout << std::format("Contains check... {}\n", ok ? "OK" : "FAIL");
    auto v = tree.get(42);
    std::cout << std::format("Get check... key=42, value={}, found={} {}\n",
                             v.value_or(0), v.has_value(),
                             (v && *v == 84) ? "OK" : "FAIL");
    const bool removed = tree.remove(42);
    const bool still = tree.contains(42);
    std::cout << std::format("Remove check... removed={}, still_exists={} {}\n",
                             removed, still, (removed && !still) ? "OK" : "FAIL");
}

void test_dynamic_scaling() {
    std::cout << "\n=== Dynamic Scaling Test ===\n";
    pavl::parallel_avl<std::int64_t, void*> tree{2, pavl::router_strategy::static_hash};
    std::cout << std::format("Inserting 500 elements with {} shards... ", tree.num_shards());
    for (int i = 0; i < 500; ++i) tree.insert(i, nullptr);
    std::cout << std::format("OK (shards: {})\n", tree.num_shards());
    std::cout << "Adding shard... ";
    const bool added = tree.add_shard();
    std::cout << std::format("{} (shards: {})\n", added ? "OK" : "FAIL", tree.num_shards());
    bool ok = true;
    for (int i = 0; i < 500; ++i) if (!tree.contains(i)) { ok = false; break; }
    std::cout << std::format("Verifying data accessibility... {}\n", ok ? "OK" : "FAIL");
    tree.force_rebalance();
    std::cout << "Force rebalanced.\n";
}

void print_header(std::string_view title) {
    std::cout << "\n+------------------------------------------------------------+\n";
    std::cout << std::format("|  {:<56}  |\n", title);
    std::cout << "+------------------------------------------------------------+\n";
}

void run_scalability_test(std::size_t num_threads, std::size_t ops_per_thread, int key_range) {
    print_header(std::format("{} Threads - Scalability Test", num_threads));
    std::cout << std::format("Total operations: {}\n", num_threads * ops_per_thread);
    std::cout << std::format("Operations per thread: {}\n", ops_per_thread);
    std::cout << std::format("Key range: {}\n\n", key_range);

    std::cout << "Baseline (single-threaded AVL):\n";
    const auto baseline = benchmark_single_avl(num_threads * ops_per_thread, key_range);
    std::cout << std::format("  Throughput: {:.0f} ops/sec\n", baseline);

    std::cout << std::format("\nParallel AVL (static_hash, {} shards):\n", num_threads);
    const auto parallel_static = benchmark_parallel_avl(num_threads, ops_per_thread,
                                                        key_range, pavl::router_strategy::static_hash);
    std::cout << std::format("  Throughput: {:.0f} ops/sec\n", parallel_static);

    std::cout << std::format("\nParallel AVL (intelligent, {} shards):\n", num_threads);
    const auto parallel_intel = benchmark_parallel_avl(num_threads, ops_per_thread,
                                                       key_range, pavl::router_strategy::intelligent);
    std::cout << std::format("  Throughput: {:.0f} ops/sec\n", parallel_intel);

    std::cout << "\n--- Analysis ---\n";
    std::cout << std::format("static_hash speedup vs baseline: {:.2f}x {}\n",
                             parallel_static / baseline,
                             parallel_static > baseline ? "[OK]" : "[SLOWER]");
    std::cout << std::format("intelligent speedup vs baseline: {:.2f}x {}\n",
                             parallel_intel / baseline,
                             parallel_intel > baseline ? "[OK]" : "[SLOWER]");
    std::cout << std::format("\nSCALABILITY (static_hash):\n  Ideal speedup:   {:.1f}x\n"
                             "  Actual speedup:  {:.2f}x\n  Efficiency:      {:.1f}%\n",
                             static_cast<double>(num_threads),
                             parallel_static / baseline,
                             (parallel_static / baseline) / static_cast<double>(num_threads) * 100);
}

void run_large_scale_benchmark() {
    print_header("Large Scale Benchmark");
    constexpr std::size_t total_ops = 1'000'000;
    constexpr int key_range = 100'000;
    std::cout << std::format("Total operations: {}\nKey range: {}\n\n", total_ops, key_range);
    std::cout << "Baseline (single-threaded AVL):\n";
    const auto baseline = benchmark_single_avl(total_ops, key_range);
    std::cout << std::format("  Throughput: {:.0f} ops/sec\n\n", baseline);
    for (std::size_t threads : {2zu, 4zu, 8zu}) {
        const auto ops = total_ops / threads;
        std::cout << std::format("Parallel AVL ({} threads, {} shards):\n", threads, threads);
        const auto th = benchmark_parallel_avl(threads, ops, key_range, pavl::router_strategy::static_hash);
        std::cout << std::format("  Throughput: {:.0f} ops/sec\n  Speedup:    {:.2f}x\n"
                                 "  Efficiency: {:.1f}%\n\n",
                                 th, th / baseline,
                                 (th / baseline) / static_cast<double>(threads) * 100);
    }
}

}  // namespace

int main() {
    print_header("Parallel AVL Tree - C++23 (Optimized)");
    std::cout << "Features:\n"
                 "  - Header-only templates (zero-cost abstraction)\n"
                 "  - Node pooling for fast allocation\n"
                 "  - Robin Hood hashing in redirect index\n"
                 "  - std::atomic statistics (lock-free reads)\n"
                 "  - alignas(64) cache-line padding\n"
                 "  - std::jthread workers, std::scoped_lock RAII\n"
                 "  - [[likely]]/[[unlikely]], [[gnu::always_inline]] on hot paths\n";

    test_basic_operations();
    test_dynamic_scaling();

    for (std::size_t threads = 2; threads <= num_cores; threads *= 2) {
        run_scalability_test(threads, 10000, 10000);
    }
    run_large_scale_benchmark();
    print_header("Benchmark Complete");
    return 0;
}
