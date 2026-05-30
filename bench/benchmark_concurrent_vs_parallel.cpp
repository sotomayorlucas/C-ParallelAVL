// Benchmark: concurrent_avl (Bronson) vs parallel_avl (sharded)
//
// Three workloads at thread counts 1, 2, 4, 8:
//   1. read_only      (100% contains)
//   2. mixed_70_15_15 (70% contains, 15% insert, 15% remove)
//   3. write_heavy    (20% contains, 40% insert, 40% remove)
//
// For each scenario the tree is pre-populated with `range` keys, then
// `threads * ops_per_thread` operations are spread across the workers.
// Throughput is total ops / wall-clock seconds.
//
// concurrent_avl is the single-tree Bronson optimistic AVL; reads are
// lock-free, writes use fine-grained per-node locks.
// parallel_avl is the sharded baseline; each shard is a sequential AVL
// behind a std::mutex; the router maps the hashed key to one shard.

#include "concurrent_avl.hpp"
#include "parallel_avl.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <format>
#include <iostream>
#include <random>
#include <string_view>
#include <thread>
#include <vector>

namespace {

using clk = std::chrono::steady_clock;
using i64 = std::int64_t;

// ---------------------------------------------------------------------
// Workload runner — templated on the tree type so we hit the same path
// for both. Both trees expose insert(K,V), contains(K), remove(K).
// ---------------------------------------------------------------------
template <typename Tree>
double run_workload(Tree& t, int threads, int ops_per_thread,
                    int range, int read_pct, int insert_pct) {
    std::atomic<int> gate{threads};
    std::atomic<bool> go{false};

    const auto t0_setup = clk::now();
    {
        std::vector<std::jthread> ws;
        ws.reserve(threads);
        for (int tid = 0; tid < threads; ++tid) {
            ws.emplace_back([&, tid]() {
                std::mt19937_64 rng(static_cast<std::uint64_t>(tid) * 7919ULL + 1);
                std::uniform_int_distribution<i64> kd(0, range - 1);
                std::uniform_int_distribution<int> od(0, 99);
                if (gate.fetch_sub(1, std::memory_order_acq_rel) == 1) {
                    go.store(true, std::memory_order_release);
                }
                while (!go.load(std::memory_order_acquire)) { /* spin */ }
                for (int i = 0; i < ops_per_thread; ++i) {
                    const auto k = kd(rng);
                    const auto op = od(rng);
                    if (op < read_pct) {
                        (void)t.contains(k);
                    } else if (op < read_pct + insert_pct) {
                        t.insert(k, k);
                    } else {
                        (void)t.remove(k);
                    }
                }
            });
        }
        // jthreads join here.
    }
    const auto dt = std::chrono::duration<double>(clk::now() - t0_setup).count();
    const auto total_ops = static_cast<double>(threads) * ops_per_thread;
    return total_ops / std::max(dt, 1e-9);
}

// Pre-populate a tree with `range` ascending keys (single thread).
template <typename Tree>
void pre_populate(Tree& t, int range) {
    for (int i = 0; i < range; ++i) t.insert(static_cast<i64>(i), static_cast<i64>(i));
}

// ---------------------------------------------------------------------
// One scenario row: builds two fresh trees, runs the workload on each,
// returns the pair of throughputs.
// ---------------------------------------------------------------------
struct row {
    double conc_ops_s;     // concurrent_avl
    double par_ops_s;      // parallel_avl
};

[[nodiscard]] row run_scenario(int threads, int ops, int range,
                               int read_pct, int insert_pct, int num_shards) {
    double conc_throughput = 0;
    {
        pavl::concurrent_avl<i64, i64> t;
        pre_populate(t, range);
        conc_throughput = run_workload(t, threads, ops, range, read_pct, insert_pct);
    }
    double par_throughput = 0;
    {
        pavl::parallel_avl<i64, i64> t{static_cast<std::size_t>(num_shards),
                                       pavl::router_strategy::static_hash};
        pre_populate(t, range);
        par_throughput = run_workload(t, threads, ops, range, read_pct, insert_pct);
    }
    return {conc_throughput, par_throughput};
}

void print_header(std::string_view title) {
    std::cout << "\n";
    std::cout << "+------------------------------------------------------------+\n";
    std::cout << std::format("|  {:<56}  |\n", title);
    std::cout << "+------------------------------------------------------------+\n";
}

void print_row(int threads, row r) {
    const auto ratio = r.par_ops_s > 0 ? r.conc_ops_s / r.par_ops_s : 0.0;
    std::cout << std::format("  {:>2} threads  |  concurrent_avl {:>10.0f} ops/s  |  parallel_avl {:>10.0f} ops/s  |  ratio {:>5.2f}x\n",
                             threads, r.conc_ops_s, r.par_ops_s, ratio);
}

void run_sweep(std::string_view title, int ops_per_thread, int range,
               int read_pct, int insert_pct) {
    print_header(title);
    std::cout << std::format("  ops/thread = {},  key range = {},  workload = {}r/{}i/{}d\n",
                             ops_per_thread, range, read_pct, insert_pct,
                             100 - read_pct - insert_pct);
    std::cout << "\n";
    for (int threads : {1, 2, 4, 8}) {
        const auto r = run_scenario(threads, ops_per_thread, range,
                                    read_pct, insert_pct, threads);
        print_row(threads, r);
    }
}

}  // namespace

int main() {
    std::cout << "concurrent_avl (Bronson)  vs  parallel_avl (sharded)\n";
    std::cout << "=====================================================\n";

    // Smaller ops at higher write fractions because they take longer
    // per op under contention.
    run_sweep("Read-only (100% contains)",
              /*ops_per_thread=*/200'000, /*range=*/100'000,
              /*read_pct=*/100, /*insert_pct=*/0);

    run_sweep("Mixed 70/15/15",
              /*ops_per_thread=*/100'000, /*range=*/50'000,
              /*read_pct=*/70, /*insert_pct=*/15);

    run_sweep("Write-heavy (20% contains, 40% insert, 40% remove)",
              /*ops_per_thread=*/40'000, /*range=*/10'000,
              /*read_pct=*/20, /*insert_pct=*/40);

    std::cout << "\nratio = concurrent_avl throughput / parallel_avl throughput\n";
    std::cout << "ratio > 1 means concurrent_avl is faster.\n";
    return 0;
}
