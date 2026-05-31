// Throughput micro-benchmark for concurrent_avl<i64, i64>.
//
// Three workloads at thread counts 1, 2, 4, 8:
//   1. read_only      (100% contains)
//   2. mixed_70_15_15 (70% contains, 15% insert, 15% remove)
//   3. write_heavy    (20% contains, 40% insert, 40% remove)
//
// For each scenario the tree is pre-populated with `range` keys, then
// `threads * ops_per_thread` operations are spread across the workers.
// Throughput is total ops / wall-clock seconds.

#include "concurrent_avl.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <format>
#include <iostream>
#include <random>
#include <string_view>
#include <thread>
#include <vector>

namespace {

using clk = std::chrono::steady_clock;
using i64 = std::int64_t;

double run_workload(pavl::concurrent_avl<i64, i64>& t,
                    int threads, int ops_per_thread,
                    int range, int read_pct, int insert_pct) {
    std::atomic<int>  gate{threads};
    std::atomic<bool> go{false};

    const auto t0 = clk::now();
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
    }
    const auto dt = std::chrono::duration<double>(clk::now() - t0).count();
    return static_cast<double>(threads) * ops_per_thread / std::max(dt, 1e-9);
}

void pre_populate(pavl::concurrent_avl<i64, i64>& t, int range) {
    for (int i = 0; i < range; ++i) t.insert(static_cast<i64>(i), static_cast<i64>(i));
}

void run_sweep(std::string_view title, int ops_per_thread, int range,
               int read_pct, int insert_pct) {
    std::cout << "\n";
    std::cout << "+------------------------------------------------------------+\n";
    std::cout << std::format("|  {:<56}  |\n", title);
    std::cout << "+------------------------------------------------------------+\n";
    std::cout << std::format("  ops/thread = {}, key range = {}, workload = {}r/{}i/{}d\n",
                             ops_per_thread, range, read_pct, insert_pct,
                             100 - read_pct - insert_pct);
    std::cout << "\n";
    for (int threads : {1, 2, 4, 8}) {
        pavl::concurrent_avl<i64, i64> t;
        pre_populate(t, range);
        const auto ops = run_workload(t, threads, ops_per_thread, range,
                                      read_pct, insert_pct);
        std::cout << std::format("  {:>2} threads  |  {:>10.0f} ops/s\n",
                                 threads, ops);
    }
}

}  // namespace

int main() {
    std::cout << "concurrent_avl<i64, i64> — Bronson optimistic AVL\n";
    std::cout << "==================================================\n";

    run_sweep("Read-only (100% contains)",
              /*ops_per_thread=*/200'000, /*range=*/100'000,
              /*read_pct=*/100, /*insert_pct=*/0);

    run_sweep("Mixed 70/15/15",
              /*ops_per_thread=*/100'000, /*range=*/50'000,
              /*read_pct=*/70, /*insert_pct=*/15);

    run_sweep("Write-heavy (20% contains, 40% insert, 40% remove)",
              /*ops_per_thread=*/40'000, /*range=*/10'000,
              /*read_pct=*/20, /*insert_pct=*/40);

    return 0;
}
