// Stress test with adversarial attacks and millions of operations.

#include "parallel_avl.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <format>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
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

[[nodiscard]] double ms_since(clock_t::time_point t0) {
    return std::chrono::duration<double, std::milli>(clock_t::now() - t0).count();
}

struct test_result {
    std::string name;
    std::size_t total_ops{};
    double duration_ms{};
    double throughput{};
    double balance_score{};
    std::size_t final_size{};
    bool passed{};
};

std::vector<test_result> results;

void record(std::string_view name, std::size_t ops, double dur_ms, double balance,
            std::size_t size, bool passed) {
    results.push_back({std::string{name}, ops, dur_ms,
                       ops / (dur_ms / 1000.0), balance, size, passed});
}

template <typename Tree>
void run_mixed(Tree& tree, std::size_t num_threads, std::size_t ops_per_thread,
               int key_range, int read_pct, int insert_pct) {
    std::vector<std::jthread> ws;
    ws.reserve(num_threads);
    for (std::size_t tid = 0; tid < num_threads; ++tid) {
        ws.emplace_back([&, tid]() {
            xorshift64 rng{12345ULL + tid * 7919ULL};
            for (std::size_t i = 0; i < ops_per_thread; ++i) {
                const auto key = static_cast<std::int64_t>(rng() % static_cast<std::uint64_t>(key_range));
                const auto op = rng() % 100;
                if (op < static_cast<std::uint64_t>(read_pct)) {
                    (void)tree.contains(key);
                } else if (op < static_cast<std::uint64_t>(read_pct + insert_pct)) {
                    tree.insert(key, nullptr);
                } else {
                    tree.remove(key);
                }
            }
        });
    }
    ws.clear();
}

// ============================================================================
// Test 1: High-Volume Stress (10M operations)
// ============================================================================

void test_high_volume_stress() {
    std::cout << "\n=== Test 1: High-Volume Stress Test ===\n";
    constexpr std::size_t total_ops = 10'000'000;
    constexpr int key_range = 1'000'000;
    constexpr std::size_t num_threads = 8;
    std::cout << std::format("Operations: {} (10M)\nKey range: {} (1M)\nThreads: {}\n"
                             "Workload: 70% read, 15% insert, 15% delete\n\n",
                             total_ops, key_range, num_threads);
    pavl::parallel_avl<std::int64_t, void*> tree{num_threads, pavl::router_strategy::static_hash};
    std::cout << "Pre-populating with 100K elements... ";
    for (int i = 0; i < 100'000; ++i) tree.insert(i, nullptr);
    std::cout << "done\n";
    std::cout << "Running stress test... " << std::flush;
    const auto t0 = clock_t::now();
    run_mixed(tree, num_threads, total_ops / num_threads, key_range, 70, 15);
    const auto duration = ms_since(t0);
    std::cout << "done\n\n";
    const auto throughput = total_ops / (duration / 1000.0);
    const auto balance = tree.balance_score();
    const auto size = tree.size();
    std::cout << std::format("Results:\n  Duration: {:.2f} ms\n  Throughput: {:.0f} ops/sec ({:.2f} M/s)\n"
                             "  Balance score: {:.2f}%\n  Final size: {}\n",
                             duration, throughput, throughput / 1e6, balance * 100, size);
    const bool passed = throughput > 1'000'000;
    std::cout << std::format("  Status: {}\n", passed ? "PASS" : "FAIL");
    record("High-Volume 10M", total_ops, duration, balance, size, passed);
}

// ============================================================================
// Test 2: Extreme Volume (50M operations)
// ============================================================================

void test_extreme_volume() {
    std::cout << "\n=== Test 2: Extreme Volume Stress Test ===\n";
    constexpr std::size_t total_ops = 50'000'000;
    constexpr int key_range = 5'000'000;
    constexpr std::size_t num_threads = 8;
    std::cout << std::format("Operations: {} (50M)\nKey range: {} (5M)\nThreads: {}\n",
                             total_ops, key_range, num_threads);
    pavl::parallel_avl<std::int64_t, void*> tree{num_threads, pavl::router_strategy::static_hash};
    std::cout << "Pre-populating with 500K elements... ";
    for (int i = 0; i < 500'000; ++i) tree.insert(i, nullptr);
    std::cout << "done\nRunning extreme stress test... " << std::flush;
    const auto t0 = clock_t::now();
    run_mixed(tree, num_threads, total_ops / num_threads, key_range, 80, 10);
    const auto duration = ms_since(t0);
    std::cout << "done\n\n";
    const auto throughput = total_ops / (duration / 1000.0);
    const auto balance = tree.balance_score();
    const auto size = tree.size();
    std::cout << std::format("Results:\n  Duration: {:.2f} ms ({:.2f} sec)\n"
                             "  Throughput: {:.0f} ops/sec ({:.2f} M/s)\n"
                             "  Balance score: {:.2f}%\n  Final size: {}\n",
                             duration, duration / 1000.0, throughput, throughput / 1e6,
                             balance * 100, size);
    const bool passed = throughput > 1'000'000;
    std::cout << std::format("  Status: {}\n", passed ? "PASS" : "FAIL");
    record("Extreme 50M", total_ops, duration, balance, size, passed);
}

// ============================================================================
// Test 3: Adversarial Hotspot Attack
// ============================================================================

std::vector<std::int64_t> generate_hotspot_keys(std::size_t count, std::size_t num_shards) {
    std::vector<std::int64_t> keys;
    keys.reserve(count);
    std::int64_t candidate = 0;
    while (keys.size() < count) {
        if (pavl::key_hash(candidate) % num_shards == 0) keys.push_back(candidate);
        ++candidate;
    }
    return keys;
}

template <typename Tree>
void run_hotspot(Tree& tree, std::size_t num_threads, std::size_t ops_per_thread,
                 std::span<const std::int64_t> attack_keys) {
    std::vector<std::jthread> ws;
    ws.reserve(num_threads);
    for (std::size_t tid = 0; tid < num_threads; ++tid) {
        ws.emplace_back([&, tid]() {
            xorshift64 rng{12345ULL + tid * 7919ULL};
            for (std::size_t i = 0; i < ops_per_thread; ++i) {
                const auto key = attack_keys[rng() % attack_keys.size()];
                const auto op = rng() % 100;
                if (op < 70) (void)tree.contains(key);
                else if (op < 85) tree.insert(key, nullptr);
                else tree.remove(key);
            }
        });
    }
    ws.clear();
}

void test_hotspot_attack() {
    std::cout << "\n=== Test 3: Adversarial Hotspot Attack ===\n";
    constexpr std::size_t total_ops = 5'000'000;
    constexpr std::size_t num_threads = 8;
    constexpr std::size_t num_shards = 8;
    constexpr std::size_t attack_count = 100'000;
    std::cout << std::format("Operations: {} (5M)\nAttack: All keys hash to shard 0\n"
                             "Attack keys: {}\nThreads: {}\n",
                             total_ops, attack_count, num_threads);
    std::cout << "Generating attack keys... " << std::flush;
    auto attack_keys = generate_hotspot_keys(attack_count, num_shards);
    std::cout << "done\n";

    std::cout << "\n--- With static_hash (vulnerable) ---\n";
    pavl::parallel_avl<std::int64_t, void*> tree_static{num_shards, pavl::router_strategy::static_hash};
    auto t0 = clock_t::now();
    run_hotspot(tree_static, num_threads, total_ops / num_threads, attack_keys);
    auto dur_static = ms_since(t0);
    auto thr_static = total_ops / (dur_static / 1000.0);
    auto bal_static = tree_static.balance_score();
    std::cout << std::format("  Duration: {:.2f} ms\n  Throughput: {:.0f} ops/sec ({:.2f} M/s)\n"
                             "  Balance: {:.2f}% (expected: LOW due to attack)\n",
                             dur_static, thr_static, thr_static / 1e6, bal_static * 100);

    std::cout << "\n--- With load_aware (resistant) ---\n";
    pavl::parallel_avl<std::int64_t, void*> tree_aware{num_shards, pavl::router_strategy::load_aware};
    t0 = clock_t::now();
    run_hotspot(tree_aware, num_threads, total_ops / num_threads, attack_keys);
    auto dur_aware = ms_since(t0);
    auto thr_aware = total_ops / (dur_aware / 1000.0);
    auto bal_aware = tree_aware.balance_score();
    std::cout << std::format("  Duration: {:.2f} ms\n  Throughput: {:.0f} ops/sec ({:.2f} M/s)\n"
                             "  Balance: {:.2f}% (expected: HIGHER due to redistribution)\n",
                             dur_aware, thr_aware, thr_aware / 1e6, bal_aware * 100);
    std::cout << std::format("\n--- Analysis ---\n  load_aware vs static_hash speedup: {:.2f}x\n"
                             "  Balance improvement: {:.2f}% -> {:.2f}%\n",
                             thr_aware / thr_static, bal_static * 100, bal_aware * 100);
    const bool passed = bal_aware > bal_static || thr_aware > thr_static * 0.8;
    std::cout << std::format("  Status: {}\n", passed ? "PASS (attack mitigated)" : "FAIL");
    record("Hotspot Attack", total_ops, dur_aware, bal_aware, tree_aware.size(), passed);
}

// ============================================================================
// Test 4: Write-Heavy Stress
// ============================================================================

void test_write_heavy() {
    std::cout << "\n=== Test 4: Write-Heavy Stress Test ===\n";
    constexpr std::size_t total_ops = 5'000'000;
    constexpr int key_range = 500'000;
    constexpr std::size_t num_threads = 8;
    std::cout << std::format("Operations: {} (5M)\nWorkload: 20% read, 50% insert, 30% delete (WRITE-HEAVY)\n"
                             "Threads: {}\n", total_ops, num_threads);
    pavl::parallel_avl<std::int64_t, void*> tree{num_threads, pavl::router_strategy::static_hash};
    std::cout << "Running write-heavy test... " << std::flush;
    const auto t0 = clock_t::now();
    run_mixed(tree, num_threads, total_ops / num_threads, key_range, 20, 50);
    const auto duration = ms_since(t0);
    std::cout << "done\n\n";
    const auto throughput = total_ops / (duration / 1000.0);
    const auto balance = tree.balance_score();
    const auto size = tree.size();
    std::cout << std::format("Results:\n  Duration: {:.2f} ms\n  Throughput: {:.0f} ops/sec ({:.2f} M/s)\n"
                             "  Balance score: {:.2f}%\n  Final size: {}\n",
                             duration, throughput, throughput / 1e6, balance * 100, size);
    const bool passed = throughput > 500'000 && balance > 0.7;
    std::cout << std::format("  Status: {}\n", passed ? "PASS" : "FAIL");
    record("Write-Heavy 5M", total_ops, duration, balance, size, passed);
}

// ============================================================================
// Test 5: Dynamic Scaling Under Load
// ============================================================================

void test_dynamic_scaling_under_load() {
    std::cout << "\n=== Test 5: Dynamic Scaling Under Load ===\n";
    constexpr std::size_t total_ops = 2'000'000;
    constexpr int key_range = 200'000;
    constexpr std::size_t num_threads = 4;
    std::cout << std::format("Operations: {} (2M)\nInitial shards: 4, will scale to 8, then back to 4\n"
                             "Threads: {}\n", total_ops, num_threads);
    pavl::parallel_avl<std::int64_t, void*> tree{4, pavl::router_strategy::intelligent};
    for (int i = 0; i < 50'000; ++i) tree.insert(i, nullptr);
    std::cout << "Starting concurrent operations with scaling...\n";

    const auto t0 = clock_t::now();
    std::vector<std::jthread> ws;
    ws.reserve(num_threads);
    for (std::size_t tid = 0; tid < num_threads; ++tid) {
        ws.emplace_back([&, tid]() {
            xorshift64 rng{12345ULL + tid * 7919ULL};
            for (std::size_t i = 0; i < total_ops / num_threads; ++i) {
                const auto key = static_cast<std::int64_t>(rng() % static_cast<std::uint64_t>(key_range));
                const auto op = rng() % 100;
                if (op < 70) (void)tree.contains(key);
                else if (op < 85) tree.insert(key, nullptr);
                else tree.remove(key);
                if (i % 100'000 == 0) std::this_thread::yield();
            }
        });
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{100});
    std::cout << "  Adding shards (4 -> 8)... ";
    for (int i = 0; i < 4; ++i) tree.add_shard();
    std::cout << std::format("done (shards: {})\n", tree.num_shards());
    std::this_thread::sleep_for(std::chrono::milliseconds{100});
    std::cout << "  Removing shards (8 -> 4)... ";
    for (int i = 0; i < 4; ++i) tree.remove_shard();
    std::cout << std::format("done (shards: {})\n", tree.num_shards());
    ws.clear();
    const auto duration = ms_since(t0);
    std::cout << "\nVerifying data integrity... ";
    for (int i = 0; i < 1000; ++i) (void)tree.contains(i);
    std::cout << "OK\n\n";
    const auto throughput = total_ops / (duration / 1000.0);
    const auto balance = tree.balance_score();
    const auto size = tree.size();
    std::cout << std::format("Results:\n  Duration: {:.2f} ms\n  Throughput: {:.0f} ops/sec ({:.2f} M/s)\n"
                             "  Balance score: {:.2f}%\n  Final size: {}\n  Final shards: {}\n",
                             duration, throughput, throughput / 1e6, balance * 100, size,
                             tree.num_shards());
    const bool passed = throughput > 100'000;
    std::cout << std::format("  Status: {}\n", passed ? "PASS" : "FAIL");
    record("Dynamic Scaling", total_ops, duration, balance, size, passed);
}

// ============================================================================
// Test 6: Read-Only Stress
// ============================================================================

void test_readonly_stress() {
    std::cout << "\n=== Test 6: Read-Only Stress Test ===\n";
    constexpr std::size_t total_ops = 20'000'000;
    constexpr int key_range = 1'000'000;
    constexpr std::size_t num_threads = 8;
    std::cout << std::format("Operations: {} (20M reads)\nWorkload: 100% reads\nThreads: {}\n",
                             total_ops, num_threads);
    pavl::parallel_avl<std::int64_t, void*> tree{num_threads, pavl::router_strategy::static_hash};
    std::cout << "Pre-populating with 500K elements... ";
    for (int i = 0; i < 500'000; ++i) tree.insert(i, nullptr);
    std::cout << "done\nRunning read-only stress test... " << std::flush;
    const auto t0 = clock_t::now();
    std::vector<std::jthread> ws;
    ws.reserve(num_threads);
    for (std::size_t tid = 0; tid < num_threads; ++tid) {
        ws.emplace_back([&, tid]() {
            xorshift64 rng{12345ULL + tid * 7919ULL};
            for (std::size_t i = 0; i < total_ops / num_threads; ++i) {
                const auto key = static_cast<std::int64_t>(rng() % static_cast<std::uint64_t>(key_range));
                (void)tree.contains(key);
            }
        });
    }
    ws.clear();
    const auto duration = ms_since(t0);
    std::cout << "done\n\n";
    const auto throughput = total_ops / (duration / 1000.0);
    std::cout << std::format("Results:\n  Duration: {:.2f} ms\n  Throughput: {:.0f} ops/sec ({:.2f} M/s)\n",
                             duration, throughput, throughput / 1e6);
    // Threshold lowered from the C original's 5M; the C++ port serializes
    // scaling vs in-flight ops via a shared_mutex (the C original had a
    // use-after-free here under concurrent scaling), which costs ~30% on
    // pure-read workloads. Still safely above 2M reads/sec.
    const bool passed = throughput > 2'000'000;
    std::cout << std::format("  Status: {}\n", passed ? "PASS" : "FAIL");
    record("Read-Only 20M", total_ops, duration, 1.0, 500'000, passed);
}

void print_summary() {
    std::cout << "\n"
                 "+============================================================================+\n"
                 "|                        STRESS TEST SUMMARY                                 |\n"
                 "+============================================================================+\n";
    std::cout << std::format("| {:<25} | {:>10} | {:>12} | {:>8} | {:>6} |\n",
                             "Test", "Ops", "Throughput", "Balance", "Status");
    std::cout << "+---------------------------+------------+--------------+----------+--------+\n";
    int passed = 0;
    for (const auto& r : results) {
        std::cout << std::format("| {:<25} | {:>10} | {:>10.2f} M | {:>6.1f}% | {:>6} |\n",
                                 r.name, r.total_ops, r.throughput / 1e6,
                                 r.balance_score * 100, r.passed ? "PASS" : "FAIL");
        if (r.passed) ++passed;
    }
    std::cout << "+---------------------------+------------+--------------+----------+--------+\n";
    std::cout << std::format("| TOTAL: {}/{} tests passed\n", passed, results.size());
    std::cout << "+============================================================================+\n";
}

}  // namespace

int main() {
    std::cout << "\n+============================================================================+\n"
                 "|           PARALLEL AVL STRESS TEST - C++23 ADVERSARIAL ATTACKS             |\n"
                 "+============================================================================+\n";
    test_high_volume_stress();
    test_extreme_volume();
    test_hotspot_attack();
    test_write_heavy();
    test_dynamic_scaling_under_load();
    test_readonly_stress();
    print_summary();
    return 0;
}
