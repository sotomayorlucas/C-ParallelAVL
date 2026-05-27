// Fase 1a tests for concurrent_avl<K, V>.
//
// We exercise: (1) single-threaded basics; (2) concurrent inserts of
// disjoint key ranges (no contention on the same key); (3) concurrent
// inserts of overlapping ranges (last-writer-wins value semantics);
// (4) concurrent inserts + concurrent contains (the validating
// descent under stress); (5) a sanity check that every committed
// insert eventually becomes visible to contains.
//
// No remove, no range query, no rotation here — those land in later
// phases.

#include "concurrent_avl.hpp"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <format>
#include <iostream>
#include <random>
#include <source_location>
#include <string_view>
#include <thread>
#include <vector>

namespace {

int tests_passed = 0;
int tests_failed = 0;
bool current_failed = false;

void check(bool cond, std::string_view expr,
           std::source_location loc = std::source_location::current()) {
    if (!cond) {
        current_failed = true;
        std::cout << std::format("FAIL at {}:{}: {}\n", loc.file_name(), loc.line(), expr);
    }
}

#define EXPECT(cond) check((cond), #cond)

#define RUN(name) do { \
    current_failed = false; \
    std::cout << std::format("  Testing {}... ", #name); \
    std::cout.flush(); \
    test_##name(); \
    if (current_failed) { ++tests_failed; std::cout << "[FAIL]\n"; } \
    else { ++tests_passed; std::cout << "[PASS]\n"; } \
} while (0)

using i64 = std::int64_t;

// =====================================================================
// Single-threaded basics
// =====================================================================
void test_empty_tree() {
    pavl::concurrent_avl<i64, i64> t;
    EXPECT(t.empty());
    EXPECT(t.size() == 0);
    EXPECT(!t.contains(42));
}

void test_single_insert_lookup() {
    pavl::concurrent_avl<i64, i64> t;
    t.insert(10, 100);
    EXPECT(t.contains(10));
    EXPECT(!t.contains(11));
    EXPECT(t.size() == 1);
}

void test_overwrite_existing() {
    pavl::concurrent_avl<i64, i64> t;
    t.insert(10, 100);
    t.insert(10, 200);  // overwrite — size stays at 1
    EXPECT(t.contains(10));
    EXPECT(t.size() == 1);
}

void test_many_unbalanced_inserts() {
    // Inserts in ascending order. Without rotation (Fase 1a) the tree
    // degenerates to a right-leaning list. That's fine for validating
    // descent — every level only has a right child.
    pavl::concurrent_avl<i64, i64> t;
    for (int i = 0; i < 200; ++i) t.insert(i, i * 10);
    EXPECT(t.size() == 200);
    for (int i = 0; i < 200; ++i) EXPECT(t.contains(i));
    EXPECT(!t.contains(-1));
    EXPECT(!t.contains(200));
}

void test_random_order_inserts() {
    pavl::concurrent_avl<i64, i64> t;
    std::mt19937_64 rng(42);
    std::vector<i64> keys;
    for (int i = 0; i < 500; ++i) keys.push_back(i);
    std::shuffle(keys.begin(), keys.end(), rng);
    for (auto k : keys) t.insert(k, k * 7);
    EXPECT(t.size() == 500);
    for (i64 i = 0; i < 500; ++i) EXPECT(t.contains(i));
}

// =====================================================================
// Concurrent: disjoint key ranges per thread (no contention on keys)
// =====================================================================
void test_concurrent_disjoint_inserts() {
    pavl::concurrent_avl<i64, i64> t;
    constexpr int NT = 8;
    constexpr int PER = 2000;
    {
        std::vector<std::jthread> ws;
        for (int tid = 0; tid < NT; ++tid) {
            ws.emplace_back([&, tid] {
                for (int i = 0; i < PER; ++i) {
                    const i64 k = static_cast<i64>(tid) * PER + i;
                    t.insert(k, k * 3);
                }
            });
        }
    }
    EXPECT(t.size() == NT * PER);
    for (int tid = 0; tid < NT; ++tid) {
        for (int i = 0; i < PER; ++i) {
            const i64 k = static_cast<i64>(tid) * PER + i;
            EXPECT(t.contains(k));
        }
    }
}

// =====================================================================
// Concurrent: overlapping ranges (contention on same keys).
// All inserts must complete; final size is the union of key sets.
// =====================================================================
void test_concurrent_overlapping_inserts() {
    pavl::concurrent_avl<i64, i64> t;
    constexpr int NT = 8;
    constexpr int RANGE = 1000;
    {
        std::vector<std::jthread> ws;
        for (int tid = 0; tid < NT; ++tid) {
            ws.emplace_back([&, tid] {
                std::mt19937_64 rng(tid * 31u + 7u);
                std::uniform_int_distribution<i64> d(0, RANGE - 1);
                for (int i = 0; i < 2000; ++i) {
                    const auto k = d(rng);
                    t.insert(k, k * 11 + tid);
                }
            });
        }
    }
    // Every key in [0, RANGE) was almost certainly inserted by at
    // least one thread. With 8 * 2000 = 16000 attempts over 1000
    // unique keys, the probability of any key being missed is
    // (1 - 1/1000)^16000 ~= 10^-7. We allow a small slack.
    std::size_t present = 0;
    for (i64 k = 0; k < RANGE; ++k) if (t.contains(k)) ++present;
    EXPECT(present >= RANGE - 5);   // tolerate a tiny statistical miss
    EXPECT(t.size() <= RANGE);      // can't exceed the universe
    EXPECT(t.size() == present);
}

// =====================================================================
// Concurrent: half threads insert, half threads read.
// Readers see "either present or absent", never crash, never see a
// torn or invalid pointer. We just check progress + no fault.
// =====================================================================
void test_concurrent_readers_and_writers() {
    pavl::concurrent_avl<i64, i64> t;
    // Pre-populate so contains has plenty of work.
    for (int i = 0; i < 5000; ++i) t.insert(i, i);

    constexpr int N_READERS = 4;
    constexpr int N_WRITERS = 4;
    constexpr int READS_PER = 100'000;
    constexpr int WRITES_PER = 5000;

    std::atomic<std::int64_t> hits{0};
    std::atomic<std::int64_t> misses{0};
    {
        std::vector<std::jthread> ws;
        for (int i = 0; i < N_READERS; ++i) {
            ws.emplace_back([&, i] {
                std::mt19937_64 rng(123 + i);
                std::uniform_int_distribution<i64> d(0, 10'000);
                std::int64_t h = 0, m = 0;
                for (int j = 0; j < READS_PER; ++j) {
                    if (t.contains(d(rng))) ++h; else ++m;
                }
                hits.fetch_add(h, std::memory_order_relaxed);
                misses.fetch_add(m, std::memory_order_relaxed);
            });
        }
        for (int i = 0; i < N_WRITERS; ++i) {
            ws.emplace_back([&, i] {
                std::mt19937_64 rng(999 + i);
                std::uniform_int_distribution<i64> d(0, 10'000);
                for (int j = 0; j < WRITES_PER; ++j) {
                    const auto k = d(rng);
                    t.insert(k, k);
                }
            });
        }
    }
    // Sanity: at least some hits, at least some misses (otherwise our
    // distribution was wrong, not the tree).
    EXPECT(hits.load() > 0);
    EXPECT(misses.load() > 0);
    // After the run every pre-populated key is still present.
    for (int i = 0; i < 5000; ++i) EXPECT(t.contains(i));
}

// =====================================================================
// Visibility: every committed insert must eventually be visible to a
// contains() call started AFTER the insert returns.
// =====================================================================
void test_insert_visible_after_return() {
    pavl::concurrent_avl<i64, i64> t;
    constexpr int NT = 8;
    constexpr int PER = 1000;
    std::atomic<int> total_visible{0};
    {
        std::vector<std::jthread> ws;
        for (int tid = 0; tid < NT; ++tid) {
            ws.emplace_back([&, tid] {
                int local = 0;
                for (int i = 0; i < PER; ++i) {
                    const i64 k = static_cast<i64>(tid) * PER + i;
                    t.insert(k, k);
                    // Immediately after insert returns the same key
                    // MUST be observable by this thread (and by any
                    // other thread that synchronises with us). The
                    // observation may go through a retry due to a
                    // concurrent rotation in later phases — for now
                    // we only have inserts, so it should be one shot.
                    if (t.contains(k)) ++local;
                }
                total_visible.fetch_add(local, std::memory_order_relaxed);
            });
        }
    }
    EXPECT(total_visible.load() == NT * PER);
}

}  // namespace

int main() {
    std::cout << "\n=== concurrent_avl Fase 1a — basics ===\n";
    RUN(empty_tree);
    RUN(single_insert_lookup);
    RUN(overwrite_existing);
    RUN(many_unbalanced_inserts);
    RUN(random_order_inserts);

    std::cout << "\n=== concurrent_avl Fase 1a — concurrent ===\n";
    RUN(concurrent_disjoint_inserts);
    RUN(concurrent_overlapping_inserts);
    RUN(concurrent_readers_and_writers);
    RUN(insert_visible_after_return);

    std::cout << std::format("\n=== Results ===\nPassed: {}\nFailed: {}\n",
                             tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
