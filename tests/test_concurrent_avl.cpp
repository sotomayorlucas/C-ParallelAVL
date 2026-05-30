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
// =====================================================================
// Fase 1b: AVL balance (Bronson concurrent rotations).
// =====================================================================
void test_avl_balance_ascending() {
    pavl::concurrent_avl<i64, i64> t;
    for (int i = 0; i < 1000; ++i) t.insert(i, i);
    EXPECT(t.size() == 1000);
    EXPECT(t.debug_check_avl_invariants());
    // AVL bound: 1.44 * log2(n+2). For n=1000, that's ~15.
    EXPECT(t.debug_root_height() <= 16);
    for (i64 i = 0; i < 1000; ++i) EXPECT(t.contains(i));
}

void test_avl_balance_descending() {
    pavl::concurrent_avl<i64, i64> t;
    for (int i = 999; i >= 0; --i) t.insert(i, i);
    EXPECT(t.size() == 1000);
    EXPECT(t.debug_check_avl_invariants());
    EXPECT(t.debug_root_height() <= 16);
    for (i64 i = 0; i < 1000; ++i) EXPECT(t.contains(i));
}

void test_avl_balance_random() {
    pavl::concurrent_avl<i64, i64> t;
    std::mt19937_64 rng(42);
    std::vector<i64> keys;
    for (int i = 0; i < 5000; ++i) keys.push_back(i);
    std::shuffle(keys.begin(), keys.end(), rng);
    for (auto k : keys) t.insert(k, k);
    EXPECT(t.size() == 5000);
    EXPECT(t.debug_check_avl_invariants());
    EXPECT(t.debug_root_height() <= 20);  // 1.44 * log2(5000) ≈ 17.6
    for (i64 i = 0; i < 5000; ++i) EXPECT(t.contains(i));
}

// =====================================================================
// Fase 2a: remove() with logical (routing) deletion.
// =====================================================================
void test_remove_basic() {
    pavl::concurrent_avl<i64, i64> t;
    t.insert(10, 100);
    t.insert(20, 200);
    EXPECT(t.size() == 2);
    EXPECT(t.contains(10));
    EXPECT(t.remove(10));
    EXPECT(!t.contains(10));
    EXPECT(t.size() == 1);
}

void test_remove_absent() {
    pavl::concurrent_avl<i64, i64> t;
    t.insert(10, 100);
    EXPECT(!t.remove(99));        // never inserted
    EXPECT(t.contains(10));
    EXPECT(t.size() == 1);
    EXPECT(t.remove(10));
    EXPECT(!t.remove(10));        // already routing
}

void test_remove_reactivation() {
    pavl::concurrent_avl<i64, i64> t;
    t.insert(42, 100);
    EXPECT(t.remove(42));
    EXPECT(!t.contains(42));
    EXPECT(t.size() == 0);
    t.insert(42, 200);            // reactivates the routing node
    EXPECT(t.contains(42));
    EXPECT(t.size() == 1);
}

void test_remove_many() {
    pavl::concurrent_avl<i64, i64> t;
    for (int i = 0; i < 200; ++i) t.insert(i, i * 10);
    EXPECT(t.size() == 200);
    for (int i = 0; i < 200; i += 2) EXPECT(t.remove(i));
    EXPECT(t.size() == 100);
    for (int i = 0; i < 200; ++i) {
        if (i % 2 == 0) EXPECT(!t.contains(i));
        else            EXPECT(t.contains(i));
    }
}

void test_concurrent_remove() {
    pavl::concurrent_avl<i64, i64> t;
    constexpr int N = 1000;
    for (int i = 0; i < N; ++i) t.insert(i, i);
    EXPECT(t.size() == N);

    constexpr int NT = 8;
    {
        std::vector<std::jthread> ws;
        for (int tid = 0; tid < NT; ++tid) {
            ws.emplace_back([&, tid] {
                // Each thread removes a disjoint slice.
                const int chunk = N / NT;
                const int lo = tid * chunk;
                const int hi = (tid == NT - 1) ? N : lo + chunk;
                for (int i = lo; i < hi; ++i) (void)t.remove(i);
            });
        }
    }
    EXPECT(t.size() == 0);
    for (int i = 0; i < N; ++i) EXPECT(!t.contains(i));
}

void test_concurrent_insert_remove_mix() {
    pavl::concurrent_avl<i64, i64> t;
    constexpr int NT = 8;
    constexpr int OPS = 1000;
    // Half threads insert into [0, 500), half remove from [0, 500).
    {
        std::vector<std::jthread> ws;
        for (int tid = 0; tid < NT; ++tid) {
            ws.emplace_back([&, tid] {
                std::mt19937_64 rng(tid * 31u + 11u);
                std::uniform_int_distribution<i64> d(0, 499);
                for (int i = 0; i < OPS; ++i) {
                    const auto k = d(rng);
                    if (tid < NT / 2) t.insert(k, 0);
                    else              (void)t.remove(k);
                }
            });
        }
    }
    // No correctness predicate beyond "didn't crash, size matches
    // contains count" — under random mixed ops we can't predict the
    // final state.
    std::size_t found = 0;
    for (int k = 0; k < 500; ++k) if (t.contains(k)) ++found;
    EXPECT(found == t.size());
}

void test_avl_balance_concurrent() {
    pavl::concurrent_avl<i64, i64> t;
    constexpr int NT = 8;
    constexpr int PER = 2000;
    {
        std::vector<std::jthread> ws;
        for (int tid = 0; tid < NT; ++tid) {
            ws.emplace_back([&, tid] {
                for (int i = 0; i < PER; ++i) {
                    t.insert(static_cast<i64>(tid) * PER + i, 0);
                }
            });
        }
    }
    EXPECT(t.size() == NT * PER);
    EXPECT(t.debug_check_avl_invariants());
    EXPECT(t.debug_root_height() <= 22);  // 1.44 * log2(16000) ≈ 20
    for (i64 k = 0; k < NT * PER; ++k) EXPECT(t.contains(k));
}

// =====================================================================
// Fase 4: insert_or_assign / try_insert / try_emplace / get
// =====================================================================
void test_insert_or_assign_is_overwrite() {
    pavl::concurrent_avl<i64, i64> t;
    t.insert_or_assign(10, 100);
    EXPECT(t.size() == 1);
    EXPECT(t.contains(10));
    t.insert_or_assign(10, 999);  // overwrite
    EXPECT(t.size() == 1);
    auto v = t.get(10);
    EXPECT(v.has_value());
    EXPECT(*v == 999);
}

void test_try_insert_new_key() {
    pavl::concurrent_avl<i64, i64> t;
    EXPECT(t.try_insert(7, 42));
    EXPECT(t.contains(7));
    EXPECT(t.size() == 1);
    auto v = t.get(7);
    EXPECT(v.has_value());
    EXPECT(*v == 42);
}

void test_try_insert_existing_key_no_overwrite() {
    pavl::concurrent_avl<i64, i64> t;
    t.insert(7, 42);
    EXPECT(!t.try_insert(7, 999));   // already present → false
    EXPECT(t.size() == 1);
    auto v = t.get(7);
    EXPECT(v.has_value());
    EXPECT(*v == 42);                // value untouched
}

void test_try_insert_reactivates_routing() {
    pavl::concurrent_avl<i64, i64> t;
    t.insert(7, 42);
    EXPECT(t.remove(7));
    EXPECT(t.size() == 0);
    // Key may still be present in the BST as a routing node. try_insert
    // should treat it as absent from the live set and return true,
    // reactivating it with the new value.
    EXPECT(t.try_insert(7, 99));
    EXPECT(t.size() == 1);
    auto v = t.get(7);
    EXPECT(v.has_value());
    EXPECT(*v == 99);
}

void test_try_emplace_new_key() {
    pavl::concurrent_avl<i64, i64> t;
    EXPECT(t.try_emplace(3, 333));
    EXPECT(t.contains(3));
    auto v = t.get(3);
    EXPECT(v.has_value());
    EXPECT(*v == 333);
}

void test_try_emplace_existing_key() {
    pavl::concurrent_avl<i64, i64> t;
    t.insert(3, 333);
    EXPECT(!t.try_emplace(3, 999));
    auto v = t.get(3);
    EXPECT(v.has_value());
    EXPECT(*v == 333);
}

void test_get_absent_returns_nullopt() {
    pavl::concurrent_avl<i64, i64> t;
    EXPECT(!t.get(42).has_value());
    t.insert(10, 100);
    EXPECT(!t.get(11).has_value());
}

void test_get_after_remove_returns_nullopt() {
    pavl::concurrent_avl<i64, i64> t;
    t.insert(10, 100);
    EXPECT(t.get(10).has_value());
    EXPECT(t.remove(10));
    EXPECT(!t.get(10).has_value());
}

void test_concurrent_try_insert_one_winner_per_key() {
    // Threads racing on try_insert for the same key set. For any
    // given key, exactly one try_insert across all threads should
    // return true; the rest see an already-live entry and return
    // false. The accounting predicate is: size == sum-of-wins.
    //
    // Density (NT * OPS_PER / RANGE) is kept comparable to the other
    // concurrent tests on this 4-core box — driving it higher just
    // amplifies the Bronson rotation-retry tail without testing
    // anything new.
    pavl::concurrent_avl<i64, i64> t;
    constexpr int NT = 4;
    constexpr int RANGE = 500;
    constexpr int OPS_PER = 1500;
    std::atomic<int> wins{0};
    {
        std::vector<std::jthread> ws;
        for (int tid = 0; tid < NT; ++tid) {
            ws.emplace_back([&, tid] {
                std::mt19937_64 rng(tid * 31u + 5u);
                std::uniform_int_distribution<i64> d(0, RANGE - 1);
                int local_wins = 0;
                for (int i = 0; i < OPS_PER; ++i) {
                    const auto k = d(rng);
                    if (t.try_insert(k, k * 10 + tid)) ++local_wins;
                }
                wins.fetch_add(local_wins, std::memory_order_relaxed);
            });
        }
    }
    EXPECT(static_cast<int>(t.size()) == wins.load());
    EXPECT(t.size() <= RANGE);
}

void test_concurrent_get_under_writers() {
    // Readers using get() must see either the previous or the new
    // value, never garbage. We only assert non-crash + lifecycle
    // (every pre-populated key is still gettable after the run).
    pavl::concurrent_avl<i64, i64> t;
    for (int i = 0; i < 2000; ++i) t.insert(i, i);

    constexpr int N_READERS = 2;
    constexpr int N_WRITERS = 2;
    constexpr int READS_PER = 20'000;
    constexpr int WRITES_PER = 2000;

    std::atomic<std::int64_t> hits{0};
    {
        std::vector<std::jthread> ws;
        for (int i = 0; i < N_READERS; ++i) {
            ws.emplace_back([&, i] {
                std::mt19937_64 rng(321 + i);
                std::uniform_int_distribution<i64> d(0, 5000);
                std::int64_t h = 0;
                for (int j = 0; j < READS_PER; ++j) {
                    if (t.get(d(rng)).has_value()) ++h;
                }
                hits.fetch_add(h, std::memory_order_relaxed);
            });
        }
        for (int i = 0; i < N_WRITERS; ++i) {
            ws.emplace_back([&, i] {
                std::mt19937_64 rng(654 + i);
                std::uniform_int_distribution<i64> d(0, 5000);
                for (int j = 0; j < WRITES_PER; ++j) {
                    const auto k = d(rng);
                    t.insert(k, k * 2);
                }
            });
        }
    }
    EXPECT(hits.load() > 0);
    for (int i = 0; i < 2000; ++i) EXPECT(t.get(i).has_value());
}

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

    std::cout << "\n=== concurrent_avl Fase 1b — balance ===\n";
    RUN(avl_balance_ascending);
    RUN(avl_balance_descending);
    RUN(avl_balance_random);
    RUN(avl_balance_concurrent);

    std::cout << "\n=== concurrent_avl Fase 2a — remove ===\n";
    RUN(remove_basic);
    RUN(remove_absent);
    RUN(remove_reactivation);
    RUN(remove_many);
    RUN(concurrent_remove);
    RUN(concurrent_insert_remove_mix);

    std::cout << "\n=== concurrent_avl Fase 4 — try_insert / insert_or_assign / try_emplace / get ===\n";
    RUN(insert_or_assign_is_overwrite);
    RUN(try_insert_new_key);
    RUN(try_insert_existing_key_no_overwrite);
    RUN(try_insert_reactivates_routing);
    RUN(try_emplace_new_key);
    RUN(try_emplace_existing_key);
    RUN(get_absent_returns_nullopt);
    RUN(get_after_remove_returns_nullopt);
    RUN(concurrent_try_insert_one_winner_per_key);
    RUN(concurrent_get_under_writers);

    std::cout << std::format("\n=== Results ===\nPassed: {}\nFailed: {}\n",
                             tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
