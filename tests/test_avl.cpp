// Unit tests for the C++23 ParallelAVL port.

#include "avl_tree.hpp"
#include "hash_table.hpp"
#include "parallel_avl.hpp"

#include <cstdint>
#include <format>
#include <iostream>
#include <source_location>
#include <string_view>

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
} while(0)

using i64 = std::int64_t;

// ===========================================================================
// avl_tree tests
// ===========================================================================

void test_avl_create_destroy() {
    pavl::avl_tree<i64, void*> t;
    EXPECT(t.size() == 0);
    EXPECT(t.empty());
}

void test_avl_insert_contains() {
    pavl::avl_tree<i64, void*> t;
    t.insert(10, nullptr);
    t.insert(5, nullptr);
    t.insert(15, nullptr);
    EXPECT(t.size() == 3);
    EXPECT(t.contains(10));
    EXPECT(t.contains(5));
    EXPECT(t.contains(15));
    EXPECT(!t.contains(20));
}

void test_avl_remove() {
    pavl::avl_tree<i64, void*> t;
    for (int i = 0; i < 100; ++i) t.insert(i, nullptr);
    EXPECT(t.size() == 100);
    EXPECT(t.remove(50));
    EXPECT(!t.contains(50));
    EXPECT(t.size() == 99);
    EXPECT(!t.remove(50));
    EXPECT(!t.remove(200));
}

void test_avl_find() {
    pavl::avl_tree<i64, i64> t;
    t.insert(42, 123);
    auto* v = t.find(42);
    EXPECT(v && *v == 123);
    EXPECT(t.find(99) == nullptr);
}

void test_avl_min_max() {
    pavl::avl_tree<i64, void*> t;
    EXPECT(!t.min_key());
    t.insert(50, nullptr);
    t.insert(25, nullptr);
    t.insert(75, nullptr);
    t.insert(10, nullptr);
    t.insert(90, nullptr);
    EXPECT(t.min_key() == 10);
    EXPECT(t.max_key() == 90);
}

void test_avl_balance() {
    pavl::avl_tree<i64, void*> t;
    for (int i = 0; i < 1000; ++i) t.insert(i, nullptr);
    for (int i = 0; i < 1000; ++i) EXPECT(t.contains(i));
}

void test_avl_node_pool() {
    pavl::avl_tree<i64, void*> t;
    for (int i = 0; i < 10000; ++i) t.insert(i, nullptr);
    EXPECT(t.size() == 10000);
    for (int i = 0; i < 5000; ++i) EXPECT(t.remove(i));
    EXPECT(t.size() == 5000);
    for (int i = 0; i < 5000; ++i) t.insert(i, nullptr);
    EXPECT(t.size() == 10000);
}

void test_avl_destructible_value() {
    // Use std::string to exercise non-trivial Value destruction.
    pavl::avl_tree<i64, std::string> t;
    for (int i = 0; i < 1000; ++i) t.insert(i, std::format("v{}", i));
    EXPECT(t.size() == 1000);
    auto* v = t.find(42);
    EXPECT(v && *v == "v42");
    t.clear();
    EXPECT(t.size() == 0);
}

void test_avl_try_insert() {
    pavl::avl_tree<i64, i64> t;
    auto r1 = t.try_insert(10, 100);
    EXPECT(r1.inserted && r1.value_ptr && *r1.value_ptr == 100);
    auto r2 = t.try_insert(10, 999);                 // already there → no-op
    EXPECT(!r2.inserted && r2.value_ptr && *r2.value_ptr == 100);
    EXPECT(t.size() == 1);
}

void test_avl_insert_or_assign() {
    pavl::avl_tree<i64, i64> t;
    auto r1 = t.insert_or_assign(10, 100);
    EXPECT(r1.inserted && *r1.value_ptr == 100);
    auto r2 = t.insert_or_assign(10, 200);           // overwrite
    EXPECT(!r2.inserted && *r2.value_ptr == 200);
    EXPECT(t.size() == 1);
}

void test_avl_try_emplace() {
    pavl::avl_tree<i64, std::string> t;
    auto r1 = t.try_emplace(7, 5, 'x');              // "xxxxx"
    EXPECT(r1.inserted && *r1.value_ptr == "xxxxx");
    auto r2 = t.try_emplace(7, "ignored");           // already there → no-op
    EXPECT(!r2.inserted && *r2.value_ptr == "xxxxx");
}

void test_avl_heterogeneous_lookup_int_short() {
    pavl::avl_tree<i64, i64> t;
    t.insert(42, 4200);
    short s = 42;
    EXPECT(t.contains(s));
    auto* v = t.find(s);
    EXPECT(v && *v == 4200);
    EXPECT(t.remove(s));
    EXPECT(t.size() == 0);
}

void test_avl_heterogeneous_lookup_sv_string() {
    pavl::avl_tree<std::string, int> t;
    t.insert("hello", 1);
    t.insert("world", 2);
    // string_view does not construct a std::string here:
    std::string_view sv = "hello";
    EXPECT(t.contains(sv));
    auto* v = t.find(sv);
    EXPECT(v && *v == 1);
    EXPECT(t.remove(std::string_view{"world"}));
    EXPECT(t.size() == 1);
}

// ===========================================================================
// hash_table tests
// ===========================================================================

void test_hash_create_destroy() {
    pavl::hash_table<i64, std::size_t> h{16};
    EXPECT(h.size() == 0);
    EXPECT(h.empty());
}

void test_hash_insert_lookup() {
    pavl::hash_table<i64, std::size_t> h{16};
    EXPECT(h.insert(100, 42));
    EXPECT(h.insert(200, 84));
    EXPECT(h.size() == 2);
    auto* v = h.find(100);
    EXPECT(v && *v == 42);
    v = h.find(200);
    EXPECT(v && *v == 84);
    EXPECT(h.find(300) == nullptr);
}

void test_hash_remove() {
    pavl::hash_table<i64, std::size_t> h{16};
    h.insert(100, 42);
    h.insert(200, 84);
    EXPECT(h.remove(100));
    EXPECT(!h.contains(100));
    EXPECT(h.size() == 1);
    EXPECT(!h.remove(100));
}

void test_hash_resize() {
    pavl::hash_table<i64, std::size_t> h{4};
    for (int i = 0; i < 100; ++i) EXPECT(h.insert(i, static_cast<std::size_t>(i * 10)));
    EXPECT(h.size() == 100);
    for (int i = 0; i < 100; ++i) {
        auto* v = h.find(i);
        EXPECT(v && *v == static_cast<std::size_t>(i * 10));
    }
}

void test_hash_robin_hood() {
    pavl::hash_table<i64, std::size_t> h{16};
    for (int i = 0; i < 1000; ++i) EXPECT(h.insert(i * 17, static_cast<std::size_t>(i)));
    for (int i = 0; i < 1000; ++i) {
        auto* v = h.find(i * 17);
        EXPECT(v && *v == static_cast<std::size_t>(i));
    }
    for (int i = 0; i < 500; ++i) EXPECT(h.remove(i * 17));
    for (int i = 500; i < 1000; ++i) {
        auto* v = h.find(i * 17);
        EXPECT(v && *v == static_cast<std::size_t>(i));
    }
}

// ===========================================================================
// parallel_avl tests
// ===========================================================================

void test_parallel_create_destroy() {
    pavl::parallel_avl<i64, void*> t{4, pavl::router_strategy::static_hash};
    EXPECT(t.size() == 0);
    EXPECT(t.num_shards() == 4);
}

void test_parallel_insert_contains() {
    pavl::parallel_avl<i64, void*> t{4, pavl::router_strategy::static_hash};
    for (int i = 0; i < 100; ++i) t.insert(i, nullptr);
    EXPECT(t.size() == 100);
    for (int i = 0; i < 100; ++i) EXPECT(t.contains(i));
    EXPECT(!t.contains(999));
}

void test_parallel_remove() {
    pavl::parallel_avl<i64, void*> t{4, pavl::router_strategy::static_hash};
    for (int i = 0; i < 100; ++i) t.insert(i, nullptr);
    EXPECT(t.remove(50));
    EXPECT(!t.contains(50));
    EXPECT(t.size() == 99);
    EXPECT(!t.remove(50));
}

void test_parallel_get() {
    pavl::parallel_avl<i64, i64> t{4, pavl::router_strategy::static_hash};
    t.insert(42, 123);
    auto v = t.get(42);
    EXPECT(v && *v == 123);
    EXPECT(!t.get(99));
}

void test_parallel_range_query() {
    pavl::parallel_avl<i64, void*> t{4, pavl::router_strategy::static_hash};
    for (int i = 0; i < 100; ++i) t.insert(i, nullptr);
    auto r = t.range_query(20, 30, 50);
    EXPECT(r.size() == 11);
    for (std::size_t i = 1; i < r.size(); ++i) EXPECT(r[i].key > r[i - 1].key);
}

void test_parallel_add_shard() {
    pavl::parallel_avl<i64, void*> t{2, pavl::router_strategy::static_hash};
    for (int i = 0; i < 100; ++i) t.insert(i, nullptr);
    EXPECT(t.num_shards() == 2);
    EXPECT(t.add_shard());
    EXPECT(t.num_shards() == 3);
    for (int i = 0; i < 100; ++i) EXPECT(t.contains(i));
}

void test_parallel_remove_shard() {
    pavl::parallel_avl<i64, void*> t{4, pavl::router_strategy::static_hash};
    for (int i = 0; i < 100; ++i) t.insert(i, nullptr);
    EXPECT(t.remove_shard());
    EXPECT(t.num_shards() == 3);
    EXPECT(t.size() == 100);
    for (int i = 0; i < 100; ++i) EXPECT(t.contains(i));
}

void test_parallel_force_rebalance() {
    pavl::parallel_avl<i64, void*> t{4, pavl::router_strategy::load_aware};
    for (int i = 0; i < 100; ++i) t.insert(i, nullptr);
    t.force_rebalance();
    for (int i = 0; i < 100; ++i) EXPECT(t.contains(i));
    EXPECT(t.balance_score() > 0.8);
}

void test_parallel_routing_strategies() {
    for (auto s : {pavl::router_strategy::static_hash, pavl::router_strategy::load_aware,
                   pavl::router_strategy::consistent_hash, pavl::router_strategy::intelligent}) {
        pavl::parallel_avl<i64, void*> t{4, s};
        for (int i = 0; i < 100; ++i) t.insert(i, nullptr);
        for (int i = 0; i < 100; ++i) EXPECT(t.contains(i));
    }
}

void test_parallel_large_scale() {
    pavl::parallel_avl<i64, i64> t{8, pavl::router_strategy::static_hash};
    for (int i = 0; i < 100000; ++i) t.insert(i, i);
    EXPECT(t.size() == 100000);
    for (int i = 0; i < 100000; i += 1000) {
        auto v = t.get(i);
        EXPECT(v && *v == i);
    }
}

void test_parallel_try_insert() {
    pavl::parallel_avl<i64, i64> t{4, pavl::router_strategy::static_hash};
    EXPECT(t.try_insert(7, 70).inserted);
    EXPECT(!t.try_insert(7, 999).inserted);
    auto v = t.get(7);
    EXPECT(v && *v == 70);
}

void test_parallel_insert_or_assign() {
    pavl::parallel_avl<i64, i64> t{4, pavl::router_strategy::static_hash};
    EXPECT(t.insert_or_assign(7, 70).inserted);
    EXPECT(!t.insert_or_assign(7, 700).inserted);
    auto v = t.get(7);
    EXPECT(v && *v == 700);
}

void test_parallel_try_emplace() {
    pavl::parallel_avl<i64, std::string> t{4, pavl::router_strategy::static_hash};
    EXPECT(t.try_emplace(1, 4, 'a').inserted);             // "aaaa"
    EXPECT(!t.try_emplace(1, "ignored").inserted);
    auto v = t.get(1);
    EXPECT(v && *v == "aaaa");
}

void test_parallel_visit() {
    pavl::parallel_avl<i64, i64> t{4, pavl::router_strategy::intelligent};
    for (int i = 0; i < 100; ++i) t.insert(i, i);
    int sum = 0;
    for (int i = 0; i < 100; ++i) {
        EXPECT(t.visit(i, [&](std::int64_t& v) { sum += static_cast<int>(v); }));
    }
    EXPECT(sum == 99 * 100 / 2);
}

}  // namespace

int main() {
    std::cout << "\n=== AVL Tree Unit Tests ===\n";
    RUN(avl_create_destroy);
    RUN(avl_insert_contains);
    RUN(avl_remove);
    RUN(avl_find);
    RUN(avl_min_max);
    RUN(avl_balance);
    RUN(avl_node_pool);
    RUN(avl_destructible_value);
    RUN(avl_try_insert);
    RUN(avl_insert_or_assign);
    RUN(avl_try_emplace);
    RUN(avl_heterogeneous_lookup_int_short);
    RUN(avl_heterogeneous_lookup_sv_string);

    std::cout << "\n=== Hash Table Unit Tests ===\n";
    RUN(hash_create_destroy);
    RUN(hash_insert_lookup);
    RUN(hash_remove);
    RUN(hash_resize);
    RUN(hash_robin_hood);

    std::cout << "\n=== Parallel AVL Unit Tests ===\n";
    RUN(parallel_create_destroy);
    RUN(parallel_insert_contains);
    RUN(parallel_remove);
    RUN(parallel_get);
    RUN(parallel_range_query);
    RUN(parallel_add_shard);
    RUN(parallel_remove_shard);
    RUN(parallel_force_rebalance);
    RUN(parallel_routing_strategies);
    RUN(parallel_large_scale);
    RUN(parallel_try_insert);
    RUN(parallel_insert_or_assign);
    RUN(parallel_try_emplace);
    RUN(parallel_visit);

    std::cout << std::format("\n=== Results ===\nPassed: {}\nFailed: {}\n",
                             tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
