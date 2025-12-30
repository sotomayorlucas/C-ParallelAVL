/**
 * @file hash_table.h
 * @brief High-performance hash table with Robin Hood hashing
 * 
 * Optimizations:
 *   - Robin Hood hashing for better cache performance
 *   - Power-of-2 sizing for fast modulo
 *   - Inline hot path functions
 *   - Separate metadata for better cache locality
 */

#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Compiler hints */
#ifdef __GNUC__
#define HT_LIKELY(x)   __builtin_expect(!!(x), 1)
#define HT_UNLIKELY(x) __builtin_expect(!!(x), 0)
#define HT_INLINE      static inline __attribute__((always_inline))
#else
#define HT_LIKELY(x)   (x)
#define HT_UNLIKELY(x) (x)
#define HT_INLINE      static inline
#endif

/* Entry states for Robin Hood */
#define HT_EMPTY    0
#define HT_OCCUPIED 1
#define HT_DELETED  2

/**
 * Hash entry - compact layout
 */
typedef struct HashEntry {
    int64_t key;
    size_t value;
    uint8_t state;      /* HT_EMPTY, HT_OCCUPIED, HT_DELETED */
    uint8_t probe_dist; /* Distance from ideal position (Robin Hood) */
    uint16_t _pad;
} HashEntry;

/**
 * Hash table structure
 */
typedef struct HashTable {
    HashEntry* entries;
    size_t capacity;    /* Always power of 2 */
    size_t mask;        /* capacity - 1 for fast modulo */
    size_t size;
    size_t tombstones;
    size_t max_probe;   /* Track max probe distance */
} HashTable;

/* ============================================================================
 * Inline Hash Functions
 * ============================================================================ */

/* Murmur3 finalizer - excellent distribution */
HT_INLINE uint64_t ht_hash(int64_t key) {
    uint64_t h = (uint64_t)key;
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;
    return h;
}

/* Fast modulo for power of 2 */
HT_INLINE size_t ht_index(uint64_t hash, size_t mask) {
    return (size_t)(hash & mask);
}

/* ============================================================================
 * Public API
 * ============================================================================ */

HashTable* hash_table_create(size_t initial_capacity);
void hash_table_destroy(HashTable* table);
bool hash_table_insert(HashTable* table, int64_t key, size_t value);
bool hash_table_lookup(const HashTable* table, int64_t key, size_t* out_value);
bool hash_table_remove(HashTable* table, int64_t key);
size_t hash_table_size(const HashTable* table);
void hash_table_clear(HashTable* table);

/* Iterator */
typedef struct HashTableIterator {
    const HashTable* table;
    size_t index;
} HashTableIterator;

HashTableIterator hash_table_iterator(const HashTable* table);
bool hash_table_next(HashTableIterator* iter, int64_t* out_key, size_t* out_value);

#ifdef __cplusplus
}
#endif

#endif /* HASH_TABLE_H */
