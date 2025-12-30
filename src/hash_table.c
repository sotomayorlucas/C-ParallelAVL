/**
 * @file hash_table.c
 * @brief High-performance hash table with Robin Hood hashing
 */

#include "../include/hash_table.h"

#define LOAD_FACTOR_MAX 0.7
#define INITIAL_CAPACITY 16

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

HT_INLINE size_t next_power_of_2(size_t n) {
    if (n == 0) return 1;
    n--;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
#if SIZE_MAX > 0xFFFFFFFF
    n |= n >> 32;
#endif
    return n + 1;
}

HT_INLINE bool is_power_of_2(size_t n) {
    return n && !(n & (n - 1));
}

static bool hash_table_resize(HashTable* table, size_t new_capacity) {
    HashEntry* old_entries = table->entries;
    size_t old_capacity = table->capacity;
    
    /* Allocate new array */
    HashEntry* new_entries = (HashEntry*)calloc(new_capacity, sizeof(HashEntry));
    if (HT_UNLIKELY(!new_entries)) return false;
    
    /* Update table */
    table->entries = new_entries;
    table->capacity = new_capacity;
    table->mask = new_capacity - 1;
    table->size = 0;
    table->tombstones = 0;
    table->max_probe = 0;
    
    /* Rehash all entries using Robin Hood insertion */
    for (size_t i = 0; i < old_capacity; i++) {
        if (old_entries[i].state == HT_OCCUPIED) {
            hash_table_insert(table, old_entries[i].key, old_entries[i].value);
        }
    }
    
    free(old_entries);
    return true;
}

/* Robin Hood insertion - swap if current probe distance > existing */
static bool robin_hood_insert(HashTable* table, int64_t key, size_t value) {
    uint64_t hash = ht_hash(key);
    size_t idx = ht_index(hash, table->mask);
    uint8_t probe_dist = 0;
    
    HashEntry entry = {key, value, HT_OCCUPIED, 0, 0};
    
    while (true) {
        HashEntry* slot = &table->entries[idx];
        
        if (slot->state != HT_OCCUPIED) {
            /* Empty or deleted slot - insert here */
            entry.probe_dist = probe_dist;
            *slot = entry;
            table->size++;
            if (probe_dist > table->max_probe) {
                table->max_probe = probe_dist;
            }
            return true;
        }
        
        if (slot->key == key) {
            /* Update existing */
            slot->value = value;
            return true;
        }
        
        /* Robin Hood: if we've probed further than existing entry, swap */
        if (probe_dist > slot->probe_dist) {
            HashEntry tmp = *slot;
            entry.probe_dist = probe_dist;
            *slot = entry;
            entry = tmp;
            probe_dist = tmp.probe_dist;
        }
        
        /* Continue probing */
        idx = (idx + 1) & table->mask;
        probe_dist++;
        
        /* Safety check */
        if (HT_UNLIKELY(probe_dist > 255)) {
            return false;
        }
    }
}

/* ============================================================================
 * Public API
 * ============================================================================ */

HashTable* hash_table_create(size_t initial_capacity) {
    HashTable* table = (HashTable*)malloc(sizeof(HashTable));
    if (HT_UNLIKELY(!table)) return NULL;
    
    size_t capacity = next_power_of_2(initial_capacity > INITIAL_CAPACITY ? 
                                       initial_capacity : INITIAL_CAPACITY);
    
    table->entries = (HashEntry*)calloc(capacity, sizeof(HashEntry));
    if (HT_UNLIKELY(!table->entries)) {
        free(table);
        return NULL;
    }
    
    table->capacity = capacity;
    table->mask = capacity - 1;
    table->size = 0;
    table->tombstones = 0;
    table->max_probe = 0;
    
    return table;
}

void hash_table_destroy(HashTable* table) {
    if (!table) return;
    free(table->entries);
    free(table);
}

bool hash_table_insert(HashTable* table, int64_t key, size_t value) {
    if (HT_UNLIKELY(!table)) return false;
    
    /* Check if resize needed */
    double load = (double)(table->size + table->tombstones + 1) / table->capacity;
    if (load > LOAD_FACTOR_MAX) {
        if (!hash_table_resize(table, table->capacity * 2)) {
            return false;
        }
    }
    
    return robin_hood_insert(table, key, value);
}

bool hash_table_lookup(const HashTable* table, int64_t key, size_t* out_value) {
    if (HT_UNLIKELY(!table)) return false;
    
    uint64_t hash = ht_hash(key);
    size_t idx = ht_index(hash, table->mask);
    uint8_t probe_dist = 0;
    
    while (probe_dist <= table->max_probe) {
        const HashEntry* slot = &table->entries[idx];
        
        if (slot->state == HT_EMPTY) {
            return false;
        }
        
        if (slot->state == HT_OCCUPIED && slot->key == key) {
            if (out_value) *out_value = slot->value;
            return true;
        }
        
        /* Robin Hood optimization: if probe_dist > slot's probe, key doesn't exist */
        if (slot->state == HT_OCCUPIED && probe_dist > slot->probe_dist) {
            return false;
        }
        
        idx = (idx + 1) & table->mask;
        probe_dist++;
    }
    
    return false;
}

bool hash_table_remove(HashTable* table, int64_t key) {
    if (HT_UNLIKELY(!table)) return false;
    
    uint64_t hash = ht_hash(key);
    size_t idx = ht_index(hash, table->mask);
    uint8_t probe_dist = 0;
    
    while (probe_dist <= table->max_probe) {
        HashEntry* slot = &table->entries[idx];
        
        if (slot->state == HT_EMPTY) {
            return false;
        }
        
        if (slot->state == HT_OCCUPIED && slot->key == key) {
            /* Use backward shift deletion for Robin Hood */
            size_t curr = idx;
            while (true) {
                size_t next = (curr + 1) & table->mask;
                HashEntry* next_slot = &table->entries[next];
                
                if (next_slot->state != HT_OCCUPIED || next_slot->probe_dist == 0) {
                    table->entries[curr].state = HT_EMPTY;
                    break;
                }
                
                /* Shift back */
                table->entries[curr] = *next_slot;
                table->entries[curr].probe_dist--;
                curr = next;
            }
            
            table->size--;
            return true;
        }
        
        if (slot->state == HT_OCCUPIED && probe_dist > slot->probe_dist) {
            return false;
        }
        
        idx = (idx + 1) & table->mask;
        probe_dist++;
    }
    
    return false;
}

size_t hash_table_size(const HashTable* table) {
    return table ? table->size : 0;
}

void hash_table_clear(HashTable* table) {
    if (!table) return;
    memset(table->entries, 0, table->capacity * sizeof(HashEntry));
    table->size = 0;
    table->tombstones = 0;
    table->max_probe = 0;
}

HashTableIterator hash_table_iterator(const HashTable* table) {
    HashTableIterator iter = {table, 0};
    return iter;
}

bool hash_table_next(HashTableIterator* iter, int64_t* out_key, size_t* out_value) {
    if (!iter || !iter->table) return false;
    
    while (iter->index < iter->table->capacity) {
        const HashEntry* entry = &iter->table->entries[iter->index];
        iter->index++;
        
        if (entry->state == HT_OCCUPIED) {
            if (out_key) *out_key = entry->key;
            if (out_value) *out_value = entry->value;
            return true;
        }
    }
    
    return false;
}
