/**
 * @file atomics.h
 * @brief Cross-platform atomic operations for C11/Windows
 * 
 * Provides atomic operations that work on both:
 *   - C11 compliant compilers (GCC, Clang)
 *   - Windows (MSVC with Interlocked functions)
 */

#ifndef ATOMICS_H
#define ATOMICS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Platform Detection and Configuration
 * ============================================================================ */

#if defined(_MSC_VER) && !defined(__clang__)
    /* MSVC - use Interlocked functions */
    #define ATOMICS_MSVC 1
    #include <intrin.h>
    #pragma intrinsic(_InterlockedIncrement64)
    #pragma intrinsic(_InterlockedDecrement64)
    #pragma intrinsic(_InterlockedExchangeAdd64)
    #pragma intrinsic(_InterlockedCompareExchange64)
    #pragma intrinsic(_InterlockedExchange64)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
    /* C11 atomics */
    #define ATOMICS_C11 1
    #include <stdatomic.h>
#else
    /* Fallback: GCC/Clang builtins */
    #define ATOMICS_BUILTIN 1
#endif

/* ============================================================================
 * Atomic Types
 * ============================================================================ */

#ifdef ATOMICS_C11
    typedef _Atomic(size_t) atomic_size;
    typedef _Atomic(int64_t) atomic_int64;
    typedef _Atomic(bool) atomic_bool_t;
    typedef _Atomic(double) atomic_double;
#else
    /* For MSVC and builtins, use volatile + functions */
    typedef volatile size_t atomic_size;
    typedef volatile int64_t atomic_int64;
    typedef volatile int atomic_bool_t;
    typedef volatile double atomic_double;
#endif

/* ============================================================================
 * Atomic Operations - size_t
 * ============================================================================ */

static inline size_t atomic_load_size(const atomic_size* ptr) {
#ifdef ATOMICS_C11
    return atomic_load_explicit(ptr, memory_order_relaxed);
#elif defined(ATOMICS_MSVC)
    return *ptr;
#else
    return __atomic_load_n(ptr, __ATOMIC_RELAXED);
#endif
}

static inline void atomic_store_size(atomic_size* ptr, size_t val) {
#ifdef ATOMICS_C11
    atomic_store_explicit(ptr, val, memory_order_relaxed);
#elif defined(ATOMICS_MSVC)
    *ptr = val;
#else
    __atomic_store_n(ptr, val, __ATOMIC_RELAXED);
#endif
}

static inline size_t atomic_fetch_add_size(atomic_size* ptr, size_t val) {
#ifdef ATOMICS_C11
    return atomic_fetch_add_explicit(ptr, val, memory_order_relaxed);
#elif defined(ATOMICS_MSVC)
    return (size_t)_InterlockedExchangeAdd64((volatile long long*)ptr, (long long)val);
#else
    return __atomic_fetch_add(ptr, val, __ATOMIC_RELAXED);
#endif
}

static inline size_t atomic_fetch_sub_size(atomic_size* ptr, size_t val) {
#ifdef ATOMICS_C11
    return atomic_fetch_sub_explicit(ptr, val, memory_order_relaxed);
#elif defined(ATOMICS_MSVC)
    return (size_t)_InterlockedExchangeAdd64((volatile long long*)ptr, -(long long)val);
#else
    return __atomic_fetch_sub(ptr, val, __ATOMIC_RELAXED);
#endif
}

static inline size_t atomic_increment_size(atomic_size* ptr) {
    return atomic_fetch_add_size(ptr, 1) + 1;
}

static inline size_t atomic_decrement_size(atomic_size* ptr) {
    return atomic_fetch_sub_size(ptr, 1) - 1;
}

/* ============================================================================
 * Atomic Operations - bool
 * ============================================================================ */

static inline bool atomic_load_bool(const atomic_bool_t* ptr) {
#ifdef ATOMICS_C11
    return atomic_load_explicit(ptr, memory_order_acquire);
#elif defined(ATOMICS_MSVC)
    return *ptr != 0;
#else
    return __atomic_load_n(ptr, __ATOMIC_ACQUIRE);
#endif
}

static inline void atomic_store_bool(atomic_bool_t* ptr, bool val) {
#ifdef ATOMICS_C11
    atomic_store_explicit(ptr, val, memory_order_release);
#elif defined(ATOMICS_MSVC)
    *ptr = val ? 1 : 0;
#else
    __atomic_store_n(ptr, val, __ATOMIC_RELEASE);
#endif
}

/* ============================================================================
 * Atomic Operations - int64_t
 * ============================================================================ */

static inline int64_t atomic_load_int64(const atomic_int64* ptr) {
#ifdef ATOMICS_C11
    return atomic_load_explicit(ptr, memory_order_relaxed);
#elif defined(ATOMICS_MSVC)
    return _InterlockedCompareExchange64((volatile long long*)ptr, 0, 0);
#else
    return __atomic_load_n(ptr, __ATOMIC_RELAXED);
#endif
}

static inline void atomic_store_int64(atomic_int64* ptr, int64_t val) {
#ifdef ATOMICS_C11
    atomic_store_explicit(ptr, val, memory_order_relaxed);
#elif defined(ATOMICS_MSVC)
    _InterlockedExchange64((volatile long long*)ptr, val);
#else
    __atomic_store_n(ptr, val, __ATOMIC_RELAXED);
#endif
}

/* ============================================================================
 * Memory Barriers
 * ============================================================================ */

static inline void atomic_thread_fence_acquire(void) {
#ifdef ATOMICS_C11
    atomic_thread_fence(memory_order_acquire);
#elif defined(ATOMICS_MSVC)
    _ReadWriteBarrier();
#else
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
#endif
}

static inline void atomic_thread_fence_release(void) {
#ifdef ATOMICS_C11
    atomic_thread_fence(memory_order_release);
#elif defined(ATOMICS_MSVC)
    _ReadWriteBarrier();
#else
    __atomic_thread_fence(__ATOMIC_RELEASE);
#endif
}

#ifdef __cplusplus
}
#endif

#endif /* ATOMICS_H */
