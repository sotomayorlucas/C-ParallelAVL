#pragma once

#include <atomic>
#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <new>
#include <type_traits>
#include <version>

namespace pavl {

// Fixed at 64 to avoid ABI variability across -mtune flags; matches typical
// x86_64/ARMv8 L1 line size. std::hardware_destructive_interference_size is
// intentionally not used here (would trigger -Winterference-size).
inline constexpr std::size_t cache_line_size = 64;

#if defined(__GNUC__) || defined(__clang__)
#  define PAVL_ALWAYS_INLINE inline __attribute__((always_inline))
#  define PAVL_HOT __attribute__((hot))
#  define PAVL_PREFETCH(x) __builtin_prefetch(x)
#else
#  define PAVL_ALWAYS_INLINE inline
#  define PAVL_HOT
#  define PAVL_PREFETCH(x) ((void)0)
#endif

template <typename K>
concept avl_key = std::totally_ordered<K> && std::copyable<K>;

template <typename V>
concept avl_value = std::movable<V>;

template <typename K>
concept hashable_key = avl_key<K> && requires(K k) {
    { static_cast<std::uint64_t>(k) } -> std::convertible_to<std::uint64_t>;
};

[[nodiscard]] PAVL_ALWAYS_INLINE constexpr std::uint64_t mix64(std::uint64_t h) noexcept {
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;
    return h;
}

template <typename K>
[[nodiscard]] PAVL_ALWAYS_INLINE constexpr std::uint64_t key_hash(K key) noexcept {
    if constexpr (std::is_integral_v<K>) {
        return mix64(static_cast<std::uint64_t>(key));
    } else if constexpr (requires { std::hash<K>{}(key); }) {
        return mix64(static_cast<std::uint64_t>(std::hash<K>{}(key)));
    } else {
        return mix64(std::bit_cast<std::uint64_t>(key));
    }
}

[[nodiscard]] PAVL_ALWAYS_INLINE constexpr bool is_power_of_two(std::size_t n) noexcept {
    return n != 0 && (n & (n - 1)) == 0;
}

[[nodiscard]] PAVL_ALWAYS_INLINE constexpr std::size_t next_power_of_two(std::size_t n) noexcept {
    if (n < 2) return 1;
    return std::size_t{1} << (std::bit_width(n - 1));
}

}  // namespace pavl
