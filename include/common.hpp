#pragma once

#include <concepts>
#include <cstddef>
#include <new>

namespace pavl {

// Fixed at 64 to avoid ABI variability across -mtune flags; matches
// typical x86_64 / ARMv8 L1 line size. We deliberately don't use
// std::hardware_destructive_interference_size — it pulls in
// -Winterference-size noise and ties our ABI to libstdc++'s choice.
inline constexpr std::size_t cache_line_size = 64;

template <typename K>
concept avl_key = std::totally_ordered<K> && std::copyable<K>;

template <typename V>
concept avl_value = std::movable<V>;

}  // namespace pavl
