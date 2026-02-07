// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_HASH_UTIL_H
#define CLV_HASH_UTIL_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>

namespace clv {

using hash_value_t = std::size_t;
using hash_32_t = std::uint32_t;
using hash_64_t = std::uint64_t;

namespace {

constexpr hash_value_t fnv_offset_basis()
{
    if constexpr (sizeof(hash_value_t) == 8)
        return 0xcbf29ce484222325;
    else
        return 0x811c9dc5;
}

constexpr hash_value_t fnv_prime()
{
    if constexpr (sizeof(hash_value_t) == 8)
        return 0x100000001b3;
    else
        return 0x01000193;
}

} // namespace

/**
 * @brief Combines multiple hash values into a single hash using FNV-1a algorithm
 * @tparam ArgsT Variadic template parameter pack for hash values
 * @param args hash values to combine
 * @return Combined hash value
 */
template <typename... ArgsT>
inline constexpr hash_value_t hash_combine(ArgsT... args)
{
    hash_value_t hash = fnv_offset_basis();
    (..., (hash ^= args, hash *= fnv_prime()));
    return hash;
}

/**
 * @brief Computes a combined hash value for multiple objects of different types
 * @tparam ArgsT Variadic template parameter pack for object types
 * @param args objects to hash
 * @return Combined hash value of all objects
 * @details Uses std::hash to compute individual hashes and combines them using FNV-1a algorithm
 */
template <typename... ArgsT>
inline constexpr hash_value_t hash_all(ArgsT... args)
{
    hash_value_t hash = fnv_offset_basis();
    (..., (hash ^= std::hash<ArgsT>()(args), hash *= fnv_prime()));
    return hash;
}

/**
 * @brief Combines two 32-bit hash values into a single 64-bit hash
 * @param first First 32-bit hash value
 * @param second Second 32-bit hash value
 * @return Combined 64-bit hash value
 * @details Combines values by shifting the first value left by 32 bits and OR-ing with the second value
 */
inline constexpr hash_64_t hash_widen(hash_32_t first, hash_32_t second)
{
    return static_cast<hash_64_t>(first) << 32 | static_cast<hash_64_t>(second);
}

/**
 * @brief Splits a hash value into multiple parts
 * @tparam hash_count Number of parts to split into
 * @param hash The hash value to split
 * @return An array containing the split hash parts
 * @details Each part is sizeof(hash_value_t) / hash_count bits, extracted from the original hash value
 */
template <std::size_t hash_count>
inline constexpr std::array<hash_value_t, hash_count> hash_split(hash_value_t hash)
{
    static_assert(hash_count > 0, "hash_count must be non-zero");

    constexpr std::size_t bits_per_part = (sizeof(hash_value_t) * 8) / hash_count;
    static_assert(bits_per_part > 0, "hash_count too large for hash_value_t width");

    constexpr std::size_t total_bits = sizeof(hash_value_t) * 8;
    const hash_value_t mask = bits_per_part == total_bits ? ~hash_value_t{0}
                                                          : (hash_value_t{1} << bits_per_part) - 1;

    std::array<hash_value_t, hash_count> parts{};
    if constexpr (hash_count == 1)
    {
        parts[0] = hash;
        return parts;
    }
    else
    {
        for (std::size_t i = 0; i < hash_count; ++i)
        {
            parts[i] = hash & mask; // low-order chunk first
            hash >>= bits_per_part;
        }
    }
    return parts;
}

} // namespace clv

#endif // CLV_HASH_UTIL_H