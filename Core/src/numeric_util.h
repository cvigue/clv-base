// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef NUMERIC_UTIL_H
#define NUMERIC_UTIL_H


#include <type_traits>
#include <limits>
#include <stdexcept>
#include <format>

namespace clv {

template <typename T>
concept numeric_type = std::is_integral_v<T> || std::is_floating_point_v<T>;
// clang-format off
template <typename T, typename U>
concept safe_conversion =
    std::is_same_v<T, U> ||
    (sizeof(T) >= sizeof(U) && std::is_signed_v<T> == std::is_signed_v<U> && std::is_floating_point_v<T> == std::is_floating_point_v<U>);
// clang-format on

// Prefer using number, in number.h for safe numeric operations. This is a hack
// that can drop into existing code that needs to do numeric clamping or safe casting.

// Clamp a numeric value to the range of the specified type T.
template <typename T, typename U>
    requires numeric_type<T> && numeric_type<U>
T clamp_to_type(U value)
{
    if constexpr (!safe_conversion<T, U>)
    {
        if constexpr (std::is_floating_point_v<T> || std::is_floating_point_v<U>)
        {
            // Convert the incoming value and the destination numeric limits to a
            // common (wide) floating-point type for safe comparisons. This avoids
            // performing casts that can cause undefined behavior when a limit cannot
            // be represented in the source type (e.g., casting a large float to int).
            long double v = static_cast<long double>(value);
            long double t_low = static_cast<long double>(std::numeric_limits<T>::lowest());
            long double t_high = static_cast<long double>(std::numeric_limits<T>::max());

            if (v < t_low)
                return std::numeric_limits<T>::lowest();
            if (v > t_high)
                return std::numeric_limits<T>::max();
        }
        else if constexpr (std::is_integral_v<T> && std::is_floating_point_v<U>)
        {
            // Floating-point to integral: clamp to integral limits
            if (value < static_cast<U>(std::numeric_limits<T>::lowest()))
                return std::numeric_limits<T>::lowest();
            if (value > static_cast<U>(std::numeric_limits<T>::max()))
                return std::numeric_limits<T>::max();
            return static_cast<T>(value);
        }
        else if constexpr (std::is_unsigned_v<T> && std::is_signed_v<U>)
        {
            if (value < 0)
                return 0;
            if (static_cast<std::make_unsigned_t<U>>(value) > std::numeric_limits<T>::max())
                return std::numeric_limits<T>::max();
        }
        else if constexpr (std::is_signed_v<T> && std::is_unsigned_v<U>)
        {
            if (value > static_cast<std::make_unsigned_t<U>>(std::numeric_limits<T>::max()))
                return std::numeric_limits<T>::max();
        }
        else
        {
            if (value < static_cast<U>(std::numeric_limits<T>::lowest()))
                return std::numeric_limits<T>::lowest();
            if (value > static_cast<U>(std::numeric_limits<T>::max()))
                return std::numeric_limits<T>::max();
        }
    }
    return static_cast<T>(value);
}

// Safe cast if possible, otherwise throw.
template <typename T, typename U>
    requires numeric_type<T> && numeric_type<U>
T safe_cast(U value)
{
    if constexpr (!safe_conversion<T, U>)
    {
        T clamped = clamp_to_type<T>(value);
        if (static_cast<U>(clamped) != value)
            throw std::range_error(
                std::format("safe_cast: value out of range for target type {}, value {}",
                            typeid(T).name(),
                            value));
        return clamped;
    }
    return static_cast<T>(value);
}

} // namespace clv

#endif // NUMERIC_UTIL_H
