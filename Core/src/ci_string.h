// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CI_STRING_H
#define CI_STRING_H

#include <string>
#include <string_view>
#include <cctype>
#include <algorithm>
#include <compare>

#include "char_util.h"
#include "hash_util.h"

namespace clv {

#ifndef CLV_CI_USELOCALE
#define CLV_CI_USELOCALE 1
#endif

// This is a helper function to convert a character to upper case with the option of
// using the locale information. It is used in the ci_char_traits class to compare
// characters in a case insensitive manner.
template <typename CharT, bool UseLocale>
    requires(sizeof(CharT) == 1)
auto to_upper_optional(CharT c) noexcept -> CharT
{
    if constexpr (UseLocale)
    {
        return static_cast<CharT>(std::toupper(c));
    }
    else
    {
        return to_upper_nolocale(c);
    }
}

/**
    @brief Case insensitive string comparison traits
    @details This is a case insensitive string comparison traits class. It is used to
             compare strings in a case insensitive manner. It is used in the ci_string
             and ci_string_view classes.
    @note Based on http://www.gotw.ca/gotw/029.htm
*/
template <bool UseLocale>
struct ci_char_traits : std::char_traits<char>
{
    static bool eq(char c1, char c2)
    {
        return to_upper_optional<char, UseLocale>(c1) == to_upper_optional<char, UseLocale>(c2);
    }

    static bool ne(char c1, char c2)
    {
        return to_upper_optional<char, UseLocale>(c1) != to_upper_optional<char, UseLocale>(c2);
    }

    static bool lt(char c1, char c2)
    {
        return to_upper_optional<char, UseLocale>(c1) < to_upper_optional<char, UseLocale>(c2);
    }

    static int compare(const char *s1,
                       const char *s2,
                       size_t n)
    {
        while (n-- && s1 && s2 && eq(*s1, *s2))
            ++s1, ++s2;
        return *s1 - *s2;
    }

    static const char *
    find(const char *s, int n, char a)
    {
        while (n-- > 0 && ne(*s, a))
            ++s;
        return s;
    }
};

// Case insensitive but case-preserving string types
/**
    @brief Case insensitive string
    @details This is a case insensitive string class. It is used to compare strings in a
             case insensitive manner. It is used in the ci_string_view class.
    @note Based on http://www.gotw.ca/gotw/029.htm
    @note This class preserves case but does not consider case for comparison purposes.
*/
template <bool UseLocale>
struct basic_ci_string : std::basic_string<char, ci_char_traits<UseLocale>>
{
    using std::basic_string<char, ci_char_traits<UseLocale>>::basic_string;

    basic_ci_string(std::string_view str)
        : std::basic_string<char, ci_char_traits<UseLocale>>(str.data(), str.length())
    {
    }
};
/**
    @brief Case insensitive string view
    @details This is a case insensitive string view class. It is used to compare strings
             in a case insensitive manner.
    @note This class preserves case but does not consider case for comparison purposes.
*/
template <bool UseLocale>
struct basic_ci_string_view : std::basic_string_view<char, ci_char_traits<UseLocale>>
{
    using std::basic_string_view<char, ci_char_traits<UseLocale>>::basic_string_view;

    basic_ci_string_view(std::string_view str)
        : std::basic_string_view<char, ci_char_traits<UseLocale>>(str.data(), str.length())
    {
    }
    basic_ci_string_view(const basic_ci_string<UseLocale> &str)
        : std::basic_string_view<char, ci_char_traits<UseLocale>>(str.data(), str.length())
    {
    }
};

using ci_string = basic_ci_string<CLV_CI_USELOCALE>;
using ci_string_view = basic_ci_string_view<CLV_CI_USELOCALE>;

// Useful comparisons to related types
// This is a 3 way helper function. It is used to compare two characters and return a C++ '20 style result.
template <typename CharT, bool UseLocale>
    requires(sizeof(CharT) == 1)
inline auto weak_compare_ci(CharT a, CharT b) noexcept -> std::weak_ordering
{
    return to_upper_optional<CharT, UseLocale>(a) <=> to_upper_optional<CharT, UseLocale>(b);
}
/**
    @brief Case insensitive string comparison
    @details Compare a case insensitive string with a case sensitive string. This allows
             for case insensitive comparisons between strings even if only one of them is
             case insensitive.
    @param lhs Left argument, a normal string
    @param rhs Right argument, a case insensitive string
    @return @c true if they are equivalent, @c false otherwise
*/
template <bool UseLocale> // UseLocale is now deduced from the type of rhs
inline bool operator==(const std::string &lhs,
                       clv::basic_ci_string_view<UseLocale> rhs) noexcept
{
    // Correct equality check: sizes must match first
    return lhs.size() == rhs.size() &&
           // If sizes match, compare the full size using the traits
           ci_char_traits<UseLocale>::compare(lhs.data(),
                                              rhs.data(),
                                              lhs.size()) // Compare full size
               == 0;
}
/**
    @brief Case insensitive string comparison, 3 way
    @details Compare a case insensitive string with a case sensitive string. This allows
             for case insensitive comparisons between strings even if only one of them is
             case insensitive.
    @param lhs Left argument, a normal string
    @param rhs Right argument, a case insensitive string
    @return the result of the comparison as a std::weak_ordering
*/
template <bool UseLocale> // UseLocale is now deduced from the type of rhs
inline auto operator<=>(const std::string &lhs,
                        clv::basic_ci_string_view<UseLocale> rhs) noexcept -> std::weak_ordering
{
    return std::lexicographical_compare_three_way(
        lhs.begin(),
        lhs.end(),
        rhs.begin(),
        rhs.end(),
        [](auto a, auto b)
    { return weak_compare_ci<decltype(a), UseLocale>(a, b); });
}
/**
    @brief Case insensitive string comparison
    @details Compare a case insensitive string with a case sensitive string. This allows
             for case insensitive comparisons between strings even if only one of them is
             case insensitive.
    @param lhs Left argument, a normal string_view
    @param rhs Right argument, a case insensitive string
    @return @c true if they are equivalent, @c false otherwise
*/
template <bool UseLocale> // UseLocale is now deduced from the type of rhs
inline bool operator==(std::string_view lhs,
                       const clv::basic_ci_string<UseLocale> &rhs) noexcept
{
    // Correct equality check: sizes must match first
    return lhs.size() == rhs.size() &&
           // If sizes match, compare the full size using the traits
           ci_char_traits<UseLocale>::compare(lhs.data(),
                                              rhs.data(),
                                              lhs.size()) // Compare full size
               == 0;
}
/**
    @brief Case insensitive string comparison, 3 way
    @details Compare a case insensitive string with a case sensitive string. This allows
             for case insensitive comparisons between strings even if only one of them is
             case insensitive.
    @param lhs Left argument, a normal string_view
    @param rhs Right argument, a case insensitive string
    @return the result of the comparison as a std::weak_ordering
*/
template <bool UseLocale> // UseLocale is now deduced from the type of rhs
inline auto operator<=>(std::string_view lhs,
                        const clv::basic_ci_string<UseLocale> &rhs) noexcept -> std::weak_ordering
{
    return std::lexicographical_compare_three_way(
        lhs.begin(),
        lhs.end(),
        rhs.begin(),
        rhs.end(),
        [](auto a, auto b)
    { return weak_compare_ci<decltype(a), UseLocale>(a, b); });
}
/**
    @brief Create a literal case insensitive string
    @param str The string to create
    @param len The length of the string
    @return constexpr ci_string
*/
inline constexpr ci_string
operator""_cis(const char *str, size_t len) noexcept
{
    return ci_string{str, len};
}
/**
    @brief Create a literal case insensitive string view
    @param str The string to create
    @param len The length of the string
    @return constexpr ci_string_view
*/
inline constexpr ci_string_view
operator""_cisv(const char *str, size_t len) noexcept
{
    return ci_string_view{str, len};
}

// This has to be done one byte at a time so strings that differ only in alignment
// will hash to the same value
template <typename CharT, bool UseLocale>
    requires(sizeof(CharT) == 1)
std::size_t hash_ci_string(const CharT *data, std::size_t length)
{
    std::size_t hash = 0;
    for (std::size_t i = 0; i < length; ++i)
        hash = hash_combine(hash,
                            static_cast<std::size_t>(to_upper_optional<CharT, UseLocale>(data[i])));
    return hash;
}

} // namespace clv

// Things that have to live in std here
namespace std {

// Conversions
/**
    @brief Convert a case insensitive string to a normal string
    @param str The case insensitive string to convert
    @return std::string
*/
inline std::string to_string(clv::ci_string_view str)
{
    return std::string(str.data(), str.length());
}
/**
    @brief Convert a normal string to a case insensitive string
    @param str The normal string to convert
    @return clv::ci_string
*/
inline clv::ci_string to_ci_str(std::string_view str)
{
    return clv::ci_string(str.data(), str.length());
}
/**
    @brief Compute the case insensitive hash of a string
    @param str The string to hash
    @return std::size_t
    @tparam  Specialized for clv::ci_string
*/
template <bool UseLocale>
struct hash<clv::basic_ci_string<UseLocale>> // Specialize for basic_ci_string<any bool>
{
    size_t operator()(const clv::basic_ci_string<UseLocale> &str) const
    {
        return clv::hash_ci_string<char, UseLocale>(str.data(), str.size());
    }
};
/**
    @brief Compute the case insensitive hash of a string
    @param str The string to hash
    @return std::size_t
    @tparam  Specialized for clv::ci_string_view
*/
template <bool UseLocale>
struct hash<clv::basic_ci_string_view<UseLocale>> // Specialize for basic_ci_string_view<any bool>
{
    size_t operator()(const clv::basic_ci_string_view<UseLocale> &str) const
    {
        return clv::hash_ci_string<char, UseLocale>(str.data(), str.size());
    }
};

} // namespace std

#endif // CI_STRING_H