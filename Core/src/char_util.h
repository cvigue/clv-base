// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLV_CHAR_UTIL_H
#define CLV_CHAR_UTIL_H

namespace clv {

/**
    @brief Convert a character to lower case without using locale
    @param c The character to convert
    @return char
    @details This function converts a character to lower case without using the locale
             information. It is a simple implementation that uses bit manipulation to
             convert the character to lower case. It is not locale aware and should not
             be used for locale sensitive applications.
*/
template <typename CharT>
    requires(sizeof(CharT) == 1)
inline CharT to_lower_nolocale(CharT c) noexcept
{
    unsigned char uc = static_cast<unsigned char>(c);
    unsigned char mask = (((uc - 'A') <= ('Z' - 'A')) & (('Z' - uc) <= ('Z' - 'A'))) * 0x20;
    return static_cast<CharT>(uc | mask);
}
/**
    @brief Convert a character to upper case without using locale
    @param c The character to convert
    @return char
    @details This function converts a character to upper case without using the locale
            information. It is a simple implementation that uses bit manipulation to
            convert the character to upper case. It is not locale aware and should not
            be used for locale sensitive applications.
*/
template <typename CharT>
    requires(sizeof(CharT) == 1)
inline CharT to_upper_nolocale(CharT c) noexcept
{
    unsigned char uc = static_cast<unsigned char>(c);
    unsigned char mask = (((uc - 'a') <= ('z' - 'a')) & (('z' - uc) <= ('z' - 'a'))) * 0x20;
    return static_cast<CharT>(uc & ~mask);
}
/**
    @brief Check if a character is lower case without using locale
    @details This function checks if a character is lower case alphabetic
             without using the locale information.
    @param c The character to check
    @return @c true if the character is lower case or @c false otherwise.
*/
inline bool is_lower_nolocale(char c) noexcept
{
    return (c >= 'a' && c <= 'z');
}
/**
    @brief Check if a character is upper case without using locale
    @param c The character to check
    @return @c true if the char is upper, @c false otherwise
    @details This function checks if a character is upper case alphabetic
             without using the locale information.
*/
inline bool is_upper_nolocale(char c) noexcept
{
    return (c >= 'A' && c <= 'Z');
}

} // namespace clv

#endif // CLV_CHAR_UTIL_H
