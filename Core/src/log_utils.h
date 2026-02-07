// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <vector>

namespace clv::vpn {

/**
 * @brief Format binary data as a hex string for logging/debugging
 *
 * @param data Binary data to format
 * @param max_bytes Maximum number of bytes to include (default 60, 0 = unlimited)
 * @param separator Character(s) to insert between hex bytes (default " ")
 * @return Hex string like "de ad be ef ..." with ellipsis if truncated
 */
inline std::string HexDump(std::span<const std::uint8_t> data,
                           std::size_t max_bytes = 60,
                           const char *separator = " ")
{
    std::string hex;
    std::size_t limit = (max_bytes == 0) ? data.size() : std::min(data.size(), max_bytes);
    hex.reserve(limit * 3 + 4); // 3 chars per byte + "..."

    for (std::size_t i = 0; i < limit; ++i)
    {
        char buf[4];
        std::snprintf(buf, sizeof(buf), "%02x", data[i]);
        hex += buf;
        if (separator && i + 1 < limit)
        {
            hex += separator;
        }
    }

    if (max_bytes > 0 && data.size() > max_bytes)
    {
        hex += "...";
    }

    return hex;
}

/**
 * @brief Format binary data as a hex string for logging/debugging (vector overload)
 *
 * @param data Binary data to format
 * @param max_bytes Maximum number of bytes to include (default 60, 0 = unlimited)
 * @param separator Character(s) to insert between hex bytes (default " ")
 * @return Hex string like "de ad be ef ..." with ellipsis if truncated
 */
inline std::string HexDump(const std::vector<std::uint8_t> &data,
                           std::size_t max_bytes = 60,
                           const char *separator = " ")
{
    return HexDump(std::span<const std::uint8_t>(data), max_bytes, separator);
}

} // namespace clv::vpn

// OpenSSL-specific utilities (requires <openssl/err.h>)
#ifdef OPENSSL_ERR_H

namespace clv::vpn {

/**
 * @brief Drain all pending OpenSSL errors into a vector of strings
 *
 * Call this after an OpenSSL operation fails to capture detailed error information.
 * The error queue is cleared after calling this function.
 *
 * @return Vector of human-readable error strings
 */
inline std::vector<std::string> DrainOpenSslErrors()
{
    std::vector<std::string> errors;
    unsigned long err;
    while ((err = ERR_get_error()) != 0)
    {
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        errors.emplace_back(err_buf);
    }
    return errors;
}

/**
 * @brief Drain OpenSSL errors and invoke a callback for each
 *
 * Convenience wrapper that drains the error queue and calls the provided
 * function for each error string.
 *
 * @tparam Func Callable taking (const std::string&)
 * @param func Callback invoked for each error string
 */
template <typename Func>
inline void ForEachOpenSslError(Func &&func)
{
    unsigned long err;
    while ((err = ERR_get_error()) != 0)
    {
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        func(std::string(err_buf));
    }
}

} // namespace clv::vpn
#endif // OPENSSL_ERR_H
