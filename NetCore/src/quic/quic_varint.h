// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace clv::quic {

/**
 * @brief Decode a QUIC variable-length integer from a byte span.
 * @param data The input byte span containing the encoded varint.
 * @details The function reads the first byte to determine the length of the varint
 *          and extracts the value accordingly. If the data is insufficient or invalid,
 *          it returns std::nullopt.
 * @return An optional pair of the decoded value and number of bytes consumed,
 *         or std::nullopt if the data is invalid or insufficient.
 * @note Format:
 *       - 1-byte: 00xxxxxx               : 6-bit value (0-63)
 *       - 2-byte: 01xxxxxx yyyyyyyy      : 14-bit value (0-16383)
 *       - 4-byte: 10xxxxxx ... (4 bytes) : 30-bit value (0-1073741823)
 *       - 8-byte: 11xxxxxx ... (8 bytes) : 62-bit value (0-4611686018427387903)
 */
[[nodiscard]] inline std::optional<std::pair<std::uint64_t, std::size_t>>
DecodeVarint(std::span<const std::uint8_t> data) noexcept
{
    if (data.empty())
        return std::nullopt;

    const std::uint8_t first = data[0];
    const std::uint8_t prefix = first >> 6;

    switch (prefix)
    {
    case 0: // 1-byte: 00xxxxxx
        {
            return std::make_pair(static_cast<std::uint64_t>(first & 0x3F), 1);
        }
    case 1: // 2-byte: 01xxxxxx yyyyyyyy
        {
            if (data.size() < 2)
                return std::nullopt;
            const std::uint64_t val = ((static_cast<std::uint64_t>(first & 0x3F) << 8) | static_cast<std::uint64_t>(data[1]));
            return std::make_pair(val, 2);
        }
    case 2: // 4-byte: 10xxxxxx + 3 more bytes
        {
            if (data.size() < 4)
                return std::nullopt;
            const std::uint64_t val = ((static_cast<std::uint64_t>(first & 0x3F) << 24) | (static_cast<std::uint64_t>(data[1]) << 16) | (static_cast<std::uint64_t>(data[2]) << 8) | static_cast<std::uint64_t>(data[3]));
            return std::make_pair(val, 4);
        }
    case 3: // 8-byte: 11xxxxxx + 7 more bytes
        {
            if (data.size() < 8)
                return std::nullopt;
            std::uint64_t val = static_cast<std::uint64_t>(first & 0x3F);
            for (std::size_t i = 1; i < 8; ++i)
            {
                val = (val << 8) | static_cast<std::uint64_t>(data[i]);
            }
            return std::make_pair(val, 8);
        }
    default:
        return std::nullopt;
    }
}

/**
 * @param value The integer value to encode.
 * @param out The output buffer span to write the encoded varint.
 * @return The number of bytes written to the buffer, or 0 if the value is out of range.
 * @todo consider byte_packer here.
 */
[[nodiscard]] inline std::size_t EncodeVarint(std::uint64_t value,
                                              std::span<std::uint8_t> out) noexcept
{
    if (value <= 63)
    {
        // 1-byte encoding: 00xxxxxx
        if (out.size() < 1)
            return 0;
        out[0] = static_cast<std::uint8_t>(value);
        return 1;
    }
    else if (value <= 16383)
    {
        // 2-byte encoding: 01xxxxxx yyyyyyyy
        if (out.size() < 2)
            return 0;
        out[0] = static_cast<std::uint8_t>(0x40 | (value >> 8));
        out[1] = static_cast<std::uint8_t>(value & 0xFF);
        return 2;
    }
    else if (value <= 1073741823)
    {
        // 4-byte encoding: 10xxxxxx + 3 bytes
        if (out.size() < 4)
            return 0;
        out[0] = static_cast<std::uint8_t>(0x80 | (value >> 24));
        out[1] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
        out[2] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
        out[3] = static_cast<std::uint8_t>(value & 0xFF);
        return 4;
    }
    else if (value <= 4611686018427387903ull)
    {
        // 8-byte encoding: 11xxxxxx + 7 bytes
        if (out.size() < 8)
            return 0;
        out[0] = static_cast<std::uint8_t>(0xC0 | (value >> 56));
        for (std::size_t i = 1; i < 8; ++i)
        {
            out[i] = static_cast<std::uint8_t>((value >> (8 * (7 - i))) & 0xFF);
        }
        return 8;
    }
    else
    {
        // Value out of range for QUIC varint (max is 2^62 - 1)
        return 0;
    }
}

/**
 * @brief Convenience wrapper that returns the encoded varint as a vector.
 * @param value The integer value to encode (max 2^62 - 1).
 * @return Encoded bytes, or empty vector if value is out of range.
 */
[[nodiscard]] inline std::vector<std::uint8_t> EncodeVarintVec(std::uint64_t value) noexcept
{
    std::array<std::uint8_t, 8> buf{};
    auto n = EncodeVarint(value, buf);
    return {buf.begin(), buf.begin() + n};
}

// Determine the number of bytes required to encode a value.
[[nodiscard]] constexpr std::size_t VarintEncodedLength(std::uint64_t value) noexcept
{
    if (value <= 63)
        return 1;
    else if (value <= 16383)
        return 2;
    else if (value <= 1073741823)
        return 4;
    else if (value <= 4611686018427387903ull)
        return 8;
    else
        return 0; // out of range
}

} // namespace clv::quic
