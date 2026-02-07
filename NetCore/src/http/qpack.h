// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_NETCORE_HTTP_QPACK_H
#define CLV_NETCORE_HTTP_QPACK_H

#include "quic/quic_varint.h"
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

// nghttp3 Huffman decoder (C library)
extern "C"
{
#include <nghttp3_qpack_huffman.h>
}

#include <http/http3_fwd.h>
#include <http/http3_frame.h>

namespace clv::http3 {

using clv::quic::DecodeVarint;
using clv::quic::EncodeVarint;

/**
 * @brief Decode Huffman-encoded string using nghttp3
 * @param data Huffman-encoded bytes
 * @return Decoded string or nullopt on error
 */
inline std::optional<std::string>
DecodeHuffman(std::span<const std::uint8_t> data)
{
    if (data.empty())
        return std::string{};

    // Huffman decoding can expand data, but never more than ~2x for HPACK/QPACK
    std::vector<std::uint8_t> decoded(data.size() * 2 + 256);

    nghttp3_qpack_huffman_decode_context ctx;
    nghttp3_qpack_huffman_decode_context_init(&ctx);

    auto result = nghttp3_qpack_huffman_decode(
        &ctx,
        decoded.data(),
        data.data(),
        data.size(),
        1 /* fin - this is the complete string */
    );

    if (result < 0)
    {
        return std::nullopt; // Decoding failed
    }

    return std::string(decoded.begin(), decoded.begin() + result);
}

/**
 * @brief Decode HPACK/QPACK prefix integer (RFC 7541 Section 5.1)
 * @param data Input bytes
 * @param prefix_bits Number of bits available in the first byte for the integer
 * @return Pair of (value, bytes_consumed) or nullopt on error
 * @todo Maybe this can be meta-unrolled with some template magic?
 */
inline std::optional<std::pair<std::uint64_t, std::size_t>>
DecodeHpackInt(std::span<const std::uint8_t> data, std::uint8_t prefix_bits)
{
    if (data.empty() || prefix_bits == 0 || prefix_bits > 8)
        return std::nullopt;

    const std::uint8_t prefix_mask = static_cast<std::uint8_t>((1 << prefix_bits) - 1);
    std::uint64_t value = data[0] & prefix_mask;
    std::size_t offset = 1;

    if (value < prefix_mask)
        return std::make_pair(value, offset); // Value fits in prefix

    // Value requires continuation bytes
    std::uint8_t shift = 0;
    while (offset < data.size())
    {
        std::uint8_t byte = data[offset++];
        value += static_cast<std::uint64_t>(byte & 0x7F) << shift;
        shift += 7;

        if ((byte & 0x80) == 0)
        {
            return std::make_pair(value, offset);
        }

        if (shift > 63)
        {
            return std::nullopt; // Overflow
        }
    }

    return std::nullopt; // Incomplete
}

/**
 * @brief Encode HPACK/QPACK prefix integer (RFC 7541 Section 5.1)
 * @param value The integer value to encode
 * @param prefix_bits Number of bits available in the first byte (1-8)
 * @param first_byte_flags Flags to OR into the first byte (e.g., 0xC0 for indexed static)
 * @return Encoded bytes
 */
inline std::vector<std::uint8_t>
EncodeHpackInt(std::uint64_t value, std::uint8_t prefix_bits, std::uint8_t first_byte_flags = 0)
{
    std::vector<std::uint8_t> result;
    const std::uint8_t prefix_mask = static_cast<std::uint8_t>((1 << prefix_bits) - 1);

    if (value < prefix_mask)
    {
        // Fits in prefix
        result.push_back(first_byte_flags | static_cast<std::uint8_t>(value));
    }
    else
    {
        // Requires continuation bytes
        result.push_back(first_byte_flags | prefix_mask);
        value -= prefix_mask;
        while (value >= 128)
        {
            result.push_back(static_cast<std::uint8_t>((value & 0x7F) | 0x80));
            value >>= 7;
        }
        result.push_back(static_cast<std::uint8_t>(value));
    }

    return result;
}

/**
 * @brief Simple QPACK encoder (RFC 9204)
 *
 * This is a simplified implementation that:
 * - Uses only the static table (no dynamic table)
 * - Supports indexed fields and literal fields
 * - Does not support dynamic table or advanced compression
 */
class QpackEncoder
{
  public:
    /**
     * @brief Encode header fields to QPACK format
     *
     * @param headers List of header fields to encode
     * @return QPACK-encoded header block
     */
    std::vector<std::uint8_t> Encode(const std::vector<HeaderField> &headers);
};

/**
 * @brief Simple QPACK decoder (RFC 9204)
 *
 * Decodes QPACK-encoded header blocks. Supports static table only.
 */
class QpackDecoder
{
  public:
    /**
     * @brief Decode QPACK-encoded header block
     *
     * @param data QPACK-encoded header block
     * @return Decoded header fields, or nullopt on error
     */
    std::optional<std::vector<HeaderField>> Decode(std::span<const std::uint8_t> data);
};

// Inline implementation
inline std::vector<std::uint8_t> QpackEncoder::Encode(const std::vector<HeaderField> &headers)
{
    std::vector<std::uint8_t> result;

    // Required Insert Count and Delta Base (0 for static-only encoding)
    result.push_back(0x00); // Required Insert Count = 0
    result.push_back(0x00); // Delta Base = 0

    for (const auto &header : headers)
    {
        // Try to find exact match in static table
        bool found = false;
        for (std::size_t i = 0; i < kQpackStaticTable.size(); ++i)
        {
            const auto &[name, value] = kQpackStaticTable[i];
            if (name == header.name && value == header.value)
            {
                // Indexed Field Line - Static (RFC 9204, Section 4.5.2)
                // Format: 1Txxxxxx - 6-bit prefix, T=1 for static table
                // 0xC0 = 11000000 (form=1, T=1)
                auto encoded = EncodeHpackInt(i, 6, 0xC0);
                result.insert(result.end(), encoded.begin(), encoded.end());
                found = true;
                break;
            }
        }

        if (!found)
        {
            // Literal Field Line with Name Reference (RFC 9204, Section 4.5.4)
            // Format: 01NTxxxx - 4-bit prefix, N=0, T=1 for static
            bool name_found = false;
            for (std::size_t i = 0; i < kQpackStaticTable.size(); ++i)
            {
                const auto &[name, value] = kQpackStaticTable[i];
                if (name == header.name)
                {
                    // 0x50 = 01010000 (01 prefix, N=0, T=1)
                    auto encoded = EncodeHpackInt(i, 4, 0x50);
                    result.insert(result.end(), encoded.begin(), encoded.end());

                    // Value: H(0) + length (7-bit prefix) + value bytes
                    auto value_len = EncodeHpackInt(header.value.size(), 7, 0x00);
                    result.insert(result.end(), value_len.begin(), value_len.end());
                    result.insert(result.end(), header.value.begin(), header.value.end());

                    name_found = true;
                    break;
                }
            }

            if (!name_found)
            {
                // Literal Field Line with Literal Name (RFC 9204, Section 4.5.6)
                // Format: 001Nxxxx - N=0, then H + name_len (3-bit prefix)
                // 0x20 = 00100000 (001 prefix, N=0, H=0)
                auto name_len = EncodeHpackInt(header.name.size(), 3, 0x20);
                result.insert(result.end(), name_len.begin(), name_len.end());
                result.insert(result.end(), header.name.begin(), header.name.end());

                // Value: H(0) + length (7-bit prefix) + value bytes
                auto value_len = EncodeHpackInt(header.value.size(), 7, 0x00);
                result.insert(result.end(), value_len.begin(), value_len.end());
                result.insert(result.end(), header.value.begin(), header.value.end());
            }
        }
    }

    return result;
}

inline std::optional<std::vector<HeaderField>> QpackDecoder::Decode(std::span<const std::uint8_t> data)
{
    if (data.size() < 2)
    {
        return std::nullopt;
    }

    std::size_t offset = 0;

    // Read Required Insert Count (8-bit prefix)
    auto ric_result = DecodeHpackInt(data.subspan(offset), 8);
    if (!ric_result)
    {
        return std::nullopt;
    }
    offset += ric_result->second;

    // Read Delta Base (7-bit prefix, with S bit)
    if (offset >= data.size())
        return std::nullopt;
    // bool sign_bit = (data[offset] & 0x80) != 0;  // S bit (ignored for now)
    auto delta_result = DecodeHpackInt(data.subspan(offset), 7);
    if (!delta_result)
    {
        return std::nullopt;
    }
    offset += delta_result->second;

    std::vector<HeaderField> headers;

    while (offset < data.size())
    {
        std::uint8_t prefix = data[offset];

        if ((prefix & 0xC0) == 0xC0)
        {
            // Indexed Field Line - Static Table (11xxxxxx) - 6-bit prefix
            auto index_result = DecodeHpackInt(data.subspan(offset), 6);
            if (!index_result)
            {
                return std::nullopt;
            }
            std::uint64_t index = index_result->first;
            offset += index_result->second;

            if (index >= kQpackStaticTable.size())
            {
                return std::nullopt; // Index out of bounds
            }

            const auto &[name, value] = kQpackStaticTable[index];
            headers.push_back({name, value});
        }
        else if ((prefix & 0xC0) == 0x80)
        {
            // Indexed Field Line - Dynamic Table (10xxxxxx) - not supported
            return std::nullopt;
        }
        else if ((prefix & 0xF0) == 0x50)
        {
            // Literal Field Line with Name Reference - Static Table (0101xxxx) - 4-bit prefix
            auto index_result = DecodeHpackInt(data.subspan(offset), 4);
            if (!index_result)
            {
                return std::nullopt;
            }
            std::uint64_t index = index_result->first;
            offset += index_result->second;

            if (index >= kQpackStaticTable.size())
            {
                return std::nullopt;
            }

            const auto &[name, _] = kQpackStaticTable[index];

            // Decode value (Huffman bit + 7-bit length prefix)
            if (offset >= data.size())
                return std::nullopt;
            bool huffman = (data[offset] & 0x80) != 0;
            auto value_len_result = DecodeHpackInt(data.subspan(offset), 7);
            if (!value_len_result)
            {
                return std::nullopt;
            }
            auto value_len = value_len_result->first;
            offset += value_len_result->second;

            if (offset + value_len > data.size())
            {
                return std::nullopt;
            }

            std::string value;
            if (huffman)
            {
                auto decoded = DecodeHuffman(data.subspan(offset, value_len));
                if (!decoded)
                    return std::nullopt;
                value = std::move(*decoded);
                offset += value_len;
            }
            else
            {
                value = std::string(data.begin() + offset, data.begin() + offset + value_len);
                offset += value_len;
            }

            headers.push_back({name, value});
        }
        else if ((prefix & 0xF0) == 0x40)
        {
            // Literal Field Line with Name Reference - Dynamic Table (0100xxxx) - not supported
            return std::nullopt;
        }
        else if ((prefix & 0xE0) == 0x20)
        {
            // Literal Field Line with Literal Name (001Hxxxx) - 3-bit prefix for name length
            if (offset >= data.size())
                return std::nullopt;
            bool name_huffman = (data[offset] & 0x08) != 0;
            auto name_len_result = DecodeHpackInt(data.subspan(offset), 3);
            if (!name_len_result)
            {
                return std::nullopt;
            }
            auto name_len = name_len_result->first;
            offset += name_len_result->second;

            if (offset + name_len > data.size())
            {
                return std::nullopt;
            }

            std::string name;
            if (name_huffman)
            {
                auto decoded = DecodeHuffman(data.subspan(offset, name_len));
                if (!decoded)
                    return std::nullopt;
                name = std::move(*decoded);
                offset += name_len;
            }
            else
            {
                name = std::string(data.begin() + offset, data.begin() + offset + name_len);
                offset += name_len;
            }

            // Decode value (Huffman bit + 7-bit length prefix)
            if (offset >= data.size())
                return std::nullopt;
            bool value_huffman = (data[offset] & 0x80) != 0;
            auto value_len_result = DecodeHpackInt(data.subspan(offset), 7);
            if (!value_len_result)
            {
                return std::nullopt;
            }
            auto value_len = value_len_result->first;
            offset += value_len_result->second;

            if (offset + value_len > data.size())
            {
                return std::nullopt;
            }

            std::string value;
            if (value_huffman)
            {
                auto decoded = DecodeHuffman(data.subspan(offset, value_len));
                if (!decoded)
                    return std::nullopt;
                value = std::move(*decoded);
                offset += value_len;
            }
            else
            {
                value = std::string(data.begin() + offset, data.begin() + offset + value_len);
                offset += value_len;
            }

            headers.push_back({name, value});
        }
        else
        {
            // Unknown encoding or unsupported
            return std::nullopt;
        }
    }

    return headers;
}

/**
 * @brief HTTP/3 SETTINGS frame parameters (RFC 9114 §7.2.4)
 */
enum class Http3Setting : std::uint64_t
{
    QpackMaxTableCapacity = 0x01, ///< SETTINGS_QPACK_MAX_TABLE_CAPACITY
    MaxFieldSectionSize = 0x06,   ///< SETTINGS_MAX_FIELD_SECTION_SIZE
    QpackBlockedStreams = 0x07,   ///< SETTINGS_QPACK_BLOCKED_STREAMS
};

/**
 * @brief Encode HTTP/3 SETTINGS frame (RFC 9114 §7.2.4)
 * @param settings Map of setting identifier to value
 * @return Encoded SETTINGS frame (type + length + payload)
 */
inline std::vector<std::uint8_t> EncodeSettingsFrame(
    const std::vector<std::pair<std::uint64_t, std::uint64_t>> &settings)
{
    std::vector<std::uint8_t> payload;

    // Encode each setting as identifier-value pair (both varints)
    for (const auto &[id, value] : settings)
    {
        auto id_bytes = EncodeVarintToVector(id);
        auto value_bytes = EncodeVarintToVector(value);
        payload.insert(payload.end(), id_bytes.begin(), id_bytes.end());
        payload.insert(payload.end(), value_bytes.begin(), value_bytes.end());
    }

    // Build frame: type (0x04) + length + payload
    std::vector<std::uint8_t> frame;
    auto type_bytes = EncodeVarintToVector(0x04); // SETTINGS frame type
    auto length_bytes = EncodeVarintToVector(payload.size());

    frame.insert(frame.end(), type_bytes.begin(), type_bytes.end());
    frame.insert(frame.end(), length_bytes.begin(), length_bytes.end());
    frame.insert(frame.end(), payload.begin(), payload.end());

    return frame;
}

/**
 * @brief Create HTTP/3 control stream data (RFC 9114 §6.2.1)
 *
 * Generates the initial data for an HTTP/3 control stream:
 * 1. Stream type byte (0x00 for control stream)
 * 2. SETTINGS frame with minimal configuration
 *
 * @return Control stream initialization data
 */
inline std::vector<std::uint8_t> CreateControlStreamData()
{
    std::vector<std::uint8_t> data;

    // Stream type: 0x00 = Control Stream (RFC 9114 §6.2.1)
    auto stream_type = EncodeVarintToVector(0x00);
    data.insert(data.end(), stream_type.begin(), stream_type.end());

    // Minimal SETTINGS frame
    std::vector<std::pair<std::uint64_t, std::uint64_t>> settings = {
        {static_cast<std::uint64_t>(Http3Setting::QpackMaxTableCapacity), 0},
        {static_cast<std::uint64_t>(Http3Setting::QpackBlockedStreams), 0}};

    auto settings_frame = EncodeSettingsFrame(settings);
    data.insert(data.end(), settings_frame.begin(), settings_frame.end());

    return data;
}

/**
 * @brief Create QPACK encoder stream data (RFC 9204 §4.2)
 * @return QPACK encoder stream initialization data (just stream type)
 */
inline std::vector<std::uint8_t> CreateQpackEncoderStreamData()
{
    std::vector<std::uint8_t> data;

    // Stream type: 0x02 = QPACK Encoder Stream (RFC 9204 §4.2)
    auto stream_type = EncodeVarintToVector(0x02);
    data.insert(data.end(), stream_type.begin(), stream_type.end());

    // No additional data needed when not using dynamic table
    return data;
}

/**
 * @brief Create QPACK decoder stream data (RFC 9204 §4.2)
 * @return QPACK decoder stream initialization data (just stream type)
 */
inline std::vector<std::uint8_t> CreateQpackDecoderStreamData()
{
    std::vector<std::uint8_t> data;

    // Stream type: 0x03 = QPACK Decoder Stream (RFC 9204 §4.2)
    auto stream_type = EncodeVarintToVector(0x03);
    data.insert(data.end(), stream_type.begin(), stream_type.end());

    // No additional data needed when not using dynamic table
    return data;
}

} // namespace clv::http3

#endif // CLV_NETCORE_HTTP_QPACK_H