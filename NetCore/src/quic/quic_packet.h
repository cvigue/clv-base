// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <system_error>
#include <variant>
#include <vector>

#include "util/byte_packer.h"
#include "connection_id.h"
#include "quic_varint.h"
#include <result_or.h>

namespace clv::quic {

// TODO: This seems very C++ as C, look into using better C++ practices later.

/// QUIC packet header types
enum class PacketType : std::uint8_t
{
    Initial = 0x00,
    ZeroRTT = 0x01,
    Handshake = 0x02,
    Retry = 0x03,
    Short = 0xFF // Sentinel value; short headers don't have an explicit type field
};

/// Long header (Initial, Handshake, 0-RTT, Retry)
struct LongHeader
{
    PacketType type{PacketType::Initial};
    std::uint32_t version{0};
    ConnectionId dest_conn_id{};
    ConnectionId src_conn_id{};
    std::uint64_t packet_number{0};

    // Initial packet only: token
    std::vector<std::uint8_t> token{};

    // Payload length (for Initial, Handshake, 0-RTT)
    std::uint64_t payload_length{0};
};

/// Short header (post-handshake application data)
struct ShortHeader
{
    ConnectionId dest_conn_id{};
    std::uint64_t packet_number{0};
    bool spin_bit{false};
    bool key_phase{false};
};

/// Parsed packet header (either long or short)
using PacketHeader = std::variant<LongHeader, ShortHeader>;

/// Parse result with header and remaining payload
struct ParsedPacket
{
    PacketHeader header;
    std::span<const std::uint8_t> payload;
};

/// Parse packet header from bytes
/// Returns the parsed header and remaining payload, or an error.
[[nodiscard]] inline clv::result_or<ParsedPacket, std::errc>
ParsePacketHeader(std::span<const std::uint8_t> data) noexcept
{
    if (data.empty())
        return std::errc::invalid_argument;

    const std::uint8_t first = data[0];
    const bool is_long_header = (first & 0x80) != 0;

    if (is_long_header)
    {
        // Long header format:
        // 1XXXXXXX VVVVVVVV VVVVVVVV VVVVVVVV VVVVVVVV
        // DCIDLEN DCID... SCIDLEN SCID... [TYPE-SPECIFIC]
        if (data.size() < 6)
            return std::errc::message_size;

        LongHeader hdr;

        // Extract packet type from first byte (bits 4-5)
        const std::uint8_t type_bits = (first & 0x30) >> 4;
        switch (type_bits)
        {
        case 0:
            hdr.type = PacketType::Initial;
            break;
        case 1:
            hdr.type = PacketType::ZeroRTT;
            break;
        case 2:
            hdr.type = PacketType::Handshake;
            break;
        case 3:
            hdr.type = PacketType::Retry;
            break;
        default:
            return std::errc::protocol_error;
        }

        // Extract version (4 bytes big-endian)
        hdr.version = netcore::bytes_to_uint(data[1], data[2], data[3], data[4]);

        std::size_t offset = 5;

        // Destination Connection ID Length (1 byte)
        const std::uint8_t dcid_len = data[offset++];
        if (dcid_len > 20)
            return std::errc::protocol_error;
        if (offset + dcid_len > data.size())
            return std::errc::message_size;

        hdr.dest_conn_id.length = dcid_len;
        std::copy_n(data.begin() + offset, dcid_len, hdr.dest_conn_id.data.begin());
        offset += dcid_len;

        // Source Connection ID Length (1 byte)
        if (offset >= data.size())
            return std::errc::message_size;
        const std::uint8_t scid_len = data[offset++];
        if (scid_len > 20)
            return std::errc::protocol_error;
        if (offset + scid_len > data.size())
            return std::errc::message_size;

        hdr.src_conn_id.length = scid_len;
        std::copy_n(data.begin() + offset, scid_len, hdr.src_conn_id.data.begin());
        offset += scid_len;

        // Type-specific fields
        if (hdr.type == PacketType::Initial)
        {
            // Token Length (varint) + Token
            auto token_len_result = DecodeVarint(data.subspan(offset));
            if (!token_len_result)
                return std::errc::protocol_error;
            const auto [token_len, token_len_bytes] = *token_len_result;
            offset += token_len_bytes;

            if (offset + token_len > data.size())
                return std::errc::message_size;

            hdr.token.resize(token_len);
            std::copy_n(data.begin() + offset, token_len, hdr.token.begin());
            offset += token_len;
        }

        if (hdr.type != PacketType::Retry)
        {
            // Length (varint) - length of packet number + payload
            auto length_result = DecodeVarint(data.subspan(offset));
            if (!length_result)
                return std::errc::protocol_error;
            const auto [length, length_bytes] = *length_result;
            offset += length_bytes;
            hdr.payload_length = length;

            // Packet Number (1-4 bytes, length encoded in first byte bits 0-1)
            // For simplicity in MVP, assume 4-byte packet number
            const std::uint8_t pn_len = ((first & 0x03) + 1);
            if (offset + pn_len > data.size())
                return std::errc::message_size;

            hdr.packet_number = 0;
            for (std::size_t i = 0; i < pn_len; ++i)
            {
                hdr.packet_number = (hdr.packet_number << 8) | data[offset++];
            }
        }

        // Remaining data is the payload (or packet protection)
        ParsedPacket result;
        result.header = hdr;
        result.payload = data.subspan(offset);
        return result;
    }
    else
    {
        // Short header format:
        // 0XXXXXXX DCID... PN...
        ShortHeader hdr;

        hdr.spin_bit = (first & 0x20) != 0;
        hdr.key_phase = (first & 0x04) != 0;

        // For short headers, we need to know the DCID length from context.
        // In the MVP, we'll attempt to match against known connection IDs.
        // This is handled by the connection manager's parse_short_dcid function.
        // Here we just extract what we can.

        // Packet number length is encoded in bits 0-1 of first byte
        // const std::uint8_t pn_len = ((first & 0x03) + 1);

        // We can't parse the DCID without knowing its length, so this will be
        // handled by the caller (connection manager) which knows the length.
        // For now, return a minimal short header.

        ParsedPacket result;
        result.header = hdr;
        result.payload = data.subspan(1); // Skip first byte
        return result;
    }
}

/// Serialize a long header to bytes
[[nodiscard]] inline std::vector<std::uint8_t> SerializeLongHeader(const LongHeader &hdr) noexcept
{
    std::vector<std::uint8_t> out;
    out.reserve(64); // Typical size

    // First byte: 1 | fixed(1) | type(2) | reserved(2) | packet_number_len(2)
    std::uint8_t first = 0xC0; // Long header bit + fixed bit
    switch (hdr.type)
    {
    case PacketType::Initial:
        first |= (0x00 << 4);
        break;
    case PacketType::ZeroRTT:
        first |= (0x01 << 4);
        break;
    case PacketType::Handshake:
        first |= (0x02 << 4);
        break;
    case PacketType::Retry:
        first |= (0x03 << 4);
        break;
    default:
        break;
    }

    // Packet number length - 1 (for 4-byte packet number, use 3)
    first |= 0x03; // 4-byte packet number

    // TODO: A lot of this can be cleaned up when insert_range is available in popular STLs
    // Pack first byte and version together (1 + 4 = 5 bytes)
    auto header_bytes = netcore::multi_uint_to_bytes(first, hdr.version);
    out.insert(out.end(), header_bytes.begin(), header_bytes.end());

    // Destination Connection ID
    out.push_back(hdr.dest_conn_id.length);
    out.insert(out.end(), hdr.dest_conn_id.data.begin(), hdr.dest_conn_id.data.begin() + hdr.dest_conn_id.length);

    // Source Connection ID
    out.push_back(hdr.src_conn_id.length);
    out.insert(out.end(), hdr.src_conn_id.data.begin(), hdr.src_conn_id.data.begin() + hdr.src_conn_id.length);

    // Type-specific fields
    if (hdr.type == PacketType::Initial)
    {
        // Token Length (varint) + Token
        std::array<std::uint8_t, 8> varint_buf;
        const auto token_len_bytes = EncodeVarint(hdr.token.size(), varint_buf);
        out.insert(out.end(), varint_buf.begin(), varint_buf.begin() + token_len_bytes);
        out.insert(out.end(), hdr.token.begin(), hdr.token.end());
    }

    if (hdr.type != PacketType::Retry)
    {
        // Length (varint) - will be filled in later when payload is known
        std::array<std::uint8_t, 8> varint_buf;
        const auto length_bytes = EncodeVarint(hdr.payload_length, varint_buf);
        out.insert(out.end(), varint_buf.begin(), varint_buf.begin() + length_bytes);

        // Packet Number (4 bytes)
        auto pn_bytes = netcore::uint_to_bytes<4>(hdr.packet_number);
        out.insert(out.end(), pn_bytes.begin(), pn_bytes.end());
    }

    return out;
}

/// Serialize a short header to bytes
[[nodiscard]] inline std::vector<std::uint8_t> SerializeShortHeader(const ShortHeader &hdr) noexcept
{
    std::vector<std::uint8_t> out;
    out.reserve(32);

    // First byte: 0 | fixed(1) | spin(1) | reserved(2) | key_phase(1) | reserved(2) | pn_len(2)
    std::uint8_t first = 0x40; // Fixed bit (must be 1)
    if (hdr.spin_bit)
        first |= 0x20;
    if (hdr.key_phase)
        first |= 0x04;
    first |= 0x03; // 4-byte packet number

    out.push_back(first);

    // Destination Connection ID
    out.insert(out.end(), hdr.dest_conn_id.data.begin(), hdr.dest_conn_id.data.begin() + hdr.dest_conn_id.length);

    // Packet Number (4 bytes)
    auto pn_bytes = netcore::uint_to_bytes<4>(hdr.packet_number);
    out.insert(out.end(), pn_bytes.begin(), pn_bytes.end());

    return out;
}

/// Serialize packet header to bytes (dispatches to long/short)
[[nodiscard]] inline std::vector<std::uint8_t> SerializeHeader(const PacketHeader &header) noexcept
{
    if (std::holds_alternative<LongHeader>(header))
    {
        return SerializeLongHeader(std::get<LongHeader>(header));
    }
    else
    {
        return SerializeShortHeader(std::get<ShortHeader>(header));
    }
}

} // namespace clv::quic
