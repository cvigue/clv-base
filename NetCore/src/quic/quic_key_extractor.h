// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_NETCORE_QUIC_KEY_EXTRACTOR_H
#define CLV_NETCORE_QUIC_KEY_EXTRACTOR_H

#include "quic/connection_id.h"
// #include "quic/quic_packet.h"
#include <algorithm>
#include <cstddef>
#include <span>
#include <cstdint>
#include <optional>

namespace clv {

/**
 * @brief Extracts destination connection ID from QUIC packets for routing
 *
 * @details Parses the QUIC packet header (long or short) to extract the
 *          destination connection ID (DCID), which is used to route packets
 *          to the correct QUIC connection/session.
 *
 * For QUIC:
 * - Long headers (Initial, Handshake, 0-RTT): DCID at fixed offset after version
 * - Short headers (1-RTT): DCID immediately after first byte
 * - Connection ID length is variable (0-20 bytes)
 *
 * Returns nullopt for:
 * - Version negotiation packets (no established connection)
 * - Malformed packets
 * - Packets too short to contain a valid header
 *
 * @note This is a stateless extractor - can be stored by value
 */
struct QuicKeyExtractor
{
    using KeyType = quic::ConnectionId;

    /**
     * @brief Extract destination connection ID from QUIC packet
     *
     * @param data Raw packet data
     * @return std::optional<quic::ConnectionId> The DCID if parseable, nullopt otherwise
     */
    std::optional<quic::ConnectionId> ExtractKey(
        std::span<const uint8_t> data) const
    {
        if (data.empty())
        {
            return std::nullopt;
        }

        // Check if long header (first bit set)
        bool is_long_header = (data[0] & 0x80) != 0;

        if (is_long_header)
        {
            return ExtractFromLongHeader(data);
        }
        else
        {
            return ExtractFromShortHeader(data);
        }
    }

  private:
    /**
     * @brief Extract DCID from long header packet
     *
     * Long header format:
     * - Byte 0: Header form (1 bit) | Fixed bit | Long packet type (2 bits) | Reserved (2 bits) | Packet number length (2 bits)
     * - Bytes 1-4: Version
     * - Byte 5: DCID Length
     * - Bytes 6+: DCID (variable)
     */
    std::optional<quic::ConnectionId> ExtractFromLongHeader(
        std::span<const uint8_t> data) const
    {
        // Need at least: 1 (flags) + 4 (version) + 1 (dcid_len) = 6 bytes
        if (data.size() < 6)
        {
            return std::nullopt;
        }

        // Parse version (bytes 1-4)
        std::uint32_t version = (static_cast<std::uint32_t>(data[1]) << 24) | (static_cast<std::uint32_t>(data[2]) << 16) | (static_cast<std::uint32_t>(data[3]) << 8) | (static_cast<std::uint32_t>(data[4]));

        // Version 0 is version negotiation - no connection ID routing
        if (version == 0)
        {
            return std::nullopt;
        }

        // Parse DCID length (byte 5)
        std::uint8_t dcid_len = data[5];

        // DCID length must be 0-20 bytes
        if (dcid_len > 20)
        {
            return std::nullopt;
        }

        // Verify we have enough data for DCID
        if (data.size() < static_cast<size_t>(6 + dcid_len))
        {
            return std::nullopt;
        }

        // Extract DCID
        quic::ConnectionId dcid;
        dcid.length = dcid_len;
        std::copy_n(data.begin() + 6, dcid_len, dcid.data.begin());

        return dcid;
    }

    /**
     * @brief Extract DCID from short header packet
     *
     * Short header format:
     * - Byte 0: Header form (0 bit) | Fixed bit | Spin bit | Reserved (2 bits) | Key phase | Packet number length (2 bits)
     * - Bytes 1+: DCID (length configured per connection, typically 8 bytes)
     *
     * Note: For short headers, we need to know the DCID length from connection state.
     * Since we're routing TO find the connection, we use a convention: try common lengths.
     * Most implementations use 8-byte connection IDs.
     */
    std::optional<quic::ConnectionId> ExtractFromShortHeader(
        std::span<const uint8_t> data) const
    {
        // Fixed bit (0x40) must be set
        if ((data[0] & 0x40) == 0)
        {
            return std::nullopt;
        }

        // Try common DCID length: 8 bytes
        // This is a limitation of the routing design - we assume standard length
        // A production implementation would need a way to determine DCID length
        // (e.g., from configuration or by trying multiple lengths)
        constexpr std::uint8_t assumed_dcid_len = 8;

        if (data.size() < static_cast<size_t>(1 + assumed_dcid_len))
        {
            return std::nullopt;
        }

        quic::ConnectionId dcid;
        dcid.length = assumed_dcid_len;
        std::copy_n(data.begin() + 1, assumed_dcid_len, dcid.data.begin());

        return dcid;
    }
};

} // namespace clv

#endif // CLV_NETCORE_QUIC_KEY_EXTRACTOR_H
