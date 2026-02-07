// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_NETCORE_QUIC_QUIC_PACKET_RECEIVER_H
#define CLV_NETCORE_QUIC_QUIC_PACKET_RECEIVER_H

#include "quic/quic_tls.h"
#include "quic_connection.h"
#include "quic_crypto.h"
#include "quic_packet.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include <spdlog/spdlog.h>

namespace clv::quic {

// Result of packet processing containing decrypted frames
struct ReceivedPacket
{
    std::vector<std::uint8_t> decrypted_payload;
    std::uint64_t packet_number;
    QuicEncryptionLevel level;
    bool is_long_header;
};

// Encapsulates packet decryption, header unprotection, and initial parsing
// Does NOT process frames - just extracts and decrypts them
class QuicPacketReceiver
{
  public:
    // Process a received packet: unprotect header, decrypt payload
    // Returns decrypted payload and metadata if successful
    std::optional<ReceivedPacket> ProcessPacket(
        std::span<std::uint8_t> packet_data,
        EncryptionLevel enc_level,
        QuicConnection &connection)
    {
        if (!connection.crypto)
            return std::nullopt;

        if (packet_data.size() < 20)
            return std::nullopt;

        std::size_t offset = 0;
        std::uint8_t first_byte = packet_data[offset++];
        bool is_long = (first_byte & 0x80) != 0;
        std::size_t pn_offset;
        std::uint64_t payload_length;

        if (is_long)
        {
            // Long header: Initial or Handshake
            // Skip version (4 bytes)
            offset += 4;

            // DCID length + DCID
            std::uint8_t dcid_len = packet_data[offset++];
            offset += dcid_len;

            // SCID length + SCID
            std::uint8_t scid_len = packet_data[offset++];
            offset += scid_len;

            // Token length (varint) - ONLY for Initial packets!
            std::uint8_t type_bits = (first_byte & 0x30) >> 4;
            PacketType pkt_type = static_cast<PacketType>(type_bits);

            if (pkt_type == PacketType::Initial)
            {
                auto token_len_result = DecodeVarint(packet_data.subspan(offset));
                if (!token_len_result)
                    return std::nullopt;
                offset += token_len_result->second + token_len_result->first;
            }

            // Payload length (varint)
            auto payload_len_result = DecodeVarint(packet_data.subspan(offset));
            if (!payload_len_result)
                return std::nullopt;
            payload_length = payload_len_result->first;
            offset += payload_len_result->second;

            pn_offset = offset;
        }
        else
        {
            // Short header (1-RTT)
            std::uint8_t dcid_len = connection.local_id.length;
            offset += dcid_len;
            pn_offset = offset;
            payload_length = packet_data.size() - pn_offset;
        }

        // Sample starts 4 bytes after pn_offset
        std::size_t sample_offset = pn_offset + 4;
        if (sample_offset + 16 > packet_data.size())
            return std::nullopt;

        std::span<const std::uint8_t> sample(packet_data.data() + sample_offset, 16);

        // Unprotect header to get actual packet number
        auto pn_length_result = connection.crypto->UnprotectHeader(
            packet_data,
            pn_offset,
            sample,
            enc_level);

        if (!pn_length_result)
        {
            spdlog::trace("[PacketReceiver] Failed to unprotect header");
            return std::nullopt;
        }

        std::size_t pn_length = *pn_length_result;

        // Extract packet number (truncated) - big-endian
        std::uint64_t truncated_pn = 0;
        for (std::size_t i = 0; i < pn_length; ++i)
        {
            truncated_pn = (truncated_pn << 8) | packet_data[pn_offset + i];
        }

        // Decode full packet number
        std::uint64_t expected_pn = connection.crypto->GetNextPacketNumber(enc_level);
        std::uint64_t packet_number = QuicCrypto::DecodePacketNumber(
            truncated_pn,
            pn_length * 8,
            expected_pn);

        spdlog::trace("[PacketReceiver] Packet number: {} (truncated: {}, length: {})",
                      packet_number,
                      truncated_pn,
                      pn_length);

        // Decrypt the payload
        std::size_t header_len = pn_offset + pn_length;
        std::span<const std::uint8_t> ciphertext(
            packet_data.data() + header_len,
            payload_length - pn_length);

        auto decrypted = connection.crypto->DecryptPacketWithAad(
            ciphertext,
            packet_number,
            enc_level,
            std::span{packet_data.data(), header_len});

        if (!decrypted)
        {
            spdlog::trace("[PacketReceiver] Failed to decrypt payload (expected during handshake/reordering)");
            return std::nullopt;
        }

        spdlog::debug("[PacketReceiver] Successfully decrypted {} bytes", decrypted->size());

        // Map EncryptionLevel to QuicEncryptionLevel
        QuicEncryptionLevel quic_level;
        switch (enc_level)
        {
        case EncryptionLevel::Initial:
            quic_level = QuicEncryptionLevel::Initial;
            break;
        case EncryptionLevel::Handshake:
            quic_level = QuicEncryptionLevel::Handshake;
            break;
        case EncryptionLevel::Application:
            quic_level = QuicEncryptionLevel::Application;
            break;
        default:
            quic_level = QuicEncryptionLevel::Initial;
        }

        ReceivedPacket result;
        result.decrypted_payload = std::move(*decrypted);
        result.packet_number = packet_number;
        result.level = quic_level;
        result.is_long_header = is_long;

        return result;
    }
};

} // namespace clv::quic

#endif // CLV_NETCORE_QUIC_QUIC_PACKET_RECEIVER_H
