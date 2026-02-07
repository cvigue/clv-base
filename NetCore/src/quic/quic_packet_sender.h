// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_NETCORE_QUIC_QUIC_PACKET_SENDER_H
#define CLV_NETCORE_QUIC_QUIC_PACKET_SENDER_H

#include "micro_udp_server_defs.h"
#include "quic/quic_tls.h"
#include "quic_connection.h"
#include "quic_crypto.h"
#include "quic_packet.h"

#include <asio/awaitable.hpp>
#include <asio/ip/udp.hpp>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <spdlog/spdlog.h>

namespace clv::quic {

// Encapsulates packet building, encryption, header protection, and sending
// Handles both long header (Initial/Handshake) and short header (Application) packets
class QuicPacketSender
{
  public:
    // Send packet with given frames at specified encryption level
    // Throws std::runtime_error on failure
    asio::awaitable<void> SendPacket(std::vector<std::uint8_t> frame_bytes,
                                     QuicEncryptionLevel level,
                                     QuicConnection &connection,
                                     UdpServerDefs::SendDatagramFnT send_fn,
                                     const asio::ip::udp::endpoint &remote_ep)
    {
        if (!connection.crypto)
        {
            throw std::runtime_error("QuicCrypto not available");
        }

        // Determine encryption level and packet type
        EncryptionLevel enc_level = EncryptionLevel::Initial;
        PacketType pkt_type = PacketType::Initial;
        bool use_short_header = false;

        if (level == QuicEncryptionLevel::Handshake)
        {
            enc_level = EncryptionLevel::Handshake;
            pkt_type = PacketType::Handshake;
        }
        else if (level == QuicEncryptionLevel::Application)
        {
            enc_level = EncryptionLevel::Application;
            use_short_header = true;
        }

        // Get packet number
        auto pn = connection.crypto->GetNextPacketNumber(enc_level);

        // Build packet header
        std::vector<std::uint8_t> packet;
        std::size_t pn_offset;
        std::size_t pn_length = 1; // Use 1-byte PN for small numbers

        if (use_short_header)
        {
            // Short header (1-RTT) format: RFC 9000 §17.3
            std::uint8_t first_byte = 0x40; // Short header (0100_0000)
            packet.push_back(first_byte);

            // DCID (no length prefix in short header)
            for (std::uint8_t i = 0; i < connection.remote_id.length; ++i)
            {
                packet.push_back(connection.remote_id.data[i]);
            }

            pn_offset = packet.size();
            packet.push_back(static_cast<std::uint8_t>(pn & 0xFF));
        }
        else
        {
            // Long header format: RFC 9000 §17.2
            std::uint8_t first_byte = 0xC0;                           // Long header (1100_0000)
            first_byte |= (static_cast<std::uint8_t>(pkt_type) << 4); // Packet type
            packet.push_back(first_byte);

            // Version (4 bytes)
            packet.push_back(0x00);
            packet.push_back(0x00);
            packet.push_back(0x00);
            packet.push_back(0x01);

            // DCID length + DCID
            packet.push_back(connection.remote_id.length);
            for (std::uint8_t i = 0; i < connection.remote_id.length; ++i)
            {
                packet.push_back(connection.remote_id.data[i]);
            }

            // SCID length + SCID
            packet.push_back(connection.local_id.length);
            for (std::uint8_t i = 0; i < connection.local_id.length; ++i)
            {
                packet.push_back(connection.local_id.data[i]);
            }

            // Token (for Initial packets, empty for now)
            if (pkt_type == PacketType::Initial)
            {
                packet.push_back(0x00); // Token length = 0
            }

            // Payload length (variable-length integer)
            std::size_t payload_length = frame_bytes.size() + 16 + 1; // +16 for AEAD tag, +1 for PN
            // TODO: Eliminate EncodeVarintVec in favour of writing directly into
            //       packet via the tighter span-based EncodeVarint overload.
            auto pl_bytes = clv::quic::EncodeVarintVec(payload_length);
            packet.insert(packet.end(), pl_bytes.begin(), pl_bytes.end());

            pn_offset = packet.size();
            packet.push_back(static_cast<std::uint8_t>(pn & 0xFF));
        }

        if (use_short_header)
        {
            spdlog::debug("[PacketSender] Building 1-RTT (Application) packet, DCID_len={}",
                          static_cast<int>(connection.remote_id.length));
        }

        // Encrypt the payload
        std::size_t header_len = packet.size();
        auto encrypted = connection.crypto->EncryptPacketWithAad(
            frame_bytes,
            pn,
            enc_level,
            std::span{packet.data(), header_len});

        if (!encrypted)
        {
            throw std::runtime_error("Failed to encrypt packet");
        }

        packet.insert(packet.end(), encrypted->begin(), encrypted->end());

        // Apply header protection
        std::span<const std::uint8_t> sample(packet.data() + pn_offset + 4, 16);
        auto protect_result = connection.crypto->ProtectHeader(
            std::span{packet.data(), packet.size()},
            pn_offset,
            pn_length,
            sample,
            enc_level);

        if (protect_result)
        {
            throw std::runtime_error("Failed to protect header: " + std::to_string(static_cast<int>(*protect_result)));
        }

        // Send the packet
        UdpServerDefs::buffer_type packet_buffer(packet.begin(), packet.end());
        co_await send_fn(std::move(packet_buffer), remote_ep);

        spdlog::debug("[PacketSender] Sent {} bytes, PN={}", packet.size(), pn);
        // Increment packet number for next packet at this level
        connection.crypto->IncrementPacketNumber(enc_level);
    }
};

} // namespace clv::quic

#endif // CLV_NETCORE_QUIC_QUIC_PACKET_SENDER_H
