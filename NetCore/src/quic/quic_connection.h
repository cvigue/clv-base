// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

#include <asio/ip/udp.hpp>

#include <spdlog/spdlog.h>

#include "connection_id.h"
#include "quic_crypto.h"
#include "quic_tls.h"
#include "quic_reliability.h"
#include "quic_congestion.h"
#include "quic_loss_detection.h"
#include "quic_packet.h"
#include "quic_varint.h"

#include <result_or.h>

namespace clv::quic {

/**
 * @brief QUIC stream state and data buffer
 * @details Manages stream-level state, flow control, and data buffering
 *
 * TODO: Full implementation in future phase
 * - Stream flow control
 * - Send/receive buffers
 * - FIN handling
 * - Stream prioritization
 */
struct QuicStream
{
    std::uint64_t stream_id{0};
    bool is_bidirectional{true};
    bool fin_sent{false};
    bool fin_received{false};
    std::uint64_t send_offset{0}; ///< Current send offset for stream data
    std::uint64_t recv_offset{0}; ///< Current receive offset for stream data
    std::vector<std::uint8_t> send_buffer;
    std::vector<std::uint8_t> recv_buffer;
};

/**
 * @brief High-level QUIC connection state machine
 * @details State progression: Initial → Handshake → Active → Closing → Draining → Closed
 *
 * State transitions:
 * - Initial: Connection created, no handshake started
 * - Handshake: TLS handshake in progress (exchanging Initial/Handshake packets)
 * - Active: Handshake complete, application data can flow
 * - Closing: Connection being closed gracefully (CONNECTION_CLOSE sent/received)
 * - Draining: Waiting for delayed packets after CONNECTION_CLOSE
 * - Closed: Connection fully terminated
 */
enum class ConnectionState
{
    Initial,   ///< Just created, no packets sent
    Handshake, ///< TLS handshake in progress
    Active,    ///< Fully established, can send/receive data
    Closing,   ///< Graceful shutdown initiated
    Draining,  ///< Waiting for lingering packets
    Closed     ///< Fully terminated
};

/**
 * @brief Complete QUIC connection implementation
 * @details Integrates all QUIC components:
 *          - QuicCrypto: Packet encryption/decryption, initial key derivation
 *          - QuicTls: TLS 1.3 handshake via quictls, key export
 *          - StreamReliability: Stream data retransmission
 *          - CongestionController: Flow control
 *          - LossDetector: Packet loss detection and recovery
 *
 * TODO Items (tracked from quic_tls implementation):
 * 1. Complete QuicTls integration with certificate support
 * 2. Implement key handoff from QuicTls to QuicCrypto
 * 3. Add 0-RTT support
 * 4. Full stream management
 * 5. Connection migration support
 */
struct QuicConnection
{
    // ========================================================================
    // Connection Identification
    // ========================================================================

    ConnectionId local_id{};  ///< Our connection ID
    ConnectionId remote_id{}; ///< Peer's connection ID
    asio::ip::udp::endpoint remote_endpoint{};

    // ========================================================================
    // State Management
    // ========================================================================

    ConnectionState state{ConnectionState::Initial};
    bool is_server{false};
    std::chrono::steady_clock::time_point last_activity{std::chrono::steady_clock::now()};

    /// Callback invoked when stream data is received
    std::function<void(std::uint64_t stream_id, std::span<const std::uint8_t> data)> on_stream_data;

    // ========================================================================
    // Cryptography & Security
    // ========================================================================

    std::optional<QuicCrypto> crypto; ///< Packet protection (encryption/decryption)
    std::optional<QuicTls> tls;       ///< TLS 1.3 handshake engine (quictls)

    // ========================================================================
    // Reliability & Congestion Control
    // ========================================================================

    std::optional<PacketTracker> reliability;       ///< Retransmission logic
    std::optional<CongestionController> congestion; ///< Flow control
    std::optional<LossDetector> loss_detector;      ///< Loss detection

    // ========================================================================
    // Streams
    // ========================================================================

    std::unordered_map<std::uint64_t, std::unique_ptr<QuicStream>> streams;
    std::uint64_t next_stream_id{0}; ///< Next stream ID to allocate

    // ========================================================================
    // Pending CRYPTO Frames
    // ========================================================================

    /// Pending CRYPTO frames generated by TLS handshake
    struct PendingCryptoFrame
    {
        EncryptionLevel level;
        std::vector<std::uint8_t> data;
    };
    std::vector<PendingCryptoFrame> pending_crypto_frames;

    // ========================================================================
    // Factory Methods
    // ========================================================================

    /// Create server-side connection
    /// @param local_cid Server's connection ID
    /// @param remote_cid Client's connection ID
    /// @param remote_ep Client's endpoint
    /// @return Initialized server connection
    static clv::result_or<QuicConnection, std::errc> CreateServer(
        const ConnectionId &local_cid,
        const ConnectionId &remote_cid,
        asio::ip::udp::endpoint remote_ep);

    /// Create client-side connection
    /// @param local_cid Client's connection ID
    /// @param remote_ep Server's endpoint
    /// @return Initialized client connection
    static clv::result_or<QuicConnection, std::errc> CreateClient(
        const ConnectionId &local_cid,
        asio::ip::udp::endpoint remote_ep);

    // ========================================================================
    // Packet Processing
    // ========================================================================

    /// Process incoming packet
    /// @param packet Raw packet data
    /// @return Error if packet processing fails
    std::optional<std::errc> ProcessPacket(std::span<const std::uint8_t> packet);

    /// Generate outgoing packets
    /// @return List of packets ready to send
    std::vector<std::vector<std::uint8_t>> GeneratePackets();

    // ========================================================================
    // State Transitions
    // ========================================================================

    /// Move to a new state
    /// @param next_state Target state
    void SetState(ConnectionState next_state) noexcept;

    /// Check if handshake is complete
    [[nodiscard]] bool IsHandshakeComplete() const noexcept;

    /// Check if connection can send data
    [[nodiscard]] bool CanSendData() const noexcept;

    // ========================================================================
    // Stream Operations (TODO: Implement in future phase)
    // ========================================================================

    /// Open a new stream
    /// @param is_bidirectional true for bidirectional stream
    /// @return Stream ID or error
    clv::result_or<std::uint64_t, std::errc> OpenStream(bool is_bidirectional);

    /// Send data on a stream
    /// @param stream_id Stream to send on
    /// @param data Data to send
    /// @return Error if send fails
    std::optional<std::errc> SendStreamData(std::uint64_t stream_id, std::span<const std::uint8_t> data);

    /// Read and consume received data from a stream
    /// @param stream_id Stream to read from
    /// @return Received data (empty if none available)
    std::vector<std::uint8_t> ReadStreamData(std::uint64_t stream_id);

    /// Close a stream
    /// @param stream_id Stream to close
    void CloseStream(std::uint64_t stream_id);
};

// ============================================================================
// Implementation
// ============================================================================

inline clv::result_or<QuicConnection, std::errc>
QuicConnection::CreateServer(const ConnectionId &local_cid,
                             const ConnectionId &remote_cid,
                             asio::ip::udp::endpoint remote_ep)
{
    QuicConnection conn;
    conn.local_id = local_cid;
    conn.remote_id = remote_cid;
    conn.remote_endpoint = remote_ep;
    conn.is_server = true;
    conn.state = ConnectionState::Initial;

    // Initialize crypto with initial keys
    auto crypto_result = QuicCrypto::CreateServer(local_cid);
    if (!crypto_result)
        return crypto_result.error();
    conn.crypto.emplace(std::move(*crypto_result));

    // Initialize reliability, congestion, loss detection
    conn.reliability.emplace();

    CongestionConfig congestion_config;
    conn.congestion.emplace(congestion_config);

    conn.loss_detector.emplace();

    // TLS will be initialized when first packet arrives
    // (need SSL_CTX which requires certificate setup)

    return conn;
}

inline clv::result_or<QuicConnection, std::errc>
QuicConnection::CreateClient(const ConnectionId &local_cid,
                             asio::ip::udp::endpoint remote_ep)
{
    QuicConnection conn;
    conn.local_id = local_cid;
    conn.remote_endpoint = remote_ep;
    conn.is_server = false;
    conn.state = ConnectionState::Initial;

    // Initialize crypto with initial keys
    auto crypto_result = QuicCrypto::CreateClient(local_cid);
    if (!crypto_result)
        return crypto_result.error();
    conn.crypto.emplace(std::move(*crypto_result));

    // Initialize reliability, congestion, loss detection
    conn.reliability.emplace();

    CongestionConfig congestion_config;
    conn.congestion.emplace(congestion_config);

    conn.loss_detector.emplace();

    // TLS will be initialized when starting handshake
    // (need SSL_CTX which requires certificate setup)

    return conn;
}

inline void QuicConnection::SetState(ConnectionState next_state) noexcept
{
    state = next_state;
}

inline bool QuicConnection::IsHandshakeComplete() const noexcept
{
    return state == ConnectionState::Active;
}

inline bool QuicConnection::CanSendData() const noexcept
{
    return state == ConnectionState::Active && crypto.has_value();
}

inline std::optional<std::errc> QuicConnection::ProcessPacket(std::span<const std::uint8_t> packet)
{
    last_activity = std::chrono::steady_clock::now();

    spdlog::debug("ProcessPacket: Entry, packet size={}", packet.size());

    if (!crypto.has_value())
    {
        spdlog::warn("ProcessPacket: No crypto context");
        return std::errc::invalid_argument;
    }

    if (packet.size() < 20) // Minimum QUIC packet size
    {
        spdlog::warn("ProcessPacket: Packet too small: {}", packet.size());
        return std::errc::message_size;
    }

    // 1. Parse packet header
    auto parse_result = ParsePacketHeader(packet);
    if (!parse_result)
    {
        spdlog::warn("ProcessPacket: Failed to parse header");
        return parse_result.error();
    }

    auto &parsed = *parse_result;
    spdlog::debug("ProcessPacket: Header parsed successfully");

    // For servers receiving Initial packets, extract the SCID to use as remote_id for responses
    if (is_server && remote_id.length == 0 && std::holds_alternative<LongHeader>(parsed.header))
    {
        const auto &long_hdr = std::get<LongHeader>(parsed.header);
        if (long_hdr.type == PacketType::Initial && long_hdr.src_conn_id.length > 0)
        {
            remote_id = long_hdr.src_conn_id;
            spdlog::debug("ProcessPacket: Server learned remote_id from Initial packet SCID (length={})",
                          remote_id.length);
        }
    }

    // Determine encryption level from packet type
    EncryptionLevel enc_level = EncryptionLevel::Application;
    if (std::holds_alternative<LongHeader>(parsed.header))
    {
        const auto &long_hdr = std::get<LongHeader>(parsed.header);
        switch (long_hdr.type)
        {
        case PacketType::Initial:
            enc_level = EncryptionLevel::Initial;
            break;
        case PacketType::Handshake:
            enc_level = EncryptionLevel::Handshake;
            break;
        case PacketType::ZeroRTT:
            enc_level = EncryptionLevel::EarlyData;
            break;
        default:
            break;
        }
    }

    // 2. Unprotect header to get packet number
    // We need a mutable copy to unprotect the header in-place
    std::vector<std::uint8_t> packet_data(packet.begin(), packet.end());

    // Calculate packet number offset by parsing raw bytes (same approach as quic_packet_receiver.h)
    std::size_t offset = 0;
    std::uint8_t first_byte = packet_data[offset++];
    bool is_long = (first_byte & 0x80) != 0;
    std::size_t pn_offset = 0;

    if (is_long)
    {
        // Long header: skip version (4 bytes)
        offset += 4;

        // DCID length + DCID
        std::uint8_t dcid_len = packet_data[offset++];
        offset += dcid_len;

        // SCID length + SCID
        std::uint8_t scid_len = packet_data[offset++];
        offset += scid_len;

        // Token length (varint) - ONLY for Initial packets
        std::uint8_t type_bits = (first_byte & 0x30) >> 4;
        PacketType pkt_type = static_cast<PacketType>(type_bits);

        if (pkt_type == PacketType::Initial)
        {
            auto token_len_result = DecodeVarint(std::span<const std::uint8_t>(packet_data).subspan(offset));
            if (!token_len_result)
            {
                spdlog::warn("ProcessPacket: Failed to decode token length");
                return std::errc::invalid_argument;
            }
            offset += token_len_result->second + token_len_result->first;
        }

        // Payload length (varint)
        auto payload_len_result = DecodeVarint(std::span<const std::uint8_t>(packet_data).subspan(offset));
        if (!payload_len_result)
        {
            spdlog::warn("ProcessPacket: Failed to decode payload length");
            return std::errc::invalid_argument;
        }
        offset += payload_len_result->second;

        pn_offset = offset;
    }
    else
    {
        // Short header (1-RTT): DCID follows first byte
        std::uint8_t dcid_len = local_id.length;
        offset += dcid_len;
        pn_offset = offset;
    }

    // Sample starts 4 bytes after PN offset (RFC 9001 §5.4.2)
    std::size_t sample_offset = pn_offset + 4;
    if (sample_offset + 16 > packet_data.size())
    {
        spdlog::debug("ProcessPacket: Packet too small for header protection sample (pn_offset={}, sample_offset={}, packet_size={})",
                      pn_offset,
                      sample_offset,
                      packet_data.size());
        return std::errc::message_size;
    }

    std::span<const std::uint8_t> sample(packet_data.data() + sample_offset, 16);

    // Unprotect header to get actual packet number length
    auto pn_length_result = crypto->UnprotectHeader(
        std::span<std::uint8_t>(packet_data),
        pn_offset,
        sample,
        enc_level);

    if (!pn_length_result)
    {
        spdlog::warn("ProcessPacket: Failed to unprotect header");
        return pn_length_result.error();
    }

    std::size_t pn_length = *pn_length_result;

    // Extract truncated packet number (big-endian)
    std::uint64_t truncated_pn = 0;
    for (std::size_t i = 0; i < pn_length; ++i)
    {
        truncated_pn = (truncated_pn << 8) | packet_data[pn_offset + i];
    }

    // Decode full packet number from truncated value
    std::uint64_t expected_pn = crypto->GetNextPacketNumber(enc_level);
    std::uint64_t packet_number = QuicCrypto::DecodePacketNumber(
        truncated_pn, pn_length * 8, expected_pn);

    spdlog::debug("ProcessPacket: Unprotected packet number: {} (truncated: {}, length: {}, pn_offset={}, sample_offset={})",
                  packet_number,
                  truncated_pn,
                  pn_length,
                  pn_offset,
                  sample_offset);

    // Extract the unprotected header bytes for AAD (after header unprotection)
    // AAD must match what was used during encryption: the unprotected header
    std::size_t header_len = pn_offset + pn_length;
    std::span<const std::uint8_t> aad_header(packet_data.data(), header_len);

    // Update encrypted payload span to account for actual PN length
    std::span<const std::uint8_t> encrypted_payload(
        packet_data.data() + header_len,
        packet_data.size() - header_len);

    // 3. Decrypt payload (use unprotected header as AAD)
    auto decrypt_result = crypto->DecryptPacketWithAad(
        encrypted_payload,
        packet_number,
        enc_level,
        aad_header);

    if (!decrypt_result)
    {
        // Decryption failed - may be wrong keys or corrupted
        spdlog::warn("ProcessPacket: Decryption failed at level {}", static_cast<int>(enc_level));
        return decrypt_result.error();
    }

    spdlog::debug("ProcessPacket: Decrypted {} bytes", decrypt_result->size());

    const auto &plaintext = *decrypt_result;

    // 4. Parse frames from decrypted payload
    std::span<const std::uint8_t> frame_data(plaintext);
    spdlog::debug("ProcessPacket: Parsing frames from {} bytes", frame_data.size());
    while (!frame_data.empty())
    {
        auto frame_result = ParseFrame(frame_data);
        if (!frame_result)
        {
            spdlog::warn("ProcessPacket: Failed to parse frame");
            break;
        }

        const auto &[frame, consumed] = *frame_result;
        frame_data = frame_data.subspan(consumed);

        // 5. Process each frame type
        std::visit(
            [this, enc_level](auto &&f)
        {
            using T = std::decay_t<decltype(f)>;

            if constexpr (std::is_same_v<T, CryptoFrame>)
            {
                spdlog::debug("ProcessPacket: CRYPTO frame with {} bytes at level {}",
                              f.data.size(),
                              static_cast<int>(enc_level));

                // Feed CRYPTO frame data to TLS
                if (tls.has_value())
                {
                    // Convert from QUIC RFC EncryptionLevel to OpenSSL ssl_encryption_level_t
                    int ssl_level = ToQuicTlsLevel(enc_level);
                    tls->ProvideData(
                        static_cast<QuicEncryptionLevel>(ssl_level),
                        f.data);

                    // Advance TLS state machine
                    int result = tls->Advance();
                    bool is_complete = tls->IsComplete();
                    spdlog::debug("ProcessPacket: TLS Advance() returned {}, IsComplete()={}", result, is_complete);

                    if (result < 0)
                    {
                        // TLS error - log OpenSSL error
                        auto err_str = QuicTls::GetErrorString();
                        spdlog::error("ProcessPacket: TLS Advance() error: {}", err_str);
                    }

                    if (result == 1 || is_complete)
                    {
                        // Handshake complete
                        spdlog::debug("ProcessPacket: TLS handshake complete!");
                        state = ConnectionState::Active;
                    }
                    else if (result < 0)
                    {
                        // TLS error
                        auto err_str = QuicTls::GetErrorString();
                        spdlog::error("ProcessPacket: TLS error! Details: {}", err_str);
                        state = ConnectionState::Closing;
                    }
                }
            }
            else if constexpr (std::is_same_v<T, StreamFrame>)
            {
                spdlog::debug("ProcessPacket: STREAM frame, id={}, data_size={}",
                              f.stream_id,
                              f.data.size());
                // Handle stream data
                auto it = streams.find(f.stream_id);
                if (it == streams.end())
                {
                    spdlog::debug("ProcessPacket: Creating new stream {}", f.stream_id);
                    // Create new stream for incoming data
                    auto stream = std::make_unique<QuicStream>();
                    stream->stream_id = f.stream_id;
                    stream->is_bidirectional = (f.stream_id & 0x02) == 0;
                    streams[f.stream_id] = std::move(stream);
                    it = streams.find(f.stream_id);
                }
                if (it != streams.end())
                {
                    // Append data to stream buffer (simplified - ignores offset)
                    it->second->recv_buffer.insert(
                        it->second->recv_buffer.end(),
                        f.data.begin(),
                        f.data.end());
                    if (f.fin)
                    {
                        it->second->fin_received = true;
                    }

                    // Invoke callback if set
                    if (on_stream_data && !f.data.empty())
                    {
                        on_stream_data(f.stream_id, f.data);
                    }
                }
            }
            else if constexpr (std::is_same_v<T, AckFrame>)
            {
                // Update reliability state
                if (reliability.has_value())
                {
                    // OnAckReceived returns frames that need retransmission
                    [[maybe_unused]] auto retransmit = reliability->OnAckReceived(f);
                }
                // Update congestion state - estimate bytes acked
                if (congestion.has_value())
                {
                    std::uint64_t acked_bytes = 0;
                    for (const auto &[start, count] : f.ranges)
                    {
                        acked_bytes += count * 1200; // Estimate: 1200 bytes per packet
                    }
                    congestion->OnPacketsAcked(acked_bytes, std::chrono::steady_clock::now());
                }
            }
            else if constexpr (std::is_same_v<T, HandshakeDoneFrame>)
            {
                // Server sends this to confirm handshake complete
                state = ConnectionState::Active;
            }
            else if constexpr (std::is_same_v<T, ConnectionCloseFrame>)
            {
                state = ConnectionState::Closing;
            }
            else if constexpr (std::is_same_v<T, PingFrame>)
            {
                // PING requires an ACK, which we'll send in GeneratePackets
            }
            // Other frame types can be added as needed
        },
            frame);
    }

    // 6. Update connection state if handshake just completed
    if (state == ConnectionState::Initial || state == ConnectionState::Handshake)
    {
        if (tls.has_value() && tls->IsComplete())
        {
            state = ConnectionState::Active;
        }
        else if (enc_level == EncryptionLevel::Handshake)
        {
            state = ConnectionState::Handshake;
        }
    }

    return std::nullopt; // Success
}

inline std::vector<std::vector<std::uint8_t>> QuicConnection::GeneratePackets()
{
    std::vector<std::vector<std::uint8_t>> packets;

    if (!crypto.has_value())
        return packets;

    // Determine which encryption level to use based on available keys
    // We prefer the highest available level that matches our connection state
    EncryptionLevel enc_level = EncryptionLevel::Initial;
    if (state == ConnectionState::Active && crypto->HasApplicationKeys())
    {
        enc_level = EncryptionLevel::Application;
    }
    else if ((state == ConnectionState::Handshake || state == ConnectionState::Active) && crypto->HasHandshakeKeys())
    {
        enc_level = EncryptionLevel::Handshake;
    }
    // else: stay at Initial level

    // Buffer to hold frames for this packet
    std::vector<std::uint8_t> frame_buffer;
    frame_buffer.reserve(1200); // MTU-safe size

    // First, check if we have pending CRYPTO frames to send
    while (!pending_crypto_frames.empty())
    {
        auto &crypto_frame = pending_crypto_frames.front();

        spdlog::debug("QuicConnection::GeneratePackets: Generating CRYPTO frame with {} bytes at level {}",
                      crypto_frame.data.size(),
                      static_cast<int>(crypto_frame.level));

        // Build CRYPTO frame: type (0x06) + offset (varint) + length (varint) + data
        frame_buffer.push_back(0x06); // CRYPTO frame type

        // Offset (varint) - for now always 0 since we're sending sequentially
        std::array<std::uint8_t, 8> varint_buf;
        auto offset_len = EncodeVarint(0, varint_buf);
        frame_buffer.insert(frame_buffer.end(), varint_buf.begin(), varint_buf.begin() + offset_len);

        // Length (varint)
        auto data_len_encoded = EncodeVarint(crypto_frame.data.size(), varint_buf);
        frame_buffer.insert(frame_buffer.end(), varint_buf.begin(), varint_buf.begin() + data_len_encoded);

        // Data
        frame_buffer.insert(frame_buffer.end(), crypto_frame.data.begin(), crypto_frame.data.end());

        // Update encryption level for this packet based on the crypto frame
        enc_level = crypto_frame.level;

        // Remove the frame we just processed
        pending_crypto_frames.erase(pending_crypto_frames.begin());

        // For now, send one CRYPTO frame per packet (simpler)
        break;
    }

    // Check if any streams have data to send
    // Allow streams during Handshake state for testing
    if (frame_buffer.empty() && (state == ConnectionState::Active || state == ConnectionState::Handshake))
    {
        for (auto &[stream_id, stream] : streams)
        {
            if (stream->send_buffer.empty() && !stream->fin_sent)
                continue;

            // Build STREAM frame
            // Frame type: 0x08 with flags (OFF=0x04, LEN=0x02, FIN=0x01)
            std::uint8_t frame_type = 0x08;
            frame_type |= 0x02; // Include length

            bool send_fin = stream->fin_sent && stream->send_buffer.empty();
            if (send_fin)
                frame_type |= 0x01;

            if (stream->send_offset > 0)
                frame_type |= 0x04; // Include offset

            frame_buffer.push_back(frame_type);

            // Stream ID (varint)
            std::array<std::uint8_t, 8> varint_buf;
            auto stream_id_len = EncodeVarint(stream_id, varint_buf);
            frame_buffer.insert(frame_buffer.end(), varint_buf.begin(), varint_buf.begin() + stream_id_len);

            // Offset (varint, if present)
            if (stream->send_offset > 0)
            {
                auto offset_len = EncodeVarint(stream->send_offset, varint_buf);
                frame_buffer.insert(frame_buffer.end(), varint_buf.begin(), varint_buf.begin() + offset_len);
            }

            // Length (varint)
            auto data_len = EncodeVarint(stream->send_buffer.size(), varint_buf);
            frame_buffer.insert(frame_buffer.end(), varint_buf.begin(), varint_buf.begin() + data_len);

            // Data
            frame_buffer.insert(frame_buffer.end(), stream->send_buffer.begin(), stream->send_buffer.end());

            // Update stream state
            stream->send_offset += stream->send_buffer.size();
            stream->send_buffer.clear();
        }
    }

    // If we have frames to send, build a packet
    if (!frame_buffer.empty())
    {
        // Build header
        std::uint64_t pn = crypto->GetNextPacketNumber(enc_level);

        PacketHeader header;
        if (state != ConnectionState::Active)
        {
            // Use long header for handshake
            LongHeader long_hdr;
            long_hdr.type = (enc_level == EncryptionLevel::Initial) ? PacketType::Initial : PacketType::Handshake;
            long_hdr.version = 0x00000001; // QUIC v1
            long_hdr.dest_conn_id = remote_id;
            long_hdr.src_conn_id = local_id;
            long_hdr.packet_number = pn;
            long_hdr.payload_length = frame_buffer.size() + 16; // + AEAD tag
            header = long_hdr;
        }
        else
        {
            // Use short header for application data
            ShortHeader short_hdr;
            short_hdr.dest_conn_id = remote_id;
            short_hdr.packet_number = pn;
            short_hdr.key_phase = (crypto->GetKeyPhase() != 0);
            header = short_hdr;
        }

        // Serialize header
        auto header_bytes = SerializeHeader(header);

        // Encrypt payload
        auto encrypt_result = crypto->EncryptPacketWithAad(frame_buffer, pn, enc_level, header_bytes);
        if (encrypt_result)
        {
            spdlog::debug("GeneratePackets: Encrypted {} bytes at level {} (pn={})",
                          encrypt_result->size(),
                          static_cast<int>(enc_level),
                          pn);
            // Combine header + encrypted payload
            std::vector<std::uint8_t> packet;
            packet.reserve(header_bytes.size() + encrypt_result->size());
            packet.insert(packet.end(), header_bytes.begin(), header_bytes.end());
            packet.insert(packet.end(), encrypt_result->begin(), encrypt_result->end());

            // Apply header protection
            if (packet.size() > header_bytes.size() + 4)
            {
                std::size_t pn_offset = header_bytes.size() - 4; // PN is at end of header
                // Sample starts 4 bytes after PN begins (RFC 9001 §5.4.2)
                std::size_t sample_offset = pn_offset + 4;
                std::span<const std::uint8_t> sample(
                    packet.data() + sample_offset, 16);

                spdlog::debug("GeneratePackets: Applying header protection (header_len={}, pn_offset={}, sample_offset={})",
                              header_bytes.size(),
                              pn_offset,
                              sample_offset);

                [[maybe_unused]] auto protect_result = crypto->ProtectHeader(
                    std::span<std::uint8_t>(packet),
                    pn_offset,
                    4, // PN length
                    sample,
                    enc_level);
            }

            packets.push_back(std::move(packet));
            crypto->IncrementPacketNumber(enc_level);
        }
        else
        {
            spdlog::warn("GeneratePackets: Failed to encrypt packet at level {} (pn={})",
                         static_cast<int>(enc_level),
                         pn);
        }
    }

    return packets;
}

inline clv::result_or<std::uint64_t, std::errc> QuicConnection::OpenStream(bool is_bidirectional)
{
    // Allow streams during Handshake state for testing without full TLS
    if (state != ConnectionState::Active && state != ConnectionState::Handshake)
        return std::errc::operation_not_permitted;

    // Stream IDs: client-initiated bidirectional: 0, 4, 8, ...
    //             server-initiated bidirectional: 1, 5, 9, ...
    //             client-initiated unidirectional: 2, 6, 10, ...
    //             server-initiated unidirectional: 3, 7, 11, ...

    std::uint64_t stream_id = next_stream_id;

    // Compute proper stream ID based on role and directionality
    std::uint64_t base = is_server ? 1 : 0;
    if (!is_bidirectional)
        base += 2;

    stream_id = base + (next_stream_id / 4) * 4;
    next_stream_id = stream_id + 4;

    auto stream = std::make_unique<QuicStream>();
    stream->stream_id = stream_id;
    stream->is_bidirectional = is_bidirectional;

    streams[stream_id] = std::move(stream);

    return stream_id;
}

inline std::optional<std::errc> QuicConnection::SendStreamData(
    std::uint64_t stream_id,
    std::span<const std::uint8_t> data)
{
    // Allow stream data during Handshake state for testing without full TLS
    if (state != ConnectionState::Active && state != ConnectionState::Handshake)
        return std::errc::operation_not_permitted;

    auto it = streams.find(stream_id);
    if (it == streams.end())
        return std::errc::invalid_argument;

    // TODO: Actual stream data queueing
    it->second->send_buffer.insert(
        it->second->send_buffer.end(),
        data.begin(),
        data.end());

    return std::nullopt;
}

inline std::vector<std::uint8_t> QuicConnection::ReadStreamData(std::uint64_t stream_id)
{
    auto it = streams.find(stream_id);
    if (it == streams.end() || it->second->recv_buffer.empty())
        return {};

    // Move data out of buffer and return it
    std::vector<std::uint8_t> data = std::move(it->second->recv_buffer);
    it->second->recv_buffer.clear();
    return data;
}

inline void QuicConnection::CloseStream(std::uint64_t stream_id)
{
    auto it = streams.find(stream_id);
    if (it != streams.end())
    {
        it->second->fin_sent = true;
        // Stream will be removed when FIN is acked
    }
}

} // namespace clv::quic
