// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_NETCORE_HTTP_HTTP3_CONNECTION_HANDLER_H
#define CLV_NETCORE_HTTP_HTTP3_CONNECTION_HANDLER_H

#include "http/ack_manager.h"
#include "http/http3_frame.h"
#include "http/http3_fwd.h"
#include "http/http3_proto.h"
#include "http/http3_request.h"
#include "http/qpack.h"
#include "micro_udp_server_defs.h"
#include "quic/quic_ack.h"
#include "quic/quic_congestion.h"
#include "quic/quic_connection.h"
#include "quic/quic_crypto.h"
#include "quic/quic_frame.h"
#include "quic/quic_loss_detection.h"
#include "quic/quic_packet.h"
#include "quic/quic_packet_receiver.h"
#include "quic/quic_packet_sender.h"
#include "quic/quic_reliability.h"
#include "quic/quic_tls.h"

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <HelpSslException.h>
#include "mutex_type.h"

#include <openssl/ssl.h>

#include <exception>
#include <stdexcept>
#include <utility>
#include <variant>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <array>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include <spdlog/spdlog.h>

namespace clv::http3 {

using clv::quic::AckRangeSet;
using clv::quic::CongestionController;
using clv::quic::ConnectionState;
using clv::quic::CryptoFrame;
using clv::quic::EncryptionLevel;
using clv::quic::LossDetector;
using clv::quic::NewConnectionIdFrame;
using clv::quic::PacketTracker;
using clv::quic::PacketType;
using clv::quic::PaddingFrame;
using clv::quic::ParseFrames;
using clv::quic::PingFrame;
using clv::quic::QuicConnection;
using clv::quic::QuicEncryptionLevel;
using clv::quic::QuicPacketReceiver;
using clv::quic::QuicPacketSender;
using clv::quic::QuicStream;
using clv::quic::QuicTls;
using clv::quic::SentPacket;
using clv::quic::StreamFrame;

// Per-level state for packet tracking and loss detection
// Note: ACK generation is now handled by AckManager
struct PerLevelState
{
    PacketTracker packet_tracker;
    LossDetector loss_detector;
    std::vector<clv::quic::Frame> pending_retransmits;
};

// Connection handler
template <typename... RoutersT>
struct ConnectionHandler
{
    using RouterDispatchT = Http3RequestDispatcher<RoutersT...>;

    asio::io_context &io_ctx;
    asio::ip::udp::endpoint remote_endpoint;
    clv::quic::QuicConnection connection;
    std::vector<RouterDispatchT> routers;
    UdpServerDefs::SendDatagramFnT send_fn;

    std::atomic<bool> &keepRunning;

    std::unordered_map<clv::quic::QuicEncryptionLevel, std::vector<std::uint8_t>> pending_crypto_data;

    // Per-level state: Initial, Handshake, Application
    std::array<PerLevelState, 3> level_state;

    // ACK management across all levels
    AckManager ack_manager_;

    // Packet sender for building/encrypting/sending packets
    QuicPacketSender packet_sender_;

    // Packet receiver for decrypting/parsing packets
    QuicPacketReceiver packet_receiver_;

    // Connection-wide congestion control
    CongestionController congestion;

    // Protected queue for incoming packets (TODO: profile and evaluate lock-free option post-MVP)
    clv::UniqueMutexType<std::deque<std::vector<std::uint8_t>>> packet_queue;

    ConnectionHandler(asio::io_context &io,
                      asio::ip::udp::endpoint remote_ep,
                      QuicConnection conn,
                      std::vector<RouterDispatchT> &&routers_vec,
                      UdpServerDefs::SendDatagramFnT send_callback,
                      std::atomic<bool> &running_flag)
        : io_ctx(io),
          remote_endpoint(std::move(remote_ep)),
          connection(std::move(conn)),
          routers(std::move(routers_vec)),
          send_fn(std::move(send_callback)),
          keepRunning(running_flag)
    {
        // Set up TLS callbacks after connection is moved
        if (connection.tls)
        {
            SetupTlsCallbacks();
        }
    }

    void EnqueuePacket(std::vector<std::uint8_t> packet)
    {
        auto queue = packet_queue.Lock();
        queue->push_back(std::move(packet));
    }

    // Helper to convert EncryptionLevel to array index
    static constexpr std::size_t LevelToIndex(EncryptionLevel level)
    {
        return std::to_underlying(level);
    }

    // Helper to convert QuicEncryptionLevel to array index
    static constexpr std::size_t QuicLevelToIndex(QuicEncryptionLevel level)
    {
        switch (level)
        {
        case QuicEncryptionLevel::Initial:
            return 0;
        case QuicEncryptionLevel::Handshake:
            return 1;
        case QuicEncryptionLevel::Application:
            return 2;
        default:
            return 0;
        }
    }

    void SetupTlsCallbacks()
    {
        // Set TLS callbacks to integrate with QuicCrypto
        connection.tls->SetSecretCallback([this](QuicEncryptionLevel level,
                                                 const SSL_CIPHER *cipher,
                                                 std::span<const std::uint8_t>
                                                     read_secret,
                                                 std::span<const std::uint8_t>
                                                     write_secret)
        {
            spdlog::debug("[TLS] Secrets ready for level {}", static_cast<int>(level));

            if (!connection.crypto)
                throw std::runtime_error("TLS SecretCallback: QuicCrypto not initialized");

            // Install keys into QuicCrypto based on encryption level
            if (level == QuicEncryptionLevel::Handshake)
            {
                // Handshake keys: server gets client's read secret and server's write secret
                bool success = connection.crypto->SetHandshakeSecrets(read_secret, write_secret);
                if (success)
                    spdlog::debug("[TLS] Handshake keys installed");
                else
                    throw OpenSSL::SslException("TLS SecretCallback: Failed to install handshake keys");
            }
            else if (level == QuicEncryptionLevel::Application)
            {
                // Application data keys
                bool success = connection.crypto->SetApplicationSecrets(read_secret, write_secret);
                if (success)
                {
                    spdlog::debug("[TLS] Application keys installed");
                    connection.SetState(ConnectionState::Active);
                }
                else
                {
                    throw OpenSSL::SslException("TLS SecretCallback: Failed to install application keys");
                }
            }
        });

        connection.tls->SetHandshakeDataCallback([this](
                                                     QuicEncryptionLevel level,
                                                     std::span<const std::uint8_t>
                                                         data)
        {
            spdlog::debug("[TLS] Handshake data ready: {} bytes at level {}", data.size(), static_cast<int>(level));

            // Store CRYPTO frame data for later sending
            auto &buffer = pending_crypto_data[level];
            buffer.insert(buffer.end(), data.begin(), data.end());

            spdlog::debug("[TLS] Queued {} bytes of CRYPTO data", data.size());
        });
    }

    // Decrypt and process an Initial, Handshake, or 1-RTT packet with header protection removal
    bool DecryptAndProcessPacket(std::span<std::uint8_t> packet_data, EncryptionLevel enc_level)
    {
        // Phase 7: Use QuicPacketReceiver to decrypt and parse packet
        auto received = packet_receiver_.ProcessPacket(packet_data, enc_level, connection);
        if (!received)
            return false;

        // Track received packet number for ACK generation using AckManager
        ack_manager_.OnPacketReceived(received->packet_number, received->level);

        // Process frames from decrypted payload
        return ProcessFrames(received->decrypted_payload, received->level, received->is_long_header);
    }

    // Extract and process frames from a decrypted packet payload
    bool ProcessFrames(std::span<const std::uint8_t> payload, QuicEncryptionLevel level, bool is_long_header)
    {
        auto frames = ParseFrames(payload);
        bool found_data = false;

        for (const auto &frame : frames)
        {
            if (std::holds_alternative<CryptoFrame>(frame))
            {
                const auto &crypto_frame = std::get<CryptoFrame>(frame);
                spdlog::debug("[CRYPTO] Found CRYPTO frame: {} bytes at offset {}", crypto_frame.data.size(), crypto_frame.offset);

                // Feed CRYPTO data to TLS
                if (connection.tls)
                {
                    connection.tls->ProvideData(level, crypto_frame.data);
                    found_data = true;
                }
            }
            else if (std::holds_alternative<PaddingFrame>(frame))
            {
                // Ignore padding
            }
            else if (std::holds_alternative<PingFrame>(frame))
            {
                spdlog::debug("[Frame] Received PING frame");
                // PING requires an ACK response (handled at packet level)
                found_data = true;
            }
            else if (std::holds_alternative<AckFrame>(frame))
            {
                const auto &ack = std::get<AckFrame>(frame);
                spdlog::debug("[Frame] Received ACK frame: largest_ack={}", ack.largest_acknowledged);

                // Phase 3: Process ACK through trackers
                std::size_t level_idx = QuicLevelToIndex(level);
                auto &state = level_state[level_idx];

                // Convert AckFrame ranges to AckRangeSet
                AckRangeSet ack_ranges;
                for (const auto &[start, length] : ack.ranges)
                {
                    if (length > 0)
                    {
                        std::uint64_t end = start + length - 1;
                        ack_ranges.AddRange(start, end);
                    }
                }

                // Track which packets were acked for congestion control
                std::uint64_t acked_bytes = 0;
                auto now = std::chrono::steady_clock::now();

                // Process ACK in PacketTracker (returns lost frames)
                auto lost_frames_tracker = state.packet_tracker.OnAckReceived(ack);

                // Process ACK in LossDetector (returns lost frames and updates RTT)
                auto lost_frames_detector = state.loss_detector.OnAckReceived(
                    ack_ranges,
                    now,
                    std::chrono::microseconds(ack.ack_delay));

                // Calculate acked bytes by checking what was removed from unacked
                // For now, use a simple heuristic based on largest_acked
                acked_bytes = 1200; // TODO: Fix computation - Approximate MTU per packet

                // Update congestion control with ACKed packets
                congestion.OnPacketsAcked(acked_bytes, now);

                // Handle lost frames from both trackers
                state.pending_retransmits.insert(
                    state.pending_retransmits.end(),
                    lost_frames_tracker.begin(),
                    lost_frames_tracker.end());
                state.pending_retransmits.insert(
                    state.pending_retransmits.end(),
                    lost_frames_detector.begin(),
                    lost_frames_detector.end());

                // If we have losses, update congestion control
                if (!lost_frames_detector.empty())
                {
                    std::uint64_t lost_bytes = lost_frames_detector.size() * 1200; // Approximate
                    std::uint64_t largest_lost_pn = ack.largest_acknowledged - 1;  // Approximate
                    congestion.OnPacketsLost(lost_bytes, largest_lost_pn, now);

                    spdlog::debug("[Loss] Detected {} lost frames, cwnd={}", lost_frames_detector.size(), congestion.GetCongestionWindow());
                }

                found_data = true;
            }
            else if (std::holds_alternative<StreamFrame>(frame))
            {
                const auto &stream = std::get<StreamFrame>(frame);
                spdlog::debug("[Frame] Received STREAM frame: stream_id={} offset={} len={} fin={}", stream.stream_id, stream.offset, stream.data.size(), stream.fin);

                // Get or create the stream
                auto stream_it = connection.streams.find(stream.stream_id);
                if (stream_it == connection.streams.end())
                {
                    // Create new stream
                    auto new_stream = std::make_unique<QuicStream>();
                    new_stream->stream_id = stream.stream_id;
                    // Unidirectional streams: client-initiated have stream_id & 0x02 set
                    new_stream->is_bidirectional = (stream.stream_id & 0x02) == 0;
                    stream_it = connection.streams.emplace(stream.stream_id, std::move(new_stream)).first;
                    spdlog::debug("[Stream] Created {} stream with ID {}", (stream_it->second->is_bidirectional ? "bidirectional" : "unidirectional"), stream.stream_id);
                }

                // Append data to stream's receive buffer
                // TODO: Handle offset properly for out-of-order data
                auto &recv_buf = stream_it->second->recv_buffer;
                recv_buf.insert(recv_buf.end(), stream.data.begin(), stream.data.end());

                if (stream.fin)
                {
                    stream_it->second->fin_received = true;
                    spdlog::debug("[Stream] FIN received on stream {}", stream.stream_id);
                }

                found_data = true;
            }
            else if (std::holds_alternative<NewConnectionIdFrame>(frame))
            {
                const auto &ncid = std::get<NewConnectionIdFrame>(frame);
                spdlog::debug("[Frame] Received NEW_CONNECTION_ID frame: seq={} retire_prior={} cid_len={}",
                              ncid.sequence_number,
                              ncid.retire_prior_to,
                              static_cast<int>(ncid.connection_id_length));
                // TODO: Store the new connection ID for potential migration
                found_data = true;
            }
            else
            {
                spdlog::debug("[Frame] Received other frame type");
            }
        }

        return found_data;
    }

    asio::awaitable<void> SendPendingCryptoFrames(bool force_handshake_ack = false)
    {
        // Send any pending CRYPTO frames with proper encryption
        // IMPORTANT: Send in order - Initial before Handshake!
        std::array<QuicEncryptionLevel, 3> levels_in_order = {
            QuicEncryptionLevel::Initial,
            QuicEncryptionLevel::Handshake,
            QuicEncryptionLevel::Application};

        for (auto level : levels_in_order)
        {
            auto it = pending_crypto_data.find(level);

            // Get the appropriate state for this level
            std::size_t level_idx = QuicLevelToIndex(level);
            auto &state = level_state[level_idx];

            bool has_crypto = (it != pending_crypto_data.end() && !it->second.empty());

            // Check if we should send an ACK using AckManager
            bool force_ack = ack_manager_.ShouldForceAck(level, force_handshake_ack);
            bool should_ack = ack_manager_.ShouldSendAck(level) || force_ack;

            if (!has_crypto && !should_ack)
                continue;

            // Phase 4: Check congestion window before sending
            if (!congestion.CanSend())
            {
                spdlog::debug("[Connection] Congestion window full (cwnd={}, in_flight={}), skipping send", congestion.GetCongestionWindow(), congestion.GetBytesInFlight());
                continue;
            }

            auto &data = it != pending_crypto_data.end() ? it->second : pending_crypto_data[level];

            spdlog::debug("[Connection] Building packet with {} bytes of CRYPTO data at level {}", data.size(), static_cast<int>(level));

            // Build CRYPTO frame if there's data
            std::vector<std::uint8_t> frame_bytes;

            if (!data.empty())
            {
                CryptoFrame crypto_frame;
                crypto_frame.offset = 0; // TODO: Track offset properly
                crypto_frame.data = data;
                frame_bytes = clv::quic::SerializeFrame(clv::quic::Frame{crypto_frame});
            }

            // Add ACK frame if needed for this level using AckManager
            if (should_ack)
            {
                auto ack_opt = ack_manager_.GenerateAckIfNeeded(level, force_ack);
                if (ack_opt)
                {
                    auto ack_bytes = clv::quic::SerializeFrame(clv::quic::Frame{*ack_opt});

                    // Prepend ACK frame to payload
                    frame_bytes.insert(frame_bytes.begin(), ack_bytes.begin(), ack_bytes.end());

                    spdlog::debug("[Connection] Including ACK for largest={}", ack_opt->largest_acknowledged);
                }
            }

            // Get packet number for tracking (sender will get it again, but we need it for tracking)
            auto pn = connection.crypto->GetNextPacketNumber(
                level == QuicEncryptionLevel::Handshake ? EncryptionLevel::Handshake : level == QuicEncryptionLevel::Application ? EncryptionLevel::Application
                                                                                                                                 : EncryptionLevel::Initial);

            // Phase 6: Use QuicPacketSender to build/encrypt/send packet
            try
            {
                co_await packet_sender_.SendPacket(
                    frame_bytes, level, connection, send_fn, remote_endpoint);
            }
            catch (const std::exception &e)
            {
                spdlog::error("[Connection] Failed to send packet at level {}: {}", static_cast<int>(level), e.what());
                continue;
            }

            // Track sent packet for reliability and loss detection (Phase 2)
            PacketTracker::SentPacket sent_pkt;
            sent_pkt.packet_number = pn;
            sent_pkt.sent_time = std::chrono::steady_clock::now();
            sent_pkt.bytes_sent = 0; // Will be updated by congestion controller
            sent_pkt.ack_eliciting = !data.empty();

            // Record frames that were sent
            if (!data.empty())
            {
                CryptoFrame crypto_frame;
                crypto_frame.offset = 0;
                crypto_frame.data = data;
                sent_pkt.frames.push_back(clv::quic::Frame{crypto_frame});
            }

            state.packet_tracker.OnPacketSent(sent_pkt);

            // Track for loss detection
            SentPacket loss_pkt;
            loss_pkt.packet_number = pn;
            loss_pkt.sent_time = sent_pkt.sent_time;
            loss_pkt.bytes_sent = 0; // Estimated
            loss_pkt.ack_eliciting = sent_pkt.ack_eliciting;
            loss_pkt.frames = sent_pkt.frames;
            state.loss_detector.OnPacketSent(loss_pkt);

            // Update congestion control (estimate packet size)
            std::size_t packet_size = frame_bytes.size() + 50; // Frame + header + overhead
            congestion.OnPacketSent(packet_size);

            data.clear();
        }
        co_return;
    }

    // Initialize HTTP/3 control streams (RFC 9114 §6.2, RFC 9204 §4.2)
    asio::awaitable<void> InitializeHttp3ControlStreams()
    {
        if (connection.state != ConnectionState::Active)
        {
            spdlog::debug("[HTTP/3] Cannot initialize control streams - connection not active");
            co_return;
        }

        spdlog::debug("[HTTP/3] Initializing control streams...");

        // Create HTTP/3 control stream (server-initiated unidirectional, ID will be 3, 7, 11...)
        auto control_stream_result = connection.OpenStream(false); // false = unidirectional
        if (!control_stream_result)
        {
            spdlog::error("[HTTP/3] Failed to create control stream");
            co_return;
        }
        std::uint64_t control_stream_id = *control_stream_result;
        spdlog::debug("[HTTP/3] Created control stream: {}", control_stream_id);

        // Create QPACK encoder stream
        auto encoder_stream_result = connection.OpenStream(false);
        if (!encoder_stream_result)
        {
            spdlog::error("[HTTP/3] Failed to create QPACK encoder stream");
            co_return;
        }
        std::uint64_t encoder_stream_id = *encoder_stream_result;
        spdlog::debug("[HTTP/3] Created QPACK encoder stream: {}", encoder_stream_id);

        // Create QPACK decoder stream
        auto decoder_stream_result = connection.OpenStream(false);
        if (!decoder_stream_result)
        {
            spdlog::error("[HTTP/3] Failed to create QPACK decoder stream");
            co_return;
        }
        std::uint64_t decoder_stream_id = *decoder_stream_result;
        spdlog::debug("[HTTP/3] Created QPACK decoder stream: {}", decoder_stream_id);

        // Queue control stream data (stream type 0x00 + SETTINGS frame)
        auto control_data = CreateControlStreamData();
        auto send_err = connection.SendStreamData(control_stream_id, control_data);
        if (send_err)
        {
            spdlog::error("[HTTP/3] Failed to send control stream data");
        }
        else
        {
            spdlog::debug("[HTTP/3] Queued {} bytes on control stream", control_data.size());
        }

        // Queue QPACK encoder stream data (stream type 0x02)
        auto encoder_data = CreateQpackEncoderStreamData();
        send_err = connection.SendStreamData(encoder_stream_id, encoder_data);
        if (send_err)
        {
            spdlog::error("[HTTP/3] Failed to send QPACK encoder stream data");
        }
        else
        {
            spdlog::debug("[HTTP/3] Queued {} bytes on QPACK encoder stream", encoder_data.size());
        }

        // Queue QPACK decoder stream data (stream type 0x03)
        auto decoder_data = CreateQpackDecoderStreamData();
        send_err = connection.SendStreamData(decoder_stream_id, decoder_data);
        if (send_err)
        {
            spdlog::error("[HTTP/3] Failed to send QPACK decoder stream data");
        }
        else
        {
            spdlog::debug("[HTTP/3] Queued {} bytes on QPACK decoder stream", decoder_data.size());
        }

        // Send all the control stream data immediately
        co_await SendPendingStreamData();

        spdlog::debug("[HTTP/3] Control streams initialized successfully");
        co_return;
    }

    // Send pending STREAM data in 1-RTT packets
    asio::awaitable<void> SendPendingStreamData()
    {
        if (connection.state != ConnectionState::Active)
            co_return;

        if (!connection.crypto)
            co_return;

        // Phase 4: Check congestion window before sending stream data
        if (!congestion.CanSend())
        {
            spdlog::debug("[Stream] Congestion window full, deferring stream sends");
            co_return;
        }

        // Collect streams with pending data
        for (auto &[stream_id, stream_ptr] : connection.streams)
        {
            if (stream_ptr->send_buffer.empty())
                continue;

            spdlog::debug("[Stream] Sending {} bytes on stream {}", stream_ptr->send_buffer.size(), stream_id);

            // Build STREAM frame
            StreamFrame stream_frame;
            stream_frame.stream_id = stream_id;
            stream_frame.offset = stream_ptr->send_offset;
            stream_frame.data.assign(stream_ptr->send_buffer.begin(), stream_ptr->send_buffer.end());
            stream_frame.fin = stream_ptr->fin_sent;

            auto frame_bytes = clv::quic::SerializeFrame(clv::quic::Frame{stream_frame});

            // Also include ACK if needed using AckManager
            auto ack_opt = ack_manager_.GenerateAckIfNeeded(QuicEncryptionLevel::Application);
            if (ack_opt)
            {
                auto ack_bytes = clv::quic::SerializeFrame(clv::quic::Frame{*ack_opt});
                frame_bytes.insert(frame_bytes.begin(), ack_bytes.begin(), ack_bytes.end());
            }

            // Get packet number for tracking
            auto pn = connection.crypto->GetNextPacketNumber(EncryptionLevel::Application);

            // Phase 6: Use QuicPacketSender to build/encrypt/send packet
            try
            {
                co_await packet_sender_.SendPacket(
                    frame_bytes, QuicEncryptionLevel::Application, connection, send_fn, remote_endpoint);
            }
            catch (const std::exception &e)
            {
                spdlog::error("[Stream] Failed to send STREAM packet: {}", e.what());
                continue;
            }

            spdlog::debug("[Stream] Sent 1-RTT packet with STREAM frame (PN={}, stream={}, fin={})", pn, stream_id, stream_frame.fin);

            // Track sent packet for reliability and loss detection (Phase 2)
            std::size_t app_level_idx_send = LevelToIndex(EncryptionLevel::Application);
            auto &app_state = level_state[app_level_idx_send];

            PacketTracker::SentPacket sent_pkt;
            sent_pkt.packet_number = pn;
            sent_pkt.sent_time = std::chrono::steady_clock::now();
            sent_pkt.bytes_sent = 0;       // Estimated
            sent_pkt.ack_eliciting = true; // STREAM frames are ack-eliciting
            sent_pkt.frames.push_back(clv::quic::Frame{stream_frame});

            app_state.packet_tracker.OnPacketSent(sent_pkt);

            // Track for loss detection
            SentPacket loss_pkt;
            loss_pkt.packet_number = pn;
            loss_pkt.sent_time = sent_pkt.sent_time;
            loss_pkt.bytes_sent = 0; // Estimated
            loss_pkt.ack_eliciting = true;
            loss_pkt.frames = sent_pkt.frames;
            app_state.loss_detector.OnPacketSent(loss_pkt);

            // Update congestion control (estimate packet size)
            std::size_t packet_size = frame_bytes.size() + 50; // Frame + header + overhead
            congestion.OnPacketSent(packet_size);

            // Update stream state
            stream_ptr->send_offset += stream_ptr->send_buffer.size();
            stream_ptr->send_buffer.clear();
        }

        co_return;
    }

    asio::awaitable<void> HandleConnection()
    {
        try
        {
            spdlog::debug("[Connection] Handling connection from {}:{}",
                          remote_endpoint.address().to_string(),
                          remote_endpoint.port());

            // Main processing loop
            while (keepRunning && connection.state != ConnectionState::Closed)
            {
                // Phase 4: Check for PTO timeouts across all levels
                auto now = std::chrono::steady_clock::now();
                for (std::size_t level_idx = 0; level_idx < 3; ++level_idx)
                {
                    auto &state = level_state[level_idx];
                    auto timeout_frames = state.loss_detector.CheckForTimeout(now);

                    if (!timeout_frames.empty())
                    {
                        spdlog::debug("[Loss] PTO timeout: {} frames at level {}", timeout_frames.size(), level_idx);

                        state.pending_retransmits.insert(
                            state.pending_retransmits.end(),
                            timeout_frames.begin(),
                            timeout_frames.end());
                    }
                }

                // Check packet queue
                std::vector<std::uint8_t> recv_buffer;
                {
                    auto queue = packet_queue.Lock();
                    if (!queue->empty())
                    {
                        recv_buffer = std::move(queue->front());
                        queue->pop_front();
                    }
                }

                if (recv_buffer.empty())
                {
                    // No packets, yield and wait
                    co_await asio::steady_timer(io_ctx.get_executor(), std::chrono::milliseconds(10)).async_wait(asio::use_awaitable);
                    continue;
                }

                std::size_t bytes_received = recv_buffer.size();
                spdlog::debug("[Connection] Processing {} bytes", bytes_received);

                // Parse packet to extract frames during handshake
                if (connection.state == ConnectionState::Initial || connection.state == ConnectionState::Handshake)
                {
                    // Determine encryption level from first byte
                    if (bytes_received < 1)
                        continue;

                    std::uint8_t first_byte = recv_buffer[0];
                    bool is_long = (first_byte & 0x80) != 0;

                    EncryptionLevel enc_level = EncryptionLevel::Initial;
                    PacketType pkt_type = PacketType::Initial;

                    if (!is_long)
                    {
                        // Short header (1-RTT) - only process if we have application keys
                        if (!connection.crypto->HasSecretsForLevel(EncryptionLevel::Application))
                        {
                            spdlog::debug("[Connection] Received short header but no application keys yet");
                            continue;
                        }
                        enc_level = EncryptionLevel::Application;
                        spdlog::debug("[Connection] Received 1-RTT packet");
                    }
                    else
                    {
                        std::uint8_t type_bits = (first_byte & 0x30) >> 4;
                        pkt_type = static_cast<PacketType>(type_bits);

                        spdlog::debug("[Connection] Received {} packet", (pkt_type == PacketType::Initial ? "Initial" : pkt_type == PacketType::Handshake ? "Handshake"
                                                                                                                                                          : "Other"));

                        if (pkt_type == PacketType::Handshake)
                            enc_level = EncryptionLevel::Handshake;
                    }

                    // Decrypt and process the packet
                    if (DecryptAndProcessPacket(std::span{recv_buffer.data(), bytes_received}, enc_level))
                    {
                        // Advance TLS handshake after providing data
                        if (connection.tls)
                        {
                            spdlog::debug("[TLS] Advancing handshake...");
                            int result = connection.tls->Advance();
                            spdlog::debug("[TLS] Advance result: {}", result);

                            if (result == 1)
                            {
                                spdlog::debug("[TLS] Handshake complete!");
                                connection.SetState(ConnectionState::Active);
                                // Force sending Handshake ACK when handshake completes
                                co_await SendPendingCryptoFrames(true);
                                // Initialize HTTP/3 control streams (required for browsers)
                                co_await InitializeHttp3ControlStreams();
                            }
                            else if (result < 0)
                            {
                                spdlog::error("[TLS] Handshake error: {}", QuicTls::GetErrorString());
                                break;
                            }
                            else
                            {
                                spdlog::debug("[TLS] Handshake in progress (need more data)");
                                connection.SetState(ConnectionState::Handshake);
                                // Send any pending CRYPTO frames generated by the handshake
                                co_await SendPendingCryptoFrames();
                            }
                        }
                    }
                }

                // Once active, process normal packets (1-RTT)
                if (connection.state == ConnectionState::Active)
                {
                    std::uint8_t first_byte = recv_buffer[0];
                    bool is_short = (first_byte & 0x80) == 0;

                    if (is_short)
                    {
                        spdlog::debug("[Connection] Processing 1-RTT packet ({} bytes)", bytes_received);

                        // Decrypt and process the 1-RTT packet
                        if (DecryptAndProcessPacket(std::span{recv_buffer.data(), bytes_received}, EncryptionLevel::Application))
                        {
                            // Send ACKs if needed
                            co_await SendPendingCryptoFrames();
                        }
                    }
                    else
                    {
                        // Late handshake packet (coalesced or retransmit) - process normally
                        std::uint8_t type_bits = (first_byte & 0x30) >> 4;
                        PacketType pkt_type = static_cast<PacketType>(type_bits);
                        EncryptionLevel enc_level = (pkt_type == PacketType::Handshake) ? EncryptionLevel::Handshake : EncryptionLevel::Initial;

                        spdlog::debug("[Connection] Processing late long-header packet");
                        DecryptAndProcessPacket(std::span{recv_buffer.data(), bytes_received}, enc_level);
                    }
                }

                // Check for complete HTTP/3 requests on streams
                for (auto &[stream_id, stream_ptr] : connection.streams)
                {
                    if (stream_ptr && !stream_ptr->recv_buffer.empty())
                    {
                        auto request = ParseHttp3Request(stream_ptr->recv_buffer);
                        if (request)
                        {
                            spdlog::debug("[HTTP/3] Request: {} {}", request->method, request->path);

                            // Try routers in sequence using dispatcher
                            std::vector<std::uint8_t> accumulated_response;
                            auto stream_writer = [&accumulated_response](std::vector<std::uint8_t> data)
                            {
                                accumulated_response.insert(accumulated_response.end(), data.begin(), data.end());
                            };

                            bool handled = false;
                            std::optional<std::vector<std::uint8_t>> response;

                            for (auto &router : routers)
                            {
                                handled = co_await router.RouteMsg(request->path, stream_writer, io_ctx);
                                if (handled)
                                {
                                    response = std::move(accumulated_response);
                                    break;
                                }
                            }

                            // Send 404 if no router handled it
                            if (!handled && !response)
                            {
                                spdlog::debug("[HTTP/3] 404 Not Found: {}", request->path);
                                QpackEncoder encoder;
                                std::vector<HeaderField> headers = {
                                    {":status", "404"},
                                    {"content-type", "text/plain"},
                                    {"content-length", "9"}};
                                auto encoded_headers = encoder.Encode(headers);

                                HeadersFrame headers_frame;
                                headers_frame.header_block = std::move(encoded_headers);

                                response = std::vector<std::uint8_t>();
                                auto type_bytes = EncodeVarintToVector(static_cast<std::uint64_t>(http3::FrameType::Headers));
                                auto length_bytes = EncodeVarintToVector(headers_frame.header_block.size());
                                response->insert(response->end(), type_bytes.begin(), type_bytes.end());
                                response->insert(response->end(), length_bytes.begin(), length_bytes.end());
                                response->insert(response->end(), headers_frame.header_block.begin(), headers_frame.header_block.end());

                                std::string body = "Not Found";
                                DataFrame data_frame;
                                data_frame.payload.assign(body.begin(), body.end());

                                type_bytes = EncodeVarintToVector(static_cast<std::uint64_t>(http3::FrameType::Data));
                                length_bytes = EncodeVarintToVector(data_frame.payload.size());
                                response->insert(response->end(), type_bytes.begin(), type_bytes.end());
                                response->insert(response->end(), length_bytes.begin(), length_bytes.end());
                                response->insert(response->end(), data_frame.payload.begin(), data_frame.payload.end());
                            }

                            // Send response on the same stream
                            if (response)
                            {
                                auto send_error = connection.SendStreamData(stream_id, *response);
                                if (send_error)
                                {
                                    spdlog::error("[HTTP/3] Error sending response: {}", static_cast<int>(*send_error));
                                }
                                else
                                {
                                    spdlog::debug("[HTTP/3] Queued response on stream {}", stream_id);
                                }

                                // Close the stream (sets FIN flag)
                                connection.CloseStream(stream_id);

                                // Actually send the STREAM frames
                                co_await SendPendingStreamData();
                            }

                            // Clear the receive buffer
                            stream_ptr->recv_buffer.clear();
                        }
                    }
                }

                // Phase 4: Process pending retransmissions
                for (std::size_t level_idx = 0; level_idx < 3; ++level_idx)
                {
                    auto &state = level_state[level_idx];
                    if (!state.pending_retransmits.empty())
                    {
                        spdlog::debug("[Retransmit] {} frames pending at level {}", state.pending_retransmits.size(), level_idx);

                        // TODO: Actually retransmit these frames
                        // For now, just clear them to avoid infinite accumulation
                        state.pending_retransmits.clear();
                    }
                }
            }

            spdlog::debug("[Connection] Connection closed");
        }
        catch (const std::exception &e)
        {
            spdlog::error("[Connection] Exception: {}", e.what());
        }
    }
};

} // namespace clv::http3

#endif // CLV_NETCORE_HTTP_HTTP3_CONNECTION_HANDLER_H