// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_NETCORE_HTTP3_SESSION_ADAPTER_H
#define CLV_NETCORE_HTTP3_SESSION_ADAPTER_H

#include "micro_udp_server_defs.h"
#include "http/http3_proto.h"
#include "http/http3_connection_handler.h"
#include "quic/connection_id.h"
#include "quic/quic_packet.h"
#include "quic/quic_tls.h"
#include "quic/quic_varint.h"

#include <array>
#include <asio/awaitable.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <asio.hpp>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace clv::http3 {

/**
 * @brief Adapts Http3ConnectionHandler for use with UdpConnectionMultiplexer
 *
 * @details This adapter wraps the existing ConnectionHandler to provide the session interface
 *          expected by the multiplexer. It:
 *          - Routes OnPacket() calls to EnqueuePacket()
 *          - Tracks last activity for IsExpired()
 *          - Stores the connection ID for GetKey()
 *          - Updates the remote endpoint on packet receipt (connection migration support)
 *
 * The adapter maintains a background coroutine that runs the ConnectionHandler's main loop,
 * similar to how quic_simple_server currently spawns HandleConnection().
 * @tparam RoutersT Router types for HTTP/3 request dispatching
 */
template <typename... RoutersT>
class Http3Session
{
  public:
    using KeyType = quic::ConnectionId;
    using HandlerType = ConnectionHandler<RoutersT...>;

    /**
     * @brief Construct a new Http3Session
     *
     * @param handler The underlying ConnectionHandler
     * @param io_ctx IO context for async operations
     */
    Http3Session(
        std::shared_ptr<HandlerType> handler,
        asio::io_context &io_ctx) : handler_(std::move(handler)),
                                    io_ctx_(io_ctx),
                                    last_activity_(std::chrono::steady_clock::now()),
                                    idle_timeout_(std::chrono::seconds{300}) // 5 minutes default
    {
        // Spawn the connection handler's main loop
        asio::co_spawn(io_ctx_, handler_->HandleConnection(), asio::detached);
    }

    /**
     * @brief Handle incoming packet
     *
     * @details Updates last activity time, updates remote endpoint for connection migration,
     *          and enqueues packet for processing by ConnectionHandler.
     */
    asio::awaitable<void> OnPacket(
        std::span<const uint8_t> data,
        asio::ip::udp::endpoint remote,
        clv::UdpServerDefs::SendDatagramFnT send_fn)
    {
        // Update last activity time
        last_activity_ = std::chrono::steady_clock::now();

        // Update remote endpoint (supports connection migration)
        handler_->remote_endpoint = remote;

        // Update send function (allows response to potentially different endpoint)
        handler_->send_fn = send_fn;

        // Enqueue packet for processing
        handler_->EnqueuePacket(std::vector<uint8_t>(data.begin(), data.end()));

        co_return;
    }

    /**
     * @brief Check if session has expired (idle timeout)
     *
     * @return true if idle timeout exceeded
     * @return false if still active
     */
    bool IsExpired() const
    {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - last_activity_);
        return elapsed > idle_timeout_;
    }

    /**
     * @brief Get the connection ID for this session
     *
     * @return quic::ConnectionId The local connection ID
     */
    quic::ConnectionId GetKey() const
    {
        return handler_->connection.local_id;
    }

    /**
     * @brief Set idle timeout for session expiry
     *
     * @param timeout Idle timeout duration
     */
    void SetIdleTimeout(std::chrono::seconds timeout)
    {
        idle_timeout_ = timeout;
    }

    /**
     * @brief Get the underlying ConnectionHandler
     *
     * @return std::shared_ptr<HandlerType> The handler
     */
    std::shared_ptr<HandlerType> GetHandler() const
    {
        return handler_;
    }

  private:
    std::shared_ptr<HandlerType> handler_;
    asio::io_context &io_ctx_;
    std::chrono::steady_clock::time_point last_activity_;
    std::chrono::seconds idle_timeout_;
};

/**
 * @brief Factory for creating Http3Session instances
 *
 * @details Creates QUIC/HTTP3 sessions from Initial packets. Handles:
 *          - Parsing Initial packet to extract connection IDs
 *          - Creating QUIC connection with proper key derivation
 *          - Setting up TLS context with certificates and ALPN
 *          - Configuring QUIC transport parameters
 * @tparam RoutersT Router types for HTTP/3 request dispatching
 */
template <typename... RoutersT>
struct Http3SessionFactory
{
    using RouterDispatchT = Http3RequestDispatcher<RoutersT...>;
    using SessionType = Http3Session<RoutersT...>;

    /**
     * @brief Construct factory with required dependencies
     *
     * @param cert_path Path to TLS certificate
     * @param key_path Path to TLS private key
     * @param routers Vector of router dispatchers
     * @param keepRunning Shutdown flag
     */
    Http3SessionFactory(
        std::string cert_path,
        std::string key_path,
        std::vector<RouterDispatchT> &&routers,
        std::atomic<bool> &keepRunning) : cert_path_(std::move(cert_path)),
                                          key_path_(std::move(key_path)),
                                          routers_(std::move(routers)),
                                          keepRunning_(keepRunning)
    {
    }

    std::shared_ptr<SessionType> Create(
        const quic::ConnectionId &key,
        std::span<const uint8_t> initial_packet,
        asio::ip::udp::endpoint remote,
        asio::io_context &io_ctx)
    {
        // Parse the Initial packet to extract connection setup information
        auto packet_result = quic::ParsePacketHeader(initial_packet);
        if (!packet_result || !std::holds_alternative<quic::LongHeader>(packet_result->header))
        {
            return nullptr;
        }

        auto &long_header = std::get<quic::LongHeader>(packet_result->header);
        if (long_header.type != quic::PacketType::Initial)
        {
            // Only handle Initial packets for new connections
            return nullptr;
        }

        // Create server connection using client's chosen DCID for Initial key derivation
        auto conn_result = quic::QuicConnection::CreateServer(
            long_header.dest_conn_id,
            long_header.src_conn_id,
            remote);

        if (!conn_result)
        {
            return nullptr;
        }

        auto connection = std::move(*conn_result);

        // Update the server's local ID to the provided key (generated by server)
        connection.local_id = key;

        // Create TLS context
        connection.tls = quic::QuicTls::CreateServer(cert_path_, key_path_);
        if (!connection.tls)
        {
            return nullptr;
        }

        // Set ALPN to "h3" for HTTP/3
        std::array<std::string_view, 1> alpn_protocols = {"h3"};
        connection.tls->SetAlpn(alpn_protocols);

        // Set QUIC transport parameters
        std::vector<std::uint8_t> transport_params = BuildTransportParameters(
            long_header.dest_conn_id,
            key);
        connection.tls->SetTransportParameters(transport_params);

        // Create a placeholder send function (will be updated by OnPacket)
        auto placeholder_send = [](UdpServerDefs::buffer_type, asio::ip::udp::endpoint) -> asio::awaitable<void>
        {
            co_return;
        };

        // Create connection handler
        std::vector<RouterDispatchT> routers_copy = routers_;
        auto handler = std::make_shared<ConnectionHandler<RoutersT...>>(
            io_ctx,
            remote,
            std::move(connection),
            std::move(routers_copy),
            placeholder_send,
            keepRunning_);

        // Create session adapter
        auto session = std::make_shared<SessionType>(handler, io_ctx);

        // Feed the initial packet to the handler
        handler->EnqueuePacket(std::vector<uint8_t>(initial_packet.begin(), initial_packet.end()));

        return session;
    }

  private:
    /**
     * @brief Build QUIC transport parameters for server
     */
    std::vector<std::uint8_t> BuildTransportParameters(
        const quic::ConnectionId &original_dcid,
        const quic::ConnectionId &server_cid)
    {
        std::vector<std::uint8_t> params;

        // TODO: Eliminate EncodeVarintVec in favour of writing directly into
        //       params via the tighter span-based EncodeVarint overload.
        using clv::quic::EncodeVarintVec;

        // Helper to add a parameter with varint value
        auto add_param_varint = [&](std::uint64_t param_id, std::uint64_t value)
        {
            auto id_bytes = EncodeVarintVec(param_id);
            auto value_bytes = EncodeVarintVec(value);
            auto len_bytes = EncodeVarintVec(value_bytes.size());

            params.insert(params.end(), id_bytes.begin(), id_bytes.end());
            params.insert(params.end(), len_bytes.begin(), len_bytes.end());
            params.insert(params.end(), value_bytes.begin(), value_bytes.end());
        };

        // Helper to add a parameter with raw bytes
        auto add_param_bytes = [&](std::uint64_t param_id, const std::vector<std::uint8_t> &value)
        {
            auto id_bytes = EncodeVarintVec(param_id);
            auto len_bytes = EncodeVarintVec(value.size());

            params.insert(params.end(), id_bytes.begin(), id_bytes.end());
            params.insert(params.end(), len_bytes.begin(), len_bytes.end());
            params.insert(params.end(), value.begin(), value.end());
        };

        // original_destination_connection_id (0x00)
        std::vector<std::uint8_t> odcid(
            original_dcid.data.begin(),
            original_dcid.data.begin() + original_dcid.length);
        add_param_bytes(0x00, odcid);

        // initial_source_connection_id (0x0f)
        std::vector<std::uint8_t> iscid(
            server_cid.data.begin(),
            server_cid.data.begin() + server_cid.length);
        add_param_bytes(0x0f, iscid);

        // max_idle_timeout (0x01) = 30 seconds
        add_param_varint(0x01, 30000);

        // max_udp_payload_size (0x03) = 65527
        add_param_varint(0x03, 65527);

        // initial_max_data (0x04) = 10MB
        add_param_varint(0x04, 10 * 1024 * 1024);

        // initial_max_stream_data_bidi_local (0x05) = 1MB
        add_param_varint(0x05, 1024 * 1024);

        // initial_max_stream_data_bidi_remote (0x06) = 1MB
        add_param_varint(0x06, 1024 * 1024);

        // initial_max_stream_data_uni (0x07) = 1MB
        add_param_varint(0x07, 1024 * 1024);

        // initial_max_streams_bidi (0x08) = 100
        add_param_varint(0x08, 100);

        // initial_max_streams_uni (0x09) = 100
        add_param_varint(0x09, 100);

        return params;
    }

  private:
    std::string cert_path_;
    std::string key_path_;
    std::vector<RouterDispatchT> routers_;
    std::atomic<bool> &keepRunning_;
};

} // namespace clv::http3

#endif // CLV_NETCORE_HTTP3_SESSION_ADAPTER_H
