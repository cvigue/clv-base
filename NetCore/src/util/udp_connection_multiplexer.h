// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_NETCORE_UDP_CONNECTION_MULTIPLEXER_H
#define CLV_NETCORE_UDP_CONNECTION_MULTIPLEXER_H

#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <asio/this_coro.hpp>
#include <cstddef>
#include <unordered_map>
#include <memory>
#include <chrono>
#include <span>
#include <cstdint>

#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include "micro_udp_server.h"

namespace clv {

/**
 * @brief Routes UDP packets to stateful protocol sessions using zero-cost abstractions
 *
 * @tparam SessionT Session implementation type (compile-time polymorphism)
 * @tparam KeyExtractorT Key extractor implementation (compile-time polymorphism)
 * @tparam SessionFactoryT Factory for creating new sessions (compile-time polymorphism)
 *
 * @details This multiplexer provides the middle layer between MicroUdpServer (UDP I/O)
 *          and protocol-specific session logic. It:
 *          - Extracts routing keys from incoming packets using KeyExtractorT
 *          - Routes packets to existing sessions or creates new ones via SessionFactoryT
 *          - Periodically prunes expired sessions based on idle timeouts
 *          - Passes send callbacks to sessions (no socket dependency)
 *
 * The multiplexer implements the MicroUdpServer handler interface, allowing it
 * to be plugged directly into a MicroUdpServer instance.
 *
 * ## Architecture
 *
 * Three-layer design with compile-time polymorphism (no virtual functions):
 * 1. **MicroUdpServer**: Owns UDP socket, handles I/O
 * 2. **UdpConnectionMultiplexer**: Routes packets, manages session lifecycle
 * 3. **Protocol Sessions**: Handle protocol-specific logic (QUIC, DTLS, etc.)
 *
 * All components are stored by value - no heap allocations for the multiplexer itself.
 * Sessions are heap-allocated via shared_ptr for flexible lifetime management.
 *
 * ## Session Interface Requirements
 *
 * Sessions must provide (duck-typed via templates):
 * ```cpp
 * struct MySession {
 *     using KeyType = ...; // Type used for routing
 *
 *     // Handle incoming packet
 *     asio::awaitable<void> OnPacket(
 *         std::span<const uint8_t> data,
 *         asio::ip::udp::endpoint remote,
 *         UdpServerDefs::SendDatagramFnT send_fn);
 *
 *     // Check if session has expired
 *     bool IsExpired() const;
 *
 *     // Get routing key for this session
 *     KeyType GetKey() const;
 * };
 * ```
 *
 * ## Key Extractor Interface Requirements
 *
 * Key extractors must provide:
 * ```cpp
 * struct MyKeyExtractor {
 *     using KeyType = ...; // Must match SessionT::KeyType
 *
 *     // Extract routing key from packet, or nullopt if invalid
 *     std::optional<KeyType> ExtractKey(std::span<const uint8_t> data) const;
 * };
 * ```
 *
 * ## Session Factory Interface Requirements
 *
 * Factories must provide:
 * ```cpp
 * struct MySessionFactory {
 *     // Create new session from initial packet
 *     std::shared_ptr<SessionT> Create(
 *         const KeyType& key,
 *         std::span<const uint8_t> initial_packet,
 *         asio::ip::udp::endpoint remote,
 *         asio::io_context& io_ctx);
 * };
 * ```
 *
 * ## Example Usage
 *
 * ```cpp
 * // Create multiplexer
 * UdpConnectionMultiplexer<Http3Session, QuicKeyExtractor, Http3SessionFactory> multiplexer(
 *     Http3SessionFactory{cert_path, key_path, routers, keepRunning},
 *     QuicKeyExtractor{});
 *
 * // Plug into UDP server
 * MicroUdpServer<decltype(multiplexer)> server(port, std::move(multiplexer), threads);
 * ```
 *
 * @note Thread-safe: All access to the session map happens on the io_context thread
 * @note Zero-cost: All polymorphism resolved at compile time, no vtable overhead
 */
template <typename SessionT, typename KeyExtractorT, typename SessionFactoryT>
class UdpConnectionMultiplexer
{
  public:
    using KeyType = typename KeyExtractorT::KeyType;

    /**
     * @brief Construct a new multiplexer
     *
     * @param factory Session factory for creating new sessions (stored by value)
     * @param key_extractor Key extractor for routing packets (stored by value)
     * @param prune_interval How often to check for expired sessions (default: 30s)
     */
    UdpConnectionMultiplexer(
        SessionFactoryT factory,
        KeyExtractorT key_extractor = KeyExtractorT{},
        std::chrono::seconds prune_interval = std::chrono::seconds{30}) : session_factory_(std::move(factory)),
                                                                          key_extractor_(std::move(key_extractor)),
                                                                          prune_interval_(prune_interval),
                                                                          io_ctx_(nullptr)
    {
    }

    /**
     * @brief Handle incoming datagram (MicroUdpServer handler interface)
     *
     * @param data The packet data
     * @param remote The sender's endpoint
     * @param send_fn Callback to send response packets
     * @param io_ctx IO context for async operations
     * @return awaitable<bool> true if packet was handled, false if invalid/unroutable
     */
    asio::awaitable<bool> HandleDatagram(
        std::span<const uint8_t> data,
        asio::ip::udp::endpoint remote,
        UdpServerDefs::SendDatagramFnT send_fn,
        asio::io_context &io_ctx)
    {
        // Start pruning task on first packet if not already started
        if (!io_ctx_)
        {
            io_ctx_ = &io_ctx;
            asio::co_spawn(io_ctx, PeriodicPruning(), asio::detached);
        }

        // Extract routing key from packet
        auto key_opt = key_extractor_.ExtractKey(data);
        if (!key_opt)
        {
            // Invalid or unroutable packet (e.g., QUIC version negotiation)
            co_return false;
        }

        // Find or create session (passing packet data for Initial packet parsing)
        auto session = GetOrCreateSession(*key_opt, data, remote, io_ctx);
        if (!session)
        {
            co_return false;
        }

        // Dispatch to session
        co_await session->OnPacket(data, remote, send_fn);

        co_return true;
    }

    /**
     * @brief Get current number of active sessions
     * @return size_t Number of sessions in the map
     */
    size_t GetSessionCount() const
    {
        return sessions_.size();
    }

    /**
     * @brief Register an existing session under an additional key
     *
     * @param key The additional routing key
     * @param session The session to register
     *
     * @details Useful for protocols like QUIC where a session may be reachable
     *          via multiple connection IDs (e.g., client's Initial DCID and
     *          server's generated CID).
     */
    void RegisterSessionKey(const KeyType &key, std::shared_ptr<SessionT> session)
    {
        sessions_.emplace(key, std::move(session));
    }

    /**
     * @brief Get a mutable reference to the session factory
     *
     * @return SessionFactoryT& Reference to the session factory
     *
     * @details Allows post-construction initialization of the factory.
     *          Useful for two-phase initialization when the factory needs
     *          a reference back to the multiplexer.
     */
    SessionFactoryT &GetSessionFactory() noexcept
    {
        return session_factory_;
    }

  private:
    /**
     * @brief Get existing session or create a new one
     *
     * @param key The routing key
     * @param packet_data Initial packet data (for new session creation)
     * @param remote Initial remote endpoint (for new sessions)
     * @param io_ctx IO context
     * @return std::shared_ptr<SessionT> The session, or nullptr if creation failed
     */
    std::shared_ptr<SessionT> GetOrCreateSession(
        const KeyType &key,
        std::span<const uint8_t> packet_data,
        asio::ip::udp::endpoint remote,
        asio::io_context &io_ctx)
    {
        // Look for existing session
        auto it = sessions_.find(key);
        if (it != sessions_.end())
        {
            return it->second;
        }

        // Create new session
        auto session = session_factory_.Create(key, packet_data, remote, io_ctx);
        if (!session)
        {
            return nullptr;
        }

        sessions_.emplace(key, session);
        return session;
    }

    /**
     * @brief Remove expired sessions from the map
     */
    void PruneSessions()
    {
        for (auto it = sessions_.begin(); it != sessions_.end();)
        {
            if (it->second->IsExpired())
            {
                it = sessions_.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }

    /**
     * @brief Coroutine that periodically prunes expired sessions
     *
     * @return awaitable<void> Runs until io_context stops
     */
    asio::awaitable<void> PeriodicPruning()
    {
        asio::steady_timer timer(co_await asio::this_coro::executor);

        while (true)
        {
            timer.expires_after(prune_interval_);
            co_await timer.async_wait(asio::use_awaitable);
            PruneSessions();
        }
    }

    std::unordered_map<KeyType, std::shared_ptr<SessionT>> sessions_;
    SessionFactoryT session_factory_; // Stored by value
    KeyExtractorT key_extractor_;     // Stored by value - typically stateless
    std::chrono::seconds prune_interval_;
    asio::io_context *io_ctx_; // Set on first HandleDatagram call
};

} // namespace clv

#endif // CLV_NETCORE_UDP_CONNECTION_MULTIPLEXER_H
