// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
#include <asio/ip/udp.hpp>
#include <asio/awaitable.hpp>

#include "numeric_util.h"
#include "connection_id.h"
#include "quic_connection.h"
#include <result_or.h>

namespace clv::quic {

/// Connection manager: demux incoming datagrams to QUIC connections
struct QuicConnectionManager
{
    using SendFnT = std::function<asio::awaitable<void>(
        std::vector<std::uint8_t> /*packet*/, asio::ip::udp::endpoint /*remote*/)>;
    using ConnPtr = std::unique_ptr<QuicConnection>;
    using ConnMap = std::unordered_map<ConnectionId, ConnPtr, ConnectionIdHash, ConnectionIdEq>;

    /// Hash and equality for udp endpoints (used by endpoint_index_)
    struct EndpointHash
    {
        std::size_t operator()(const asio::ip::udp::endpoint &ep) const noexcept
        {
            auto h1 = std::hash<std::string>{}(ep.address().to_string());
            auto h2 = std::hash<std::uint16_t>{}(ep.port());
            return h1 ^ (h2 << 16);
        }
    };
    struct EndpointEq
    {
        bool operator()(const asio::ip::udp::endpoint &a,
                        const asio::ip::udp::endpoint &b) const noexcept
        {
            return a == b;
        }
    };
    using EndpointMap = std::unordered_map<asio::ip::udp::endpoint, ConnectionId, EndpointHash, EndpointEq>;

    /// Callback invoked when a new connection is accepted (before handshake completes)
    using NewConnectionCb = std::function<void(QuicConnection &, const asio::ip::udp::endpoint &)>;

    /// Callback invoked when handshake completes successfully
    using HandshakeCompleteCb = std::function<void(QuicConnection &)>;

    /// Callback invoked when stream data is received
    using StreamDataCb = std::function<void(QuicConnection &, std::uint64_t stream_id, std::span<const std::uint8_t> data)>;

    QuicConnectionManager(asio::io_context &io_ctx, SendFnT send_fn);

    /// Set callback for new connections
    void SetNewConnectionCallback(NewConnectionCb cb)
    {
        mNewConnCb = std::move(cb);
    }

    /// Set callback for handshake completion
    void SetHandshakeCompleteCb(HandshakeCompleteCb cb)
    {
        mHandshakeCb = std::move(cb);
    }

    /// Set callback for stream data
    void SetStreamDataCallback(StreamDataCb cb)
    {
        mStreamDataCb = std::move(cb);
    }

    /// Route an incoming packet to the appropriate connection. Parsing will evolve in Phase 3.
    asio::awaitable<void> RoutePacket(std::span<const std::uint8_t> packet,
                                      asio::ip::udp::endpoint remote);

    /// Accept (or create) a server-side connection identified by dest connection id.
    QuicConnection &AcceptConnection(const ConnectionId &dest_id, asio::ip::udp::endpoint remote);

    /// Register a client-side connection (for outbound connections)
    void RegisterClientConnection(const ConnectionId &local_id, ConnPtr connection);

    /// Get a connection by ID (returns nullptr if not found)
    QuicConnection *GetConnection(const ConnectionId &conn_id);

    /// Client-side connect placeholder (Phase 3/4 will flesh this out).
    asio::awaitable<clv::result_or<QuicConnection *, std::error_code>> Connect(std::string_view host,
                                                                               std::uint16_t port);

    /// Remove idle connections beyond the timeout.
    void PruneConnections(std::chrono::steady_clock::duration idle_timeout);

    /// Get connection count
    [[nodiscard]] std::size_t ConnectionCount() const noexcept
    {
        return mConnections.size();
    }

  private:
    asio::io_context &mIoCtx;
    SendFnT mSendFn;
    ConnMap mConnections;
    asio::steady_timer mCleanupTimer;
    NewConnectionCb mNewConnCb;
    HandshakeCompleteCb mHandshakeCb;
    StreamDataCb mStreamDataCb;

    /// Maps remote endpoint → ConnectionId for client connections.
    /// Used as fallback routing when DCID doesn't match any known connection
    /// (e.g. server response packets carry the server's CID, not the client's).
    EndpointMap mEndpointIndex;
};

inline QuicConnectionManager::QuicConnectionManager(asio::io_context &io_ctx, SendFnT send_fn)
    : mIoCtx(io_ctx),
      mSendFn(std::move(send_fn)),
      mCleanupTimer(io_ctx)
{
}

inline asio::awaitable<void> QuicConnectionManager::RoutePacket(std::span<const std::uint8_t> packet,
                                                                asio::ip::udp::endpoint remote)
{
    // Minimal parsing: extract destination Connection ID and hand off to (or create) a connection.
    // This supports long headers (Initial/Handshake/0-RTT) and a best-effort match for short headers
    // by comparing known connection ID lengths in the map.

    auto parse_long_dcid = [](std::span<const std::uint8_t> pkt) -> std::optional<ConnectionId>
    {
        // Long header: 1B flags, 4B version, 1B DCID len, DCID, 1B SCID len, SCID, ...
        if (pkt.size() < 6)
        {
            spdlog::warn("parse_long_dcid: Packet too short: {} bytes", pkt.size());
            return std::nullopt;
        }
        const auto dcid_len = pkt[5];
        spdlog::debug("parse_long_dcid: DCID length byte at offset 5 = {}", dcid_len);
        if (dcid_len == 0 || dcid_len > 20)
        {
            spdlog::warn("parse_long_dcid: Invalid DCID length: {}", dcid_len);
            return std::nullopt;
        }
        if (pkt.size() < safe_cast<std::size_t>(6 + dcid_len))
        {
            spdlog::warn("parse_long_dcid: Packet too short for DCID: size={}, need={}",
                         pkt.size(),
                         6 + dcid_len);
            return std::nullopt;
        }
        ConnectionId cid;
        cid.length = dcid_len;
        std::copy_n(pkt.data() + 6, dcid_len, cid.data.begin());
        spdlog::debug("parse_long_dcid: Successfully parsed DCID, length={}", dcid_len);
        return cid;
    };

    auto parse_short_dcid = [this](std::span<const std::uint8_t> pkt) -> std::optional<ConnectionId>
    {
        if (pkt.size() < 2)
            return std::nullopt;
        // Short header: flags byte followed by DCID of negotiated length. We try to match against
        // known connection IDs by length and value.
        for (const auto &entry : mConnections)
        {
            const auto &known = entry.first;
            if (known.length == 0)
                continue;
            const auto required = static_cast<std::size_t>(1 + known.length);
            if (pkt.size() < required)
                continue;
            if (std::equal(known.data.begin(),
                           known.data.begin() + known.length,
                           pkt.begin() + 1))
                return known;
        }
        return std::nullopt;
    };

    if (packet.empty())
    {
        spdlog::warn("RoutePacket: Empty packet received");
        co_return;
    }

    const bool long_header = (packet[0] & 0x80) != 0;
    spdlog::debug("RoutePacket: Received packet, size={}, long_header={}", packet.size(), long_header);

    std::optional<ConnectionId> dest_id = long_header ? parse_long_dcid(packet)
                                                      : parse_short_dcid(packet);

    if (!dest_id)
    {
        spdlog::warn("RoutePacket: Failed to parse destination connection ID");
        co_return; // Unable to parse/demux
    }

    spdlog::debug("RoutePacket: Parsed DCID, length={}", dest_id->length);

    // First try direct DCID lookup
    QuicConnection *conn_ptr = nullptr;
    if (auto it = mConnections.find(*dest_id); it != mConnections.end())
    {
        it->second->remote_endpoint = remote;
        conn_ptr = it->second.get();
    }
    else
    {
        // DCID not found — check if this packet is from an endpoint with a pending
        // client connection (e.g. server response carrying the server's own CID).
        if (auto ep_it = mEndpointIndex.find(remote); ep_it != mEndpointIndex.end())
        {
            if (auto conn_it = mConnections.find(ep_it->second); conn_it != mConnections.end())
            {
                spdlog::debug("RoutePacket: Matched packet from {} to existing client connection by endpoint",
                              remote.address().to_string());
                conn_it->second->remote_endpoint = remote;
                conn_ptr = conn_it->second.get();
            }
        }
    }

    // If still no match, accept as a new inbound server connection
    if (!conn_ptr)
    {
        conn_ptr = &AcceptConnection(*dest_id, remote);
    }

    auto &conn = *conn_ptr;

    // Check handshake state before processing
    bool was_complete = conn.tls.has_value() && conn.tls->IsComplete();

    conn.ProcessPacket(packet);

    // Check if handshake just completed
    if (!was_complete && conn.tls.has_value() && conn.tls->IsComplete())
    {
        spdlog::debug("RoutePacket: Handshake completed, invoking callback");
        if (mHandshakeCb)
        {
            mHandshakeCb(conn);
        }
    }

    // Phase 3 will parse frames and dispatch into the connection's handler/strand.
    co_return;
}

inline QuicConnection &QuicConnectionManager::AcceptConnection(const ConnectionId &dest_id,
                                                               asio::ip::udp::endpoint remote)
{
    if (auto it = mConnections.find(dest_id); it != mConnections.end())
    {
        it->second->remote_endpoint = remote;
        return *it->second.get();
    }

    // Create new connection
    auto result = QuicConnection::CreateServer(dest_id, ConnectionId{}, remote);
    ConnPtr conn;
    if (result)
    {
        conn = std::make_unique<QuicConnection>(std::move(*result));
    }
    else
    {
        // Fallback to basic initialization if CreateServer fails
        conn = std::make_unique<QuicConnection>();
        conn->local_id = dest_id;
        conn->remote_endpoint = remote;
        conn->is_server = true;
    }
    conn->last_activity = std::chrono::steady_clock::now();

    auto *raw_ptr = conn.get();
    mConnections.emplace(dest_id, std::move(conn));

    // Notify callback of new connection
    if (mNewConnCb)
    {
        mNewConnCb(*raw_ptr, remote);
    }

    return *raw_ptr;
}

inline void QuicConnectionManager::RegisterClientConnection(const ConnectionId &local_id,
                                                            ConnPtr connection)
{
    if (!connection)
        return;

    connection->last_activity = std::chrono::steady_clock::now();

    // Index by remote endpoint so response packets can be routed back
    // even when their DCID doesn't match our local CID
    mEndpointIndex[connection->remote_endpoint] = local_id;

    mConnections.emplace(local_id, std::move(connection));
}

inline QuicConnection *QuicConnectionManager::GetConnection(const ConnectionId &conn_id)
{
    auto it = mConnections.find(conn_id);
    if (it == mConnections.end())
        return nullptr;
    return it->second.get();
}

inline asio::awaitable<clv::result_or<QuicConnection *, std::error_code>>
QuicConnectionManager::Connect(std::string_view /*host*/, std::uint16_t /*port*/)
{
    // mIoCtx retained for future client connect work; suppress unused warning for now.
    (void)mIoCtx;
    co_return clv::result_or<QuicConnection *, std::error_code>{
        std::make_error_code(std::errc::function_not_supported)};
}

inline void QuicConnectionManager::PruneConnections(std::chrono::steady_clock::duration idle_timeout)
{
    const auto now = std::chrono::steady_clock::now();
    for (auto it = mConnections.begin(); it != mConnections.end();)
    {
        const bool idle = (now - it->second->last_activity) > idle_timeout;
        if (idle)
        {
            // Remove from endpoint index if present
            for (auto ep_it = mEndpointIndex.begin(); ep_it != mEndpointIndex.end(); ++ep_it)
            {
                if (ConnectionIdEq{}(ep_it->second, it->first))
                {
                    mEndpointIndex.erase(ep_it);
                    break;
                }
            }
            it = mConnections.erase(it);
        }
        else
            ++it;
    }
}

} // namespace clv::quic
