// Copyright (c) 2026- Charlie Vigue. All rights reserved.
//
// clv::quic Endpoint — Phase 1 Step 2. Owns a bound UDP socket and
// drives an asio-coroutine receive loop that dispatches datagrams to
// the registered PacketHandler. Connection demux, ngtcp2 callbacks,
// and TLS plumbing land in subsequent commits.

#include "quic/endpoint.h"

#include "quic/connection.h"

// ngtcp2 headers are included here (not transitively) so that the rest
// of NetCore stays free of ngtcp2 symbols. Including them in this TU
// also validates the toolchain linkage path end-to-end.
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_quictls.h>

#include <asio/as_tuple.hpp>
#include <asio/buffer.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/ip/udp.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <spdlog/spdlog.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <memory>
#include <unordered_map>
#include <utility>
#include <vector>

namespace clv::quic {

namespace {
// QUIC requires support for at least 1200-byte datagrams; common path
// MTUs land near 1452 over Ethernet. We size the receive buffer to
// 1500 to comfortably cover the unfragmented IPv4/IPv6 path MTU and
// avoid truncation. Jumbo-frame paths are out of scope for Phase 1.
constexpr std::size_t kReceiveBufferSize = 1500;

// Short-header DCID length used when peeking inbound datagrams. ngtcp2
// requires this to be known a priori because short headers do not
// carry a length field. Phase 1 uses 8-byte CIDs end-to-end; this
// becomes configurable once non-uniform CID lengths matter.
constexpr std::size_t kShortDcidLen = 8;

// Hash a CID's bytes for use as an unordered_map key.
struct CidKey
{
    std::array<std::uint8_t, ConnectionId::kMaxLen> bytes{};
    std::size_t len{0};

    bool operator==(const CidKey &other) const noexcept
    {
        return len == other.len && std::memcmp(bytes.data(), other.bytes.data(), len) == 0;
    }
};
struct CidKeyHash
{
    std::size_t operator()(const CidKey &k) const noexcept
    {
        // FNV-1a 64-bit over k.bytes[0..k.len). Sufficient for an
        // in-process demux table; CIDs are random so collisions are
        // statistically negligible.
        std::uint64_t h = 0xcbf29ce484222325ULL;
        for (std::size_t i = 0; i < k.len; ++i)
        {
            h ^= k.bytes[i];
            h *= 0x100000001b3ULL;
        }
        return static_cast<std::size_t>(h);
    }
};

CidKey MakeCidKey(const ConnectionId &id) noexcept
{
    CidKey k{};
    k.len = id.len;
    std::memcpy(k.bytes.data(), id.data.data(), id.len);
    return k;
}

} // namespace

struct Endpoint::Impl
{
    asio::io_context &mIoCtx;
    asio::ip::udp::socket mSocket;
    PacketHandler mHandler;
    std::array<std::uint8_t, kReceiveBufferSize> mRxBuffer{};
    bool mStarted{false};
    std::unordered_map<CidKey, Connection *, CidKeyHash> mDemux;

    // Per-registered-Connection expiry timer. ngtcp2 needs
    // handle_expiry() called when its earliest deadline (PTO, loss
    // detection, idle timeout) fires; we wrap that in a steady_timer
    // that is re-armed after every read_packet / write_to so the
    // connection makes progress even with no inbound traffic.
    std::unordered_map<Connection *, std::shared_ptr<asio::steady_timer>> mTimers;

    Impl(asio::io_context &io_ctx, asio::ip::udp::endpoint local)
        : mIoCtx(io_ctx), mSocket(io_ctx, std::move(local))
    {
    }

    // Send a single datagram synchronously through the bound socket.
    // Used both by the receive-loop flush and by the expiry-timer
    // flush so the two share identical UDP semantics.
    void SendSync(std::span<const std::uint8_t> bytes,
                  const asio::ip::udp::endpoint &dest)
    {
        asio::error_code ec;
        auto n = mSocket.send_to(asio::buffer(bytes.data(), bytes.size()), dest, 0, ec);
        if (ec)
        {
            spdlog::warn("SendSync send_to({}:{}) failed: {} (sent {} of {})",
                         dest.address().to_string(),
                         dest.port(),
                         ec.message(),
                         n,
                         bytes.size());
        }
    }

    // (Re-)arm the per-Connection expiry timer. Called after every
    // ngtcp2 state advance (post-read_packet, post-write_to, and
    // recursively from the timer handler itself). Safe to call when
    // conn is not registered — no-op.
    void ArmTimer(Connection *conn)
    {
        auto it = mTimers.find(conn);
        if (it == mTimers.end())
        {
            return;
        }
        auto timer = it->second;
        auto deadline = conn->expiry();
        // ngtcp2 returns time_point::max() when no deadline is armed
        // (typically just after construction). Skip arming in that
        // case; the next read_packet/write_to cycle will re-check.
        if (deadline == std::chrono::steady_clock::time_point::max())
        {
            timer->cancel();
            return;
        }
        // expires_at cancels any pending wait, then schedules a new
        // one. The handler captures `this` (Impl*) plus conn — both
        // outlive the timer because unregister_connection cancels
        // and drops the timer before the Connection can be destroyed.
        timer->expires_at(deadline);
        Impl *self = this;
        timer->async_wait(
            [self, conn, timer](const asio::error_code &ec)
        {
            if (ec == asio::error::operation_aborted)
            {
                return;
            }
            // Re-check registration: the Connection may have been
            // unregistered between scheduling and firing.
            if (self->mTimers.find(conn) == self->mTimers.end())
            {
                return;
            }
            if (conn->handle_expiry() != 0)
            {
                // ngtcp2 entered closing/draining; nothing more to do.
                return;
            }
            conn->write_to(
                [self](std::span<const std::uint8_t> bytes,
                       const asio::ip::udp::endpoint &dest)
            {
                self->SendSync(bytes, dest);
            });
            self->ArmTimer(conn);
        });
    }

    // Look up the Connection responsible for the inbound datagram by
    // peeking its DCID. Returns nullptr if no registered Connection
    // owns this DCID (caller falls back to PacketHandler).
    Connection *Lookup(std::span<const std::uint8_t> data) const
    {
        ngtcp2_version_cid vc{};
        int rv = ngtcp2_pkt_decode_version_cid(&vc, data.data(), data.size(), kShortDcidLen);
        if (rv != 0 && rv != NGTCP2_ERR_VERSION_NEGOTIATION)
        {
            return nullptr;
        }
        if (vc.dcidlen == 0 || vc.dcidlen > ConnectionId::kMaxLen)
        {
            return nullptr;
        }
        CidKey key{};
        key.len = vc.dcidlen;
        std::memcpy(key.bytes.data(), vc.dcid, vc.dcidlen);
        auto it = mDemux.find(key);
        return it == mDemux.end() ? nullptr : it->second;
    }
};

Endpoint::Endpoint(asio::io_context &io_ctx, asio::ip::udp::endpoint local)
    : mImpl(std::make_unique<Impl>(io_ctx, std::move(local)))
{
}

Endpoint::~Endpoint() = default;

asio::ip::udp::endpoint Endpoint::local_endpoint() const
{
    return mImpl->mSocket.local_endpoint();
}

void Endpoint::set_packet_handler(PacketHandler handler)
{
    mImpl->mHandler = std::move(handler);
}

void Endpoint::start()
{
    if (mImpl->mStarted)
    {
        return;
    }
    mImpl->mStarted = true;

    // The receive loop captures the raw Impl* — safe because Endpoint
    // is non-movable and the io_context is owned by the caller (who
    // must keep both alive while packets may arrive). stop() closes
    // the socket, which causes async_receive_from to complete with
    // operation_aborted and the coroutine to exit.
    Impl *impl = mImpl.get();
    asio::co_spawn(
        mImpl->mIoCtx,
        [impl]() -> asio::awaitable<void>
    {
        asio::ip::udp::endpoint peer;
        for (;;)
        {
            auto [ec, n] = co_await impl->mSocket.async_receive_from(
                asio::buffer(impl->mRxBuffer), peer, asio::as_tuple(asio::use_awaitable));
            if (ec)
            {
                // operation_aborted on stop(); any other error also
                // terminates the loop. Phase 2 may add reopen/retry.
                co_return;
            }
            std::span<const std::uint8_t> pkt(impl->mRxBuffer.data(), n);
            Connection *conn = impl->Lookup(pkt);
            if (conn)
            {
                int rrv = conn->read_packet(pkt, peer);
                (void)rrv;
                // Flush any packets ngtcp2 wants to emit in response
                // (ACKs, handshake continuation, retransmissions).
                int wrv = conn->write_to(
                    [impl](std::span<const std::uint8_t> bytes,
                           const asio::ip::udp::endpoint &dest)
                {
                    impl->SendSync(bytes, dest);
                });
                (void)wrv;
                // ngtcp2's deadline shifts after every state advance;
                // re-arm so PTO / idle-timeout stays accurate.
                impl->ArmTimer(conn);
                continue;
            }
            if (impl->mHandler)
            {
                impl->mHandler(pkt, peer);
            }
        }
    },
        asio::detached);
}

void Endpoint::stop()
{
    if (!mImpl->mStarted)
    {
        return;
    }
    mImpl->mStarted = false;
    if (mImpl->mSocket.is_open())
    {
        asio::error_code ignored;
        mImpl->mSocket.close(ignored);
    }
}

asio::awaitable<void> Endpoint::send(std::vector<std::uint8_t> datagram,
                                     asio::ip::udp::endpoint remote)
{
    auto [ec, n] = co_await mImpl->mSocket.async_send_to(
        asio::buffer(datagram), remote, asio::as_tuple(asio::use_awaitable));
    (void)ec;
    (void)n;
    co_return;
}

void Endpoint::send_sync(std::span<const std::uint8_t> datagram,
                         const asio::ip::udp::endpoint &remote)
{
    mImpl->SendSync(datagram, remote);
}

void Endpoint::register_connection(Connection &conn)
{
    for (auto const &id : conn.local_scids())
    {
        mImpl->mDemux.insert_or_assign(MakeCidKey(id), &conn);
    }
    // Install the expiry timer on first registration. Subsequent
    // re-registrations (e.g., to refresh SCIDs after issue/retire)
    // keep the existing timer.
    auto [it, inserted] = mImpl->mTimers.try_emplace(
        &conn, std::make_shared<asio::steady_timer>(mImpl->mIoCtx));
    if (inserted)
    {
        // Arm against the current ngtcp2 deadline (may be max() if
        // the connection has not yet exchanged a packet, in which
        // case ArmTimer is a no-op until the first read/write).
        mImpl->ArmTimer(&conn);
    }
}

void Endpoint::register_cid_alias(Connection &conn,
                                  std::span<const std::uint8_t> cid)
{
    if (cid.empty() || cid.size() > ConnectionId::kMaxLen)
    {
        return;
    }
    CidKey k{};
    k.len = static_cast<std::uint8_t>(cid.size());
    std::memcpy(k.bytes.data(), cid.data(), cid.size());
    mImpl->mDemux.insert_or_assign(k, &conn);
}

void Endpoint::unregister_connection(Connection &conn)
{
    // Cancel and drop the expiry timer before clearing demux entries
    // so that any in-flight wait handler exits before the caller
    // destroys the Connection.
    if (auto it = mImpl->mTimers.find(&conn); it != mImpl->mTimers.end())
    {
        it->second->cancel();
        mImpl->mTimers.erase(it);
    }
    // Erase every entry pointing at this Connection. Phase 1 has at
    // most a handful of registered connections per endpoint, so the
    // linear scan is fine; a reverse index can be added if hot.
    for (auto it = mImpl->mDemux.begin(); it != mImpl->mDemux.end();)
    {
        if (it->second == &conn)
        {
            it = mImpl->mDemux.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

// Force-instantiate at least one ngtcp2 symbol use so the linker
// resolves against libngtcp2.a even before any protocol code lands.
// Removed once Connection lands.
namespace {
[[maybe_unused]] const char *ngtcp2_version_probe()
{
    return ngtcp2_strerror(0);
}
} // namespace

} // namespace clv::quic
