// Copyright (c) 2026- Charlie Vigue. All rights reserved.
//
// clv::quic Connection — Phase 1 Step 4.
//
// Wraps a single ngtcp2_conn (server or client role) together with its
// per-connection SSL state. This step covers construction, lifecycle,
// and callback wiring; ingress/egress drive and the expiry timer land
// in Step 5.
//
// See _planning/todo.md → "QUIC Transport: Migrate to ngtcp2".

#ifndef CLV_NETCORE_QUIC2_CONNECTION_H
#define CLV_NETCORE_QUIC2_CONNECTION_H

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <asio/ip/udp.hpp>

namespace clv::quic {

class TlsContext;

/**
 * QUIC connection identifier as carried on the wire. Max length is
 * NGTCP2_MAX_CIDLEN (20); the byte buffer is sized to 20 unconditionally
 * to keep this header free of <ngtcp2/...> includes.
 */
struct ConnectionId
{
    static constexpr std::size_t kMaxLen = 20;
    std::array<std::uint8_t, kMaxLen> data{};
    std::size_t len{0};
};

/** Generate a random ConnectionId of `len` bytes (1..kMaxLen). */
ConnectionId MakeRandomConnectionId(std::size_t len);

/** CIDs extracted from a QUIC long-header packet (Initial / Handshake). */
struct PacketCids
{
    ConnectionId dcid;
    ConnectionId scid;
};

/**
 * Decode the QUIC long-header CIDs from a received datagram. The
 * Endpoint demux uses this to route the first Initial to a freshly
 * minted server Connection.
 *
 * Throws std::invalid_argument if `data` is not a valid QUIC long
 * header.
 */
PacketCids DecodePacketCids(std::span<const std::uint8_t> data);

/**
 * Connection — one peer relationship in clv::quic. Owns the ngtcp2_conn
 * pointer and the SSL* derived from the supplied TlsContext.
 *
 * Phase 1 status: construction + lifecycle. Ingress (read_pkt) and
 * egress (writev_stream) drive land in Step 5; stream open/write/recv
 * land in Step 6.
 *
 * Non-copyable, non-movable: ngtcp2 callbacks capture a stable
 * `this` pointer through `user_data`, and OpenSSL stores the same via
 * `SSL_set_app_data` on the per-connection SSL*.
 */
class Connection
{
  public:
    /** Invoked when the QUIC handshake completes (1-RTT keys installed). */
    using HandshakeCompleteCb = std::function<void()>;

    /**
     * Datagram send callback. Used by both write_to() and the pre-write
     * hook to ship a single UDP datagram. The Endpoint owns the actual
     * UDP socket; this layer simply provides bytes + remote endpoint.
     */
    using SendFn = std::function<void(std::span<const std::uint8_t>, const asio::ip::udp::endpoint &)>;

    /** Invoked for each chunk of stream data; `fin` true on stream EOF. */
    using StreamDataCb = std::function<void(std::int64_t stream_id, std::span<const std::uint8_t> data, bool fin)>;

    /** Invoked when a stream is closed (graceful or aborted). */
    using StreamCloseCb = std::function<void(std::int64_t stream_id, std::uint64_t app_error_code)>;

    /**
     * Invoked when previously-sent stream data has been acknowledged by
     * the peer. `datalen` is the number of newly-acked bytes starting at
     * `offset`. Used by HTTP/3 (and other higher layers) to release send
     * buffers and advance their own flow-control bookkeeping.
     */
    using AckedStreamDataOffsetCb = std::function<void(std::int64_t stream_id,
                                                       std::uint64_t offset,
                                                       std::uint64_t datalen)>;

    /**
     * Build a server-side connection from the CIDs extracted from the
     * client's first Initial packet.
     *
     * @param client_dcid The DCID field of the client's first Initial.
     *        This is the value the client chose for its destination
     *        and becomes `original_dcid` in the server's transport
     *        parameters.
     * @param client_scid The SCID field of the client's first Initial.
     *        The server uses this as the destination CID on all
     *        packets it sends back to the client.
     *
     * The server's own outgoing source CID is generated randomly
     * inside this factory.
     */
    static std::unique_ptr<Connection> MakeServer(TlsContext &tls, ConnectionId client_dcid,
                                                  ConnectionId client_scid,
                                                  const asio::ip::udp::endpoint &local,
                                                  const asio::ip::udp::endpoint &remote);

    /**
     * Build a client-side connection. Generates random DCID/SCID
     * internally; the DCID is what the server will see as its initial
     * destination connection id.
     */
    static std::unique_ptr<Connection> MakeClient(TlsContext &tls,
                                                  const asio::ip::udp::endpoint &local,
                                                  const asio::ip::udp::endpoint &remote,
                                                  std::string_view server_name = {});

    Connection(const Connection &) = delete;
    Connection &operator=(const Connection &) = delete;
    Connection(Connection &&) = delete;
    Connection &operator=(Connection &&) = delete;
    ~Connection();

    void set_handshake_complete_cb(HandshakeCompleteCb cb);
    void set_stream_data_cb(StreamDataCb cb);
    void set_stream_close_cb(StreamCloseCb cb);
    void set_acked_stream_data_offset_cb(AckedStreamDataOffsetCb cb);

    /**
     * Invoked at the start of every `write_to()`. Higher layers (e.g.,
     * HTTP/3) use this hook to push any pending application stream data
     * into ngtcp2 before the QUIC-only flush runs. The callback receives
     * the same send function passed to `write_to()`.
     */
    using PreWriteCb = std::function<void(const SendFn &)>;
    void set_pre_write_cb(PreWriteCb cb);

    /** Underlying ngtcp2_conn*. Returned as void* to keep this header
     *  free of <ngtcp2/ngtcp2.h>. */
    [[nodiscard]] void *native_conn() const noexcept;

    [[nodiscard]] const asio::ip::udp::endpoint &local_endpoint() const noexcept;
    [[nodiscard]] const asio::ip::udp::endpoint &remote_endpoint() const noexcept;

    /** True if the handshake has reached the application encryption level. */
    [[nodiscard]] bool handshake_completed() const noexcept;

    /**
     * Feed a received UDP datagram into the ngtcp2 state machine. The
     * `remote` endpoint identifies the source so ngtcp2 can validate
     * path migration. Returns 0 on success or a negative ngtcp2 error
     * code. A closed connection returns NGTCP2_ERR_DRAINING /
     * NGTCP2_ERR_CLOSING; the caller should stop driving thereafter.
     */
    int read_packet(std::span<const std::uint8_t> data,
                    const asio::ip::udp::endpoint &remote);

    /**
     * Pump pending outbound packets. ngtcp2 may emit zero, one, or many
     * datagrams per call. For each emitted datagram, `send_fn` is
     * invoked synchronously with the datagram bytes and the destination
     * endpoint. Loop terminates when ngtcp2 reports it has nothing more
     * to send right now (writev_stream returns 0).
     *
     * The send callback is invoked synchronously; the bytes must be
     * copied or transmitted before it returns.
     *
     * Returns 0 on success or a negative ngtcp2 error code.
     */
    int write_to(const SendFn &send_fn);

    /**
     * Open a new bidirectional stream. Returns the assigned stream id
     * via the out parameter. May be called once the handshake has
     * completed (1-RTT keys installed); returns NGTCP2_ERR_INVALID_STATE
     * otherwise.
     */
    int open_bidi_stream(std::int64_t &stream_id);

    /**
     * Append `data` to the send queue for `stream_id`, optionally
     * marking the FIN. Pumps outbound packets through `send_fn` until
     * ngtcp2 stops accepting more (flow / congestion control hit) or
     * the buffer is fully queued. If `bytes_written` is non-null, the
     * number of bytes ngtcp2 actually consumed is stored there; callers
     * sending bodies larger than the peer's current flow-control budget
     * must re-call with the remainder once additional credit is granted
     * (typically from `pre_write_cb`).
     */
    int write_stream(std::int64_t stream_id, std::span<const std::uint8_t> data, bool fin,
                     const SendFn &send_fn, std::size_t *bytes_written = nullptr);

    /**
     * Earliest time at which this connection needs servicing for loss
     * detection, PTO, or idle timeout. The returned time_point is on
     * std::chrono::steady_clock. Returns time_point::max() if no
     * deadline is currently armed (e.g., immediately after construction
     * before the first packet exchange).
     *
     * Endpoint schedules an asio::steady_timer against this and calls
     * handle_expiry() when it fires; ngtcp2 may then need write_to() to
     * be pumped to emit a probe / retransmission.
     */
    [[nodiscard]] std::chrono::steady_clock::time_point expiry() const noexcept;

    /**
     * Service expiry events: invokes ngtcp2_conn_handle_expiry. Caller
     * should follow with write_to() to flush any resulting packets.
     * Returns 0 on success or a negative ngtcp2 error code.
     */
    int handle_expiry();

    /**
     * Enumerate the SCIDs ngtcp2 currently considers active for this
     * connection. An inbound packet whose DCID matches one of these
     * identifies this Connection at the Endpoint demux. The list
     * changes over the connection's lifetime as ngtcp2 retires and
     * issues new CIDs; callers must re-fetch periodically (or hook
     * the get_new_connection_id / remove_connection_id callbacks).
     */
    [[nodiscard]] std::vector<ConnectionId> local_scids() const;

    /**
     * DER encoding of the peer's end-entity certificate as observed
     * during the TLS handshake, or an empty vector if no peer cert is
     * available (e.g., handshake not yet complete, or peer did not
     * present one). Used by the mesh layer to derive the peer's
     * stable identity (SHA-256 of SubjectPublicKeyInfo).
     */
    [[nodiscard]] std::vector<std::uint8_t> peer_certificate_der() const;

    // Public for the benefit of the in-TU helper functions that wire
    // ngtcp2 callbacks; concrete fields stay defined only in the .cpp.
    struct Impl;

  private:
    std::unique_ptr<Impl> mImpl;

    explicit Connection(std::unique_ptr<Impl> impl) noexcept;
};

} // namespace clv::quic

#endif // CLV_NETCORE_QUIC2_CONNECTION_H
