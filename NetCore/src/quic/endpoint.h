// Copyright (c) 2026- Charlie Vigue. All rights reserved.
//
// clv::quic — ngtcp2-based QUIC transport. Sole QUIC implementation in the
// tree; the previous custom stack at clv::quic_legacy was deleted on
// 2026-05-28 after Phase 5 step (2) interop validation went green.
//
// Public surface:
//   - SendFnT outbound callback,
//   - asio io_context ownership,
//   - NewConnection / HandshakeComplete / StreamData callbacks.
//
// See _planning/todo.md → "QUIC Transport: Migrate to ngtcp2".

#ifndef CLV_NETCORE_QUIC2_ENDPOINT_H
#define CLV_NETCORE_QUIC2_ENDPOINT_H

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <vector>

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>

namespace clv::quic {

/**
 * Endpoint — owns a single UDP socket and demultiplexes inbound packets
 * to QUIC connections (server-side accept or client-side route). Each
 * Endpoint corresponds to one local socket address; a process may host
 * many endpoints if it needs to bind multiple addresses.
 *
 * Lifetime: the caller owns the asio::io_context and must keep it alive
 * for the lifetime of the Endpoint. Endpoint is non-copyable.
 *
 * Phase 1 status: scaffolding + datagram I/O. The receive loop dispatches
 * inbound packets to the registered PacketHandler. Connection demux,
 * TLS, and stream wiring land in subsequent commits.
 */
class Endpoint
{
  public:
    /**
     * Inbound packet callback. The span is valid only for the duration
     * of the call (it points into the Endpoint's receive buffer); copy
     * if you need to retain the bytes. Invoked on the io_context that
     * owns the Endpoint.
     */
    using PacketHandler = std::function<void(std::span<const std::uint8_t>, const asio::ip::udp::endpoint &)>;

    /**
     * Construct and bind a UDP socket at `local`. Throws asio::system_error
     * if the bind fails.
     */
    Endpoint(asio::io_context &io_ctx, asio::ip::udp::endpoint local);

    Endpoint(const Endpoint &) = delete;
    Endpoint &operator=(const Endpoint &) = delete;
    Endpoint(Endpoint &&) = delete;
    Endpoint &operator=(Endpoint &&) = delete;

    ~Endpoint();

    /** Local bound endpoint (may differ from constructor arg if port 0 was requested). */
    [[nodiscard]] asio::ip::udp::endpoint local_endpoint() const;

    /**
     * Register the inbound packet handler. Must be called before start();
     * changing it after start() is not supported. Pass an empty function
     * to drop packets (useful in unit tests).
     */
    void set_packet_handler(PacketHandler handler);

    /**
     * Start the asynchronous receive loop. Idempotent. Requires the
     * caller's io_context to be run() on some thread for packets to be
     * dispatched.
     */
    void start();

    /**
     * Stop the receive loop and close the socket. Idempotent. Any
     * pending async_receive_from completes with operation_aborted, after
     * which the receive coroutine exits cleanly.
     */
    void stop();

    /**
     * Send a single UDP datagram. The returned awaitable completes when
     * the kernel has accepted the buffer; the caller owns the bytes
     * until then. Errors from the underlying socket are swallowed at
     * this layer — Phase 1 leaves loss recovery to ngtcp2.
     */
    asio::awaitable<void> send(std::vector<std::uint8_t> datagram,
                               asio::ip::udp::endpoint remote);

    /**
     * Synchronous variant of send(). Performs a blocking send_to on
     * the bound socket and returns once the kernel has accepted (or
     * rejected) the buffer. Intended for callsites inside the
     * io_context where running another coroutine to drain a send
     * could reorder packets — ngtcp2 packetizes handshake responses
     * into multiple ordered datagrams and requires they hit the wire
     * in the order produced. Errors from the underlying socket are
     * swallowed at this layer.
     */
    void send_sync(std::span<const std::uint8_t> datagram,
                   const asio::ip::udp::endpoint &remote);

    /**
     * Register `conn` for DCID-based inbound demux. The Endpoint reads
     * the connection's current local SCIDs (see Connection::local_scids)
     * and routes inbound datagrams whose DCID matches to
     * conn->read_packet(). The caller owns the Connection's lifetime
     * and must call unregister_connection before destroying it.
     *
     * If `conn` is the only connection registered when an inbound
     * packet arrives whose DCID is unknown to the demux table, the
     * packet falls through to the PacketHandler (if set).
     */
    void register_connection(class Connection &conn);

    /**
     * Register an additional CID alias that should route inbound
     * datagrams to `conn`. Used for the client-chosen original DCID
     * during a server handshake: ngtcp2's `local_scids` only returns
     * server-issued SCIDs, but the client retransmits Initials with
     * the original DCID until it learns one of the server SCIDs.
     * The alias is cleared by unregister_connection.
     */
    void register_cid_alias(class Connection &conn,
                            std::span<const std::uint8_t> cid);

    /** Remove `conn` from the demux table. Idempotent. */
    void unregister_connection(class Connection &conn);

  private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};

} // namespace clv::quic

#endif // CLV_NETCORE_QUIC2_ENDPOINT_H
