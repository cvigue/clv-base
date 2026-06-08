// Copyright (c) 2023- Charlie Vigue. All rights reserved.

/**
 * @file stun_io.h
 * @brief Injectable UDP I/O surface for @ref stun_discovery.
 */

#ifndef CLV_NETCORE_STUN_IO_HPP
#define CLV_NETCORE_STUN_IO_HPP

#include "stun_types.h"

#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/use_awaitable.hpp>
#include <atomic>
#include <functional>
#include <optional>
#include <span>
#include <vector>

namespace clv::netcore {

/**
 * @brief Injectable UDP I/O for STUN discovery.
 *
 * @ref make_socket_stun_io wires an owned socket with exclusive
 * @c async_receive_from. Shared-socket integrations (e.g. mesh QUIC) set
 * @c send_to to the application socket and @c receive_with_timeout to a demuxer
 * that completes when a matching STUN binding response arrives.
 *
 * All callbacks must run on the same @c io_context thread as the caller.
 */
struct stun_io
{
    /** Send a STUN request datagram to @p dest. */
    std::function<asio::awaitable<void>(std::span<const std::uint8_t>,
                                        const asio::ip::udp::endpoint &)>
        send_to;

    /** Await the next STUN response (or timeout). Empty optional on failure. */
    std::function<asio::awaitable<std::optional<std::vector<std::uint8_t>>>(
        std::chrono::milliseconds timeout)>
        receive_with_timeout;

    /** Cancel an in-flight @c receive_with_timeout (e.g. socket @c cancel). */
    std::function<void()> cancel_receive;

    /** Local bound endpoint of the socket used for STUN (NAT analysis). */
    std::function<asio::ip::udp::endpoint()> local_endpoint;
};

/**
 * @brief Build @ref stun_io over an owned UDP socket (exclusive receive).
 *
 * Suitable for @c stun_client and standalone tests. Not for sockets shared
 * with another protocol unless receive is demuxed elsewhere.
 */
[[nodiscard]] inline stun_io make_socket_stun_io(asio::ip::udp::socket &socket,
                                                 asio::io_context &io_context)
{
    stun_io io;

    io.send_to = [&socket](std::span<const std::uint8_t> data,
                           const asio::ip::udp::endpoint &dest) -> asio::awaitable<void>
    {
        co_await socket.async_send_to(asio::buffer(data), dest, asio::use_awaitable);
    };

    io.receive_with_timeout = [&socket, &io_context](
                                  std::chrono::milliseconds timeout) -> asio::awaitable<std::optional<std::vector<std::uint8_t>>>
    {
        std::array<std::uint8_t, stun_defaults::max_stun_response_size> response_buffer{};
        asio::ip::udp::endpoint sender_endpoint;

        asio::steady_timer timer{io_context};
        timer.expires_after(timeout);

        std::atomic<bool> timeout_occurred{false};
        timer.async_wait([&](std::error_code ec)
        {
            if (!ec)
            {
                timeout_occurred = true;
                socket.cancel();
            }
        });

        std::error_code recv_ec;
        std::size_t bytes_received = 0;
        try
        {
            bytes_received = co_await socket.async_receive_from(
                asio::buffer(response_buffer), sender_endpoint, asio::use_awaitable);
        }
        catch (const std::system_error &e)
        {
            recv_ec = e.code();
        }

        timer.cancel();

        if (recv_ec)
            co_return std::nullopt;

        if (bytes_received == 0)
            co_return std::nullopt;

        co_return std::vector<std::uint8_t>(response_buffer.begin(),
                                            response_buffer.begin()
                                                + static_cast<std::ptrdiff_t>(bytes_received));
    };

    io.cancel_receive = [&socket]()
    { socket.cancel(); };

    io.local_endpoint = [&socket]() -> asio::ip::udp::endpoint
    { return socket.local_endpoint(); };

    return io;
}

} // namespace clv::netcore

#endif // CLV_NETCORE_STUN_IO_HPP
