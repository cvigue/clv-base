// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include "gtest/gtest.h"
#include "stun/stun_discovery.h"
#include "stun/stun_io.h"
#include "stun/stun_types.h"
#include "stun/stun_utils.h"

#include <algorithm>
#include <array>
#include <asio.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/use_future.hpp>
#include <bits/chrono.h>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

using namespace clv::netcore;
using namespace testing;
using namespace std::chrono_literals;

namespace {

std::vector<std::uint8_t> make_binding_response(const transaction_id &trans_id,
                                                asio::ip::address_v4 client_ip,
                                                std::uint16_t client_port)
{
    constexpr std::size_t attr_length = 12;
    std::vector<std::uint8_t> response(stun_constants::header_size + attr_length);

    response[0] = 0x01;
    response[1] = 0x01;
    response[2] = 0x00;
    response[3] = static_cast<std::uint8_t>(attr_length);

    const std::uint32_t cookie = stun_constants::magic_cookie;
    response[4] = static_cast<std::uint8_t>((cookie >> 24) & 0xFF);
    response[5] = static_cast<std::uint8_t>((cookie >> 16) & 0xFF);
    response[6] = static_cast<std::uint8_t>((cookie >> 8) & 0xFF);
    response[7] = static_cast<std::uint8_t>(cookie & 0xFF);

    std::copy(trans_id.begin(), trans_id.end(), response.begin() + 8);

    std::size_t offset = stun_constants::header_size;
    response[offset++] = static_cast<std::uint8_t>((stun_constants::attr_xor_mapped_address >> 8) & 0xFF);
    response[offset++] = static_cast<std::uint8_t>(stun_constants::attr_xor_mapped_address & 0xFF);
    response[offset++] = 0x00;
    response[offset++] = 0x08;
    response[offset++] = 0x00;
    response[offset++] = 0x01;

    const std::uint16_t xor_port = client_port ^ static_cast<std::uint16_t>(cookie >> 16);
    response[offset++] = static_cast<std::uint8_t>((xor_port >> 8) & 0xFF);
    response[offset++] = static_cast<std::uint8_t>(xor_port & 0xFF);

    const std::uint32_t xor_ip = client_ip.to_uint() ^ cookie;
    response[offset++] = static_cast<std::uint8_t>((xor_ip >> 24) & 0xFF);
    response[offset++] = static_cast<std::uint8_t>((xor_ip >> 16) & 0xFF);
    response[offset++] = static_cast<std::uint8_t>((xor_ip >> 8) & 0xFF);
    response[offset++] = static_cast<std::uint8_t>(xor_ip & 0xFF);

    return response;
}

stun_io make_mock_stun_io(std::vector<std::uint8_t> response_packet,
                          bool fail_send = false,
                          bool empty_response = false)
{
    stun_io io;
    io.send_to = [fail_send](std::span<const std::uint8_t>, const asio::ip::udp::endpoint &) -> asio::awaitable<void>
    {
        if (fail_send)
            throw std::system_error(std::make_error_code(std::errc::connection_refused));
        co_return;
    };
    io.receive_with_timeout = [response_packet, empty_response](std::chrono::milliseconds) -> asio::awaitable<std::optional<std::vector<std::uint8_t>>>
    {
        (void)empty_response;
        if (empty_response)
            co_return std::nullopt;
        co_return response_packet;
    };
    io.cancel_receive = []() {};
    io.local_endpoint = []() -> asio::ip::udp::endpoint
    { return asio::ip::udp::endpoint{asio::ip::address_v4::loopback(), 12345}; };
    return io;
}

template <typename Awaitable>
auto run_coro(asio::io_context &io_context, Awaitable &&awaitable)
{
    io_context.restart();
    auto future = asio::co_spawn(io_context, std::forward<Awaitable>(awaitable), asio::use_future);
    io_context.run();
    return future.get();
}

} // namespace

TEST(StunDiscoveryTest, DiscoverPublicAddressViaMockIo)
{
    asio::io_context io_context;

    const auto trans_id = stun_utils::generate_transaction_id();
    auto response = make_binding_response(trans_id, asio::ip::address_v4::loopback(), 4242);

    auto io = make_mock_stun_io(std::move(response));
    const std::vector servers{stun_server_endpoint{"127.0.0.1", 3478}};

    const auto result = run_coro(io_context, stun_discovery::discover_public_address(io, io_context, servers, 500ms));

    EXPECT_TRUE(result.success);
    EXPECT_TRUE(result.public_addr.is_valid());
    EXPECT_EQ(result.public_addr.address, asio::ip::address_v4::loopback());
    EXPECT_EQ(result.public_addr.port, 4242u);
}

TEST(StunDiscoveryTest, DiscoverPublicAddressFailsWhenNoResponse)
{
    asio::io_context io_context;

    auto io = make_mock_stun_io({}, false, true);
    const std::vector servers{stun_server_endpoint{"127.0.0.1", 3478}};

    const auto result = run_coro(io_context, stun_discovery::discover_public_address(io, io_context, servers, 100ms));

    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.error_message.empty());
}

TEST(StunDiscoveryTest, TryServersWithTimingUsesSecondServer)
{
    asio::io_context io_context;

    const auto trans_id = stun_utils::generate_transaction_id();
    auto response = make_binding_response(trans_id, asio::ip::make_address_v4("203.0.113.1"), 9999);

    int attempts = 0;
    auto io = make_mock_stun_io(std::move(response));
    io.send_to = [&attempts](std::span<const std::uint8_t>, const asio::ip::udp::endpoint &) -> asio::awaitable<void>
    {
        ++attempts;
        if (attempts == 1)
            throw std::system_error(std::make_error_code(std::errc::connection_refused));
        co_return;
    };

    const std::vector servers{
        stun_server_endpoint{"127.0.0.1", 3478},
        stun_server_endpoint{"127.0.0.1", 3479},
    };

    const auto result = run_coro(io_context, stun_discovery::discover_public_address(io, io_context, servers, 500ms));

    EXPECT_TRUE(result.success);
    EXPECT_EQ(attempts, 2);
    EXPECT_EQ(result.public_addr.address, asio::ip::make_address_v4("203.0.113.1"));
}

TEST(StunDiscoveryTest, MakeSocketStunIoRoundTripWithMockServer)
{
    asio::io_context io_context;

    asio::ip::udp::socket server_socket{io_context, asio::ip::udp::endpoint{asio::ip::udp::v4(), 0}};
    const auto server_port = server_socket.local_endpoint().port();

    asio::ip::udp::socket client_socket{io_context, asio::ip::udp::endpoint{asio::ip::udp::v4(), 0}};
    auto io = make_socket_stun_io(client_socket, io_context);

    std::array<std::uint8_t, 1500> request_buf{};
    asio::ip::udp::endpoint remote;

    asio::co_spawn(
        io_context,
        [&]() -> asio::awaitable<void>
    {
        const std::size_t n = co_await server_socket.async_receive_from(
            asio::buffer(request_buf), remote, asio::use_awaitable);
        if (n < stun_constants::header_size)
            co_return;

        const auto trans_id = *stun_utils::extract_transaction_id(std::span{request_buf.data(), n});
        const auto response = make_binding_response(
            trans_id,
            remote.address().to_v4(),
            remote.port());

        co_await server_socket.async_send_to(
            asio::buffer(response), remote, asio::use_awaitable);
    },
        asio::detached);

    const std::vector servers{stun_server_endpoint{"127.0.0.1", server_port}};
    const auto result = run_coro(
        io_context,
        stun_discovery::discover_public_address(io, io_context, servers, 2000ms));

    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.public_addr.port, client_socket.local_endpoint().port());
}
