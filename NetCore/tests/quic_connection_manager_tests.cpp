// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/io_context.hpp>
#include <asio/use_future.hpp>

#include "quic/quic_connection_manager.h"

using namespace clv::quic;
using namespace std::chrono_literals;

namespace {

// Helper: make a simple awaitable send function
inline auto MakeNoopSendFn()
{
    return [](std::vector<std::uint8_t>, asio::ip::udp::endpoint) -> asio::awaitable<void>
    {
        co_return;
    };
}

// Helper: build a long-header packet with given DCID bytes
inline std::vector<std::uint8_t> MakeLongHeaderPacket(std::initializer_list<std::uint8_t> dcid)
{
    // flags(1) + version(4) + dcid_len(1) + dcid + scid_len(1) (no scid)
    std::vector<std::uint8_t> pkt;
    pkt.reserve(1 + 4 + 1 + dcid.size() + 1);
    pkt.push_back(0xC0); // Long header bit set
    pkt.push_back(0x00);
    pkt.push_back(0x00);
    pkt.push_back(0x00);
    pkt.push_back(0x01); // version
    pkt.push_back(static_cast<std::uint8_t>(dcid.size()));
    pkt.insert(pkt.end(), dcid.begin(), dcid.end());
    pkt.push_back(0x00); // scid len = 0
    return pkt;
}

// Helper: build a short-header packet with given DCID bytes (flags + dcid)
inline std::vector<std::uint8_t> MakeShortHeaderPacket(std::initializer_list<std::uint8_t> dcid)
{
    std::vector<std::uint8_t> pkt;
    pkt.reserve(1 + dcid.size());
    pkt.push_back(0x40); // short header pattern (0b0100....)
    pkt.insert(pkt.end(), dcid.begin(), dcid.end());
    return pkt;
}

TEST(QuicConnectionManagerTests, RoutesLongHeaderCreatesConnection)
{
    asio::io_context io;
    QuicConnectionManager mgr(io, MakeNoopSendFn());

    const auto packet = MakeLongHeaderPacket({0xAA, 0xBB, 0xCC, 0xDD});
    asio::ip::udp::endpoint remote(asio::ip::make_address("127.0.0.1"), 9001);

    auto fut = asio::co_spawn(io, mgr.RoutePacket(packet, remote), asio::use_future);
    io.run();
    fut.get();

    ConnectionId cid{};
    cid.length = 4;
    cid.data[0] = 0xAA;
    cid.data[1] = 0xBB;
    cid.data[2] = 0xCC;
    cid.data[3] = 0xDD;

    // A subsequent AcceptConnection should retrieve the same connection and preserve endpoint
    auto &conn = mgr.AcceptConnection(cid, remote);
    EXPECT_EQ(conn.local_id.length, 4);
    EXPECT_EQ(conn.local_id.data[0], 0xAA);
    EXPECT_EQ(conn.remote_endpoint, remote);
    EXPECT_GE(conn.last_activity, std::chrono::steady_clock::now() - 2s);
}

TEST(QuicConnectionManagerTests, RoutesShortHeaderMatchesExistingConnection)
{
    asio::io_context io;
    QuicConnectionManager mgr(io, MakeNoopSendFn());

    ConnectionId cid{};
    cid.length = 3;
    cid.data[0] = 0x11;
    cid.data[1] = 0x22;
    cid.data[2] = 0x33;

    asio::ip::udp::endpoint remote(asio::ip::make_address("127.0.0.1"), 9002);
    auto &existing = mgr.AcceptConnection(cid, remote);
    ASSERT_NE(&existing, nullptr);
    const auto before = existing.last_activity;

    const auto packet = MakeShortHeaderPacket({0x11, 0x22, 0x33});
    auto fut = asio::co_spawn(io, mgr.RoutePacket(packet, remote), asio::use_future);
    io.run();
    fut.get();

    auto &conn = mgr.AcceptConnection(cid, remote);
    ASSERT_EQ(&conn, &existing); // Should reuse same connection
    EXPECT_GT(conn.last_activity, before);
}

} // namespace
