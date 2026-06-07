// Copyright (c) 2026- Charlie Vigue. All rights reserved.
//
// clv::quic Endpoint smoke tests — Phase 1 scaffolding. Verifies the
// module is reachable and a UDP-bound endpoint can be constructed and
// torn down without leaks. Real handshake + stream tests land as the
// protocol wiring fills in.

#include "quic/endpoint.h"

#include "quic/connection.h"
#include "quic/tls_context.h"

#include <gtest/gtest.h>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string_view>
#include <vector>

namespace {

TEST(Quic2EndpointSmoke, BindsEphemeralPort)
{
    asio::io_context io;
    asio::ip::udp::endpoint local(asio::ip::udp::v4(), 0);

    clv::quic::Endpoint ep(io, local);
    const auto bound = ep.local_endpoint();

    EXPECT_NE(bound.port(), 0) << "Ephemeral port should resolve to a non-zero value after bind";
    EXPECT_EQ(bound.address(), asio::ip::address_v4::any());
}

TEST(Quic2EndpointSmoke, StartStopIdempotent)
{
    asio::io_context io;
    clv::quic::Endpoint ep(io, asio::ip::udp::endpoint(asio::ip::udp::v4(), 0));

    ep.start();
    ep.start(); // second call should be a no-op
    ep.stop();
    ep.stop(); // second call should be a no-op
    SUCCEED();
}

// Exercises the full datagram I/O path: sender Endpoint A transmits to
// receiver Endpoint B's bound port; B's PacketHandler captures the
// payload. Confirms the receive coroutine wakes, the buffer is sized
// correctly, and the peer endpoint is populated.
TEST(Quic2EndpointSmoke, RoundTripDatagram)
{
    asio::io_context io;

    clv::quic::Endpoint a(io, asio::ip::udp::endpoint(asio::ip::address_v4::loopback(), 0));
    clv::quic::Endpoint b(io, asio::ip::udp::endpoint(asio::ip::address_v4::loopback(), 0));

    constexpr std::string_view kPayload{"hello-quic2"};
    std::vector<std::uint8_t> received;
    asio::ip::udp::endpoint received_from;
    std::atomic<bool> got_packet{false};

    b.set_packet_handler(
        [&](std::span<const std::uint8_t> data, const asio::ip::udp::endpoint &from)
    {
        received.assign(data.begin(), data.end());
        received_from = from;
        got_packet.store(true, std::memory_order_release);
    });
    b.start();

    std::vector<std::uint8_t> datagram(kPayload.begin(), kPayload.end());
    asio::co_spawn(io, a.send(datagram, b.local_endpoint()), asio::detached);

    // Pump the io_context until the handler fires or a deadline elapses.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!got_packet.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline)
    {
        io.run_for(std::chrono::milliseconds(10));
    }

    b.stop();
    io.run_for(std::chrono::milliseconds(50));

    ASSERT_TRUE(got_packet.load()) << "Receive handler never fired";
    EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(received.data()), received.size()),
              kPayload);
    EXPECT_EQ(received_from.address(), a.local_endpoint().address());
    EXPECT_EQ(received_from.port(), a.local_endpoint().port());
}

// End-to-end: two Endpoints exchange a full QUIC handshake over real
// UDP sockets, with the Endpoint demuxing inbound packets to the
// matching Connection by DCID. The server-side accept is handled by
// the fallback PacketHandler — it inspects the first long-header
// packet, builds a server Connection from the announced CIDs, and
// registers it for subsequent short-header routing.
TEST(Quic2EndpointSmoke, HandshakeOverRealSocket)
{
    const std::filesystem::path kCert{"cert.pem"};
    const std::filesystem::path kKey{"pvtkey.pem"};

    asio::io_context io;

    clv::quic::Endpoint client_ep(io, asio::ip::udp::endpoint(asio::ip::address_v4::loopback(), 0));
    clv::quic::Endpoint server_ep(io, asio::ip::udp::endpoint(asio::ip::address_v4::loopback(), 0));

    auto client_tls = clv::quic::TlsContext::MakeClient({"clv-mesh/1"});
    auto server_tls = clv::quic::TlsContext::MakeServer(kCert, kKey, {"clv-mesh/1"});

    auto client_conn = clv::quic::Connection::MakeClient(
        client_tls, client_ep.local_endpoint(), server_ep.local_endpoint(), /*server_name=*/"localhost");

    std::atomic<bool> client_done{false};
    std::atomic<bool> server_done{false};
    client_conn->set_handshake_complete_cb([&]
    { client_done.store(true, std::memory_order_release); });

    client_ep.register_connection(*client_conn);

    // Server-side accept: on the first inbound long-header packet,
    // decode CIDs, build a server Connection, register it for demux,
    // and feed the packet into it. Subsequent packets route directly
    // via Endpoint::Lookup.
    std::unique_ptr<clv::quic::Connection> server_conn;
    server_ep.set_packet_handler(
        [&](std::span<const std::uint8_t> data, const asio::ip::udp::endpoint &peer)
    {
        if (server_conn)
        {
            // Demux missed (e.g., reordered short-header before
            // SCID propagation). Feed directly.
            server_conn->read_packet(data, peer);
            return;
        }
        auto cids = clv::quic::DecodePacketCids(data);
        server_conn = clv::quic::Connection::MakeServer(
            server_tls, cids.dcid, cids.scid, server_ep.local_endpoint(), peer);
        server_conn->set_handshake_complete_cb(
            [&]
        { server_done.store(true, std::memory_order_release); });
        server_ep.register_connection(*server_conn);
        server_conn->read_packet(data, peer);
        server_conn->write_to(
            [&](std::span<const std::uint8_t> bytes, const asio::ip::udp::endpoint &dest)
        {
            std::vector<std::uint8_t> copy(bytes.begin(), bytes.end());
            asio::co_spawn(io, server_ep.send(std::move(copy), dest), asio::detached);
        });
    });

    server_ep.start();
    client_ep.start();

    // Kick the client: produce the first Initial and ship it.
    client_conn->write_to(
        [&](std::span<const std::uint8_t> bytes, const asio::ip::udp::endpoint &dest)
    {
        std::vector<std::uint8_t> copy(bytes.begin(), bytes.end());
        asio::co_spawn(io, client_ep.send(std::move(copy), dest), asio::detached);
    });

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while ((!client_done.load(std::memory_order_acquire) || !server_done.load(std::memory_order_acquire)) && std::chrono::steady_clock::now() < deadline)
    {
        io.run_for(std::chrono::milliseconds(10));
    }

    if (server_conn)
    {
        server_ep.unregister_connection(*server_conn);
    }
    client_ep.unregister_connection(*client_conn);
    server_ep.stop();
    client_ep.stop();
    io.run_for(std::chrono::milliseconds(50));

    EXPECT_TRUE(client_done.load()) << "Client handshake did not complete";
    EXPECT_TRUE(server_done.load()) << "Server handshake did not complete";
}

} // namespace
