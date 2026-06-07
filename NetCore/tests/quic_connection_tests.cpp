// Copyright (c) 2026- Charlie Vigue. All rights reserved.
//
// clv::quic Connection construction tests — Phase 1 Step 4. Verifies
// that server and client Connection objects can be built against
// TlsContexts, ngtcp2_conn pointers are valid, and destruction is
// clean (no leaks under ASAN). The actual handshake exchange lands in
// Step 5 once the read/write drive exists.

#include "quic/connection.h"
#include "quic/tls_context.h"

#include <gtest/gtest.h>

#include <asio/ip/udp.hpp>

#include <filesystem>
#include <memory>

namespace {

const std::filesystem::path kCert{"cert.pem"};
const std::filesystem::path kKey{"pvtkey.pem"};

asio::ip::udp::endpoint LoopbackEp(std::uint16_t port)
{
    return {asio::ip::address_v4::loopback(), port};
}

TEST(Quic2Connection, RandomConnectionIdLength)
{
    auto cid = clv::quic::MakeRandomConnectionId(8);
    EXPECT_EQ(cid.len, 8u);
    EXPECT_THROW(clv::quic::MakeRandomConnectionId(0), std::invalid_argument);
    EXPECT_THROW(clv::quic::MakeRandomConnectionId(21), std::invalid_argument);
}

TEST(Quic2Connection, ServerConstructs)
{
    auto tls = clv::quic::TlsContext::MakeServer(kCert, kKey, {"clv-mesh/1"});
    auto dcid = clv::quic::MakeRandomConnectionId(8);
    auto scid = clv::quic::MakeRandomConnectionId(8);

    auto conn = clv::quic::Connection::MakeServer(tls, dcid, scid, LoopbackEp(12000), LoopbackEp(12001));
    ASSERT_NE(conn, nullptr);
    EXPECT_NE(conn->native_conn(), nullptr);
    EXPECT_FALSE(conn->handshake_completed());
    EXPECT_EQ(conn->local_endpoint().port(), 12000);
    EXPECT_EQ(conn->remote_endpoint().port(), 12001);
}

TEST(Quic2Connection, ClientConstructs)
{
    auto tls = clv::quic::TlsContext::MakeClient({"clv-mesh/1"});
    auto conn = clv::quic::Connection::MakeClient(tls, LoopbackEp(13000), LoopbackEp(13001),
                                                  /*server_name=*/"localhost");
    ASSERT_NE(conn, nullptr);
    EXPECT_NE(conn->native_conn(), nullptr);
    EXPECT_FALSE(conn->handshake_completed());
}

TEST(Quic2Connection, RoleMismatchThrows)
{
    auto server_tls = clv::quic::TlsContext::MakeServer(kCert, kKey, {"clv-mesh/1"});
    EXPECT_THROW(
        clv::quic::Connection::MakeClient(server_tls, LoopbackEp(0), LoopbackEp(0)),
        std::invalid_argument);

    auto client_tls = clv::quic::TlsContext::MakeClient({"clv-mesh/1"});
    auto dcid = clv::quic::MakeRandomConnectionId(8);
    auto scid = clv::quic::MakeRandomConnectionId(8);
    EXPECT_THROW(
        clv::quic::Connection::MakeServer(client_tls, dcid, scid, LoopbackEp(0), LoopbackEp(0)),
        std::invalid_argument);
}

// Exit-gate test for Phase 1: two Connection objects must complete the
// TLS+QUIC handshake when datagrams are shuttled between them. No
// asio, no sockets — just synchronous read_packet/write_to in a loop.
// This isolates the ngtcp2 + quictls integration from the I/O layer.
TEST(Quic2Connection, HandshakeExchange)
{
    auto server_tls = clv::quic::TlsContext::MakeServer(kCert, kKey, {"clv-mesh/1"});
    auto client_tls = clv::quic::TlsContext::MakeClient({"clv-mesh/1"});

    const auto client_ep = LoopbackEp(40001);
    const auto server_ep = LoopbackEp(40002);

    auto client = clv::quic::Connection::MakeClient(client_tls, client_ep, server_ep,
                                                    /*server_name=*/"localhost");

    // Drive one client write to produce the first Initial datagram, then
    // peek at it to learn the CIDs the server needs.
    std::vector<std::vector<std::uint8_t>> client_to_server;
    std::vector<std::vector<std::uint8_t>> server_to_client;

    auto client_send = [&](std::span<const std::uint8_t> pkt,
                           const asio::ip::udp::endpoint &)
    {
        client_to_server.emplace_back(pkt.begin(), pkt.end());
    };
    auto server_send = [&](std::span<const std::uint8_t> pkt,
                           const asio::ip::udp::endpoint &)
    {
        server_to_client.emplace_back(pkt.begin(), pkt.end());
    };

    ASSERT_EQ(client->write_to(client_send), 0);
    ASSERT_FALSE(client_to_server.empty()) << "client must emit at least one Initial";

    auto cids = clv::quic::DecodePacketCids(client_to_server.front());
    auto server = clv::quic::Connection::MakeServer(server_tls, cids.dcid, cids.scid, server_ep, client_ep);

    // Pump datagrams back and forth until both sides report
    // handshake_completed(). Cap iterations to avoid infinite loops
    // when something has gone wrong.
    for (int round = 0; round < 16; ++round)
    {
        // Drain client→server queue into server.
        std::vector<std::vector<std::uint8_t>> in = std::move(client_to_server);
        client_to_server.clear();
        for (auto &pkt : in)
        {
            ASSERT_EQ(server->read_packet(pkt, client_ep), 0)
                << "server read_packet failed on round " << round;
        }
        ASSERT_EQ(server->write_to(server_send), 0);

        // Drain server→client queue into client.
        in = std::move(server_to_client);
        server_to_client.clear();
        for (auto &pkt : in)
        {
            ASSERT_EQ(client->read_packet(pkt, server_ep), 0)
                << "client read_packet failed on round " << round;
        }
        ASSERT_EQ(client->write_to(client_send), 0);

        if (client->handshake_completed() && server->handshake_completed())
        {
            break;
        }
    }

    EXPECT_TRUE(client->handshake_completed());
    EXPECT_TRUE(server->handshake_completed());
}

// Phase 1 exit gate: two peers complete a handshake AND exchange a
// stream payload. After the handshake, the client opens a bidi
// stream, writes a payload, and the server's stream-data callback
// receives the same bytes intact.
TEST(Quic2Connection, StreamPayloadRoundTrip)
{
    auto server_tls = clv::quic::TlsContext::MakeServer(kCert, kKey, {"clv-mesh/1"});
    auto client_tls = clv::quic::TlsContext::MakeClient({"clv-mesh/1"});

    const auto client_ep = LoopbackEp(40101);
    const auto server_ep = LoopbackEp(40102);

    auto client = clv::quic::Connection::MakeClient(client_tls, client_ep, server_ep,
                                                    /*server_name=*/"localhost");

    std::vector<std::vector<std::uint8_t>> c2s;
    std::vector<std::vector<std::uint8_t>> s2c;
    auto client_send = [&](std::span<const std::uint8_t> p,
                           const asio::ip::udp::endpoint &)
    {
        c2s.emplace_back(p.begin(), p.end());
    };
    auto server_send = [&](std::span<const std::uint8_t> p,
                           const asio::ip::udp::endpoint &)
    {
        s2c.emplace_back(p.begin(), p.end());
    };

    ASSERT_EQ(client->write_to(client_send), 0);
    ASSERT_FALSE(c2s.empty());

    auto cids = clv::quic::DecodePacketCids(c2s.front());
    auto server = clv::quic::Connection::MakeServer(server_tls, cids.dcid, cids.scid, server_ep, client_ep);

    std::vector<std::uint8_t> received;
    bool received_fin = false;
    server->set_stream_data_cb(
        [&](std::int64_t /*stream_id*/, std::span<const std::uint8_t> data, bool fin)
    {
        received.insert(received.end(), data.begin(), data.end());
        received_fin = fin;
    });

    auto pump_one_round = [&]()
    {
        std::vector<std::vector<std::uint8_t>> in = std::move(c2s);
        c2s.clear();
        for (auto &pkt : in)
        {
            ASSERT_EQ(server->read_packet(pkt, client_ep), 0);
        }
        ASSERT_EQ(server->write_to(server_send), 0);

        in = std::move(s2c);
        s2c.clear();
        for (auto &pkt : in)
        {
            ASSERT_EQ(client->read_packet(pkt, server_ep), 0);
        }
        ASSERT_EQ(client->write_to(client_send), 0);
    };

    // Complete the handshake.
    for (int round = 0; round < 16; ++round)
    {
        pump_one_round();
        if (client->handshake_completed() && server->handshake_completed())
        {
            break;
        }
    }
    ASSERT_TRUE(client->handshake_completed());
    ASSERT_TRUE(server->handshake_completed());

    // Open a bidi stream client-side and write the payload + FIN.
    std::int64_t stream_id = -1;
    ASSERT_EQ(client->open_bidi_stream(stream_id), 0);
    ASSERT_GE(stream_id, 0);

    const std::string payload_str = "hello, clv::quic mesh peer";
    std::span<const std::uint8_t> payload(
        reinterpret_cast<const std::uint8_t *>(payload_str.data()), payload_str.size());
    ASSERT_EQ(client->write_stream(stream_id, payload, /*fin=*/true, client_send), 0);

    // Drain until the server has received the full payload + FIN.
    for (int round = 0; round < 16 && !received_fin; ++round)
    {
        pump_one_round();
    }

    EXPECT_TRUE(received_fin);
    EXPECT_EQ(std::string(received.begin(), received.end()), payload_str);
}

// Phase 1 Step 5b — expiry timer and SCID enumeration. Validates that
// a freshly constructed connection has a finite expiry (idle timeout
// is armed at construction) and that ngtcp2 exposes at least one
// active SCID matching the one we supplied at construction time.
TEST(Quic2Connection, ExpiryAndScids)
{
    auto server_tls = clv::quic::TlsContext::MakeServer(kCert, kKey, {"clv-mesh/1"});
    auto client_tls = clv::quic::TlsContext::MakeClient({"clv-mesh/1"});

    auto client = clv::quic::Connection::MakeClient(client_tls, LoopbackEp(40201), LoopbackEp(40202));

    // Idle timeout is armed at construction; expiry must be finite.
    auto exp = client->expiry();
    EXPECT_LT(exp, std::chrono::steady_clock::time_point::max());

    // handle_expiry on a not-yet-fired deadline is a no-op (0).
    EXPECT_EQ(client->handle_expiry(), 0);

    // Client advertises at least one SCID (its initial local SCID).
    auto scids = client->local_scids();
    EXPECT_GE(scids.size(), 1u);
    for (auto const &id : scids)
    {
        EXPECT_GT(id.len, 0u);
        EXPECT_LE(id.len, clv::quic::ConnectionId::kMaxLen);
    }
}

} // namespace
