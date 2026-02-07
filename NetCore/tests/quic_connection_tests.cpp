// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "quic/quic_connection.h"

#include <gtest/gtest.h>

#include <chrono>
#include <vector>

using namespace clv::quic;
using namespace std::chrono_literals;

// ============================================================================
// Test Helpers
// ============================================================================

namespace {

ConnectionId MakeTestConnectionId(std::uint8_t value)
{
    ConnectionId cid;
    cid.length = 8;
    cid.data.fill(value);
    return cid;
}

asio::ip::udp::endpoint MakeTestEndpoint()
{
    return asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 4433);
}

} // anonymous namespace

// ============================================================================
// Factory Method Tests
// ============================================================================

TEST(QuicConnectionTests, CreateServer_ValidInputs)
{
    auto local_cid = MakeTestConnectionId(0x01);
    auto remote_cid = MakeTestConnectionId(0x02);
    auto remote_ep = MakeTestEndpoint();

    auto result = QuicConnection::CreateServer(local_cid, remote_cid, remote_ep);

    ASSERT_TRUE(result.has_value());

    const auto &conn = *result;
    EXPECT_EQ(conn.local_id, local_cid);
    EXPECT_EQ(conn.remote_id, remote_cid);
    EXPECT_EQ(conn.remote_endpoint, remote_ep);
    EXPECT_TRUE(conn.is_server);
    EXPECT_EQ(conn.state, ConnectionState::Initial);
    EXPECT_TRUE(conn.crypto.has_value());
    EXPECT_TRUE(conn.reliability.has_value());
    EXPECT_TRUE(conn.congestion.has_value());
    EXPECT_TRUE(conn.loss_detector.has_value());
}

TEST(QuicConnectionTests, CreateClient_ValidInputs)
{
    auto local_cid = MakeTestConnectionId(0x01);
    auto remote_ep = MakeTestEndpoint();

    auto result = QuicConnection::CreateClient(local_cid, remote_ep);

    ASSERT_TRUE(result.has_value());

    const auto &conn = *result;
    EXPECT_EQ(conn.local_id, local_cid);
    EXPECT_EQ(conn.remote_endpoint, remote_ep);
    EXPECT_FALSE(conn.is_server);
    EXPECT_EQ(conn.state, ConnectionState::Initial);
    EXPECT_TRUE(conn.crypto.has_value());
    EXPECT_TRUE(conn.reliability.has_value());
    EXPECT_TRUE(conn.congestion.has_value());
    EXPECT_TRUE(conn.loss_detector.has_value());
}

TEST(QuicConnectionTests, CreateServer_EmptyConnectionId)
{
    ConnectionId empty_cid{}; // length = 0
    auto remote_cid = MakeTestConnectionId(0x02);
    auto remote_ep = MakeTestEndpoint();

    auto result = QuicConnection::CreateServer(empty_cid, remote_cid, remote_ep);

    // Should fail because crypto can't derive keys from empty CID
    EXPECT_FALSE(result.has_value());
}

TEST(QuicConnectionTests, CreateClient_EmptyConnectionId)
{
    ConnectionId empty_cid{};
    auto remote_ep = MakeTestEndpoint();

    auto result = QuicConnection::CreateClient(empty_cid, remote_ep);

    // Should fail because crypto can't derive keys from empty CID
    EXPECT_FALSE(result.has_value());
}

// ============================================================================
// State Management Tests
// ============================================================================

TEST(QuicConnectionTests, InitialState)
{
    auto result = QuicConnection::CreateServer(
        MakeTestConnectionId(0x01),
        MakeTestConnectionId(0x02),
        MakeTestEndpoint());

    ASSERT_TRUE(result.has_value());
    auto &conn = *result;

    EXPECT_EQ(conn.state, ConnectionState::Initial);
    EXPECT_FALSE(conn.IsHandshakeComplete());
    EXPECT_FALSE(conn.CanSendData());
}

TEST(QuicConnectionTests, SetState_ToHandshake)
{
    auto result = QuicConnection::CreateServer(
        MakeTestConnectionId(0x01),
        MakeTestConnectionId(0x02),
        MakeTestEndpoint());

    ASSERT_TRUE(result.has_value());
    auto &conn = *result;

    conn.SetState(ConnectionState::Handshake);

    EXPECT_EQ(conn.state, ConnectionState::Handshake);
    EXPECT_FALSE(conn.IsHandshakeComplete());
    EXPECT_FALSE(conn.CanSendData());
}

TEST(QuicConnectionTests, SetState_ToActive)
{
    auto result = QuicConnection::CreateServer(
        MakeTestConnectionId(0x01),
        MakeTestConnectionId(0x02),
        MakeTestEndpoint());

    ASSERT_TRUE(result.has_value());
    auto &conn = *result;

    conn.SetState(ConnectionState::Active);

    EXPECT_EQ(conn.state, ConnectionState::Active);
    EXPECT_TRUE(conn.IsHandshakeComplete());
    EXPECT_TRUE(conn.CanSendData());
}

TEST(QuicConnectionTests, StateProgression_FullLifecycle)
{
    auto result = QuicConnection::CreateServer(
        MakeTestConnectionId(0x01),
        MakeTestConnectionId(0x02),
        MakeTestEndpoint());

    ASSERT_TRUE(result.has_value());
    auto &conn = *result;

    // Initial → Handshake
    EXPECT_EQ(conn.state, ConnectionState::Initial);
    conn.SetState(ConnectionState::Handshake);
    EXPECT_EQ(conn.state, ConnectionState::Handshake);

    // Handshake → Active
    conn.SetState(ConnectionState::Active);
    EXPECT_EQ(conn.state, ConnectionState::Active);
    EXPECT_TRUE(conn.IsHandshakeComplete());

    // Active → Closing
    conn.SetState(ConnectionState::Closing);
    EXPECT_EQ(conn.state, ConnectionState::Closing);

    // Closing → Draining
    conn.SetState(ConnectionState::Draining);
    EXPECT_EQ(conn.state, ConnectionState::Draining);

    // Draining → Closed
    conn.SetState(ConnectionState::Closed);
    EXPECT_EQ(conn.state, ConnectionState::Closed);
}

// ============================================================================
// Stream Management Tests
// ============================================================================

TEST(QuicConnectionTests, OpenStream_BeforeHandshakeComplete)
{
    auto result = QuicConnection::CreateClient(
        MakeTestConnectionId(0x01),
        MakeTestEndpoint());

    ASSERT_TRUE(result.has_value());
    auto &conn = *result;

    // Try to open stream before connection is active
    auto stream_result = conn.OpenStream(true);

    EXPECT_FALSE(stream_result.has_value());
    EXPECT_EQ(stream_result.error(), std::errc::operation_not_permitted);
}

TEST(QuicConnectionTests, OpenStream_ClientBidirectional)
{
    auto result = QuicConnection::CreateClient(
        MakeTestConnectionId(0x01),
        MakeTestEndpoint());

    ASSERT_TRUE(result.has_value());
    auto &conn = *result;
    conn.SetState(ConnectionState::Active);

    // Client-initiated bidirectional stream should have ID 0, 4, 8, ...
    auto stream1 = conn.OpenStream(true);
    ASSERT_TRUE(stream1.has_value());
    EXPECT_EQ(*stream1, 0u);

    auto stream2 = conn.OpenStream(true);
    ASSERT_TRUE(stream2.has_value());
    EXPECT_EQ(*stream2, 4u);

    auto stream3 = conn.OpenStream(true);
    ASSERT_TRUE(stream3.has_value());
    EXPECT_EQ(*stream3, 8u);
}

TEST(QuicConnectionTests, OpenStream_ServerBidirectional)
{
    auto result = QuicConnection::CreateServer(
        MakeTestConnectionId(0x01),
        MakeTestConnectionId(0x02),
        MakeTestEndpoint());

    ASSERT_TRUE(result.has_value());
    auto &conn = *result;
    conn.SetState(ConnectionState::Active);

    // Server-initiated bidirectional stream should have ID 1, 5, 9, ...
    auto stream1 = conn.OpenStream(true);
    ASSERT_TRUE(stream1.has_value());
    EXPECT_EQ(*stream1, 1u);

    auto stream2 = conn.OpenStream(true);
    ASSERT_TRUE(stream2.has_value());
    EXPECT_EQ(*stream2, 5u);
}

TEST(QuicConnectionTests, OpenStream_ClientUnidirectional)
{
    auto result = QuicConnection::CreateClient(
        MakeTestConnectionId(0x01),
        MakeTestEndpoint());

    ASSERT_TRUE(result.has_value());
    auto &conn = *result;
    conn.SetState(ConnectionState::Active);

    // Client-initiated unidirectional stream should have ID 2, 6, 10, ...
    auto stream1 = conn.OpenStream(false);
    ASSERT_TRUE(stream1.has_value());
    EXPECT_EQ(*stream1, 2u);

    auto stream2 = conn.OpenStream(false);
    ASSERT_TRUE(stream2.has_value());
    EXPECT_EQ(*stream2, 6u);
}

TEST(QuicConnectionTests, OpenStream_ServerUnidirectional)
{
    auto result = QuicConnection::CreateServer(
        MakeTestConnectionId(0x01),
        MakeTestConnectionId(0x02),
        MakeTestEndpoint());

    ASSERT_TRUE(result.has_value());
    auto &conn = *result;
    conn.SetState(ConnectionState::Active);

    // Server-initiated unidirectional stream should have ID 3, 7, 11, ...
    auto stream1 = conn.OpenStream(false);
    ASSERT_TRUE(stream1.has_value());
    EXPECT_EQ(*stream1, 3u);

    auto stream2 = conn.OpenStream(false);
    ASSERT_TRUE(stream2.has_value());
    EXPECT_EQ(*stream2, 7u);
}

TEST(QuicConnectionTests, SendStreamData_Success)
{
    auto result = QuicConnection::CreateClient(
        MakeTestConnectionId(0x01),
        MakeTestEndpoint());

    ASSERT_TRUE(result.has_value());
    auto &conn = *result;
    conn.SetState(ConnectionState::Active);

    auto stream_id = conn.OpenStream(true);
    ASSERT_TRUE(stream_id.has_value());

    std::vector<std::uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    auto send_result = conn.SendStreamData(*stream_id, data);

    EXPECT_FALSE(send_result.has_value()); // Success = nullopt

    // Verify data was queued
    auto it = conn.streams.find(*stream_id);
    ASSERT_NE(it, conn.streams.end());
    EXPECT_EQ(it->second->send_buffer, data);
}

TEST(QuicConnectionTests, SendStreamData_InvalidStream)
{
    auto result = QuicConnection::CreateClient(
        MakeTestConnectionId(0x01),
        MakeTestEndpoint());

    ASSERT_TRUE(result.has_value());
    auto &conn = *result;
    conn.SetState(ConnectionState::Active);

    std::vector<std::uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    auto send_result = conn.SendStreamData(999, data); // Non-existent stream

    EXPECT_TRUE(send_result.has_value());
    EXPECT_EQ(*send_result, std::errc::invalid_argument);
}

TEST(QuicConnectionTests, SendStreamData_BeforeActive)
{
    auto result = QuicConnection::CreateClient(
        MakeTestConnectionId(0x01),
        MakeTestEndpoint());

    ASSERT_TRUE(result.has_value());
    auto &conn = *result;

    std::vector<std::uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    auto send_result = conn.SendStreamData(0, data);

    EXPECT_TRUE(send_result.has_value());
    EXPECT_EQ(*send_result, std::errc::operation_not_permitted);
}

TEST(QuicConnectionTests, CloseStream)
{
    auto result = QuicConnection::CreateClient(
        MakeTestConnectionId(0x01),
        MakeTestEndpoint());

    ASSERT_TRUE(result.has_value());
    auto &conn = *result;
    conn.SetState(ConnectionState::Active);

    auto stream_id = conn.OpenStream(true);
    ASSERT_TRUE(stream_id.has_value());

    conn.CloseStream(*stream_id);

    // Verify FIN was marked
    auto it = conn.streams.find(*stream_id);
    ASSERT_NE(it, conn.streams.end());
    EXPECT_TRUE(it->second->fin_sent);
}

// ============================================================================
// Packet Processing Tests (Basic)
// ============================================================================

TEST(QuicConnectionTests, ProcessPacket_UpdatesActivity)
{
    auto result = QuicConnection::CreateServer(
        MakeTestConnectionId(0x01),
        MakeTestConnectionId(0x02),
        MakeTestEndpoint());

    ASSERT_TRUE(result.has_value());
    auto &conn = *result;

    auto before = conn.last_activity;

    // Small delay to ensure time progresses
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    std::vector<std::uint8_t> dummy_packet = {0x01, 0x02, 0x03};
    conn.ProcessPacket(dummy_packet);

    EXPECT_GT(conn.last_activity, before);
}

TEST(QuicConnectionTests, ProcessPacket_NoCryptoFails)
{
    QuicConnection conn;
    conn.local_id = MakeTestConnectionId(0x01);
    // Don't initialize crypto

    std::vector<std::uint8_t> dummy_packet = {0x01, 0x02, 0x03};
    auto result = conn.ProcessPacket(dummy_packet);

    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result, std::errc::invalid_argument);
}

// ============================================================================
// Packet Generation Tests (Basic)
// ============================================================================

TEST(QuicConnectionTests, GeneratePackets_NoCryptoReturnsEmpty)
{
    QuicConnection conn;
    conn.local_id = MakeTestConnectionId(0x01);
    // Don't initialize crypto

    auto packets = conn.GeneratePackets();

    EXPECT_TRUE(packets.empty());
}

TEST(QuicConnectionTests, GeneratePackets_InitialState)
{
    auto result = QuicConnection::CreateClient(
        MakeTestConnectionId(0x01),
        MakeTestEndpoint());

    ASSERT_TRUE(result.has_value());
    auto &conn = *result;

    auto packets = conn.GeneratePackets();

    // TODO: When full implementation is done, this should generate Initial packets
    // For now, returns empty (placeholder implementation)
    EXPECT_TRUE(packets.empty());
}

// ============================================================================
// Integration Tests
// ============================================================================

TEST(QuicConnectionTests, ServerClientDifferentStreamIds)
{
    auto server = QuicConnection::CreateServer(
        MakeTestConnectionId(0x01),
        MakeTestConnectionId(0x02),
        MakeTestEndpoint());

    auto client = QuicConnection::CreateClient(
        MakeTestConnectionId(0x02),
        MakeTestEndpoint());

    ASSERT_TRUE(server.has_value());
    ASSERT_TRUE(client.has_value());

    server->SetState(ConnectionState::Active);
    client->SetState(ConnectionState::Active);

    // Server and client should allocate different stream IDs
    auto server_stream = server->OpenStream(true);
    auto client_stream = client->OpenStream(true);

    ASSERT_TRUE(server_stream.has_value());
    ASSERT_TRUE(client_stream.has_value());

    EXPECT_NE(*server_stream, *client_stream);
    EXPECT_EQ(*server_stream, 1u); // Server bidirectional
    EXPECT_EQ(*client_stream, 0u); // Client bidirectional
}

TEST(QuicConnectionTests, MultipleStreams_IndependentBuffers)
{
    auto result = QuicConnection::CreateClient(
        MakeTestConnectionId(0x01),
        MakeTestEndpoint());

    ASSERT_TRUE(result.has_value());
    auto &conn = *result;
    conn.SetState(ConnectionState::Active);

    // Open multiple streams
    auto stream1 = conn.OpenStream(true);
    auto stream2 = conn.OpenStream(true);
    auto stream3 = conn.OpenStream(true);

    ASSERT_TRUE(stream1.has_value());
    ASSERT_TRUE(stream2.has_value());
    ASSERT_TRUE(stream3.has_value());

    // Send different data on each stream
    std::vector<std::uint8_t> data1 = {0x01, 0x01, 0x01};
    std::vector<std::uint8_t> data2 = {0x02, 0x02, 0x02};
    std::vector<std::uint8_t> data3 = {0x03, 0x03, 0x03};

    conn.SendStreamData(*stream1, data1);
    conn.SendStreamData(*stream2, data2);
    conn.SendStreamData(*stream3, data3);

    // Verify each stream has its own data
    EXPECT_EQ(conn.streams[*stream1]->send_buffer, data1);
    EXPECT_EQ(conn.streams[*stream2]->send_buffer, data2);
    EXPECT_EQ(conn.streams[*stream3]->send_buffer, data3);
}
