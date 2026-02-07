// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>
#include <vector>

#include "quic/quic_frame.h"

using namespace clv::quic;

TEST(QuicFrameTests, ParsePaddingFrame)
{
    std::vector<std::uint8_t> data = {0x00, 0x00, 0x00}; // 3 padding bytes
    auto result = ParseFrame(data);
    ASSERT_TRUE(result.has_value());

    ASSERT_TRUE(std::holds_alternative<PaddingFrame>(result->first));
    const auto &frame = std::get<PaddingFrame>(result->first);
    EXPECT_EQ(frame.length, 3);
    EXPECT_EQ(result->second, 3); // Consumed all padding
}

TEST(QuicFrameTests, ParsePingFrame)
{
    std::vector<std::uint8_t> data = {0x01};
    auto result = ParseFrame(data);
    ASSERT_TRUE(result.has_value());

    ASSERT_TRUE(std::holds_alternative<PingFrame>(result->first));
    EXPECT_EQ(result->second, 1);
}

TEST(QuicFrameTests, ParseAckFrameSingleRange)
{
    std::vector<std::uint8_t> data;
    data.push_back(0x02); // ACK frame
    data.push_back(0x0A); // Largest Acknowledged = 10
    data.push_back(0x40); // ACK Delay = 100 µs (2-byte varint: 0x4064)
    data.push_back(0x64);
    data.push_back(0x00); // ACK Range Count = 0
    data.push_back(0x05); // First ACK Range = 5 (packets 5-10)

    auto result = ParseFrame(data);
    ASSERT_TRUE(result.has_value());

    ASSERT_TRUE(std::holds_alternative<AckFrame>(result->first));
    const auto &frame = std::get<AckFrame>(result->first);
    EXPECT_EQ(frame.largest_acknowledged, 10);
    EXPECT_EQ(frame.ack_delay, 100);
    EXPECT_EQ(frame.ranges.size(), 1);
    EXPECT_EQ(frame.ranges[0].first, 5);  // Start
    EXPECT_EQ(frame.ranges[0].second, 6); // Length (5-10 inclusive = 6 packets)
}

TEST(QuicFrameTests, ParseCryptoFrame)
{
    std::vector<std::uint8_t> data;
    data.push_back(0x06); // CRYPTO frame
    data.push_back(0x00); // Offset = 0
    data.push_back(0x05); // Length = 5
    data.push_back(0x48); // "Hello"
    data.push_back(0x65);
    data.push_back(0x6C);
    data.push_back(0x6C);
    data.push_back(0x6F);

    auto result = ParseFrame(data);
    ASSERT_TRUE(result.has_value());

    ASSERT_TRUE(std::holds_alternative<CryptoFrame>(result->first));
    const auto &frame = std::get<CryptoFrame>(result->first);
    EXPECT_EQ(frame.offset, 0);
    EXPECT_EQ(frame.data.size(), 5);
    EXPECT_EQ(frame.data[0], 'H');
    EXPECT_EQ(frame.data[4], 'o');
}

TEST(QuicFrameTests, ParseStreamFrameWithOffset)
{
    std::vector<std::uint8_t> data;
    data.push_back(0x0E); // STREAM frame: offset=1, length=1, fin=0
    data.push_back(0x04); // Stream ID = 4
    data.push_back(0x0A); // Offset = 10
    data.push_back(0x04); // Length = 4
    data.push_back(0x44); // "Data"
    data.push_back(0x61);
    data.push_back(0x74);
    data.push_back(0x61);

    auto result = ParseFrame(data);
    ASSERT_TRUE(result.has_value());

    ASSERT_TRUE(std::holds_alternative<StreamFrame>(result->first));
    const auto &frame = std::get<StreamFrame>(result->first);
    EXPECT_EQ(frame.stream_id, 4);
    EXPECT_EQ(frame.offset, 10);
    EXPECT_FALSE(frame.fin);
    EXPECT_EQ(frame.data.size(), 4);
}

TEST(QuicFrameTests, ParseStreamFrameWithFin)
{
    std::vector<std::uint8_t> data;
    data.push_back(0x09); // STREAM frame: offset=0, length=0, fin=1
    data.push_back(0x08); // Stream ID = 8
    // No explicit length, so remaining bytes are data
    data.push_back(0x46);
    data.push_back(0x49);
    data.push_back(0x4E);

    auto result = ParseFrame(data);
    ASSERT_TRUE(result.has_value());

    ASSERT_TRUE(std::holds_alternative<StreamFrame>(result->first));
    const auto &frame = std::get<StreamFrame>(result->first);
    EXPECT_EQ(frame.stream_id, 8);
    EXPECT_EQ(frame.offset, 0);
    EXPECT_TRUE(frame.fin);
    EXPECT_EQ(frame.data.size(), 3);
}

TEST(QuicFrameTests, ParseConnectionCloseFrame)
{
    std::vector<std::uint8_t> data;
    data.push_back(0x1C); // CONNECTION_CLOSE frame
    data.push_back(0x0A); // Error Code = 10
    data.push_back(0x02); // Frame Type = 2 (ACK)
    data.push_back(0x05); // Reason Length = 5
    data.push_back(0x45); // "Error"
    data.push_back(0x72);
    data.push_back(0x72);
    data.push_back(0x6F);
    data.push_back(0x72);

    auto result = ParseFrame(data);
    ASSERT_TRUE(result.has_value());

    ASSERT_TRUE(std::holds_alternative<ConnectionCloseFrame>(result->first));
    const auto &frame = std::get<ConnectionCloseFrame>(result->first);
    EXPECT_EQ(frame.error_code, 10);
    EXPECT_EQ(frame.frame_type, 2);
    EXPECT_EQ(frame.reason, "Error");
}

TEST(QuicFrameTests, ParseMaxDataFrame)
{
    std::vector<std::uint8_t> data;
    data.push_back(0x10); // MAX_DATA frame
    data.push_back(0x43); // Max Data = 1000 (2-byte varint: 0x43E8)
    data.push_back(0xE8);
    data.push_back(0x80); // Extra byte to verify we stop at right point

    auto result = ParseFrame(data);
    ASSERT_TRUE(result.has_value());

    ASSERT_TRUE(std::holds_alternative<MaxDataFrame>(result->first));
    const auto &frame = std::get<MaxDataFrame>(result->first);
    EXPECT_EQ(frame.max_data, 1000);
    EXPECT_EQ(result->second, 3); // Should have consumed 3 bytes
}

TEST(QuicFrameTests, ParseMaxStreamDataFrame)
{
    std::vector<std::uint8_t> data;
    data.push_back(0x11); // MAX_STREAM_DATA frame
    data.push_back(0x04); // Stream ID = 4
    data.push_back(0x47); // Max Stream Data = 2000 (2-byte varint: 0x47D0)
    data.push_back(0xD0);
    data.push_back(0x00);

    auto result = ParseFrame(data);
    ASSERT_TRUE(result.has_value());

    ASSERT_TRUE(std::holds_alternative<MaxStreamDataFrame>(result->first));
    const auto &frame = std::get<MaxStreamDataFrame>(result->first);
    EXPECT_EQ(frame.stream_id, 4);
    EXPECT_EQ(frame.max_stream_data, 2000);
}

TEST(QuicFrameTests, ParseResetStreamFrame)
{
    std::vector<std::uint8_t> data;
    data.push_back(0x04); // RESET_STREAM frame
    data.push_back(0x08); // Stream ID = 8
    data.push_back(0x0F); // Error Code = 15
    data.push_back(0x44); // Final Size = 1234 (2-byte varint: 0x44D2)
    data.push_back(0xD2);

    auto result = ParseFrame(data);
    ASSERT_TRUE(result.has_value());

    ASSERT_TRUE(std::holds_alternative<ResetStreamFrame>(result->first));
    const auto &frame = std::get<ResetStreamFrame>(result->first);
    EXPECT_EQ(frame.stream_id, 8);
    EXPECT_EQ(frame.error_code, 15);
    EXPECT_EQ(frame.final_size, 1234);
}

TEST(QuicFrameTests, ParseHandshakeDoneFrame)
{
    std::vector<std::uint8_t> data = {0x1E};
    auto result = ParseFrame(data);
    ASSERT_TRUE(result.has_value());

    ASSERT_TRUE(std::holds_alternative<HandshakeDoneFrame>(result->first));
    EXPECT_EQ(result->second, 1);
}

TEST(QuicFrameTests, SerializePingFrame)
{
    PingFrame frame;
    auto serialized = SerializeFrame(frame);
    EXPECT_EQ(serialized.size(), 1);
    EXPECT_EQ(serialized[0], 0x01);
}

TEST(QuicFrameTests, SerializePaddingFrame)
{
    PaddingFrame frame;
    frame.length = 5;
    auto serialized = SerializeFrame(frame);
    EXPECT_EQ(serialized.size(), 5);
    for (auto byte : serialized)
        EXPECT_EQ(byte, 0x00);
}

TEST(QuicFrameTests, SerializeCryptoFrame)
{
    CryptoFrame frame;
    frame.offset = 0;
    frame.data = {'T', 'e', 's', 't'};

    auto serialized = SerializeFrame(frame);
    EXPECT_EQ(serialized[0], 0x06); // CRYPTO frame type
    EXPECT_EQ(serialized[1], 0x00); // Offset
    EXPECT_EQ(serialized[2], 0x04); // Length
    EXPECT_EQ(serialized[3], 'T');
    EXPECT_EQ(serialized[6], 't');
}

TEST(QuicFrameTests, SerializeStreamFrame)
{
    StreamFrame frame;
    frame.stream_id = 4;
    frame.offset = 100;
    frame.fin = true;
    frame.data = {'A', 'B', 'C'};

    auto serialized = SerializeFrame(frame);
    EXPECT_EQ(serialized[0], 0x0F); // STREAM frame with offset, length, fin
    // Check stream ID follows
    EXPECT_EQ(serialized[1], 0x04);
}

TEST(QuicFrameTests, SerializeAckFrame)
{
    AckFrame frame;
    frame.largest_acknowledged = 10;
    frame.ack_delay = 50;
    frame.ranges.emplace_back(5, 6); // Packets 5-10

    auto serialized = SerializeFrame(frame);
    EXPECT_EQ(serialized[0], 0x02); // ACK frame type
    EXPECT_EQ(serialized[1], 0x0A); // Largest ack
    EXPECT_EQ(serialized[2], 0x32); // ACK delay = 50
}

TEST(QuicFrameTests, SerializeConnectionCloseFrame)
{
    ConnectionCloseFrame frame;
    frame.error_code = 42;
    frame.frame_type = 6;
    frame.reason = "Test";

    auto serialized = SerializeFrame(frame);
    EXPECT_EQ(serialized[0], 0x1C);
    EXPECT_EQ(serialized[1], 0x2A); // Error code 42
    EXPECT_EQ(serialized[2], 0x06); // Frame type
    EXPECT_EQ(serialized[3], 0x04); // Reason length
    EXPECT_EQ(serialized[4], 'T');
}

TEST(QuicFrameTests, ParseMultipleFrames)
{
    std::vector<std::uint8_t> data;
    // PING frame
    data.push_back(0x01);
    // PADDING frame
    data.push_back(0x00);
    data.push_back(0x00);
    // PING frame
    data.push_back(0x01);

    auto frames = ParseFrames(data);
    EXPECT_EQ(frames.size(), 3);
    EXPECT_TRUE(std::holds_alternative<PingFrame>(frames[0]));
    EXPECT_TRUE(std::holds_alternative<PaddingFrame>(frames[1]));
    EXPECT_TRUE(std::holds_alternative<PingFrame>(frames[2]));
}

TEST(QuicFrameTests, RoundTripCryptoFrame)
{
    CryptoFrame original;
    original.offset = 42;
    original.data = {0xDE, 0xAD, 0xBE, 0xEF};

    auto serialized = SerializeFrame(original);
    auto result = ParseFrame(serialized);

    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(std::holds_alternative<CryptoFrame>(result->first));

    const auto &parsed = std::get<CryptoFrame>(result->first);
    EXPECT_EQ(parsed.offset, original.offset);
    EXPECT_EQ(parsed.data, original.data);
}

TEST(QuicFrameTests, RoundTripStreamFrame)
{
    StreamFrame original;
    original.stream_id = 8;
    original.offset = 1000;
    original.fin = true;
    original.data = {0x01, 0x02, 0x03, 0x04, 0x05};

    auto serialized = SerializeFrame(original);
    auto result = ParseFrame(serialized);

    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(std::holds_alternative<StreamFrame>(result->first));

    const auto &parsed = std::get<StreamFrame>(result->first);
    EXPECT_EQ(parsed.stream_id, original.stream_id);
    EXPECT_EQ(parsed.offset, original.offset);
    EXPECT_EQ(parsed.fin, original.fin);
    EXPECT_EQ(parsed.data, original.data);
}
