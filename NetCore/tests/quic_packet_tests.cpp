// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>
#include <vector>

#include "quic/quic_packet.h"

using namespace clv::quic;

TEST(QuicPacketTests, ParseLongHeaderInitial)
{
    // Construct a minimal Initial packet
    std::vector<std::uint8_t> packet;
    packet.push_back(0xC3); // 11000011: long header, Initial (00), pn_len=4 (11)
    // Version (4 bytes)
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x01);
    // DCID length + DCID
    packet.push_back(0x08); // 8-byte DCID
    for (int i = 0; i < 8; ++i)
        packet.push_back(static_cast<std::uint8_t>(0x11 + i));
    // SCID length + SCID
    packet.push_back(0x00); // 0-byte SCID
    // Token length (varint)
    packet.push_back(0x00); // No token
    // Length (varint) - for now, say 100 bytes
    packet.push_back(0x40);
    packet.push_back(0x64);
    // Packet number (4 bytes)
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x01);
    // Payload (dummy)
    for (int i = 0; i < 10; ++i)
        packet.push_back(0xAA);

    auto result = ParsePacketHeader(packet);
    ASSERT_TRUE(result.has_value());

    const auto &parsed = result.value();
    ASSERT_TRUE(std::holds_alternative<LongHeader>(parsed.header));

    const auto &hdr = std::get<LongHeader>(parsed.header);
    EXPECT_EQ(hdr.type, PacketType::Initial);
    EXPECT_EQ(hdr.version, 1);
    EXPECT_EQ(hdr.dest_conn_id.length, 8);
    EXPECT_EQ(hdr.dest_conn_id.data[0], 0x11);
    EXPECT_EQ(hdr.dest_conn_id.data[7], 0x18);
    EXPECT_EQ(hdr.src_conn_id.length, 0);
    EXPECT_EQ(hdr.token.size(), 0);
    EXPECT_EQ(hdr.payload_length, 100);
    EXPECT_EQ(hdr.packet_number, 1);
}

TEST(QuicPacketTests, ParseLongHeaderHandshake)
{
    std::vector<std::uint8_t> packet;
    packet.push_back(0xE3); // 11100011: long header, Handshake (10), pn_len=4 (11)
    // Version
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x01);
    // DCID
    packet.push_back(0x04);
    packet.push_back(0xAA);
    packet.push_back(0xBB);
    packet.push_back(0xCC);
    packet.push_back(0xDD);
    // SCID
    packet.push_back(0x04);
    packet.push_back(0x11);
    packet.push_back(0x22);
    packet.push_back(0x33);
    packet.push_back(0x44);
    // Length (varint)
    packet.push_back(0x40);
    packet.push_back(0x32); // 50 bytes
    // Packet number
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x0A);

    auto result = ParsePacketHeader(packet);
    ASSERT_TRUE(result.has_value());

    const auto &parsed = result.value();
    ASSERT_TRUE(std::holds_alternative<LongHeader>(parsed.header));

    const auto &hdr = std::get<LongHeader>(parsed.header);
    EXPECT_EQ(hdr.type, PacketType::Handshake);
    EXPECT_EQ(hdr.dest_conn_id.length, 4);
    EXPECT_EQ(hdr.dest_conn_id.data[0], 0xAA);
    EXPECT_EQ(hdr.src_conn_id.length, 4);
    EXPECT_EQ(hdr.src_conn_id.data[0], 0x11);
    EXPECT_EQ(hdr.packet_number, 10);
}

TEST(QuicPacketTests, ParseLongHeaderWithToken)
{
    std::vector<std::uint8_t> packet;
    packet.push_back(0xC3); // Initial packet
    // Version
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x01);
    // DCID
    packet.push_back(0x04);
    packet.push_back(0x01);
    packet.push_back(0x02);
    packet.push_back(0x03);
    packet.push_back(0x04);
    // SCID
    packet.push_back(0x00);
    // Token length (varint) - 5 bytes
    packet.push_back(0x05);
    packet.push_back(0xDE);
    packet.push_back(0xAD);
    packet.push_back(0xBE);
    packet.push_back(0xEF);
    packet.push_back(0x00);
    // Length
    packet.push_back(0x40);
    packet.push_back(0x14); // 20 bytes
    // Packet number
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x01);

    auto result = ParsePacketHeader(packet);
    ASSERT_TRUE(result.has_value());

    const auto &hdr = std::get<LongHeader>(result.value().header);
    EXPECT_EQ(hdr.type, PacketType::Initial);
    EXPECT_EQ(hdr.token.size(), 5);
    EXPECT_EQ(hdr.token[0], 0xDE);
    EXPECT_EQ(hdr.token[4], 0x00);
}

TEST(QuicPacketTests, ParseShortHeader)
{
    // Short header is context-dependent, so this is a minimal test
    std::vector<std::uint8_t> packet;
    packet.push_back(0x43); // 01000011: short header, fixed bit, pn_len=4
    // DCID (if any) would follow, but we can't parse without knowing length
    // For now, just verify it recognizes as short header

    auto result = ParsePacketHeader(packet);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(std::holds_alternative<ShortHeader>(result.value().header));
}

TEST(QuicPacketTests, SerializeLongHeaderInitial)
{
    LongHeader hdr;
    hdr.type = PacketType::Initial;
    hdr.version = 1;
    hdr.dest_conn_id.length = 4;
    hdr.dest_conn_id.data[0] = 0xAA;
    hdr.dest_conn_id.data[1] = 0xBB;
    hdr.dest_conn_id.data[2] = 0xCC;
    hdr.dest_conn_id.data[3] = 0xDD;
    hdr.src_conn_id.length = 0;
    hdr.payload_length = 100;
    hdr.packet_number = 1;

    auto serialized = SerializeLongHeader(hdr);

    EXPECT_EQ(serialized[0], 0xC3); // Initial, 4-byte pn
    EXPECT_EQ(serialized[1], 0x00);
    EXPECT_EQ(serialized[2], 0x00);
    EXPECT_EQ(serialized[3], 0x00);
    EXPECT_EQ(serialized[4], 0x01); // Version = 1
    EXPECT_EQ(serialized[5], 0x04); // DCID length
    EXPECT_EQ(serialized[6], 0xAA);
    EXPECT_EQ(serialized[9], 0xDD);
    EXPECT_EQ(serialized[10], 0x00); // SCID length
    EXPECT_EQ(serialized[11], 0x00); // Token length (0)
    EXPECT_EQ(serialized[12], 0x40); // Length varint
    EXPECT_EQ(serialized[13], 0x64); // 100
}

TEST(QuicPacketTests, SerializeShortHeader)
{
    ShortHeader hdr;
    hdr.dest_conn_id.length = 4;
    hdr.dest_conn_id.data[0] = 0x11;
    hdr.dest_conn_id.data[1] = 0x22;
    hdr.dest_conn_id.data[2] = 0x33;
    hdr.dest_conn_id.data[3] = 0x44;
    hdr.packet_number = 42;
    hdr.spin_bit = true;
    hdr.key_phase = false;

    auto serialized = SerializeShortHeader(hdr);

    EXPECT_EQ(serialized[0], 0x63); // 01100011: short, fixed, spin, no key_phase, pn_len=4
    EXPECT_EQ(serialized[1], 0x11);
    EXPECT_EQ(serialized[4], 0x44);
    EXPECT_EQ(serialized[5], 0x00);
    EXPECT_EQ(serialized[6], 0x00);
    EXPECT_EQ(serialized[7], 0x00);
    EXPECT_EQ(serialized[8], 0x2A); // 42
}

TEST(QuicPacketTests, RoundTripLongHeader)
{
    LongHeader original;
    original.type = PacketType::Handshake;
    original.version = 0x00000001;
    original.dest_conn_id.length = 8;
    for (std::uint8_t i = 0; i < 8; ++i)
        original.dest_conn_id.data[i] = 0x10 + i;
    original.src_conn_id.length = 4;
    for (std::uint8_t i = 0; i < 4; ++i)
        original.src_conn_id.data[i] = 0xA0 + i;
    original.payload_length = 200;
    original.packet_number = 123;

    auto serialized = SerializeLongHeader(original);
    auto result = ParsePacketHeader(serialized);

    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(std::holds_alternative<LongHeader>(result.value().header));

    const auto &parsed = std::get<LongHeader>(result.value().header);
    EXPECT_EQ(parsed.type, original.type);
    EXPECT_EQ(parsed.version, original.version);
    EXPECT_EQ(parsed.dest_conn_id.length, original.dest_conn_id.length);
    EXPECT_EQ(parsed.src_conn_id.length, original.src_conn_id.length);
    EXPECT_EQ(parsed.packet_number, original.packet_number);
}

TEST(QuicPacketTests, ParseEmptyPacket)
{
    std::vector<std::uint8_t> packet;
    auto result = ParsePacketHeader(packet);
    EXPECT_FALSE(result.has_value());
}

TEST(QuicPacketTests, ParseTruncatedPacket)
{
    std::vector<std::uint8_t> packet = {0xC3, 0x00, 0x00}; // Incomplete
    auto result = ParsePacketHeader(packet);
    EXPECT_FALSE(result.has_value());
}
