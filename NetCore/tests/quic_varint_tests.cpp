// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include "quic/quic_varint.h"

using namespace clv::quic;

TEST(QuicVarintTests, Decode1Byte)
{
    // 00xxxxxx format (6-bit value)
    std::vector<std::uint8_t> data = {0x25}; // 00100101 = 37
    auto result = DecodeVarint(data);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->first, 37);
    EXPECT_EQ(result->second, 1);
}

TEST(QuicVarintTests, Decode1ByteMax)
{
    // Maximum 1-byte value (63)
    std::vector<std::uint8_t> data = {0x3F}; // 00111111 = 63
    auto result = DecodeVarint(data);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->first, 63);
    EXPECT_EQ(result->second, 1);
}

TEST(QuicVarintTests, Decode2Byte)
{
    // 01xxxxxx yyyyyyyy format (14-bit value)
    std::vector<std::uint8_t> data = {0x7B, 0xBD}; // 01111011 10111101 = 15293
    auto result = DecodeVarint(data);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->first, 15293);
    EXPECT_EQ(result->second, 2);
}

TEST(QuicVarintTests, Decode2ByteMax)
{
    // Maximum 2-byte value (16383)
    std::vector<std::uint8_t> data = {0x7F, 0xFF}; // 01111111 11111111 = 16383
    auto result = DecodeVarint(data);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->first, 16383);
    EXPECT_EQ(result->second, 2);
}

TEST(QuicVarintTests, Decode4Byte)
{
    // 10xxxxxx + 3 bytes format (30-bit value)
    std::vector<std::uint8_t> data = {0x9D, 0x7F, 0x3E, 0x7D}; // 494878333
    auto result = DecodeVarint(data);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->first, 494878333);
    EXPECT_EQ(result->second, 4);
}

TEST(QuicVarintTests, Decode4ByteMax)
{
    // Maximum 4-byte value (1073741823)
    std::vector<std::uint8_t> data = {0xBF, 0xFF, 0xFF, 0xFF};
    auto result = DecodeVarint(data);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->first, 1073741823);
    EXPECT_EQ(result->second, 4);
}

TEST(QuicVarintTests, Decode8Byte)
{
    // 11xxxxxx + 7 bytes format (62-bit value)
    std::vector<std::uint8_t> data = {0xC2, 0x19, 0x7C, 0x5E, 0xFF, 0x14, 0xE8, 0x8C};
    auto result = DecodeVarint(data);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->first, 151288809941952652ull);
    EXPECT_EQ(result->second, 8);
}

TEST(QuicVarintTests, Decode8ByteMax)
{
    // Maximum 8-byte value (4611686018427387903 = 2^62 - 1)
    std::vector<std::uint8_t> data = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    auto result = DecodeVarint(data);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->first, 4611686018427387903ull);
    EXPECT_EQ(result->second, 8);
}

TEST(QuicVarintTests, DecodeEmptyData)
{
    std::vector<std::uint8_t> data = {};
    auto result = DecodeVarint(data);
    EXPECT_FALSE(result.has_value());
}

TEST(QuicVarintTests, DecodeInsufficientData2Byte)
{
    std::vector<std::uint8_t> data = {0x7B}; // 2-byte encoding but only 1 byte
    auto result = DecodeVarint(data);
    EXPECT_FALSE(result.has_value());
}

TEST(QuicVarintTests, DecodeInsufficientData4Byte)
{
    std::vector<std::uint8_t> data = {0x9D, 0x7F, 0x3E}; // 4-byte encoding but only 3 bytes
    auto result = DecodeVarint(data);
    EXPECT_FALSE(result.has_value());
}

TEST(QuicVarintTests, DecodeInsufficientData8Byte)
{
    std::vector<std::uint8_t> data = {0xC2, 0x19, 0x7C, 0x5E, 0xFF, 0x14, 0xE8}; // 8-byte but only 7
    auto result = DecodeVarint(data);
    EXPECT_FALSE(result.has_value());
}

TEST(QuicVarintTests, Encode1Byte)
{
    std::array<std::uint8_t, 8> buf{};
    auto bytes = EncodeVarint(37, buf);
    EXPECT_EQ(bytes, 1);
    EXPECT_EQ(buf[0], 0x25);
}

TEST(QuicVarintTests, Encode1ByteMax)
{
    std::array<std::uint8_t, 8> buf{};
    auto bytes = EncodeVarint(63, buf);
    EXPECT_EQ(bytes, 1);
    EXPECT_EQ(buf[0], 0x3F);
}

TEST(QuicVarintTests, Encode2Byte)
{
    std::array<std::uint8_t, 8> buf{};
    auto bytes = EncodeVarint(15293, buf);
    EXPECT_EQ(bytes, 2);
    EXPECT_EQ(buf[0], 0x7B);
    EXPECT_EQ(buf[1], 0xBD);
}

TEST(QuicVarintTests, Encode2ByteMax)
{
    std::array<std::uint8_t, 8> buf{};
    auto bytes = EncodeVarint(16383, buf);
    EXPECT_EQ(bytes, 2);
    EXPECT_EQ(buf[0], 0x7F);
    EXPECT_EQ(buf[1], 0xFF);
}

TEST(QuicVarintTests, Encode4Byte)
{
    std::array<std::uint8_t, 8> buf{};
    auto bytes = EncodeVarint(494878333, buf);
    EXPECT_EQ(bytes, 4);
    EXPECT_EQ(buf[0], 0x9D);
    EXPECT_EQ(buf[1], 0x7F);
    EXPECT_EQ(buf[2], 0x3E);
    EXPECT_EQ(buf[3], 0x7D);
}

TEST(QuicVarintTests, Encode4ByteMax)
{
    std::array<std::uint8_t, 8> buf{};
    auto bytes = EncodeVarint(1073741823, buf);
    EXPECT_EQ(bytes, 4);
    EXPECT_EQ(buf[0], 0xBF);
    EXPECT_EQ(buf[1], 0xFF);
    EXPECT_EQ(buf[2], 0xFF);
    EXPECT_EQ(buf[3], 0xFF);
}

TEST(QuicVarintTests, Encode8Byte)
{
    std::array<std::uint8_t, 8> buf{};
    auto bytes = EncodeVarint(151288809941952652ull, buf);
    EXPECT_EQ(bytes, 8);
    EXPECT_EQ(buf[0], 0xC2);
    EXPECT_EQ(buf[1], 0x19);
    EXPECT_EQ(buf[2], 0x7C);
    EXPECT_EQ(buf[3], 0x5E);
    EXPECT_EQ(buf[4], 0xFF);
    EXPECT_EQ(buf[5], 0x14);
    EXPECT_EQ(buf[6], 0xE8);
    EXPECT_EQ(buf[7], 0x8C);
}

TEST(QuicVarintTests, Encode8ByteMax)
{
    std::array<std::uint8_t, 8> buf{};
    auto bytes = EncodeVarint(4611686018427387903ull, buf);
    EXPECT_EQ(bytes, 8);
    EXPECT_EQ(buf[0], 0xFF);
    EXPECT_EQ(buf[1], 0xFF);
    EXPECT_EQ(buf[2], 0xFF);
    EXPECT_EQ(buf[3], 0xFF);
    EXPECT_EQ(buf[4], 0xFF);
    EXPECT_EQ(buf[5], 0xFF);
    EXPECT_EQ(buf[6], 0xFF);
    EXPECT_EQ(buf[7], 0xFF);
}

TEST(QuicVarintTests, EncodeOutOfRange)
{
    // Value exceeds 2^62 - 1
    std::array<std::uint8_t, 8> buf{};
    auto bytes = EncodeVarint(4611686018427387904ull, buf);
    EXPECT_EQ(bytes, 0); // Should fail
}

TEST(QuicVarintTests, EncodeInsufficientBuffer1Byte)
{
    std::array<std::uint8_t, 0> buf{};
    auto bytes = EncodeVarint(37, buf);
    EXPECT_EQ(bytes, 0);
}

TEST(QuicVarintTests, EncodeInsufficientBuffer2Byte)
{
    std::array<std::uint8_t, 1> buf{};
    auto bytes = EncodeVarint(15293, buf);
    EXPECT_EQ(bytes, 0);
}

TEST(QuicVarintTests, EncodeInsufficientBuffer4Byte)
{
    std::array<std::uint8_t, 3> buf{};
    auto bytes = EncodeVarint(494878333, buf);
    EXPECT_EQ(bytes, 0);
}

TEST(QuicVarintTests, EncodeInsufficientBuffer8Byte)
{
    std::array<std::uint8_t, 7> buf{};
    auto bytes = EncodeVarint(151288809941952652ull, buf);
    EXPECT_EQ(bytes, 0);
}

TEST(QuicVarintTests, RoundTrip1Byte)
{
    std::array<std::uint8_t, 8> buf{};
    const std::uint64_t value = 42;
    auto enc_bytes = EncodeVarint(value, buf);
    auto result = DecodeVarint(std::span(buf.data(), enc_bytes));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->first, value);
    EXPECT_EQ(result->second, enc_bytes);
}

TEST(QuicVarintTests, RoundTrip2Byte)
{
    std::array<std::uint8_t, 8> buf{};
    const std::uint64_t value = 12345;
    auto enc_bytes = EncodeVarint(value, buf);
    auto result = DecodeVarint(std::span(buf.data(), enc_bytes));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->first, value);
    EXPECT_EQ(result->second, enc_bytes);
}

TEST(QuicVarintTests, RoundTrip4Byte)
{
    std::array<std::uint8_t, 8> buf{};
    const std::uint64_t value = 987654321;
    auto enc_bytes = EncodeVarint(value, buf);
    auto result = DecodeVarint(std::span(buf.data(), enc_bytes));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->first, value);
    EXPECT_EQ(result->second, enc_bytes);
}

TEST(QuicVarintTests, RoundTrip8Byte)
{
    std::array<std::uint8_t, 8> buf{};
    const std::uint64_t value = 1234567890123456789ull;
    auto enc_bytes = EncodeVarint(value, buf);
    auto result = DecodeVarint(std::span(buf.data(), enc_bytes));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->first, value);
    EXPECT_EQ(result->second, enc_bytes);
}

TEST(QuicVarintTests, EncodedLength)
{
    EXPECT_EQ(VarintEncodedLength(0), 1);
    EXPECT_EQ(VarintEncodedLength(63), 1);
    EXPECT_EQ(VarintEncodedLength(64), 2);
    EXPECT_EQ(VarintEncodedLength(16383), 2);
    EXPECT_EQ(VarintEncodedLength(16384), 4);
    EXPECT_EQ(VarintEncodedLength(1073741823), 4);
    EXPECT_EQ(VarintEncodedLength(1073741824), 8);
    EXPECT_EQ(VarintEncodedLength(4611686018427387903ull), 8);
    EXPECT_EQ(VarintEncodedLength(4611686018427387904ull), 0); // Out of range
}
