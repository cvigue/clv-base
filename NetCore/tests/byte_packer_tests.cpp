// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>
#include <array>
#include <cstdint>

#include "util/byte_packer.h"

using namespace clv::netcore;

TEST(BytePackerTests, UintToBytes4Byte)
{
    auto bytes = uint_to_bytes<4>(0x12345678u);
    EXPECT_EQ(bytes[0], 0x12);
    EXPECT_EQ(bytes[1], 0x34);
    EXPECT_EQ(bytes[2], 0x56);
    EXPECT_EQ(bytes[3], 0x78);
}

TEST(BytePackerTests, UintToBytes2Byte)
{
    auto bytes = uint_to_bytes<2>(0xABCDu);
    EXPECT_EQ(bytes[0], 0xAB);
    EXPECT_EQ(bytes[1], 0xCD);
}

TEST(BytePackerTests, UintToBytes1Byte)
{
    auto bytes = uint_to_bytes<1>(0x42u);
    EXPECT_EQ(bytes[0], 0x42);
}

TEST(BytePackerTests, UintToBytes8Byte)
{
    auto bytes = uint_to_bytes<8>(0x0102030405060708ull);
    EXPECT_EQ(bytes[0], 0x01);
    EXPECT_EQ(bytes[1], 0x02);
    EXPECT_EQ(bytes[2], 0x03);
    EXPECT_EQ(bytes[3], 0x04);
    EXPECT_EQ(bytes[4], 0x05);
    EXPECT_EQ(bytes[5], 0x06);
    EXPECT_EQ(bytes[6], 0x07);
    EXPECT_EQ(bytes[7], 0x08);
}

TEST(BytePackerTests, UintToBytesDeduced)
{
    auto bytes32 = uint_to_bytes(std::uint32_t{0x12345678});
    EXPECT_EQ(bytes32.size(), 4);
    EXPECT_EQ(bytes32[0], 0x12);
    EXPECT_EQ(bytes32[3], 0x78);

    auto bytes16 = uint_to_bytes(std::uint16_t{0xABCD});
    EXPECT_EQ(bytes16.size(), 2);
    EXPECT_EQ(bytes16[0], 0xAB);
    EXPECT_EQ(bytes16[1], 0xCD);
}

TEST(BytePackerTests, UintToBytesPartial)
{
    // Extract lower 2 bytes from a uint32_t
    auto bytes = uint_to_bytes<2>(0x12345678u);
    EXPECT_EQ(bytes[0], 0x56);
    EXPECT_EQ(bytes[1], 0x78);
}

TEST(BytePackerTests, RoundTripBytesToUintToBytes)
{
    // Test round-trip: uint -> bytes -> uint
    constexpr std::uint32_t original = 0x87654321u;

    auto bytes = uint_to_bytes<4>(original);
    auto reconstructed = bytes_to_uint<std::uint32_t>(bytes[0], bytes[1], bytes[2], bytes[3]);

    EXPECT_EQ(original, reconstructed);
}

TEST(BytePackerTests, ConstexprUintToBytes)
{
    // Verify it's constexpr
    constexpr auto bytes = uint_to_bytes<4>(0x12345678u);
    static_assert(bytes[0] == 0x12, "constexpr failed");
    static_assert(bytes[1] == 0x34, "constexpr failed");
    static_assert(bytes[2] == 0x56, "constexpr failed");
    static_assert(bytes[3] == 0x78, "constexpr failed");

    EXPECT_EQ(bytes[0], 0x12);
}

TEST(BytePackerTests, ZeroValue)
{
    auto bytes = uint_to_bytes<4>(0u);
    EXPECT_EQ(bytes[0], 0x00);
    EXPECT_EQ(bytes[1], 0x00);
    EXPECT_EQ(bytes[2], 0x00);
    EXPECT_EQ(bytes[3], 0x00);
}

TEST(BytePackerTests, MaxValue)
{
    auto bytes = uint_to_bytes<4>(0xFFFFFFFFu);
    EXPECT_EQ(bytes[0], 0xFF);
    EXPECT_EQ(bytes[1], 0xFF);
    EXPECT_EQ(bytes[2], 0xFF);
    EXPECT_EQ(bytes[3], 0xFF);
}

// Tests for multi_uint_to_bytes

TEST(BytePackerTests, MultiUintToBytesTwo)
{
    auto bytes = multi_uint_to_bytes(std::uint8_t{0x12}, std::uint32_t{0x34567890});
    ASSERT_EQ(bytes.size(), 5);
    EXPECT_EQ(bytes[0], 0x12);
    EXPECT_EQ(bytes[1], 0x34);
    EXPECT_EQ(bytes[2], 0x56);
    EXPECT_EQ(bytes[3], 0x78);
    EXPECT_EQ(bytes[4], 0x90);
}

TEST(BytePackerTests, MultiUintToBytesThree)
{
    auto bytes = multi_uint_to_bytes(
        std::uint8_t{0xC0},
        std::uint32_t{0x00000001},
        std::uint16_t{0xABCD});
    ASSERT_EQ(bytes.size(), 7);
    EXPECT_EQ(bytes[0], 0xC0);
    EXPECT_EQ(bytes[1], 0x00);
    EXPECT_EQ(bytes[2], 0x00);
    EXPECT_EQ(bytes[3], 0x00);
    EXPECT_EQ(bytes[4], 0x01);
    EXPECT_EQ(bytes[5], 0xAB);
    EXPECT_EQ(bytes[6], 0xCD);
}

TEST(BytePackerTests, MultiUintToBytesSingle)
{
    auto bytes = multi_uint_to_bytes(std::uint32_t{0x12345678});
    ASSERT_EQ(bytes.size(), 4);
    EXPECT_EQ(bytes[0], 0x12);
    EXPECT_EQ(bytes[1], 0x34);
    EXPECT_EQ(bytes[2], 0x56);
    EXPECT_EQ(bytes[3], 0x78);
}

TEST(BytePackerTests, MultiUintToBytesConstexpr)
{
    constexpr auto bytes = multi_uint_to_bytes(std::uint8_t{0xFF}, std::uint16_t{0x1234});
    static_assert(bytes.size() == 3, "size should be 3");
    static_assert(bytes[0] == 0xFF, "first byte");
    static_assert(bytes[1] == 0x12, "second byte");
    static_assert(bytes[2] == 0x34, "third byte");
}

// ========== Tests for bytes_to_uint ==========

TEST(BytePackerTests, BytesToUint4Bytes)
{
    auto val = bytes_to_uint<std::uint32_t>(0x12, 0x34, 0x56, 0x78);
    EXPECT_EQ(val, 0x12345678u);
}

TEST(BytePackerTests, BytesToUint2Bytes)
{
    auto val = bytes_to_uint(std::uint8_t{0xAB}, std::uint8_t{0xCD});
    static_assert(std::is_same_v<decltype(val), std::uint16_t>);
    EXPECT_EQ(val, 0xABCDu);
}

TEST(BytePackerTests, BytesToUint1Byte)
{
    auto val = bytes_to_uint(std::uint8_t{0x42});
    EXPECT_EQ(val, 0x42u);
}

TEST(BytePackerTests, BytesToUintDeduced)
{
    // Deduced to uint16_t from 2 bytes
    auto val2 = bytes_to_uint(0x12, 0x34);
    static_assert(std::is_same_v<decltype(val2), std::uint16_t>);
    EXPECT_EQ(val2, 0x1234u);

    // Deduced to uint32_t from 4 bytes
    auto val4 = bytes_to_uint(0x12, 0x34, 0x56, 0x78);
    static_assert(std::is_same_v<decltype(val4), std::uint32_t>);
    EXPECT_EQ(val4, 0x12345678u);
}

TEST(BytePackerTests, BytesToUintConstexpr)
{
    constexpr auto val = bytes_to_uint<std::uint32_t>(0x01, 0x02, 0x03, 0x04);
    static_assert(val == 0x01020304u, "constexpr failed");
    EXPECT_EQ(val, 0x01020304u);
}

// ========== Tests for read_uint ==========

TEST(BytePackerTests, ReadUint4Bytes)
{
    std::array<std::uint8_t, 4> data = {0x12, 0x34, 0x56, 0x78};
    auto val = read_uint<4>(std::span{data});
    EXPECT_EQ(val, 0x12345678u);
}

TEST(BytePackerTests, ReadUint2Bytes)
{
    std::array<std::uint8_t, 4> data = {0xAB, 0xCD, 0x00, 0x00};
    auto val = read_uint<2>(std::span{data});
    EXPECT_EQ(val, 0xABCDu);
}

TEST(BytePackerTests, ReadUint8Bytes)
{
    std::array<std::uint8_t, 8> data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    auto val = read_uint<8>(std::span{data});
    EXPECT_EQ(val, 0x0102030405060708ull);
}

TEST(BytePackerTests, ReadUintTyped)
{
    std::array<std::uint8_t, 4> data = {0x12, 0x34, 0x56, 0x78};
    auto val = read_uint<std::uint32_t>(std::span{data});
    EXPECT_EQ(val, 0x12345678u);
}

TEST(BytePackerTests, ReadUintFromMiddle)
{
    std::array<std::uint8_t, 8> data = {0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00};
    auto val = read_uint<4>(std::span{data}.subspan(2));
    EXPECT_EQ(val, 0x12345678u);
}

// ========== Tests for write_uint ==========

TEST(BytePackerTests, WriteUint4Bytes)
{
    std::array<std::uint8_t, 4> data = {};
    write_uint<4>(std::span{data}, 0x12345678u);
    EXPECT_EQ(data[0], 0x12);
    EXPECT_EQ(data[1], 0x34);
    EXPECT_EQ(data[2], 0x56);
    EXPECT_EQ(data[3], 0x78);
}

TEST(BytePackerTests, WriteUint2Bytes)
{
    std::array<std::uint8_t, 2> data = {};
    write_uint<2>(std::span{data}, 0xABCDu);
    EXPECT_EQ(data[0], 0xAB);
    EXPECT_EQ(data[1], 0xCD);
}

TEST(BytePackerTests, WriteUintDeduced)
{
    std::array<std::uint8_t, 4> data = {};
    write_uint(std::span{data}, std::uint32_t{0x12345678});
    EXPECT_EQ(data[0], 0x12);
    EXPECT_EQ(data[1], 0x34);
    EXPECT_EQ(data[2], 0x56);
    EXPECT_EQ(data[3], 0x78);
}

TEST(BytePackerTests, WriteUintToMiddle)
{
    std::array<std::uint8_t, 8> data = {};
    write_uint<4>(std::span{data}.subspan(2), 0x12345678u);
    EXPECT_EQ(data[0], 0x00);
    EXPECT_EQ(data[1], 0x00);
    EXPECT_EQ(data[2], 0x12);
    EXPECT_EQ(data[3], 0x34);
    EXPECT_EQ(data[4], 0x56);
    EXPECT_EQ(data[5], 0x78);
    EXPECT_EQ(data[6], 0x00);
    EXPECT_EQ(data[7], 0x00);
}

TEST(BytePackerTests, ReadWriteRoundTrip)
{
    std::array<std::uint8_t, 8> data = {};
    constexpr std::uint64_t original = 0xDEADBEEFCAFEBABEull;

    write_uint(std::span{data}, original);
    auto result = read_uint<std::uint64_t>(std::span{data});

    EXPECT_EQ(result, original);
}

// ========== Tests for append_length_prefixed_string ==========

TEST(BytePackerTests, AppendLengthPrefixedStringBasic)
{
    std::vector<std::uint8_t> buffer;
    append_length_prefixed_string(buffer, "hello");

    // Length = 6 (5 chars + null), big-endian 2 bytes
    ASSERT_EQ(buffer.size(), 2 + 5 + 1); // len + string + null
    EXPECT_EQ(buffer[0], 0x00);
    EXPECT_EQ(buffer[1], 0x06);
    EXPECT_EQ(buffer[2], 'h');
    EXPECT_EQ(buffer[3], 'e');
    EXPECT_EQ(buffer[4], 'l');
    EXPECT_EQ(buffer[5], 'l');
    EXPECT_EQ(buffer[6], 'o');
    EXPECT_EQ(buffer[7], 0x00);
}

TEST(BytePackerTests, AppendLengthPrefixedStringEmpty)
{
    std::vector<std::uint8_t> buffer;
    append_length_prefixed_string(buffer, "");

    // Length = 1 (just null terminator)
    ASSERT_EQ(buffer.size(), 3);
    EXPECT_EQ(buffer[0], 0x00);
    EXPECT_EQ(buffer[1], 0x01);
    EXPECT_EQ(buffer[2], 0x00);
}

TEST(BytePackerTests, AppendLengthPrefixedString1ByteLen)
{
    std::vector<std::uint8_t> buffer;
    append_length_prefixed_string<1>(buffer, "hi");

    ASSERT_EQ(buffer.size(), 1 + 2 + 1);
    EXPECT_EQ(buffer[0], 0x03); // 1-byte length
    EXPECT_EQ(buffer[1], 'h');
    EXPECT_EQ(buffer[2], 'i');
    EXPECT_EQ(buffer[3], 0x00);
}

TEST(BytePackerTests, AppendLengthPrefixedString4ByteLen)
{
    std::vector<std::uint8_t> buffer;
    append_length_prefixed_string<4>(buffer, "test");

    ASSERT_EQ(buffer.size(), 4 + 4 + 1);
    EXPECT_EQ(buffer[0], 0x00);
    EXPECT_EQ(buffer[1], 0x00);
    EXPECT_EQ(buffer[2], 0x00);
    EXPECT_EQ(buffer[3], 0x05); // 4-byte length = 5
    EXPECT_EQ(buffer[4], 't');
    EXPECT_EQ(buffer[5], 'e');
    EXPECT_EQ(buffer[6], 's');
    EXPECT_EQ(buffer[7], 't');
    EXPECT_EQ(buffer[8], 0x00);
}

TEST(BytePackerTests, AppendLengthPrefixedStringMultiple)
{
    std::vector<std::uint8_t> buffer;
    append_length_prefixed_string(buffer, "one");
    append_length_prefixed_string(buffer, "two");

    // First: len(2) + "one"(3) + null(1) = 6
    // Second: len(2) + "two"(3) + null(1) = 6
    ASSERT_EQ(buffer.size(), 12);
}

// ========== Tests for read_length_prefixed_string ==========

TEST(BytePackerTests, ReadLengthPrefixedStringBasic)
{
    std::vector<std::uint8_t> data = {0x00, 0x06, 'h', 'e', 'l', 'l', 'o', 0x00};
    std::size_t pos = 0;

    auto result = read_length_prefixed_string(std::span{data}, pos);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "hello");
    EXPECT_EQ(pos, 8);
}

TEST(BytePackerTests, ReadLengthPrefixedStringEmpty)
{
    std::vector<std::uint8_t> data = {0x00, 0x01, 0x00};
    std::size_t pos = 0;

    auto result = read_length_prefixed_string(std::span{data}, pos);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "");
    EXPECT_EQ(pos, 3);
}

TEST(BytePackerTests, ReadLengthPrefixedStringZeroLength)
{
    std::vector<std::uint8_t> data = {0x00, 0x00};
    std::size_t pos = 0;

    auto result = read_length_prefixed_string(std::span{data}, pos);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "");
    EXPECT_EQ(pos, 2);
}

TEST(BytePackerTests, ReadLengthPrefixedString1ByteLen)
{
    std::vector<std::uint8_t> data = {0x03, 'h', 'i', 0x00};
    std::size_t pos = 0;

    auto result = read_length_prefixed_string<1>(std::span{data}, pos);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "hi");
    EXPECT_EQ(pos, 4);
}

TEST(BytePackerTests, ReadLengthPrefixedString4ByteLen)
{
    std::vector<std::uint8_t> data = {0x00, 0x00, 0x00, 0x05, 't', 'e', 's', 't', 0x00};
    std::size_t pos = 0;

    auto result = read_length_prefixed_string<4>(std::span{data}, pos);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "test");
    EXPECT_EQ(pos, 9);
}

TEST(BytePackerTests, ReadLengthPrefixedStringInsufficientDataForLength)
{
    std::vector<std::uint8_t> data = {0x00}; // Only 1 byte, need 2 for length
    std::size_t pos = 0;

    auto result = read_length_prefixed_string(std::span{data}, pos);

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(pos, 0); // pos unchanged on failure
}

TEST(BytePackerTests, ReadLengthPrefixedStringInsufficientDataForString)
{
    std::vector<std::uint8_t> data = {0x00, 0x10, 'h', 'i'}; // Claims 16 bytes, only has 2
    std::size_t pos = 0;

    auto result = read_length_prefixed_string(std::span{data}, pos);

    EXPECT_FALSE(result.has_value());
}

TEST(BytePackerTests, ReadLengthPrefixedStringMultiple)
{
    std::vector<std::uint8_t> data = {
        0x00, 0x04, 'o', 'n', 'e', 0x00, 0x00, 0x04, 't', 'w', 'o', 0x00};
    std::size_t pos = 0;

    auto first = read_length_prefixed_string(std::span{data}, pos);
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(*first, "one");

    auto second = read_length_prefixed_string(std::span{data}, pos);
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(*second, "two");

    EXPECT_EQ(pos, 12);
}

TEST(BytePackerTests, ReadLengthPrefixedStringFromMiddle)
{
    std::vector<std::uint8_t> data = {0xFF, 0xFF, 0x00, 0x03, 'h', 'i', 0x00, 0xFF};
    std::size_t pos = 2;

    auto result = read_length_prefixed_string(std::span{data}, pos);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "hi");
    EXPECT_EQ(pos, 7);
}

TEST(BytePackerTests, AppendAndReadRoundTrip)
{
    std::vector<std::uint8_t> buffer;
    append_length_prefixed_string(buffer, "first");
    append_length_prefixed_string(buffer, "second");
    append_length_prefixed_string(buffer, "third");

    std::size_t pos = 0;
    auto r1 = read_length_prefixed_string(std::span{buffer}, pos);
    auto r2 = read_length_prefixed_string(std::span{buffer}, pos);
    auto r3 = read_length_prefixed_string(std::span{buffer}, pos);

    ASSERT_TRUE(r1.has_value());
    ASSERT_TRUE(r2.has_value());
    ASSERT_TRUE(r3.has_value());

    EXPECT_EQ(*r1, "first");
    EXPECT_EQ(*r2, "second");
    EXPECT_EQ(*r3, "third");
    EXPECT_EQ(pos, buffer.size());
}
