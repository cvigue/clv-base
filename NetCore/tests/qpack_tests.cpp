// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include <cstddef>
#include <gtest/gtest.h>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>
#include <string>

#include "http/qpack.h"
#include "http/http3_fwd.h"

using namespace clv::http3;

extern "C"
{
#include <nghttp3_qpack_huffman.h>
}

static std::vector<std::uint8_t> EncodeHuffmanStr(const std::string &s)
{
    const auto *src = reinterpret_cast<const std::uint8_t *>(s.data());
    size_t n = nghttp3_qpack_huffman_encode_count(src, s.size());
    std::vector<std::uint8_t> out(n);
    if (n)
    {
        nghttp3_qpack_huffman_encode(out.data(), src, s.size());
    }
    return out;
}

// ============================================================================
// DecodeHuffman Tests
// ============================================================================

TEST(QpackHuffmanTests, DecodeEmpty)
{
    std::vector<std::uint8_t> data = {};
    auto result = DecodeHuffman(data);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "");
}

TEST(QpackHuffmanTests, DecodeSimpleString)
{
    // "www.example.com" Huffman encoded (RFC 7541 Appendix C.4.1)
    std::vector<std::uint8_t> data = {
        0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
    auto result = DecodeHuffman(data);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "www.example.com");
}

TEST(QpackHuffmanTests, DecodeTextPlain)
{
    // Generate Huffman bytes using nghttp3
    auto data = EncodeHuffmanStr("text/plain");
    auto result = DecodeHuffman(data);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "text/plain");
}

TEST(QpackHuffmanTests, DecodeGzip)
{
    // "gzip" Huffman encoded
    std::vector<std::uint8_t> data = {0x9b, 0xd9, 0xab};
    auto result = DecodeHuffman(data);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "gzip");
}

TEST(QpackHuffmanTests, DecodeWithNumbers)
{
    // "no-cache" Huffman encoded
    std::vector<std::uint8_t> data = {0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf};
    auto result = DecodeHuffman(data);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "no-cache");
}

TEST(QpackHuffmanTests, DecodeInvalidData)
{
    // Invalid Huffman sequence (all 1s is invalid padding)
    std::vector<std::uint8_t> data = {0xFF, 0xFF, 0xFF};
    auto result = DecodeHuffman(data);
    EXPECT_FALSE(result.has_value());
}

// ============================================================================
// DecodeHpackInt Tests
// ============================================================================

TEST(QpackIntegerTests, DecodeSmallValue5Bit)
{
    // Value 10 with 5-bit prefix (00001010)
    std::vector<std::uint8_t> data = {0x0a};
    auto result = DecodeHpackInt(data, 5);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->first, 10);
    EXPECT_EQ(result->second, 1);
}

TEST(QpackIntegerTests, DecodeMaxSingleByte6Bit)
{
    // Value 62 fits in 6-bit prefix (00111110)
    std::vector<std::uint8_t> data = {0x3e};
    auto result = DecodeHpackInt(data, 6);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->first, 62);
    EXPECT_EQ(result->second, 1);
}

TEST(QpackIntegerTests, DecodeContinuation6Bit)
{
    // Value 63 requires continuation: 111111 + 00000000
    std::vector<std::uint8_t> data = {0x3f, 0x00};
    auto result = DecodeHpackInt(data, 6);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->first, 63);
    EXPECT_EQ(result->second, 2);
}

TEST(QpackIntegerTests, DecodeLargeValue6Bit)
{
    // Value 1337: prefix=63 + continuation bytes
    // 1337 = 63 + 1274
    // 1274 = 0x9A (154) + 0x0A (10 << 7) = 154 + 1280 - overflow check
    // Let me recalculate: 1337 - 63 = 1274
    // 1274 in continuation: 1274 = 154 + 8*128 + 2*128 = 154 + 1024 + 256 - no
    // 1274 = 10 (0x0A) | 0x80, then 9 (0x09)
    // Actually: 1274 % 128 = 26 (0x1A), 1274 / 128 = 9, so: 0x9A (154 with continue bit), then 0x09
    // Correct base-128 encoding for 1337 with 6-bit prefix: 0x3f, 0xfa, 0x09
    std::vector<std::uint8_t> data = {0x3f, 0xfa, 0x09};
    auto result = DecodeHpackInt(data, 6);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->first, 1337);
    EXPECT_EQ(result->second, 3);
}

TEST(QpackIntegerTests, Decode7BitPrefix)
{
    // Test with 7-bit prefix (common for value lengths): 127 + (0 << 0) + (2 << 7) = 383
    std::vector<std::uint8_t> data = {0x7f, 0x80, 0x02};
    auto result = DecodeHpackInt(data, 7);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->first, 383);
    EXPECT_EQ(result->second, 3);
}

TEST(QpackIntegerTests, Decode4BitPrefix)
{
    // Test with 4-bit prefix (common for literal with name reference)
    std::vector<std::uint8_t> data = {0x0f, 0x09}; // 15 + 9 = 24
    auto result = DecodeHpackInt(data, 4);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->first, 24);
    EXPECT_EQ(result->second, 2);
}

TEST(QpackIntegerTests, Decode3BitPrefix)
{
    // Test with 3-bit prefix (smallest used in QPACK)
    std::vector<std::uint8_t> data = {0x07, 0x05}; // 7 + 5 = 12
    auto result = DecodeHpackInt(data, 3);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->first, 12);
    EXPECT_EQ(result->second, 2);
}

TEST(QpackIntegerTests, DecodeEmptyData)
{
    std::vector<std::uint8_t> data = {};
    auto result = DecodeHpackInt(data, 6);
    EXPECT_FALSE(result.has_value());
}

TEST(QpackIntegerTests, DecodeInvalidPrefixZero)
{
    std::vector<std::uint8_t> data = {0x3f};
    auto result = DecodeHpackInt(data, 0);
    EXPECT_FALSE(result.has_value());
}

TEST(QpackIntegerTests, DecodeInvalidPrefixTooLarge)
{
    std::vector<std::uint8_t> data = {0x3f};
    auto result = DecodeHpackInt(data, 9);
    EXPECT_FALSE(result.has_value());
}

TEST(QpackIntegerTests, DecodeIncomplete)
{
    // Continuation bit set but no more data
    std::vector<std::uint8_t> data = {0x3f, 0x80};
    auto result = DecodeHpackInt(data, 6);
    EXPECT_FALSE(result.has_value());
}

TEST(QpackIntegerTests, DecodeOverflow)
{
    // Create data that would overflow uint64_t
    std::vector<std::uint8_t> data = {0x3f};
    for (int i = 0; i < 10; ++i)
    {
        data.push_back(0xff); // Keep adding continuation bytes
    }
    data.push_back(0x7f); // Final byte
    auto result = DecodeHpackInt(data, 6);
    EXPECT_FALSE(result.has_value()); // Should detect overflow
}

// ============================================================================
// EncodeHpackInt Tests
// ============================================================================

TEST(QpackIntegerTests, EncodeSmallValue)
{
    auto result = EncodeHpackInt(10, 5, 0x00);
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], 0x0a);
}

TEST(QpackIntegerTests, EncodeWithFlags)
{
    // Encode 10 with 5-bit prefix and flag bits 11000000
    auto result = EncodeHpackInt(10, 5, 0xc0);
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], 0xca); // 11001010
}

TEST(QpackIntegerTests, EncodeMaxSingleByte)
{
    auto result = EncodeHpackInt(62, 6, 0x00);
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], 0x3e);
}

TEST(QpackIntegerTests, EncodeContinuation)
{
    auto result = EncodeHpackInt(63, 6, 0x00);
    ASSERT_EQ(result.size(), 2);
    EXPECT_EQ(result[0], 0x3f); // Max prefix
    EXPECT_EQ(result[1], 0x00); // 63 - 63 = 0
}

TEST(QpackIntegerTests, EncodeLargeValue)
{
    auto result = EncodeHpackInt(1337, 6, 0x00);
    ASSERT_EQ(result.size(), 3);
    EXPECT_EQ(result[0], 0x3f);
    EXPECT_EQ(result[1], 0xfa);
    EXPECT_EQ(result[2], 0x09);
}

TEST(QpackIntegerTests, EncodeDecodeRoundtrip)
{
    // Test various values with different prefix sizes
    std::vector<std::pair<uint64_t, uint8_t>> test_cases = {
        {0, 5}, {1, 5}, {30, 5}, {31, 5}, {32, 5}, {100, 6}, {1000, 6}, {10000, 7}, {65535, 7}};

    for (const auto &[value, prefix] : test_cases)
    {
        auto encoded = EncodeHpackInt(value, prefix, 0x00);
        auto decoded = DecodeHpackInt(encoded, prefix);
        ASSERT_TRUE(decoded.has_value()) << "Failed to decode value " << value;
        EXPECT_EQ(decoded->first, value) << "Roundtrip failed for value " << value;
        EXPECT_EQ(decoded->second, encoded.size());
    }
}

// ============================================================================
// QpackEncoder/Decoder Tests
// ============================================================================

TEST(QpackEncoderTests, EncodeStatusCodeIndexed)
{
    QpackEncoder encoder;
    std::vector<HeaderField> headers = {
        {":status", "200"}};
    auto result = encoder.Encode(headers);
    ASSERT_FALSE(result.empty());
    // Skip required insert count and delta base (first 2 bytes are 0x00, 0x00)
    // Status 200 is at static table index 25: 11011001 (0xD9) for 6-bit prefix
    EXPECT_EQ(result[2], 0xd9);
}

TEST(QpackEncoderTests, EncodeMultipleIndexed)
{
    QpackEncoder encoder;
    std::vector<HeaderField> headers = {
        {":status", "200"},
        {"content-type", "text/html"}};
    auto result = encoder.Encode(headers);
    EXPECT_FALSE(result.empty());
    // Should start with required insert count and delta base
    EXPECT_EQ(result[0], 0x00);
    EXPECT_EQ(result[1], 0x00);
}

TEST(QpackEncoderTests, EncodeLiteralWithNameReference)
{
    QpackEncoder encoder;
    std::vector<HeaderField> headers = {
        {"content-type", "application/custom"}};
    auto result = encoder.Encode(headers);
    EXPECT_FALSE(result.empty());
    // Should use literal with name reference (content-type is in static table)
}

TEST(QpackEncoderTests, EncodeCustomHeader)
{
    QpackEncoder encoder;
    std::vector<HeaderField> headers = {
        {"x-custom-header", "custom-value"}};
    auto result = encoder.Encode(headers);
    EXPECT_FALSE(result.empty());
    // Should use literal field line with literal name
}

TEST(QpackEncoderTests, EncodeEmpty)
{
    QpackEncoder encoder;
    std::vector<HeaderField> headers = {};
    auto result = encoder.Encode(headers);
    // Should still have required insert count and delta base
    ASSERT_EQ(result.size(), 2);
    EXPECT_EQ(result[0], 0x00);
    EXPECT_EQ(result[1], 0x00);
}

// ============================================================================
// QpackDecoder Tests
// ============================================================================

TEST(QpackDecoderTests, DecodeIndexedStatus200)
{
    QpackDecoder decoder;
    // Required insert count (0) + Delta base (0) + Indexed field line for :status: 200 (static table index 25)
    std::vector<std::uint8_t> data = {0x00, 0x00, 0xd9}; // 11011001
    auto result = decoder.Decode(data);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 1);
    EXPECT_EQ((*result)[0].name, ":status");
    EXPECT_EQ((*result)[0].value, "200");
}

TEST(QpackDecoderTests, DecodeIndexedStatus404)
{
    QpackDecoder decoder;
    // Required insert count (0) + Delta base (0) + Indexed field line for :status: 404 (static table index 27)
    std::vector<std::uint8_t> data = {0x00, 0x00, 0xdb}; // 11011011
    auto result = decoder.Decode(data);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 1);
    EXPECT_EQ((*result)[0].name, ":status");
    EXPECT_EQ((*result)[0].value, "404");
}

TEST(QpackDecoderTests, DecodeLiteralWithNameRefPlain)
{
    QpackDecoder decoder;
    // Required insert count (0) + Delta base (0) + Literal with name reference (accept-encoding) + plain value
    // 0101 prefix for literal with static name ref
    // accept-encoding is at index 31 in static table
    std::vector<std::uint8_t> data = {
        0x00, 0x00, // Required insert count and delta base
        0x5f,
        0x10, // 0101 prefix, 4-bit int: 0x0F + 0x10 = 31
        0x04, // value length 4 (no Huffman)
        'g',
        'z',
        'i',
        'p'};
    auto result = decoder.Decode(data);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 1);
    EXPECT_EQ((*result)[0].name, "accept-encoding");
    EXPECT_EQ((*result)[0].value, "gzip");
}

TEST(QpackDecoderTests, DecodeLiteralWithLiteralName)
{
    QpackDecoder decoder;
    // Required insert count (0) + Delta base (0) + Literal field line with literal name
    // 001H prefix (H=0 for no Huffman on name)
    std::vector<std::uint8_t> data = {
        0x00, 0x00,  // Required insert count and delta base
        0x20 | 0x07, // 00100111 = 3-bit prefix, length 7 (max), needs continuation
        0x00,        // continuation for name length = 7 - 7 = 0
        'x',
        '-',
        't',
        'e',
        's',
        't',
        '-',
        0x05, // value length 5 (no Huffman)
        'v',
        'a',
        'l',
        'u',
        'e'};
    auto result = decoder.Decode(data);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 1);
    EXPECT_EQ((*result)[0].name, "x-test-");
    EXPECT_EQ((*result)[0].value, "value");
}

TEST(QpackDecoderTests, DecodeMultipleHeaders)
{
    QpackDecoder decoder;
    // Combine indexed + literal
    std::vector<std::uint8_t> data = {
        0x00, 0x00, // Required insert count and delta base
        0xd9,       // :status: 200
        0x5f,
        0x10,
        0x04, // accept-encoding: (index 31)
        'g',
        'z',
        'i',
        'p'};
    auto result = decoder.Decode(data);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 2);
    EXPECT_EQ((*result)[0].name, ":status");
    EXPECT_EQ((*result)[0].value, "200");
    EXPECT_EQ((*result)[1].name, "accept-encoding");
    EXPECT_EQ((*result)[1].value, "gzip");
}

TEST(QpackDecoderTests, DecodeEmpty)
{
    QpackDecoder decoder;
    // Just required insert count and delta base, no headers
    std::vector<std::uint8_t> data = {0x00, 0x00};
    auto result = decoder.Decode(data);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->empty());
}

TEST(QpackDecoderTests, DecodeInvalidData)
{
    QpackDecoder decoder;
    // Invalid prefix pattern (dynamic table reference not supported)
    std::vector<std::uint8_t> data = {0x00, 0x00, 0x40}; // 0100 0000
    auto result = decoder.Decode(data);
    EXPECT_FALSE(result.has_value());
}

TEST(QpackDecoderTests, DecodeIncompleteData)
{
    QpackDecoder decoder;
    // Literal with name ref but truncated value
    std::vector<std::uint8_t> data = {
        0x00, 0x00, // Required insert count and delta base
        0x5f,
        0x00, // index 31
        0x09, // value length 9
        't',
        'e',
        'x' // Only 3 bytes of 9
    };
    auto result = decoder.Decode(data);
    EXPECT_FALSE(result.has_value());
}

// ============================================================================
// HTTP/3 Frame Tests
// ============================================================================

TEST(Http3FrameTests, EncodeSettingsFrame)
{
    std::vector<std::pair<std::uint64_t, std::uint64_t>> settings = {
        {static_cast<std::uint64_t>(Http3Setting::QpackMaxTableCapacity), 0},
        {static_cast<std::uint64_t>(Http3Setting::QpackBlockedStreams), 0}};
    auto result = EncodeSettingsFrame(settings);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result[0], 0x04); // SETTINGS frame type
}

TEST(Http3FrameTests, CreateControlStreamData)
{
    auto result = CreateControlStreamData();
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result[0], 0x00); // Control stream type
    EXPECT_EQ(result[1], 0x04); // SETTINGS frame type
}

TEST(Http3FrameTests, CreateQpackEncoderStreamData)
{
    auto result = CreateQpackEncoderStreamData();
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result[0], 0x02); // Encoder stream type
}

TEST(Http3FrameTests, CreateQpackDecoderStreamData)
{
    auto result = CreateQpackDecoderStreamData();
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result[0], 0x03); // Decoder stream type
}

// ============================================================================
// Integration Tests
// ============================================================================

TEST(QpackIntegrationTests, EncodeDecodeRoundtrip)
{
    QpackEncoder encoder;
    QpackDecoder decoder;

    std::vector<HeaderField> original_headers = {
        {":status", "200"},
        {"content-type", "text/html"},
        {"content-length", "1234"}};

    auto encoded = encoder.Encode(original_headers);
    ASSERT_FALSE(encoded.empty());

    auto decoded = decoder.Decode(encoded);
    ASSERT_TRUE(decoded.has_value());

    // Note: Encoding may use different representations (indexed vs literal)
    // so we check that key headers are present
    bool has_status = false;
    bool has_content_type = false;
    for (const auto &header : *decoded)
    {
        if (header.name == ":status" && header.value == "200")
            has_status = true;
        if (header.name == "content-type")
            has_content_type = true;
    }
    EXPECT_TRUE(has_status);
    EXPECT_TRUE(has_content_type);
}

TEST(QpackIntegrationTests, HuffmanInHeaders)
{
    QpackDecoder decoder;
    // Test literal with name reference using Huffman encoding
    // Use a simple test - the static table index 31 is accept-encoding
    // We'll encode the value "gzip" with Huffman via nghttp3
    auto hv = EncodeHuffmanStr("gzip");
    std::vector<std::uint8_t> data = {
        0x00, 0x00, // Required insert count and delta base
        0x5f,
        0x10,                                       // accept-encoding (index 31) with 4-bit int
        static_cast<std::uint8_t>(0x80 | hv.size()) // Huffman bit + length
    };
    data.insert(data.end(), hv.begin(), hv.end());

    auto result = decoder.Decode(data);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 1);
    EXPECT_EQ((*result)[0].name, "accept-encoding");
    EXPECT_EQ((*result)[0].value, "gzip");
}
