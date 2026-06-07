// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>

#include <util/ipv6_utils.h>

#include <array>

using namespace clv::vpn::ipv6;

// ================================================================================================
// ParseIpv6
// ================================================================================================

TEST(Ipv6UtilsTest, ParseIpv6Valid)
{
    auto result = ParseIpv6("fd00::1");
    ASSERT_TRUE(result.has_value());
    // fd00::1 — first two bytes are fd 00, last byte is 01, rest zero
    EXPECT_EQ((*result)[0], 0xfd);
    EXPECT_EQ((*result)[1], 0x00);
    EXPECT_EQ((*result)[15], 0x01);
}

TEST(Ipv6UtilsTest, ParseIpv6Loopback)
{
    auto result = ParseIpv6("::1");
    ASSERT_TRUE(result.has_value());
    Ipv6Address expected = {};
    expected[15] = 1;
    EXPECT_EQ(*result, expected);
}

TEST(Ipv6UtilsTest, ParseIpv6AllZeros)
{
    auto result = ParseIpv6("::");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, Ipv6Address{});
}

TEST(Ipv6UtilsTest, ParseIpv6FullAddress)
{
    auto result = ParseIpv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ((*result)[0], 0x20);
    EXPECT_EQ((*result)[1], 0x01);
}

TEST(Ipv6UtilsTest, ParseIpv6Invalid)
{
    EXPECT_FALSE(ParseIpv6("not-an-address").has_value());
    EXPECT_FALSE(ParseIpv6("::gggg").has_value());
    EXPECT_FALSE(ParseIpv6("").has_value());
}

// ================================================================================================
// ParseCidr6
// ================================================================================================

TEST(Ipv6UtilsTest, ParseCidr6Valid)
{
    auto result = ParseCidr6("fd00::/112");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->second, 112);
    EXPECT_EQ(result->first[0], 0xfd);
    EXPECT_EQ(result->first[1], 0x00);
}

TEST(Ipv6UtilsTest, ParseCidr6PrefixBoundaries)
{
    auto r0 = ParseCidr6("::/0");
    ASSERT_TRUE(r0.has_value());
    EXPECT_EQ(r0->second, 0);

    auto r128 = ParseCidr6("::1/128");
    ASSERT_TRUE(r128.has_value());
    EXPECT_EQ(r128->second, 128);
}

TEST(Ipv6UtilsTest, ParseCidr6NoSlash)
{
    EXPECT_FALSE(ParseCidr6("fd00::").has_value());
}

TEST(Ipv6UtilsTest, ParseCidr6BadPrefix)
{
    EXPECT_FALSE(ParseCidr6("fd00::/129").has_value());
    EXPECT_FALSE(ParseCidr6("fd00::/-1").has_value());
    EXPECT_FALSE(ParseCidr6("fd00::/").has_value());
}

TEST(Ipv6UtilsTest, ParseCidr6BadAddress)
{
    EXPECT_FALSE(ParseCidr6("gggg::/64").has_value());
}

TEST(Ipv6UtilsTest, ParseCidr6TrailingChars)
{
    // "64abc" is not a valid integer
    EXPECT_FALSE(ParseCidr6("fd00::/64abc").has_value());
}

// ================================================================================================
// Ipv6MatchesPrefix
// ================================================================================================

TEST(Ipv6UtilsTest, MatchesPrefixLoopback)
{
    auto net = ParseIpv6("::1");
    ASSERT_TRUE(net.has_value());
    EXPECT_TRUE(Ipv6MatchesPrefix(*net, *net, 128));
}

TEST(Ipv6UtilsTest, MatchesPrefixDefaultRoute)
{
    auto ip = ParseIpv6("2001:db8::1");
    ASSERT_TRUE(ip.has_value());
    EXPECT_TRUE(Ipv6MatchesPrefix(*ip, Ipv6Address{}, 0));
}

TEST(Ipv6UtilsTest, MatchesPrefixIn112Subnet)
{
    // fd00::/112 — addresses fd00::0 through fd00::ffff match
    auto net = ParseIpv6("fd00::");
    auto host = ParseIpv6("fd00::a");
    auto outside = ParseIpv6("fd00:0:0:0:0:0:1:0"); // one group too far
    ASSERT_TRUE(net.has_value());
    ASSERT_TRUE(host.has_value());
    ASSERT_TRUE(outside.has_value());

    EXPECT_TRUE(Ipv6MatchesPrefix(*host, *net, 112));
    EXPECT_FALSE(Ipv6MatchesPrefix(*outside, *net, 112));
}

TEST(Ipv6UtilsTest, MatchesPrefixBoundaryBitExact)
{
    // /65: first 65 bits must match
    auto net = *ParseIpv6("fd00::");
    // address with bit 65 set differs
    Ipv6Address differ = net;
    differ[8] = 0x80; // byte 8, bit 0 (= bit 64, the 65th bit)
    EXPECT_FALSE(Ipv6MatchesPrefix(differ, net, 65));

    // address where only bits above 65 differ should still match
    Ipv6Address same_prefix = net;
    same_prefix[9] = 0xFF;
    EXPECT_TRUE(Ipv6MatchesPrefix(same_prefix, net, 65));
}

// ================================================================================================
// NormalizeNetwork
// ================================================================================================

TEST(Ipv6UtilsTest, NormalizeNetworkClearsHostBits)
{
    // fd00::ff with /112 — low byte should be zeroed
    auto addr = *ParseIpv6("fd00::ff");
    auto normalized = NormalizeNetwork(addr, 112);
    auto expected = *ParseIpv6("fd00::");
    EXPECT_EQ(normalized, expected);
}

TEST(Ipv6UtilsTest, NormalizeNetworkFullPrefix)
{
    auto addr = *ParseIpv6("fd00::1");
    auto normalized = NormalizeNetwork(addr, 128);
    EXPECT_EQ(normalized, addr); // host route — no change
}

TEST(Ipv6UtilsTest, NormalizeNetworkZeroPrefix)
{
    auto addr = *ParseIpv6("2001:db8::1");
    auto normalized = NormalizeNetwork(addr, 0);
    EXPECT_EQ(normalized, Ipv6Address{}); // default route — all zeros
}

TEST(Ipv6UtilsTest, NormalizeBoundaryByte)
{
    // /65: byte 8 has boundary at bit 0; all bits in byte 8 from bit 1 onwards are host bits
    auto addr = *ParseIpv6("fd00::");
    Ipv6Address with_host_bits = addr;
    with_host_bits[8] = 0x7F; // low 7 bits of boundary byte are host bits
    with_host_bits[9] = 0xFF;
    auto normalized = NormalizeNetwork(with_host_bits, 65);
    // byte 8: bit 7 (0x80) is network, bits 0-6 are host → masked to 0x00
    EXPECT_EQ(normalized[8], 0x00);
    EXPECT_EQ(normalized[9], 0x00);
}

// ================================================================================================
// Ipv6ToString
// ================================================================================================

TEST(Ipv6UtilsTest, ToStringLoopback)
{
    auto addr = *ParseIpv6("::1");
    EXPECT_EQ(Ipv6ToString(addr), "::1");
}

TEST(Ipv6UtilsTest, ToStringRoundTrip)
{
    std::string_view original = "fd00::1";
    auto addr = ParseIpv6(original);
    ASSERT_TRUE(addr.has_value());
    EXPECT_EQ(Ipv6ToString(*addr), original);
}

TEST(Ipv6UtilsTest, ToStringAllZeros)
{
    EXPECT_EQ(Ipv6ToString(Ipv6Address{}), "::");
}
