// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>
#include <util/nla_helpers.h>

#include <cstdint>
#include <cstring>
#include <linux/netlink.h>

using namespace clv::vpn;

// ==================== NlaPut tests ====================

TEST(NlaHelpersTest, NlaPutBasicU32)
{
    alignas(4) char buf[256] = {};
    size_t offset = 0;
    uint32_t val = 0xDEADBEEF;

    ASSERT_TRUE(NlaPut(buf, offset, sizeof(buf), 1, &val, sizeof(val)));

    auto *attr = reinterpret_cast<struct nlattr *>(buf);
    EXPECT_EQ(attr->nla_type, 1);
    EXPECT_EQ(attr->nla_len, NLA_HDRLEN + sizeof(uint32_t));

    uint32_t out = 0;
    std::memcpy(&out, NLA_DATA(attr), sizeof(out));
    EXPECT_EQ(out, 0xDEADBEEF);

    // offset should be aligned
    EXPECT_EQ(offset, NLA_ALIGN(NLA_HDRLEN + sizeof(uint32_t)));
}

TEST(NlaHelpersTest, NlaPutZeroLength)
{
    alignas(4) char buf[64] = {};
    size_t offset = 0;

    ASSERT_TRUE(NlaPut(buf, offset, sizeof(buf), 42, nullptr, 0));

    auto *attr = reinterpret_cast<struct nlattr *>(buf);
    EXPECT_EQ(attr->nla_type, 42);
    EXPECT_EQ(attr->nla_len, NLA_HDRLEN);
    EXPECT_EQ(offset, NLA_ALIGN(NLA_HDRLEN));
}

TEST(NlaHelpersTest, NlaPutMultipleAttributes)
{
    alignas(4) char buf[256] = {};
    size_t offset = 0;

    uint16_t v1 = 0x1234;
    uint32_t v2 = 0xAABBCCDD;

    ASSERT_TRUE(NlaPut(buf, offset, sizeof(buf), 1, &v1, sizeof(v1)));
    size_t first_end = offset;
    ASSERT_TRUE(NlaPut(buf, offset, sizeof(buf), 2, &v2, sizeof(v2)));

    // Second attribute starts where first ended
    auto *attr2 = reinterpret_cast<struct nlattr *>(buf + first_end);
    EXPECT_EQ(attr2->nla_type, 2);

    uint32_t out = 0;
    std::memcpy(&out, NLA_DATA(attr2), sizeof(out));
    EXPECT_EQ(out, 0xAABBCCDD);
}

TEST(NlaHelpersTest, NlaPutBoundsCheckExact)
{
    // Buffer exactly large enough for one u32 attribute
    constexpr size_t needed = NLA_ALIGN(NLA_HDRLEN + sizeof(uint32_t));
    alignas(4) char buf[needed] = {};
    size_t offset = 0;
    uint32_t val = 1;

    ASSERT_TRUE(NlaPut(buf, offset, needed, 1, &val, sizeof(val)));
    EXPECT_EQ(offset, needed);
}

TEST(NlaHelpersTest, NlaPutBoundsCheckOverflow)
{
    // Buffer one byte too small
    constexpr size_t needed = NLA_ALIGN(NLA_HDRLEN + sizeof(uint32_t));
    alignas(4) char buf[needed] = {};
    size_t offset = 0;
    uint32_t val = 1;

    EXPECT_FALSE(NlaPut(buf, offset, needed - 1, 1, &val, sizeof(val)));
    EXPECT_EQ(offset, 0u); // unchanged on failure
}

TEST(NlaHelpersTest, NlaPutBoundsCheckWithOffset)
{
    // Buffer has space for two u32 attrs but offset already past first
    constexpr size_t attr_size = NLA_ALIGN(NLA_HDRLEN + sizeof(uint32_t));
    alignas(4) char buf[attr_size * 2] = {};
    size_t offset = attr_size; // pretend first attr already written
    uint32_t val = 1;

    // Second fits
    ASSERT_TRUE(NlaPut(buf, offset, sizeof(buf), 1, &val, sizeof(val)));

    // Third won't fit
    EXPECT_FALSE(NlaPut(buf, offset, sizeof(buf), 1, &val, sizeof(val)));
}

TEST(NlaHelpersTest, NlaPutOddLengthPadding)
{
    alignas(4) char buf[256] = {};
    size_t offset = 0;
    uint8_t data[3] = {0xAA, 0xBB, 0xCC};

    ASSERT_TRUE(NlaPut(buf, offset, sizeof(buf), 5, data, 3));

    auto *attr = reinterpret_cast<struct nlattr *>(buf);
    EXPECT_EQ(attr->nla_len, NLA_HDRLEN + 3);
    // offset must be 4-byte aligned
    EXPECT_EQ(offset % 4, 0u);
    EXPECT_EQ(offset, NLA_ALIGN(NLA_HDRLEN + 3));
}

// ==================== NlaBeginNested tests ====================

TEST(NlaHelpersTest, NlaBeginNestedBasic)
{
    alignas(4) char buf[256] = {};
    size_t offset = 0;

    auto *nested = NlaBeginNested(buf, offset, sizeof(buf), 10);
    ASSERT_NE(nested, nullptr);

    // Type should have NLA_F_NESTED flag set
    EXPECT_EQ(nested->nla_type, 10 | NLA_F_NESTED);
    EXPECT_EQ(offset, NLA_HDRLEN);

    // Now add a child attribute
    uint32_t child_val = 42;
    ASSERT_TRUE(NlaPut(buf, offset, sizeof(buf), 1, &child_val, sizeof(child_val)));

    // Close the nested: set nla_len to cover header + children
    nested->nla_len = static_cast<decltype(nested->nla_len)>(offset);

    EXPECT_EQ(nested->nla_len, NLA_HDRLEN + NLA_ALIGN(NLA_HDRLEN + sizeof(uint32_t)));
}

TEST(NlaHelpersTest, NlaBeginNestedBoundsCheck)
{
    // Buffer too small for even the header
    alignas(4) char buf[2] = {};
    size_t offset = 0;

    auto *nested = NlaBeginNested(buf, offset, sizeof(buf), 1);
    EXPECT_EQ(nested, nullptr);
    EXPECT_EQ(offset, 0u);
}

TEST(NlaHelpersTest, NlaBeginNestedAtBufferEnd)
{
    // Buffer exactly fits the nested header but nothing else
    alignas(4) char buf[NLA_HDRLEN] = {};
    size_t offset = 0;

    auto *nested = NlaBeginNested(buf, offset, NLA_HDRLEN, 1);
    ASSERT_NE(nested, nullptr);
    EXPECT_EQ(offset, NLA_HDRLEN);

    // Can't fit any child
    uint32_t val = 1;
    EXPECT_FALSE(NlaPut(buf, offset, NLA_HDRLEN, 1, &val, sizeof(val)));
}

TEST(NlaHelpersTest, NlaBeginNestedDoublyNested)
{
    alignas(4) char buf[512] = {};
    size_t offset = 0;

    // Outer nested
    auto *outer = NlaBeginNested(buf, offset, sizeof(buf), 1);
    ASSERT_NE(outer, nullptr);
    size_t outer_start = 0;

    // Inner nested
    size_t inner_start = offset;
    auto *inner = NlaBeginNested(buf, offset, sizeof(buf), 2);
    ASSERT_NE(inner, nullptr);

    // Child inside inner
    uint32_t val = 99;
    ASSERT_TRUE(NlaPut(buf, offset, sizeof(buf), 3, &val, sizeof(val)));

    // Close inner
    inner->nla_len = static_cast<decltype(inner->nla_len)>(offset - inner_start);

    // Close outer
    outer->nla_len = static_cast<decltype(outer->nla_len)>(offset - outer_start);

    // Verify structure
    EXPECT_GT(outer->nla_len, inner->nla_len);
    EXPECT_EQ(outer->nla_type, 1 | NLA_F_NESTED);
    EXPECT_EQ(inner->nla_type, 2 | NLA_F_NESTED);
}

// ==================== NLA macro tests ====================

TEST(NlaHelpersTest, NlaAlignRoundsUp)
{
    EXPECT_EQ(NLA_ALIGN(0), 0u);
    EXPECT_EQ(NLA_ALIGN(1), 4u);
    EXPECT_EQ(NLA_ALIGN(2), 4u);
    EXPECT_EQ(NLA_ALIGN(3), 4u);
    EXPECT_EQ(NLA_ALIGN(4), 4u);
    EXPECT_EQ(NLA_ALIGN(5), 8u);
    EXPECT_EQ(NLA_ALIGN(100), 100u);
    EXPECT_EQ(NLA_ALIGN(101), 104u);
}

TEST(NlaHelpersTest, NlaHdrlenIsAligned)
{
    EXPECT_EQ(NLA_HDRLEN % 4, 0u);
    EXPECT_EQ(NLA_HDRLEN, NLA_ALIGN(sizeof(struct nlattr)));
}
