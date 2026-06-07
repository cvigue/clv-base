// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "log_utils.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <span>
#include <vector>

using namespace clv;

class HexDumpTest : public ::testing::Test
{
  protected:
    const std::vector<std::uint8_t> empty_data{};
    const std::vector<std::uint8_t> single_byte{0xAB};
    const std::vector<std::uint8_t> sample_data{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67};
    const std::vector<std::uint8_t> zeros{0x00, 0x00, 0x00};
    const std::vector<std::uint8_t> max_values{0xFF, 0xFF, 0xFF};
};

TEST_F(HexDumpTest, EmptyDataReturnsEmptyString)
{
    EXPECT_EQ(HexDump(empty_data), "");
}

TEST_F(HexDumpTest, SingleByteFormatted)
{
    EXPECT_EQ(HexDump(single_byte), "ab");
}

TEST_F(HexDumpTest, MultipleBytesSeparatedBySpace)
{
    EXPECT_EQ(HexDump(sample_data), "de ad be ef 01 23 45 67");
}

TEST_F(HexDumpTest, ZerosFormattedCorrectly)
{
    EXPECT_EQ(HexDump(zeros), "00 00 00");
}

TEST_F(HexDumpTest, MaxValuesFormattedCorrectly)
{
    EXPECT_EQ(HexDump(max_values), "ff ff ff");
}

TEST_F(HexDumpTest, TruncatesWithEllipsisWhenExceedsMaxBytes)
{
    std::vector<std::uint8_t> large_data(100, 0xAA);
    EXPECT_EQ(HexDump(large_data, 5), "aa aa aa aa aa...");
}

TEST_F(HexDumpTest, NoEllipsisWhenExactlyMaxBytes)
{
    EXPECT_EQ(HexDump(sample_data, 8), "de ad be ef 01 23 45 67");
}

TEST_F(HexDumpTest, NoEllipsisWhenLessThanMaxBytes)
{
    EXPECT_EQ(HexDump(sample_data, 100), "de ad be ef 01 23 45 67");
}

TEST_F(HexDumpTest, CustomSeparatorEmpty)
{
    EXPECT_EQ(HexDump(sample_data, 60, ""), "deadbeef01234567");
}

TEST_F(HexDumpTest, CustomSeparatorColon)
{
    EXPECT_EQ(HexDump(sample_data, 60, ":"), "de:ad:be:ef:01:23:45:67");
}

TEST_F(HexDumpTest, CustomSeparatorMultiChar)
{
    std::vector<std::uint8_t> short_data{0xAA, 0xBB, 0xCC};
    EXPECT_EQ(HexDump(short_data, 60, " | "), "aa | bb | cc");
}

TEST_F(HexDumpTest, NullSeparatorNoSeparation)
{
    EXPECT_EQ(HexDump(sample_data, 60, nullptr), "deadbeef01234567");
}

TEST_F(HexDumpTest, UnlimitedBytesWithZeroMaxBytes)
{
    std::vector<std::uint8_t> large_data(100, 0xBB);
    auto result = HexDump(large_data, 0, "");
    EXPECT_EQ(result.size(), 200u); // 2 hex chars per byte, no separators
    EXPECT_TRUE(result.find("...") == std::string::npos);
}

TEST_F(HexDumpTest, SpanOverloadWorks)
{
    std::span<const std::uint8_t> span_data(sample_data);
    EXPECT_EQ(HexDump(span_data), "de ad be ef 01 23 45 67");
}

TEST_F(HexDumpTest, VectorOverloadWorks)
{
    EXPECT_EQ(HexDump(sample_data), "de ad be ef 01 23 45 67");
}

TEST_F(HexDumpTest, LowercaseHexOutput)
{
    std::vector<std::uint8_t> data{0xAB, 0xCD, 0xEF};
    auto result = HexDump(data);
    EXPECT_EQ(result, "ab cd ef");
    EXPECT_TRUE(result.find('A') == std::string::npos);
}

TEST_F(HexDumpTest, MaxBytesOneShowsOneByte)
{
    EXPECT_EQ(HexDump(sample_data, 1), "de...");
}

TEST_F(HexDumpTest, LargeDataDefaultMaxBytes)
{
    std::vector<std::uint8_t> large_data(100, 0x42);
    auto result = HexDump(large_data); // default max_bytes=60
    size_t space_count = std::count(result.begin(), result.end(), ' ');
    EXPECT_EQ(space_count, 59u); // 59 separators between 60 bytes
    EXPECT_TRUE(result.ends_with("..."));
}
