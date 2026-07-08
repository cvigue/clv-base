// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>

#include "parse_intake.h"

using namespace clv;

TEST(ParseIntakeTest, ParseBoundedSignedSuccess)
{
    EXPECT_EQ(ParseBounded<int>("42", 0, 100), 42);
    EXPECT_EQ(ParseBounded<int>("-5", -10, 10), -5);
}

TEST(ParseIntakeTest, ParseBoundedSignedFailure)
{
    EXPECT_FALSE(ParseBounded<int>("abc", 0, 100).has_value());
    EXPECT_EQ(ParseBounded<int>("abc", 0, 100).error(), ParseError::NotInteger);
    EXPECT_EQ(ParseBounded<int>("200", 0, 100).error(), ParseError::OutOfRange);
    EXPECT_EQ(ParseBounded<int>("12.5", 0, 100).error(), ParseError::NotInteger);
}

TEST(ParseIntakeTest, ParseBoundedUnsignedSuccess)
{
    EXPECT_EQ(ParseBounded<std::uint16_t>("65535", 1, 65535), 65535);
}

TEST(ParseIntakeTest, ParseBoundedOrThrow)
{
    EXPECT_EQ(ParseBoundedOrThrow<int>("7", 0, 10, {.source = "Test", .field = "port"},
                                       [](const std::string &msg)
                                       { return std::runtime_error(msg); }),
              7);
    EXPECT_THROW([[maybe_unused]]auto x = ParseBoundedOrThrow<int>("999", 0, 10, {.source = "Test", .field = "port"},
                                         [](const std::string &msg)
                                         { return std::runtime_error(msg); }),
                 std::runtime_error);
}

TEST(ParseIntakeTest, RequireJsonInt)
{
    const nlohmann::json json = {{"port", 8443}, {"bad", "x"}, {"big", 999999}};
    EXPECT_EQ(*RequireJsonInt<std::uint16_t>(json, "port", 1, 65535), 8443);
    EXPECT_EQ(RequireJsonInt<int>(json, "bad", 0, 10).error(), ParseError::NotInteger);
    EXPECT_EQ(RequireJsonInt<std::uint16_t>(json, "big", 1, 100).error(), ParseError::OutOfRange);
}

TEST(ParseIntakeTest, ParseAffinityField)
{
    nlohmann::json json = {{"cpu_affinity", "off"}, {"rx_thread_affinity", "auto"}, {"tx_thread_affinity", 3}};
    int cpu = 0;
    int rx = 0;
    int tx = 0;
    ParseAffinityField(json, "cpu_affinity", cpu);
    ParseAffinityField(json, "rx_thread_affinity", rx);
    ParseAffinityField(json, "tx_thread_affinity", tx);
    EXPECT_EQ(cpu, -1);
    EXPECT_EQ(rx, -2);
    EXPECT_EQ(tx, 3);
}
