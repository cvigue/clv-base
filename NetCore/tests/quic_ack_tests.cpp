// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "quic/quic_ack.h"

#include <gtest/gtest.h>
#include <set>

using namespace clv::quic;

// ================================================================================================
// AckRange Tests
// ================================================================================================

TEST(AckRangeTests, Contains_SinglePacket)
{
    AckRange range{5, 5};
    EXPECT_TRUE(range.Contains(5));
    EXPECT_FALSE(range.Contains(4));
    EXPECT_FALSE(range.Contains(6));
}

TEST(AckRangeTests, Contains_MultiplePackets)
{
    AckRange range{10, 15};
    EXPECT_TRUE(range.Contains(10));
    EXPECT_TRUE(range.Contains(12));
    EXPECT_TRUE(range.Contains(15));
    EXPECT_FALSE(range.Contains(9));
    EXPECT_FALSE(range.Contains(16));
}

TEST(AckRangeTests, Count)
{
    EXPECT_EQ((AckRange{5, 5}.Count()), 1u);
    EXPECT_EQ((AckRange{10, 15}.Count()), 6u);
    EXPECT_EQ((AckRange{100, 200}.Count()), 101u);
}

TEST(AckRangeTests, IsAdjacentTo)
{
    AckRange range1{10, 15};
    AckRange range2{16, 20}; // Adjacent (15+1 == 16)
    AckRange range3{5, 9};   // Adjacent (9+1 == 10)
    AckRange range4{17, 20}; // Not adjacent (gap)

    EXPECT_TRUE(range1.IsAdjacentTo(range2));
    EXPECT_TRUE(range1.IsAdjacentTo(range3));
    EXPECT_FALSE(range1.IsAdjacentTo(range4));
}

TEST(AckRangeTests, Overlaps)
{
    AckRange range1{10, 20};
    AckRange range2{15, 25}; // Overlaps
    AckRange range3{5, 12};  // Overlaps
    AckRange range4{25, 30}; // No overlap

    EXPECT_TRUE(range1.Overlaps(range2));
    EXPECT_TRUE(range1.Overlaps(range3));
    EXPECT_FALSE(range1.Overlaps(range4));
}

TEST(AckRangeTests, Merge)
{
    AckRange range1{10, 15};
    AckRange range2{16, 20};
    auto merged = range1.Merge(range2);

    EXPECT_EQ(merged.start, 10u);
    EXPECT_EQ(merged.end, 20u);
}

// ================================================================================================
// AckRangeSet Tests
// ================================================================================================

TEST(AckRangeSetTests, AddPacketNumber_Single)
{
    AckRangeSet ack_set;
    ack_set.AddPacketNumber(5);

    EXPECT_TRUE(ack_set.Contains(5));
    EXPECT_FALSE(ack_set.Contains(4));
    EXPECT_EQ(ack_set.RangeCount(), 1u);
    EXPECT_EQ(ack_set.TotalCount(), 1u);
}

TEST(AckRangeSetTests, AddPacketNumber_Consecutive)
{
    AckRangeSet ack_set;
    ack_set.AddPacketNumber(5);
    ack_set.AddPacketNumber(6);
    ack_set.AddPacketNumber(7);

    // Should merge into single range
    EXPECT_EQ(ack_set.RangeCount(), 1u);
    EXPECT_EQ(ack_set.TotalCount(), 3u);
    EXPECT_TRUE(ack_set.Contains(5));
    EXPECT_TRUE(ack_set.Contains(6));
    EXPECT_TRUE(ack_set.Contains(7));

    const auto &ranges = ack_set.GetRanges();
    ASSERT_EQ(ranges.size(), 1u);
    EXPECT_EQ(ranges[0].start, 5u);
    EXPECT_EQ(ranges[0].end, 7u);
}

TEST(AckRangeSetTests, AddPacketNumber_NonConsecutive)
{
    AckRangeSet ack_set;
    ack_set.AddPacketNumber(5);
    ack_set.AddPacketNumber(10);
    ack_set.AddPacketNumber(15);

    // Should create separate ranges
    EXPECT_EQ(ack_set.RangeCount(), 3u);
    EXPECT_EQ(ack_set.TotalCount(), 3u);
    EXPECT_TRUE(ack_set.Contains(5));
    EXPECT_TRUE(ack_set.Contains(10));
    EXPECT_TRUE(ack_set.Contains(15));
    EXPECT_FALSE(ack_set.Contains(7));
}

TEST(AckRangeSetTests, AddPacketNumber_Duplicate)
{
    AckRangeSet ack_set;
    ack_set.AddPacketNumber(5);
    ack_set.AddPacketNumber(5); // Duplicate

    EXPECT_EQ(ack_set.RangeCount(), 1u);
    EXPECT_EQ(ack_set.TotalCount(), 1u);
}

TEST(AckRangeSetTests, AddPacketNumber_ExtendRange)
{
    AckRangeSet ack_set;
    ack_set.AddPacketNumber(10);
    ack_set.AddPacketNumber(11);
    ack_set.AddPacketNumber(9); // Extend backwards

    EXPECT_EQ(ack_set.RangeCount(), 1u);
    const auto &ranges = ack_set.GetRanges();
    EXPECT_EQ(ranges[0].start, 9u);
    EXPECT_EQ(ranges[0].end, 11u);
}

TEST(AckRangeSetTests, AddPacketNumber_FillGap)
{
    AckRangeSet ack_set;
    ack_set.AddPacketNumber(5);
    ack_set.AddPacketNumber(7);
    ack_set.AddPacketNumber(6); // Fill gap

    // Should merge into single range
    EXPECT_EQ(ack_set.RangeCount(), 1u);
    const auto &ranges = ack_set.GetRanges();
    EXPECT_EQ(ranges[0].start, 5u);
    EXPECT_EQ(ranges[0].end, 7u);
}

TEST(AckRangeSetTests, AddRange)
{
    AckRangeSet ack_set;
    ack_set.AddRange(10, 15);

    EXPECT_EQ(ack_set.RangeCount(), 1u);
    EXPECT_EQ(ack_set.TotalCount(), 6u);
    EXPECT_TRUE(ack_set.Contains(10));
    EXPECT_TRUE(ack_set.Contains(15));
    EXPECT_FALSE(ack_set.Contains(9));
    EXPECT_FALSE(ack_set.Contains(16));
}

TEST(AckRangeSetTests, AddRange_Overlapping)
{
    AckRangeSet ack_set;
    ack_set.AddRange(10, 15);
    ack_set.AddRange(12, 20);

    // Should merge
    EXPECT_EQ(ack_set.RangeCount(), 1u);
    const auto &ranges = ack_set.GetRanges();
    EXPECT_EQ(ranges[0].start, 10u);
    EXPECT_EQ(ranges[0].end, 20u);
}

TEST(AckRangeSetTests, AddRange_Adjacent)
{
    AckRangeSet ack_set;
    ack_set.AddRange(10, 15);
    ack_set.AddRange(16, 20);

    // Should merge adjacent ranges
    EXPECT_EQ(ack_set.RangeCount(), 1u);
    const auto &ranges = ack_set.GetRanges();
    EXPECT_EQ(ranges[0].start, 10u);
    EXPECT_EQ(ranges[0].end, 20u);
}

TEST(AckRangeSetTests, GetLargest)
{
    AckRangeSet ack_set;
    EXPECT_EQ(ack_set.GetLargest(), 0u); // Empty

    ack_set.AddPacketNumber(10);
    EXPECT_EQ(ack_set.GetLargest(), 10u);

    ack_set.AddPacketNumber(5);
    EXPECT_EQ(ack_set.GetLargest(), 10u); // Still 10

    ack_set.AddPacketNumber(20);
    EXPECT_EQ(ack_set.GetLargest(), 20u); // Now 20
}

TEST(AckRangeSetTests, Clear)
{
    AckRangeSet ack_set;
    ack_set.AddPacketNumber(5);
    ack_set.AddPacketNumber(10);

    EXPECT_EQ(ack_set.RangeCount(), 2u);

    ack_set.Clear();
    EXPECT_EQ(ack_set.RangeCount(), 0u);
    EXPECT_FALSE(ack_set.Contains(5));
    EXPECT_FALSE(ack_set.Contains(10));
}

TEST(AckRangeSetTests, FromPacketNumbers)
{
    std::set<std::uint64_t> packet_numbers = {1, 2, 3, 5, 6, 10};
    auto ack_set = AckRangeSet::FromPacketNumbers(packet_numbers);

    EXPECT_EQ(ack_set.RangeCount(), 3u); // [1-3], [5-6], [10]
    EXPECT_TRUE(ack_set.Contains(1));
    EXPECT_TRUE(ack_set.Contains(3));
    EXPECT_FALSE(ack_set.Contains(4));
    EXPECT_TRUE(ack_set.Contains(5));
    EXPECT_TRUE(ack_set.Contains(10));
}

TEST(AckRangeSetTests, RangesSortedDescending)
{
    AckRangeSet ack_set;
    ack_set.AddPacketNumber(5);
    ack_set.AddPacketNumber(10);
    ack_set.AddPacketNumber(15);

    const auto &ranges = ack_set.GetRanges();
    // Ranges should be sorted in descending order (highest first)
    ASSERT_EQ(ranges.size(), 3u);
    EXPECT_EQ(ranges[0].start, 15u);
    EXPECT_EQ(ranges[1].start, 10u);
    EXPECT_EQ(ranges[2].start, 5u);
}

TEST(AckRangeSetTests, ComplexScenario)
{
    AckRangeSet ack_set;

    // Add packets: 1, 2, 3, 5, 6, 7, 10, 15, 16, 17
    for (std::uint64_t pn : {1, 2, 3, 5, 6, 7, 10, 15, 16, 17})
    {
        ack_set.AddPacketNumber(pn);
    }

    EXPECT_EQ(ack_set.RangeCount(), 4u); // [1-3], [5-7], [10], [15-17]
    EXPECT_EQ(ack_set.TotalCount(), 10u);
    EXPECT_EQ(ack_set.GetLargest(), 17u);

    const auto &ranges = ack_set.GetRanges();
    ASSERT_EQ(ranges.size(), 4u);

    // Check ranges (sorted descending)
    EXPECT_EQ(ranges[0].start, 15u);
    EXPECT_EQ(ranges[0].end, 17u);
    EXPECT_EQ(ranges[1].start, 10u);
    EXPECT_EQ(ranges[1].end, 10u);
    EXPECT_EQ(ranges[2].start, 5u);
    EXPECT_EQ(ranges[2].end, 7u);
    EXPECT_EQ(ranges[3].start, 1u);
    EXPECT_EQ(ranges[3].end, 3u);
}

TEST(AckRangeSetTests, OutOfOrderInsertionAndMerging)
{
    AckRangeSet ack_set;

    // Add in random order
    ack_set.AddPacketNumber(10);
    ack_set.AddPacketNumber(5);
    ack_set.AddPacketNumber(7);
    ack_set.AddPacketNumber(6);
    ack_set.AddPacketNumber(8);
    ack_set.AddPacketNumber(9);

    // Should merge into two ranges: [5-10]
    EXPECT_EQ(ack_set.RangeCount(), 1u);
    const auto &ranges = ack_set.GetRanges();
    EXPECT_EQ(ranges[0].start, 5u);
    EXPECT_EQ(ranges[0].end, 10u);
}
