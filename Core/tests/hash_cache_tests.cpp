// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>

#include <functional>

#include "hash_cache.h"

using namespace clv;

class HashCacheTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }
};

TEST_F(HashCacheTest, BasicFunctionality)
{
    HashCache<int, int, std::hash<int>, 8> cache;
    cache[1] = 10;
    ASSERT_EQ(cache[1], 10);
    ASSERT_EQ(cache.capacity(), 8u);
}

TEST_F(HashCacheTest, MultipleElements)
{
    HashCache<int, int, std::hash<int>, 8> cache;
    cache[1] = 10;
    cache[2] = 20;
    cache[3] = 30;
    ASSERT_EQ(cache[1], 10);
    ASSERT_EQ(cache[2], 20);
    ASSERT_EQ(cache[3], 30);
    ASSERT_EQ(cache.capacity(), 8u);
}

TEST_F(HashCacheTest, OverWrite)
{
    HashCache<int, int, std::hash<int>, 8> cache;
    cache[1] = 10;
    cache[2] = 20;
    cache[3] = 30;
    cache[4] = 40;
    cache[5] = 50;
    cache[6] = 60;
    cache[7] = 70;
    cache[8] = 80;
    cache[9] = 90;
    ASSERT_EQ(cache[1], 90);
    ASSERT_EQ(cache[9], 90);
    ASSERT_EQ(cache.capacity(), 8u);
}

TEST_F(HashCacheTest, ConstOperatorBracket)
{
    HashCache<int, int, std::hash<int>, 8> cache;
    cache[5] = 55;
    const auto &const_cache = cache;
    EXPECT_EQ(const_cache[5], 55);
    EXPECT_EQ(const_cache.capacity(), 8u);
}

TEST_F(HashCacheTest, CapacityRoundsUpToNextPowerOfTwo)
{
    EXPECT_EQ((HashCache<int, int, std::hash<int>, 1>{}.capacity()), 1u);
    EXPECT_EQ((HashCache<int, int, std::hash<int>, 5>{}.capacity()), 8u);
    EXPECT_EQ((HashCache<int, int, std::hash<int>, 8>{}.capacity()), 8u);
    EXPECT_EQ((HashCache<int, int, std::hash<int>, 9>{}.capacity()), 16u);
    EXPECT_EQ((HashCache<int, int, std::hash<int>, 16>{}.capacity()), 16u);
    EXPECT_EQ((HashCache<int, int, std::hash<int>, 17>{}.capacity()), 32u);
}

TEST_F(HashCacheTest, UnassignedSlotIsWritable)
{
    HashCache<int, int, std::hash<int>, 8> cache;
    cache[99] = 42;
    EXPECT_EQ(cache[99], 42);
}

struct OffsetHash
{
    size_t operator()(int key) const noexcept
    {
        return static_cast<size_t>(key + 1000);
    }
};

TEST_F(HashCacheTest, CustomHasherUsesSlot)
{
    HashCache<int, int, OffsetHash, 4> cache;
    cache[1] = 111;
    cache[2] = 222;
    EXPECT_EQ(cache[1], 111);
    EXPECT_EQ(cache[2], 222);
    EXPECT_EQ(cache.capacity(), 4u);
}

struct SlotValue
{
    int key{0};
    int value{-1};
};

TEST_F(HashCacheTest, StructValueType)
{
    HashCache<int, SlotValue, std::hash<int>, 4> cache;
    cache[7] = SlotValue{7, 700};
    EXPECT_EQ(cache[7].key, 7);
    EXPECT_EQ(cache[7].value, 700);
    cache[3] = SlotValue{3, 300};
    EXPECT_EQ(cache[3].value, 300);
}
