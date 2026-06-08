// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <string>
#include <tuple>

#include "lru_cache.h"

using namespace clv;
using namespace std::literals;

template <typename PairT>
class LruCacheTest : public ::testing::Test
{
  protected:
    using KeyT = typename PairT::first_type;
    using ValueT = typename PairT::second_type;
    LruCache<KeyT, ValueT> cache{2};

    void SetUp() override
    {
        // Initial setup if needed
    }

    void TearDown() override
    {
        // Cleanup if needed
    }
};

using TestTypes = ::testing::Types<
    std::pair<int, std::string>,
    std::pair<int, int>,
    std::pair<std::string, std::string>>;

static auto test_data = std::make_tuple(
    std::array<std::pair<int, std::string>, 4>{
        std::make_pair(1, "one"s),
        std::make_pair(2, "two"s),
        std::make_pair(3, "three"s),
        std::make_pair(4, "four"s)},
    std::array<std::pair<int, int>, 4>{
        std::make_pair(1, 1),
        std::make_pair(2, 2),
        std::make_pair(3, 3),
        std::make_pair(4, 4)},
    std::array<std::pair<std::string, std::string>, 4>{
        std::make_pair("one"s, "one"s),
        std::make_pair("two"s, "two"s),
        std::make_pair("three"s, "three"s),
        std::make_pair("four"s, "four"s)});

TYPED_TEST_SUITE(LruCacheTest, TestTypes);

TYPED_TEST(LruCacheTest, BasicPutAndGet)
{
    using KeyT = typename TypeParam::first_type;
    using ValueT = typename TypeParam::second_type;

    auto data = std::get<std::array<std::pair<KeyT, ValueT>, 4>>(test_data);

    LruCache<KeyT, ValueT> cache(2);
    EXPECT_FALSE(cache.put(data[0].first, data[0].second));
    EXPECT_EQ(cache.get(data[0].first).value(), data[0].second);
    EXPECT_FALSE(cache.put(data[1].first, data[1].second));
    EXPECT_EQ(cache.get(data[1].first).value(), data[1].second);
}

TYPED_TEST(LruCacheTest, UpdateExistingKey)
{
    using KeyT = typename TypeParam::first_type;
    using ValueT = typename TypeParam::second_type;

    auto data = std::get<std::array<std::pair<KeyT, ValueT>, 4>>(test_data);

    LruCache<KeyT, ValueT> cache(2);
    cache.put(data[0].first, data[0].second);
    EXPECT_TRUE(cache.put(data[0].first, data[1].second));
    EXPECT_EQ(cache.get(data[0].first).value(), data[1].second);
}

TYPED_TEST(LruCacheTest, ExceedingCapacity)
{
    using KeyT = typename TypeParam::first_type;
    using ValueT = typename TypeParam::second_type;

    auto data = std::get<std::array<std::pair<KeyT, ValueT>, 4>>(test_data);

    LruCache<KeyT, ValueT> cache(2);
    cache.put(data[0].first, data[0].second);
    cache.put(data[1].first, data[1].second);
    EXPECT_FALSE(cache.put(data[2].first, data[2].second));
    EXPECT_FALSE(cache.get(data[0].first).has_value()); // should be evicted
    EXPECT_EQ(cache.get(data[2].first).value(), data[2].second);
    EXPECT_EQ(cache.get(data[1].first).value(), data[1].second);
}

TYPED_TEST(LruCacheTest, GetTypesCorrect)
{
    using KeyT = typename TypeParam::first_type;
    using ValueT = typename TypeParam::second_type;

    LruCache<KeyT, ValueT> cache(2);

    auto data = std::get<std::array<std::pair<KeyT, ValueT>, 4>>(test_data);

    EXPECT_TRUE((std::is_same_v<decltype(cache.get(data[0].first)), optional_ref<ValueT &>>));
    EXPECT_FALSE((std::is_same_v<decltype(cache.get(data[0].first)), optional_ref<const ValueT &>>));
}

TYPED_TEST(LruCacheTest, PutAndGet)
{
    using KeyT = typename TypeParam::first_type;
    using ValueT = typename TypeParam::second_type;

    auto data = std::get<std::array<std::pair<KeyT, ValueT>, 4>>(test_data);

    LruCache<KeyT, ValueT> cache(2);

    EXPECT_FALSE(cache.put(data[0].first, data[0].second));
    EXPECT_FALSE(cache.put(data[1].first, data[1].second));
    EXPECT_EQ(cache.get(data[0].first).value(), data[0].second);
    EXPECT_EQ(cache.get(data[1].first).value(), data[1].second);
}

TYPED_TEST(LruCacheTest, CapacityLimit)
{
    using KeyT = typename TypeParam::first_type;
    using ValueT = typename TypeParam::second_type;

    auto data = std::get<std::array<std::pair<KeyT, ValueT>, 4>>(test_data);

    LruCache<KeyT, ValueT> cache(2);

    EXPECT_FALSE(cache.put(data[0].first, data[0].second));
    EXPECT_FALSE(cache.put(data[1].first, data[1].second));
    EXPECT_FALSE(cache.put(data[2].first, data[2].second)); // evicts key 1
    EXPECT_EQ(cache.get(data[0].first), std::nullopt);
    EXPECT_EQ(cache.get(data[2].first).value(), data[2].second);
}

TYPED_TEST(LruCacheTest, LRUOrder)
{
    using KeyT = typename TypeParam::first_type;
    using ValueT = typename TypeParam::second_type;

    auto data = std::get<std::array<std::pair<KeyT, ValueT>, 4>>(test_data);

    LruCache<KeyT, ValueT> cache(2);

    EXPECT_FALSE(cache.put(data[0].first, data[0].second));
    EXPECT_FALSE(cache.put(data[1].first, data[1].second));
    EXPECT_FALSE(cache.put(data[2].first, data[2].second)); // evicts key 1
    EXPECT_TRUE(cache.put(data[1].first, data[3].second));
    EXPECT_FALSE(cache.put(data[3].first, data[3].second)); // evicts key 2
    EXPECT_FALSE(cache.get(data[2].first));
    EXPECT_TRUE(cache.get(data[3].first));
    EXPECT_EQ(*cache.get(data[3].first), data[3].second);
}

TYPED_TEST(LruCacheTest, MoveSemanticsPut)
{
    using KeyT = typename TypeParam::first_type;
    using ValueT = typename TypeParam::second_type;

    auto data = std::get<std::array<std::pair<KeyT, ValueT>, 4>>(test_data);

    LruCache<KeyT, ValueT> cache(2);

    ValueT value = data[0].second;
    EXPECT_FALSE(cache.put(data[0].first, std::move(value)));
    EXPECT_EQ(cache.get(data[0].first).value(), data[0].second);
}

TYPED_TEST(LruCacheTest, MoveSemanticsUpdate)
{
    using KeyT = typename TypeParam::first_type;
    using ValueT = typename TypeParam::second_type;

    auto data = std::get<std::array<std::pair<KeyT, ValueT>, 4>>(test_data);

    LruCache<KeyT, ValueT> cache(2);

    cache.put(data[0].first, data[0].second);
    ValueT value = data[1].second;
    EXPECT_TRUE(cache.put(data[0].first, std::move(value)));
    EXPECT_EQ(cache.get(data[0].first).value(), data[1].second);
}

TYPED_TEST(LruCacheTest, CopySemanticsPut)
{
    using KeyT = typename TypeParam::first_type;
    using ValueT = typename TypeParam::second_type;

    auto data = std::get<std::array<std::pair<KeyT, ValueT>, 4>>(test_data);

    LruCache<KeyT, ValueT> cache(2);

    ValueT value = data[0].second;
    EXPECT_FALSE(cache.put(data[0].first, value));
    EXPECT_EQ(cache.get(data[0].first).value(), data[0].second);
}

TYPED_TEST(LruCacheTest, CopySemanticsUpdate)
{
    using KeyT = typename TypeParam::first_type;
    using ValueT = typename TypeParam::second_type;

    auto data = std::get<std::array<std::pair<KeyT, ValueT>, 4>>(test_data);

    LruCache<KeyT, ValueT> cache(2);

    cache.put(data[0].first, data[0].second);
    ValueT value = data[1].second;
    EXPECT_TRUE(cache.put(data[0].first, value));
    EXPECT_EQ(cache.get(data[0].first).value(), data[1].second);
}

TYPED_TEST(LruCacheTest, GetUpdate)
{
    using KeyT = typename TypeParam::first_type;
    using ValueT = typename TypeParam::second_type;

    auto data = std::get<std::array<std::pair<KeyT, ValueT>, 4>>(test_data);

    LruCache<KeyT, ValueT> cache(2);

    cache.put(data[0].first, data[0].second);
    auto ref = cache.get(data[0].first);
    ASSERT_TRUE(ref.has_value());
    ref.value() = data[1].second;
    EXPECT_EQ(cache.get(data[0].first).value(), data[1].second);
}

TYPED_TEST(LruCacheTest, GetNoUpdate)
{
    using KeyT = typename TypeParam::first_type;
    using ValueT = typename TypeParam::second_type;

    auto data = std::get<std::array<std::pair<KeyT, ValueT>, 4>>(test_data);

    LruCache<KeyT, ValueT> cache(2);

    cache.put(data[0].first, data[0].second);
    auto ref = cache.get(data[0].first);
    ASSERT_TRUE(ref.has_value());
    EXPECT_EQ(cache.get(data[0].first).value(), data[0].second);
}

TYPED_TEST(LruCacheTest, GetNoUpdateEvictionCheck)
{
    using KeyT = typename TypeParam::first_type;
    using ValueT = typename TypeParam::second_type;

    auto data = std::get<std::array<std::pair<KeyT, ValueT>, 4>>(test_data);

    LruCache<KeyT, ValueT> cache(2);

    cache.put(data[0].first, data[0].second);
    cache.put(data[1].first, data[1].second);
    auto ref = cache.get(data[0].first); // Now MRU
    ASSERT_TRUE(ref.has_value());
    cache.put(data[2].first, data[2].second); // Evict LRU
    EXPECT_EQ(cache.get(data[0].first).value(), data[0].second);
    EXPECT_FALSE(cache.get(data[1].first));
    EXPECT_EQ(cache.get(data[2].first).value(), data[2].second);
}

TYPED_TEST(LruCacheTest, GetUpdateEvictionCheck)
{
    using KeyT = typename TypeParam::first_type;
    using ValueT = typename TypeParam::second_type;

    auto data = std::get<std::array<std::pair<KeyT, ValueT>, 4>>(test_data);

    LruCache<KeyT, ValueT> cache(2);

    cache.put(data[0].first, data[0].second);
    cache.put(data[1].first, data[1].second);
    auto ref = cache.get(data[0].first); // Now MRU
    ASSERT_TRUE(ref.has_value());
    ref.value() = data[2].second;
    cache.put(data[3].first, data[3].second);
    EXPECT_FALSE(cache.get(data[1].first));
    EXPECT_EQ(cache.get(data[0].first).value(), data[2].second);
    EXPECT_EQ(cache.get(data[3].first).value(), data[3].second);
}

TYPED_TEST(LruCacheTest, PeekTypesCorrect)
{
    using KeyT = typename TypeParam::first_type;
    using ValueT = typename TypeParam::second_type;

    LruCache<KeyT, ValueT> cache(2);

    auto data = std::get<std::array<std::pair<KeyT, ValueT>, 4>>(test_data);

    EXPECT_TRUE((std::is_same_v<decltype(cache.peek(data[0].first)), optional_ref<const ValueT &>>));
    EXPECT_FALSE((std::is_same_v<decltype(cache.peek(data[0].first)), optional_ref<ValueT &>>));
}

TYPED_TEST(LruCacheTest, PeekExistingKey)
{
    using KeyT = typename TypeParam::first_type;
    using ValueT = typename TypeParam::second_type;

    auto data = std::get<std::array<std::pair<KeyT, ValueT>, 4>>(test_data);

    LruCache<KeyT, ValueT> cache(2);

    cache.put(data[0].first, data[0].second);
    EXPECT_EQ(cache.peek(data[0].first).value(), data[0].second);
}

TYPED_TEST(LruCacheTest, OperatorBracketDelegatesToGet)
{
    using KeyT = typename TypeParam::first_type;
    using ValueT = typename TypeParam::second_type;

    auto data = std::get<std::array<std::pair<KeyT, ValueT>, 4>>(test_data);

    LruCache<KeyT, ValueT> cache(2);
    cache.put(data[0].first, data[0].second);
    cache.put(data[1].first, data[1].second);
    ASSERT_TRUE(cache[data[0].first].has_value());
    cache.put(data[2].first, data[2].second);
    EXPECT_TRUE(cache[data[0].first].has_value());
    EXPECT_FALSE(cache[data[1].first].has_value());
}

TYPED_TEST(LruCacheTest, RvaluePutInsert)
{
    using KeyT = typename TypeParam::first_type;
    using ValueT = typename TypeParam::second_type;

    auto data = std::get<std::array<std::pair<KeyT, ValueT>, 4>>(test_data);

    LruCache<KeyT, ValueT> cache(2);
    KeyT key = data[0].first;
    ValueT value = data[0].second;
    EXPECT_FALSE(cache.put(std::move(key), std::move(value)));
    EXPECT_EQ(cache.get(data[0].first).value(), data[0].second);
}

TYPED_TEST(LruCacheTest, RvaluePutUpdate)
{
    using KeyT = typename TypeParam::first_type;
    using ValueT = typename TypeParam::second_type;

    auto data = std::get<std::array<std::pair<KeyT, ValueT>, 4>>(test_data);

    LruCache<KeyT, ValueT> cache(2);
    cache.put(data[0].first, data[0].second);
    KeyT key = data[0].first;
    ValueT value = data[1].second;
    EXPECT_TRUE(cache.put(std::move(key), std::move(value)));
    EXPECT_EQ(cache.get(data[0].first).value(), data[1].second);
}

TYPED_TEST(LruCacheTest, EraseRemovesEntry)
{
    using KeyT = typename TypeParam::first_type;
    using ValueT = typename TypeParam::second_type;

    auto data = std::get<std::array<std::pair<KeyT, ValueT>, 4>>(test_data);

    LruCache<KeyT, ValueT> cache(2);
    cache.put(data[0].first, data[0].second);
    EXPECT_TRUE(cache.erase(data[0].first));
    EXPECT_FALSE(cache.get(data[0].first).has_value());
    EXPECT_FALSE(cache.erase(data[0].first));
}

TEST(LruCachePinnedKeyTest, PinnedSurvivesEviction)
{
    LruCache<int, int> cache(2);
    cache.set_pinned_key(1);
    cache.put(1, 100);
    cache.put(2, 200);
    cache.put(3, 300);
    EXPECT_EQ(cache.get(1).value(), 100);
    EXPECT_FALSE(cache.get(2).has_value());
    EXPECT_EQ(cache.get(3).value(), 300);
}

TEST(LruCachePinnedKeyTest, SetPinnedKeyCanBeCleared)
{
    LruCache<int, int> cache(2);
    cache.set_pinned_key(1);
    cache.put(1, 100);
    cache.put(2, 200);
    cache.set_pinned_key(std::nullopt);
    cache.put(3, 300);
    EXPECT_FALSE(cache.get(1).has_value());
    EXPECT_TRUE(cache.get(2).has_value());
    EXPECT_TRUE(cache.get(3).has_value());
}

TEST(LruCachePinnedKeyTest, AllPinnedFallbackEvictsAnyway)
{
    LruCache<int, int> cache(1);
    cache.set_pinned_key(1);
    EXPECT_FALSE(cache.put(1, 100));
    EXPECT_EQ(cache.size(), 1u);
    EXPECT_FALSE(cache.put(2, 200));
    EXPECT_EQ(cache.size(), 1u);
    EXPECT_FALSE(cache.get(1).has_value());
    EXPECT_EQ(cache.get(2).value(), 200);
}

TEST(LruCacheCapacityTest, ZeroCapacityDefaultsToOne)
{
    LruCache<int, int> cache(0);
    EXPECT_EQ(cache.capacity(), 1u);
    EXPECT_FALSE(cache.put(1, 100));
    EXPECT_EQ(cache.size(), 1u);
    EXPECT_FALSE(cache.put(2, 200));
    EXPECT_EQ(cache.size(), 1u);
    EXPECT_FALSE(cache.get(1).has_value());
    EXPECT_EQ(cache.get(2).value(), 200);
}

TEST(LruCacheCapacityTest, SizeTracksOccupancy)
{
    LruCache<int, int> cache(3);
    EXPECT_EQ(cache.size(), 0u);
    cache.put(1, 100);
    EXPECT_EQ(cache.size(), 1u);
    cache.put(2, 200);
    EXPECT_EQ(cache.size(), 2u);
    cache.erase(1);
    EXPECT_EQ(cache.size(), 1u);
}

TEST(LruCacheLookupTest, GetMissingKeyReturnsNullopt)
{
    LruCache<int, int> cache(2);
    EXPECT_FALSE(cache.get(42).has_value());
    cache.put(1, 100);
    EXPECT_FALSE(cache.get(99).has_value());
}

TEST(LruCacheLookupTest, PeekMissingKeyReturnsNullopt)
{
    LruCache<int, int> cache(2);
    EXPECT_FALSE(cache.peek(42).has_value());
}

TEST(LruCacheLookupTest, PeekDoesNotPromoteEntry)
{
    LruCache<int, int> cache(2);
    cache.put(1, 100);
    cache.put(2, 200);
    ASSERT_TRUE(cache.peek(1).has_value());
    EXPECT_EQ(cache.peek(1).value(), 100);
    cache.put(3, 300);
    EXPECT_FALSE(cache.get(1).has_value()) << "peek must not refresh LRU order";
    EXPECT_TRUE(cache.get(2).has_value());
    EXPECT_TRUE(cache.get(3).has_value());
}

TEST(LruCacheLookupTest, EraseFreesSlotForInsert)
{
    LruCache<int, int> cache(2);
    cache.put(1, 100);
    cache.put(2, 200);
    ASSERT_TRUE(cache.erase(1));
    cache.put(3, 300);
    EXPECT_TRUE(cache.get(2).has_value());
    EXPECT_TRUE(cache.get(3).has_value());
    EXPECT_EQ(cache.size(), 2u);
}

struct ArrayKey
{
    std::array<int, 2> bytes{};

    bool operator==(const ArrayKey &other) const noexcept
    {
        return bytes == other.bytes;
    }
};

struct ArrayKeyHash
{
    size_t operator()(const ArrayKey &key) const noexcept
    {
        return static_cast<size_t>(key.bytes[0]) << 8 | static_cast<size_t>(key.bytes[1]);
    }
};

TEST(LruCacheHashTest, CustomHasherWorks)
{
    LruCache<ArrayKey, int, ArrayKeyHash> cache(2);
    ArrayKey k1{{1, 2}};
    ArrayKey k2{{3, 4}};
    EXPECT_FALSE(cache.put(k1, 10));
    EXPECT_FALSE(cache.put(k2, 20));
    EXPECT_EQ(cache.get(k1).value(), 10);
    EXPECT_EQ(cache.get(k2).value(), 20);
}
