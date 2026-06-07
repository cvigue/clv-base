// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>

#include "static_vector.h"

#include <algorithm>
#include <numeric>
#include <span>
#include <stdexcept>
#include <vector>

using namespace clv;

// ================================================================================================
// Construction
// ================================================================================================

TEST(StaticVector, default_construct_empty)
{
    StaticVector<int, 8> v;
    EXPECT_EQ(v.size(), 0u);
    EXPECT_EQ(v.capacity(), 8u);
    EXPECT_TRUE(v.empty());
}

TEST(StaticVector, default_construct_max_size)
{
    StaticVector<int, 16> v;
    EXPECT_EQ(v.max_size(), 16u);
}

TEST(StaticVector, iter_range_construct_basic)
{
    int src[] = {10, 20, 30};
    StaticVector<int, 8> v(std::begin(src), std::end(src));
    EXPECT_EQ(v.size(), 3u);
    EXPECT_EQ(v[0], 10);
    EXPECT_EQ(v[1], 20);
    EXPECT_EQ(v[2], 30);
}

TEST(StaticVector, iter_range_construct_exactly_full)
{
    int src[] = {1, 2, 3, 4};
    StaticVector<int, 4> v(std::begin(src), std::end(src));
    EXPECT_EQ(v.size(), 4u);
    EXPECT_FALSE(v.empty());
}

TEST(StaticVector, iter_range_construct_overflow_throws)
{
    int src[] = {1, 2, 3, 4, 5};
    EXPECT_THROW((StaticVector<int, 4>(std::begin(src), std::end(src))), std::runtime_error);
}

TEST(StaticVector, move_vector_construct_basic)
{
    std::vector<int> src = {10, 20, 30};
    StaticVector<int, 8> v(std::move(src));
    EXPECT_EQ(v.size(), 3u);
    EXPECT_EQ(v[0], 10);
    EXPECT_EQ(v[2], 30);
}

TEST(StaticVector, move_vector_construct_exactly_full)
{
    std::vector<int> src = {1, 2, 3, 4};
    StaticVector<int, 4> v(std::move(src));
    EXPECT_EQ(v.size(), 4u);
}

TEST(StaticVector, move_vector_construct_overflow_throws)
{
    std::vector<int> src = {1, 2, 3, 4, 5};
    EXPECT_THROW((StaticVector<int, 4>(std::move(src))), std::runtime_error);
}

TEST(StaticVector, copy_construct)
{
    StaticVector<int, 8> a;
    a.push_back(1);
    a.push_back(2);

    StaticVector<int, 8> b = a;
    EXPECT_EQ(b.size(), 2u);
    EXPECT_EQ(b[0], 1);
    EXPECT_EQ(b[1], 2);
}

TEST(StaticVector, move_construct)
{
    StaticVector<int, 8> a;
    a.push_back(42);

    StaticVector<int, 8> b = std::move(a);
    EXPECT_EQ(b.size(), 1u);
    EXPECT_EQ(b[0], 42);
}

// ================================================================================================
// push_back / pop_back
// ================================================================================================

TEST(StaticVector, push_back_increments_size)
{
    StaticVector<int, 4> v;
    v.push_back(1);
    EXPECT_EQ(v.size(), 1u);
    EXPECT_FALSE(v.empty());
    v.push_back(2);
    EXPECT_EQ(v.size(), 2u);
}

TEST(StaticVector, push_back_fills_to_capacity)
{
    StaticVector<int, 4> v;
    for (int i = 0; i < 4; ++i)
        v.push_back(i);
    EXPECT_EQ(v.size(), 4u);
}

TEST(StaticVector, push_back_overflow_throws)
{
    StaticVector<int, 4> v;
    for (int i = 0; i < 4; ++i)
        v.push_back(i);
    EXPECT_THROW(v.push_back(99), std::runtime_error);
}

TEST(StaticVector, pop_back_decrements_size)
{
    StaticVector<int, 4> v;
    v.push_back(1);
    v.push_back(2);
    v.pop_back();
    EXPECT_EQ(v.size(), 1u);
    EXPECT_EQ(v[0], 1);
}

TEST(StaticVector, pop_back_on_empty_is_noop)
{
    StaticVector<int, 4> v;
    EXPECT_NO_THROW(v.pop_back());
    EXPECT_EQ(v.size(), 0u);
    EXPECT_TRUE(v.empty());
}

// ================================================================================================
// back()
// ================================================================================================

TEST(StaticVector, back_returns_last_element)
{
    StaticVector<int, 4> v;
    v.push_back(10);
    v.push_back(20);
    v.push_back(30);
    EXPECT_EQ(v.back(), 30);
}

TEST(StaticVector, back_on_single_element)
{
    StaticVector<int, 4> v;
    v.push_back(99);
    EXPECT_EQ(v.back(), 99);
}

TEST(StaticVector, back_on_empty_throws)
{
    StaticVector<int, 4> v;
    EXPECT_THROW(v.back(), std::runtime_error);
}

TEST(StaticVector, const_back_on_empty_throws)
{
    const StaticVector<int, 4> v;
    EXPECT_THROW(v.back(), std::runtime_error);
}

TEST(StaticVector, back_is_mutable)
{
    StaticVector<int, 4> v;
    v.push_back(1);
    v.back() = 42;
    EXPECT_EQ(v[0], 42);
}

// ================================================================================================
// clear
// ================================================================================================

TEST(StaticVector, clear_resets_size)
{
    StaticVector<int, 8> v;
    v.push_back(1);
    v.push_back(2);
    v.clear();
    EXPECT_EQ(v.size(), 0u);
    EXPECT_TRUE(v.empty());
}

TEST(StaticVector, clear_capacity_unchanged)
{
    StaticVector<int, 8> v;
    v.push_back(1);
    v.clear();
    EXPECT_EQ(v.capacity(), 8u);
}

TEST(StaticVector, clear_allows_repush)
{
    StaticVector<int, 4> v;
    for (int i = 0; i < 4; ++i)
        v.push_back(i);
    v.clear();
    EXPECT_NO_THROW(v.push_back(42));
    EXPECT_EQ(v.size(), 1u);
}

// ================================================================================================
// resize
// ================================================================================================

TEST(StaticVector, resize_grows_size)
{
    StaticVector<int, 8> v;
    v.resize(5);
    EXPECT_EQ(v.size(), 5u);
}

TEST(StaticVector, resize_shrinks_size)
{
    StaticVector<int, 8> v;
    v.push_back(1);
    v.push_back(2);
    v.push_back(3);
    v.resize(1);
    EXPECT_EQ(v.size(), 1u);
    EXPECT_EQ(v[0], 1);
}

TEST(StaticVector, resize_to_zero)
{
    StaticVector<int, 8> v;
    v.push_back(1);
    v.resize(0);
    EXPECT_EQ(v.size(), 0u);
    EXPECT_TRUE(v.empty());
}

TEST(StaticVector, resize_exactly_to_capacity)
{
    StaticVector<int, 4> v;
    EXPECT_NO_THROW(v.resize(4));
    EXPECT_EQ(v.size(), 4u);
}

TEST(StaticVector, resize_overflow_throws)
{
    StaticVector<int, 4> v;
    EXPECT_THROW(v.resize(5), std::runtime_error);
}

// ================================================================================================
// reserve
// ================================================================================================

TEST(StaticVector, reserve_sets_capacity)
{
    // reserve() sets mCapacity to exactly new_cap (used by ArrayDeque for headroom tracking).
    StaticVector<int, 8> v;
    v.reserve(5);
    EXPECT_EQ(v.capacity(), 5u);
}

TEST(StaticVector, reserve_to_full_capacity)
{
    StaticVector<int, 8> v;
    v.reserve(8);
    EXPECT_EQ(v.capacity(), 8u);
}

TEST(StaticVector, reserve_can_shrink_capacity)
{
    // This is intentional — ArrayDeque uses reserve() to track virtual headroom.
    StaticVector<int, 8> v;
    v.reserve(3);
    EXPECT_EQ(v.capacity(), 3u);
    v.reserve(1);
    EXPECT_EQ(v.capacity(), 1u);
}

TEST(StaticVector, reserve_overflow_throws)
{
    StaticVector<int, 4> v;
    EXPECT_THROW(v.reserve(5), std::runtime_error);
}

TEST(StaticVector, reserve_does_not_change_size)
{
    StaticVector<int, 8> v;
    v.push_back(1);
    v.push_back(2);
    v.reserve(6);
    EXPECT_EQ(v.size(), 2u);
}

// ================================================================================================
// span()
// ================================================================================================

TEST(StaticVector, span_reflects_size)
{
    StaticVector<int, 8> v;
    v.push_back(10);
    v.push_back(20);
    v.push_back(30);
    auto s = v.span();
    EXPECT_EQ(s.size(), 3u);
    EXPECT_EQ(s[0], 10);
    EXPECT_EQ(s[2], 30);
}

TEST(StaticVector, span_empty)
{
    StaticVector<int, 8> v;
    EXPECT_EQ(v.span().size(), 0u);
}

TEST(StaticVector, span_after_resize)
{
    StaticVector<int, 8> v;
    v.resize(5);
    EXPECT_EQ(v.span().size(), 5u);
}

TEST(StaticVector, const_span_reflects_size)
{
    StaticVector<int, 8> v;
    v.push_back(7);
    const auto &cv = v;
    auto s = cv.span();
    EXPECT_EQ(s.size(), 1u);
    EXPECT_EQ(s[0], 7);
}

// ================================================================================================
// data()
// ================================================================================================

TEST(StaticVector, data_points_to_first_element)
{
    StaticVector<int, 4> v;
    v.push_back(42);
    EXPECT_EQ(v.data(), &v[0]);
}

TEST(StaticVector, const_data_points_to_first_element)
{
    StaticVector<int, 4> v;
    v.push_back(42);
    const auto &cv = v;
    EXPECT_EQ(cv.data(), &cv[0]);
}

// ================================================================================================
// Iterators
// ================================================================================================

TEST(StaticVector, iterators_cover_used_elements)
{
    StaticVector<int, 8> v;
    v.push_back(1);
    v.push_back(2);
    v.push_back(3);

    std::vector<int> result(v.begin(), v.end());
    EXPECT_EQ(result, (std::vector<int>{1, 2, 3}));
}

TEST(StaticVector, range_for)
{
    StaticVector<int, 8> v;
    v.push_back(10);
    v.push_back(20);

    int sum = 0;
    for (int x : v)
        sum += x;
    EXPECT_EQ(sum, 30);
}

TEST(StaticVector, cbegin_cend)
{
    StaticVector<int, 8> v;
    v.push_back(5);
    v.push_back(6);

    int product = 1;
    for (auto it = v.cbegin(); it != v.cend(); ++it)
        product *= *it;
    EXPECT_EQ(product, 30);
}

TEST(StaticVector, std_fill_via_iterators)
{
    StaticVector<int, 4> v;
    v.resize(4);
    std::fill(v.begin(), v.end(), 99);
    for (int i = 0; i < 4; ++i)
        EXPECT_EQ(v[i], 99);
}

TEST(StaticVector, std_iota_via_iterators)
{
    StaticVector<int, 8> v;
    v.resize(5);
    std::iota(v.begin(), v.end(), 1);
    EXPECT_EQ(v[0], 1);
    EXPECT_EQ(v[4], 5);
}

// ================================================================================================
// operator[]
// ================================================================================================

TEST(StaticVector, index_operator_read)
{
    StaticVector<int, 4> v;
    v.push_back(10);
    v.push_back(20);
    EXPECT_EQ(v[0], 10);
    EXPECT_EQ(v[1], 20);
}

TEST(StaticVector, index_operator_write)
{
    StaticVector<int, 4> v;
    v.push_back(0);
    v[0] = 55;
    EXPECT_EQ(v[0], 55);
}

TEST(StaticVector, const_index_operator)
{
    StaticVector<int, 4> v;
    v.push_back(77);
    const auto &cv = v;
    EXPECT_EQ(cv[0], 77);
}

// ================================================================================================
// char / uint8_t — typical usage patterns
// ================================================================================================

TEST(StaticVector, push_back_chars)
{
    StaticVector<char, 16> v;
    for (char c : std::string("hello"))
        v.push_back(c);
    EXPECT_EQ(v.size(), 5u);
    EXPECT_EQ(v[0], 'h');
    EXPECT_EQ(v[4], 'o');
}

TEST(StaticVector, uint8_span_roundtrip)
{
    StaticVector<uint8_t, 8> v;
    v.resize(4);
    std::iota(v.begin(), v.end(), uint8_t{0xA0});
    auto s = v.span();
    EXPECT_EQ(s[0], 0xA0);
    EXPECT_EQ(s[3], 0xA3);
}

// ================================================================================================
// Edge: N == 0 is excluded by the trivially-destructible constraint but test N == 1
// ================================================================================================

TEST(StaticVector, single_element_capacity)
{
    StaticVector<int, 1> v;
    EXPECT_EQ(v.max_size(), 1u);
    v.push_back(42);
    EXPECT_EQ(v.back(), 42);
    EXPECT_THROW(v.push_back(1), std::runtime_error);
}
