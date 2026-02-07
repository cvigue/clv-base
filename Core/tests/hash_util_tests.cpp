// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#include "gtest/gtest.h"

#include <functional>
#include <string>

#include "hash_util.h"

using namespace clv;

TEST(hash_util, combine_00)
{
    auto hasher = std::hash<std::size_t>();
    auto h = hasher(0);
    EXPECT_NE(h, hash_combine(h, h));
    EXPECT_NE(0, hash_combine(h, h));
}

TEST(hash_util, combine_2)
{
    auto hasher = std::hash<std::string>();
    auto h = hasher("Hello Hasher");
    EXPECT_NE(h, hash_combine(h, h));
}

TEST(hash_util, combine_2_1)
{
    auto hasher = std::hash<std::string>();
    auto h1 = hasher("Hello ");
    auto h2 = hasher("Hasher");
    auto h3 = hasher("Hello Hasher");

    EXPECT_NE(h3, hash_combine(h1, h2));
    EXPECT_NE(h3, hash_combine(h2, h1));
    EXPECT_NE(hash_combine(h1, h2), hash_combine(h2, h1));
}

TEST(hash_util, combine_3)
{
    auto hasher = std::hash<std::string>();
    auto h1 = hasher("Hello ");
    auto h2 = hasher("Hasher");
    auto h3 = hasher("!!!");
    auto h4 = hasher("Hello Hasher!!!");

    EXPECT_NE(h4, hash_combine(h1, h2, h3));
    EXPECT_NE(h4, hash_combine(h3, h2, h1));
    EXPECT_NE(hash_combine(h1, h2, h3), hash_combine(h1, h2, h3, h4));
    EXPECT_NE(hash_combine(h1, h2, h3), hash_combine(h1, h2));
    EXPECT_NE(hash_combine(h1, h2, h3), hash_combine(h2, h3));
    EXPECT_NE(hash_combine(h1, h2, h3), hash_combine(h2, h1));
    EXPECT_NE(hash_combine(h1, h2, h3), hash_combine(h3, h2));
    EXPECT_NE(hash_combine(h1, h2, h3), hash_combine(h3, h2, h1));
    EXPECT_NE(hash_combine(h2, h1, h3), hash_combine(h3, h2, h1));
}

TEST(hash_util, directly_hash_N)
{
    auto hasher = std::hash<std::string>();

    auto str1 = std::string("Hello ");
    auto str2 = std::string("Hasher");
    auto str3 = std::string("!!!");

    auto h1 = hasher(str1);
    auto h2 = hasher(str2);
    auto h3 = hasher(str3);

    EXPECT_EQ(hash_all(str1), hash_combine(h1));
    EXPECT_EQ(hash_all(str1, str2), hash_combine(h1, h2));
    EXPECT_EQ(hash_all(str1, str2, str3), hash_combine(h1, h2, h3));
    EXPECT_NE(hash_all(str1, str2, str3), hash_combine(h1, h2));
    EXPECT_NE(hash_all(str1, str2, str3), hash_combine(h2, h3));
}

TEST(hash_util, split_single_part_roundtrip)
{
    constexpr hash_value_t value = static_cast<hash_value_t>(0xA5A5A5A5A5A5A5A5ULL);
    const auto parts = hash_split<1>(value);
    EXPECT_EQ(parts[0], value);
}

TEST(hash_util, split_two_parts_roundtrip)
{
    constexpr std::size_t bits_per_part = (sizeof(hash_value_t) * 8) / 2;
    const hash_value_t value = sizeof(hash_value_t) >= 8 ? static_cast<hash_value_t>(0x1122334455667788ULL)
                                                         : static_cast<hash_value_t>(0x89ABCDEFUL);

    const auto parts = hash_split<2>(value);

    hash_value_t reconstructed = 0;
    for (std::size_t i = 0; i < 2; ++i)
        reconstructed |= parts[i] << (bits_per_part * i);

    EXPECT_EQ(reconstructed, value);
    EXPECT_NE(parts[0], parts[1]);
}

TEST(hash_util, split_three_parts_masks_high_bits)
{
    constexpr std::size_t hash_count = 3;
    constexpr std::size_t bits_per_part = (sizeof(hash_value_t) * 8) / hash_count;

    const hash_value_t value = ~hash_value_t{0};
    const auto parts = hash_split<hash_count>(value);

    hash_value_t reconstructed = 0;
    for (std::size_t i = 0; i < hash_count; ++i)
        reconstructed |= parts[i] << (bits_per_part * i);

    constexpr std::size_t used_bits = bits_per_part * hash_count;
    const hash_value_t expected = used_bits == (sizeof(hash_value_t) * 8)
                                      ? value
                                      : (hash_value_t{1} << used_bits) - 1;

    EXPECT_EQ(reconstructed, expected);
    EXPECT_GT(parts[0], 0u);
}

TEST(hash_util, split_four_parts_roundtrip)
{
    constexpr std::size_t hash_count = 4;
    constexpr std::size_t bits_per_part = (sizeof(hash_value_t) * 8) / hash_count;

    const hash_value_t value = sizeof(hash_value_t) >= 8 ? static_cast<hash_value_t>(0xDEADBEEFCAFEBABEULL)
                                                         : static_cast<hash_value_t>(0x89ABCDEFUL);

    const auto parts = hash_split<hash_count>(value);

    hash_value_t reconstructed = 0;
    for (std::size_t i = 0; i < hash_count; ++i)
        reconstructed |= parts[i] << (bits_per_part * i);

    EXPECT_EQ(reconstructed, value);
}