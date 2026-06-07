// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>

#include <limits>
#include <type_traits> // For std::is_signed

#include "char_util.h"

// Define the types to test
using CharTypes = testing::Types<char, signed char, unsigned char>;

// Create a typed test fixture
template <typename T>
class CharUtilTypedTest : public testing::Test
{
};

TYPED_TEST_SUITE(CharUtilTypedTest, CharTypes);

TYPED_TEST(CharUtilTypedTest, tolower)
{
    using CharT = TypeParam;
    // Loop through all possible values for the character type
    for (int i = std::numeric_limits<CharT>::min(); i <= std::numeric_limits<CharT>::max(); ++i)
    {
        CharT c = static_cast<CharT>(i);
        if (c >= 'A' && c <= 'Z')
            EXPECT_EQ(clv::to_lower_nolocale(c), static_cast<CharT>(c + 32));
        else
            EXPECT_EQ(clv::to_lower_nolocale(c), c);
    }
}

TYPED_TEST(CharUtilTypedTest, toupper)
{
    using CharT = TypeParam;
    for (int i = std::numeric_limits<CharT>::min(); i <= std::numeric_limits<CharT>::max(); ++i)
    {
        CharT c = static_cast<CharT>(i);
        if (c >= 'a' && c <= 'z')
            EXPECT_EQ(clv::to_upper_nolocale(c), static_cast<CharT>(c - 32));
        else
            EXPECT_EQ(clv::to_upper_nolocale(c), c);
    }
}

TYPED_TEST(CharUtilTypedTest, islower)
{
    using CharT = TypeParam;
    for (int i = std::numeric_limits<CharT>::min(); i <= std::numeric_limits<CharT>::max(); ++i)
    {
        CharT c = static_cast<CharT>(i);
        if (c >= 'a' && c <= 'z')
            EXPECT_TRUE(clv::is_lower_nolocale(c));
        else
            EXPECT_FALSE(clv::is_lower_nolocale(c));
    }
}

TYPED_TEST(CharUtilTypedTest, isupper)
{
    using CharT = TypeParam;
    for (int i = std::numeric_limits<CharT>::min(); i <= std::numeric_limits<CharT>::max(); ++i)
    {
        CharT c = static_cast<CharT>(i);
        if (c >= 'A' && c <= 'Z')
            EXPECT_TRUE(clv::is_upper_nolocale(c));
        else
            EXPECT_FALSE(clv::is_upper_nolocale(c));
    }
}