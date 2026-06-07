// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#include <gtest/gtest.h>

#include <string>
#include <string_view>

#include "ci_string.h"

using namespace clv;

using namespace std::literals;

TEST(ci_string_tests, compare_same)
{
    auto s1 = ci_string("Hello World");
    auto s2 = ci_string("Hello World");

    EXPECT_EQ(s1, s2);
}

TEST(ci_string_tests, compare_similar)
{
    auto s1 = ci_string("Hello World!");
    auto s2 = ci_string("Hello World");

    EXPECT_NE(s1, s2);
}

TEST(ci_string_tests, compare_view)
{
    auto s1 = ci_string("Hello World!");
    auto s2 = ci_string_view("Hello World");

    EXPECT_NE(s1, s2);
    EXPECT_FALSE(s1 == s2);
    EXPECT_FALSE(s1 == "Faddle"sv);
}

TEST(ci_string_tests, compare_ne)
{
    auto s1 = ci_string("Some other string");
    auto s2 = ci_string("Hello World");

    EXPECT_NE(s1, s2);
}

TEST(ci_string_tests, compare_ci1)
{
    auto s1 = ci_string("hello World");
    auto s2 = ci_string("Hello World");

    EXPECT_EQ(s1, s2);
}

TEST(ci_string_tests, compare_ci2)
{
    auto s1 = ci_string("HELLO WORLD");
    auto s2 = ci_string("Hello World");

    EXPECT_EQ(s1, s2);
}

TEST(ci_string_tests, convert)
{
    auto s1 = ci_string("Hello World");
    auto s2 = to_string(s1);
    auto s3 = to_ci_str(s2);

    EXPECT_EQ(std::string("Hello World"), s2);
    EXPECT_EQ(s1, s3);
}

TEST(ci_string_tests, string_compare)
{
    auto s1 = ci_string("Hello World");
    auto s2 = std::string("Hello World");

    EXPECT_TRUE(s1 == s2);
    EXPECT_FALSE(s1 < s2);
    EXPECT_FALSE(s1 > s2);
}

TEST(ci_string_tests, string_compare_ci)
{
    auto s1 = ci_string("Hello World");
    auto s2 = std::string("HELLO World");

    EXPECT_TRUE(s1 == s2);
    EXPECT_FALSE(s1 < s2);
    EXPECT_FALSE(s1 > s2);
}

TEST(ci_string_tests, string_compare_ne)
{
    auto s1 = ci_string("Hello World");
    auto s2 = std::string("HELL World");

    EXPECT_FALSE(s1 == s2);
}

TEST(ci_string_tests, string_compare_lt)
{
    auto s1 = ci_string("Hello World");
    auto s2 = std::string("HELLO World");

    EXPECT_FALSE(s1 < s2);
}

TEST(ci_string_tests, string_compare_gt)
{
    auto s1 = ci_string("Hello World");
    auto s2 = std::string("HELLO World");

    EXPECT_FALSE(s1 > s2);
}

TEST(ci_string_tests, string_compare_le)
{
    auto s1 = ci_string("Hello World");
    auto s2 = std::string("HELLO World");

    EXPECT_TRUE(s1 <= s2);
}

TEST(ci_string_tests, string_compare_ge)
{
    auto s1 = ci_string("Hello World");
    auto s2 = std::string("HELLO World");

    EXPECT_TRUE(s1 >= s2);
}

TEST(ci_string_tests, string_view_compare)
{
    auto s1 = ci_string("Hello World");
    auto s2 = std::string_view("Hello World");

    EXPECT_TRUE(s1 == s2);
}

TEST(ci_string_tests, string_view_compare_ci)
{
    auto s1 = ci_string("Hello World");
    auto s2 = std::string_view("HELLO World");

    EXPECT_TRUE(s1 == s2);
}

TEST(ci_string_tests, string_view_compare_ne)
{
    auto s1 = ci_string("Hello World");
    auto s2 = std::string_view("HELL World");

    EXPECT_FALSE(s1 == s2);
}

TEST(ci_string_tests, string_view_compare_lt)
{
    auto s1 = ci_string("Hello World");
    auto s2 = std::string_view("HELLO World");

    EXPECT_FALSE(s1 < s2);
}

TEST(ci_string_tests, string_view_compare_gt)
{
    auto s1 = ci_string("Hello World");
    auto s2 = std::string_view("HELLO World");

    EXPECT_FALSE(s1 > s2);
}

TEST(ci_string_tests, string_view_compare_le)
{
    auto s1 = ci_string("Hello World");
    auto s2 = std::string_view("HELLO World");

    EXPECT_TRUE(s1 <= s2);
}

TEST(ci_string_tests, string_view_compare_ge)
{
    auto s1 = ci_string("Hello World");
    auto s2 = std::string_view("HELLO World");

    EXPECT_TRUE(s1 >= s2);
}

TEST(ci_string_tests, hash_ne)
{
    auto s1 = ci_string("Hello World");
    auto s2 = ci_string("HELLO WORLD!");

    EXPECT_NE(std::hash<ci_string>{}(s1), std::hash<ci_string>{}(s2));
}

TEST(ci_string_tests, hash_view_ne)
{
    auto s1 = ci_string_view("Hello World");
    auto s2 = ci_string_view("HELLO WORLD!");

    EXPECT_NE(std::hash<ci_string_view>{}(s1), std::hash<ci_string_view>{}(s2));
}

TEST(ci_string_tests, hash_view_eq)
{
    auto s1 = ci_string_view("Hello World");
    auto s2 = ci_string_view("HELLO WORLD");

    EXPECT_EQ(std::hash<ci_string_view>{}(s1), std::hash<ci_string_view>{}(s2));
}

TEST(ci_string_tests, hash_eq)
{
    auto s1 = ci_string("Hello World");
    auto s2 = ci_string("HELLO WORLD");

    EXPECT_EQ(std::hash<ci_string>{}(s1), std::hash<ci_string>{}(s2));
}

TEST(ci_string_tests, hash_eq_nolocale)
{
    using ci_nolocale_str = basic_ci_string<false>;
    auto s1 = ci_nolocale_str("Hello World");
    auto s2 = ci_nolocale_str("HELLO WORLD");

    EXPECT_EQ(s1, s2);
    EXPECT_EQ(std::hash<ci_nolocale_str>{}(s1), std::hash<ci_nolocale_str>{}(s2));
}

TEST(ci_string_tests, from_string)
{
    auto s1 = ci_string("Hello World"s);
    auto s2 = ci_string("HELLO WORLD"s);

    EXPECT_EQ(s1, s2);
}

TEST(ci_string_tests, from_string_view)
{
    auto s1 = ci_string("Hello World"sv);
    auto s2 = ci_string("HELLO WORLD"sv);

    EXPECT_EQ(s1, s2);
}
