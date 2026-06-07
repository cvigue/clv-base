// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>

#include "result_or.h"

#include <string>
#include <utility>

using namespace clv;

// ================================================================================================
// Basic construction
// ================================================================================================

TEST(result_or_suite, construct_from_value)
{
    result_or<int, std::string> r(42);
    EXPECT_TRUE(r.has_value());
    EXPECT_TRUE(static_cast<bool>(r));
    EXPECT_EQ(r.value(), 42);
    EXPECT_EQ(*r, 42);
}

TEST(result_or_suite, construct_from_error)
{
    result_or<int, std::string> r(std::string("oops"));
    EXPECT_FALSE(r.has_value());
    EXPECT_FALSE(static_cast<bool>(r));
    EXPECT_EQ(r.error(), "oops");
}

// ================================================================================================
// Value access
// ================================================================================================

TEST(result_or_suite, arrow_operator)
{
    struct Point
    {
        int x = 3, y = 4;
    };
    result_or<Point, std::string> r(Point{});
    EXPECT_EQ(r->x, 3);
    EXPECT_EQ(r->y, 4);
}

TEST(result_or_suite, deref_const_ref)
{
    const result_or<int, std::string> r(7);
    EXPECT_EQ(*r, 7);
}

TEST(result_or_suite, value_wrong_type_throws)
{
    result_or<int, std::string> r(std::string("err"));
    EXPECT_THROW((void)r.value(), std::bad_variant_access);
}

TEST(result_or_suite, error_wrong_type_throws)
{
    result_or<int, std::string> r(5);
    EXPECT_THROW((void)r.error(), std::bad_variant_access);
}

// ================================================================================================
// Move semantics
// ================================================================================================

TEST(result_or_suite, move_value_out)
{
    result_or<std::string, int> r(std::string("hello"));
    std::string moved = std::move(r).value();
    EXPECT_EQ(moved, "hello");
}

TEST(result_or_suite, value_lvalue_ref_is_mutable)
{
    result_or<int, std::string> r(10);
    r.value() = 99;
    EXPECT_EQ(*r, 99);
}

// ================================================================================================
// Non-trivial value type
// ================================================================================================

TEST(result_or_suite, non_trivial_value)
{
    result_or<std::string, int> r(std::string("content"));
    EXPECT_TRUE(r.has_value());
    EXPECT_EQ(*r, "content");
}

TEST(result_or_suite, non_trivial_error)
{
    result_or<int, std::string> r(std::string("failure"));
    EXPECT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), "failure");
}

// ================================================================================================
// Const correctness
// ================================================================================================

TEST(result_or_suite, const_value_access)
{
    const result_or<int, std::string> r(42);
    EXPECT_EQ(r.value(), 42);
    EXPECT_EQ(*r, 42);
    EXPECT_EQ(r.operator->(), &r.value());
}

TEST(result_or_suite, const_error_access)
{
    const result_or<int, std::string> r(std::string("bad"));
    EXPECT_EQ(r.error(), "bad");
}
