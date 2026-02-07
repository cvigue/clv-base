// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#include "gtest/gtest.h"


#include "optional_ref.h"


struct test_optional_ref
{
    int i = 0;
};

using namespace clv;

TEST(optional_ref_suite, simple)
{
    int i = 42;
    auto o = optional_ref<int &>(i);
    EXPECT_TRUE(o);
    EXPECT_EQ(o.value(), i);
    EXPECT_EQ(*o, i);
}

TEST(optional_ref_suite, simple_const)
{
    const int i = 42;
    auto o = optional_ref<const int &>(i);
    EXPECT_TRUE(o);
    EXPECT_EQ(o.value(), i);
    EXPECT_EQ(*o, i);
}

TEST(optional_ref_suite, assign_to)
{
    int i = 42;
    auto o = optional_ref<int &>(i);
    int j = 0;
    o = optional_ref<int &>(j);
    j = 96;
    EXPECT_TRUE(o);
    EXPECT_EQ(o.value(), j);
    EXPECT_EQ(*o, j);
}

TEST(optional_ref_suite, assign_thru)
{
    int i = 42;
    auto o = optional_ref<int &>(i);
    EXPECT_TRUE(o);
    EXPECT_EQ(42, *o);
    *o = 96;
    EXPECT_EQ(i, 96);
}

TEST(optional_ref_suite, invalid)
{
    auto o = optional_ref<int &>();
    EXPECT_THROW([[maybe_unused]] auto _ = o.value(), std::runtime_error);
    EXPECT_THROW(*o, std::runtime_error);
}

TEST(optional_ref_suite, invalid_nullopt)
{
    auto o = optional_ref<int &>(std::nullopt);
    EXPECT_THROW([[maybe_unused]] auto _ = o.value(), std::runtime_error);
    EXPECT_THROW(*o, std::runtime_error);
}

TEST(optional_ref_suite, assign_nullopt)
{
    int i = 42;
    auto o = optional_ref<int &>(i);
    EXPECT_TRUE(o);
    EXPECT_EQ(o.value(), i);
    EXPECT_EQ(*o, i);
    o = std::nullopt;
    EXPECT_THROW([[maybe_unused]] auto _ = o.value(), std::runtime_error);
    EXPECT_THROW(*o, std::runtime_error);
}

TEST(optional_ref_suite, value_or_default)
{
    auto o = optional_ref<int &>(std::nullopt);
    EXPECT_FALSE(o);
    EXPECT_EQ(o.value_or(42), 42);
}

TEST(optional_ref_suite, deref)
{
    auto t = test_optional_ref();
    auto o = optional_ref<test_optional_ref &>(t);
    EXPECT_EQ(o->i, 0);
    o->i = 42;
    EXPECT_EQ(o->i, 42);
}

TEST(optional_ref_suite, deref_invalid)
{
    auto o = optional_ref<test_optional_ref &>();
    EXPECT_FALSE(o);
    // cast to suppress warning
    EXPECT_THROW(static_cast<void>(o->i), std::runtime_error);
}

TEST(optional_ref_suite, less_than)
{
    int i = 42;
    int j = 96;

    auto o1 = optional_ref<int &>(i);
    auto o2 = optional_ref<int &>(i);
    auto o3 = optional_ref<int &>();
    auto o4 = optional_ref<int &>(j);

    EXPECT_LT(o3, o1);
    EXPECT_LT(o1, o4);
    EXPECT_LT(o2, o4);
}

TEST(optional_ref_suite, equal)
{
    int i = 42;
    int j = 96;

    auto o1 = optional_ref<int &>(i);
    auto o2 = optional_ref<int &>(i);
    auto o3 = optional_ref<int &>();
    auto o4 = optional_ref<int &>(j);

    EXPECT_EQ(o1, o2);
    EXPECT_EQ(o3, o3);
    EXPECT_EQ(o4, o4);
}

TEST(optional_ref_suite, not_equal)
{
    int i = 42;
    int j = 96;

    auto o1 = optional_ref<int &>(i);
    auto o2 = optional_ref<int &>(i);
    auto o3 = optional_ref<int &>();
    auto o4 = optional_ref<int &>(j);

    EXPECT_NE(o1, o3);
    EXPECT_NE(o1, o4);
    EXPECT_NE(o2, o3);
    EXPECT_NE(o2, o4);
    EXPECT_NE(o3, o4);
}

TEST(optional_ref_suite, greater_than)
{
    int i = 42;
    int j = 96;

    auto o1 = optional_ref<int &>(i);
    auto o2 = optional_ref<int &>(i);
    auto o3 = optional_ref<int &>();
    auto o4 = optional_ref<int &>(j);

    EXPECT_GT(o1, o3);
    EXPECT_GT(o2, o3);
    EXPECT_GT(o4, o1);
}

TEST(optional_ref_suite, less_than_or_equal)
{
    int i = 42;

    auto o1 = optional_ref<int &>(i);
    auto o2 = optional_ref<int &>(i);
    auto o3 = optional_ref<int &>();

    EXPECT_LE(o3, o1);
    EXPECT_LE(o1, o2);
}

TEST(optional_ref_suite, greater_than_or_equal)
{
    int i = 42;

    auto o1 = optional_ref<int &>(i);
    auto o2 = optional_ref<int &>(i);
    auto o3 = optional_ref<int &>();

    EXPECT_GE(o1, o3);
    EXPECT_GE(o1, o2);
}
