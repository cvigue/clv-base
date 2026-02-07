// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include "gtest/gtest.h"
#include "mutex_type.h"

using namespace clv;

template <typename T>
class MutexTypeTest : public ::testing::Test
{
};

using TestTypes = ::testing::Types<SharedMutexType<int>,
                                   UniqueMutexType<int>,
                                   SpinlockType<int>>;

TYPED_TEST_SUITE(MutexTypeTest, TestTypes);

TYPED_TEST(MutexTypeTest, MutexDefaultCtor)
{
    TypeParam mt{};
    auto ptr = mt.Lock();
    ptr.get() = 2;
    *ptr = 3;
    EXPECT_TRUE(*ptr == 3);
    EXPECT_TRUE(ptr.owns_lock());
}

TYPED_TEST(MutexTypeTest, IntMutex)
{
    auto mt = TypeParam(0);
    auto ptr = mt.Lock();
    ptr.get() = 2;
    *ptr = 3;
    EXPECT_TRUE(*ptr == 3);
    EXPECT_TRUE(ptr.owns_lock());
}

TYPED_TEST(MutexTypeTest, RoIntMutex)
{
    TypeParam cmt(22);
    auto ptr = cmt.LockRO();
    auto i = *ptr;

    EXPECT_TRUE(std::is_const_v<typename decltype(ptr)::value_type>);
    EXPECT_EQ(i, 22);
}

TYPED_TEST(MutexTypeTest, ConstIntMutex)
{
    const TypeParam cmt(22);
    auto ptr = cmt.Lock();
    auto i = *ptr;

    EXPECT_TRUE(std::is_const_v<typename decltype(ptr)::value_type>);
    EXPECT_EQ(i, 22);
}
TYPED_TEST(MutexTypeTest, ConstIntMutexTry)
{
    const TypeParam cmt(22);
    auto ptr = cmt.Try();
    auto i = *ptr;

    EXPECT_TRUE(std::is_const_v<typename decltype(ptr)::value_type>);
    EXPECT_EQ(i, 22);
}
TYPED_TEST(MutexTypeTest, IntMutexTry)
{
    TypeParam mt(33);
    auto ptr = mt.Try();
    EXPECT_EQ(*ptr, 33);
    ptr.get() = 2;
    *ptr = 3;
    EXPECT_TRUE(*ptr == 3);
    EXPECT_TRUE(ptr.owns_lock());
}

TYPED_TEST(MutexTypeTest, IntMutexStdLock)
{
    TypeParam mt1(33);
    TypeParam mt2(34);
    TypeParam mt3(35);

    auto p1 = mt1.Defer();
    auto p2 = mt2.Defer();
    auto p3 = mt3.Defer();

    EXPECT_FALSE(p1.owns_lock());
    EXPECT_FALSE(p2.owns_lock());
    EXPECT_FALSE(p3.owns_lock());

    std::lock(p1, p2, p3);

    EXPECT_TRUE(p1.owns_lock());
    EXPECT_TRUE(p2.owns_lock());
    EXPECT_TRUE(p3.owns_lock());
}

TYPED_TEST(MutexTypeTest, IntMutexBool)
{
    TypeParam mt1(33);
    TypeParam mt2(34);
    TypeParam mt3(35);

    auto p1 = mt1.Defer();
    auto p2 = mt2.Defer();
    auto p3 = mt3.Defer();

    EXPECT_FALSE(p1);
    EXPECT_FALSE(p2);
    EXPECT_FALSE(p3);

    std::lock(p1, p2, p3);

    EXPECT_TRUE(p1);
    EXPECT_TRUE(p2);
    EXPECT_TRUE(p3);
}

TYPED_TEST(MutexTypeTest, IntMutexTryGet)
{
    TypeParam mt1(33);
    TypeParam mt2(34);

    auto p1 = mt1.Defer();
    auto p2 = mt2.Defer();

    auto v1 = p1.try_get();
    auto v2 = p2.try_get();

    EXPECT_TRUE(v1);
    EXPECT_TRUE(v2);
    EXPECT_EQ(*v1, 33);
    EXPECT_EQ(*v2, 34);
}

TYPED_TEST(MutexTypeTest, ConstIntMutexTryLock)
{
    const TypeParam mt1(33);
    const TypeParam mt2(34);

    auto p1 = mt1.Defer();
    auto p2 = mt2.Defer();

    auto v1 = p1.try_get();
    auto v2 = p2.try_get();

    EXPECT_TRUE(v1);
    EXPECT_TRUE(v2);
    EXPECT_EQ(*v1, 33);
    EXPECT_EQ(*v2, 34);
}


TYPED_TEST(MutexTypeTest, IntMutexTryGet2)
{
    TypeParam mt1(33);
    TypeParam mt2(34);

    auto p1 = mt1.Defer();
    auto p2 = mt2.Defer();

    auto v1 = p1.try_get();
    auto v2 = p2.try_get();

    EXPECT_TRUE(v1);
    EXPECT_TRUE(v2);
    EXPECT_EQ(*v1, 33);
    EXPECT_EQ(*v2, 34);
    EXPECT_NO_THROW(p1.try_get());
    EXPECT_NO_THROW(p2.try_get());
}
