// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include "gtest/gtest.h"

#include "HelpSslNoRc.h"

using namespace clv::OpenSSL;

struct SslMock
{
    SslMock(int i_)
        : i(i_)
    {
        ++instanceCnt;
    }
    int i = 42;
    static inline int instanceCnt = 0;
};

SslMock *CreateMock(int i)
{
    return new SslMock(i);
}

void FreeMock(SslMock *m)
{
    --SslMock::instanceCnt;
    delete m;
}

void TestFunc(SslMock *ssl, int expected)
{
    EXPECT_NE(ssl, nullptr);
    EXPECT_EQ(ssl->i, expected);
}

using SslNoRcMock = SslNoRc<SslMock, CreateMock, FreeMock>;

template <typename T>
class SslHelpBaseTest : public ::testing::Test
{
};

using Implementations = ::testing::Types<SslNoRcMock>;
TYPED_TEST_SUITE(SslHelpBaseTest, Implementations);

TYPED_TEST(SslHelpBaseTest, SslHelp_create)
{
    {
        EXPECT_EQ(SslMock::instanceCnt, 0);
        auto ssl = TypeParam(96);
        EXPECT_NE(ssl.Get(), nullptr);
        EXPECT_EQ(ssl.Get()->i, 96);
        EXPECT_EQ(SslMock::instanceCnt, 1);
    }
    EXPECT_EQ(SslMock::instanceCnt, 0);
}

TYPED_TEST(SslHelpBaseTest, SslHelp_use)
{
    auto ssl = TypeParam(42);
    EXPECT_NE(ssl.Get(), nullptr);
    EXPECT_EQ(ssl.Get()->i, 42);
    EXPECT_NO_THROW(TestFunc(ssl.Get(), 42));
    EXPECT_NO_THROW(TestFunc(ssl, 42));
}
