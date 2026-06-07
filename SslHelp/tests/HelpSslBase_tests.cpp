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

// =============================================================================
// ThrowIfNull
// =============================================================================

TYPED_TEST(SslHelpBaseTest, ThrowIfNull_WhenValid_DoesNotThrow)
{
    auto ssl = TypeParam(1);
    EXPECT_NO_THROW(ssl.ThrowIfNull());
    EXPECT_NO_THROW(ssl.ThrowIfNull("should not throw"));
}

TYPED_TEST(SslHelpBaseTest, ThrowIfNull_WhenNull_Throws)
{
    TypeParam ssl(nullptr);
    EXPECT_THROW(ssl.ThrowIfNull(), clv::OpenSSL::SslException);
}

TYPED_TEST(SslHelpBaseTest, ThrowIfNull_WhenNull_MessageIncluded)
{
    TypeParam ssl(nullptr);
    try
    {
        ssl.ThrowIfNull("my context");
        FAIL() << "Expected SslException";
    }
    catch (const clv::OpenSSL::SslException &e)
    {
        EXPECT_NE(std::string(e.what()).find("my context"), std::string::npos);
    }
}

// =============================================================================
// Reset
// =============================================================================

TYPED_TEST(SslHelpBaseTest, Reset_NullptrOverload_SetsNullAndFrees)
{
    EXPECT_EQ(SslMock::instanceCnt, 0);
    TypeParam ssl(7);
    EXPECT_EQ(SslMock::instanceCnt, 1);
    ssl.Reset(); // Reset(nullptr_t)
    EXPECT_EQ(ssl.Get(), nullptr);
    EXPECT_EQ(SslMock::instanceCnt, 0);
}

TYPED_TEST(SslHelpBaseTest, Reset_ValidPtr_ReplacesManaged)
{
    TypeParam ssl(10);
    EXPECT_EQ(ssl.Get()->i, 10);
    EXPECT_EQ(SslMock::instanceCnt, 1);

    // Reset with a new raw pointer (takes ownership)
    ssl.Reset(new SslMock(99));
    EXPECT_EQ(SslMock::instanceCnt, 1); // old freed, new held
    EXPECT_EQ(ssl.Get()->i, 99);
}

TYPED_TEST(SslHelpBaseTest, Reset_NullPtr_Throws)
{
    TypeParam ssl(5);
    EXPECT_THROW(ssl.Reset(static_cast<SslMock *>(nullptr)), clv::OpenSSL::SslException);
    // Original pointer should be gone (reset already took it)
    EXPECT_EQ(ssl.Get(), nullptr);
}

// =============================================================================
// Release
// =============================================================================

TYPED_TEST(SslHelpBaseTest, Release_ReturnsRawPointer)
{
    TypeParam ssl(55);
    EXPECT_EQ(SslMock::instanceCnt, 1);

    SslMock *raw = ssl.Release();
    ASSERT_NE(raw, nullptr);
    EXPECT_EQ(raw->i, 55);
    // Wrapper should now be null
    EXPECT_EQ(ssl.Get(), nullptr);
    // Instance not freed yet
    EXPECT_EQ(SslMock::instanceCnt, 1);

    // Clean up manually
    FreeMock(raw);
    EXPECT_EQ(SslMock::instanceCnt, 0);
}

TYPED_TEST(SslHelpBaseTest, Release_ThenThrowIfNull_Throws)
{
    TypeParam ssl(3);
    // Release transfers ownership out — caller must free to avoid leak
    SslMock *raw = ssl.Release();
    FreeMock(raw);
    EXPECT_THROW(ssl.ThrowIfNull(), clv::OpenSSL::SslException);
}

// =============================================================================
// NullptrConstructor / nullptr get
// =============================================================================

TYPED_TEST(SslHelpBaseTest, NullptrCtor_GetReturnsNull)
{
    TypeParam ssl(nullptr);
    EXPECT_EQ(ssl.Get(), nullptr);
    EXPECT_EQ(SslMock::instanceCnt, 0); // nothing allocated
}

TYPED_TEST(SslHelpBaseTest, NullptrCtor_DestructDoesNotFreeMock)
{
    {
        TypeParam ssl(nullptr);
    }
    EXPECT_EQ(SslMock::instanceCnt, 0);
}

// =============================================================================
// BorrowRef — operator T* and operator const T*
// =============================================================================

TYPED_TEST(SslHelpBaseTest, OperatorTPtr_ReturnsRawPointer)
{
    TypeParam ssl(77);
    SslMock *raw = static_cast<SslMock *>(ssl);
    ASSERT_NE(raw, nullptr);
    EXPECT_EQ(raw->i, 77);
}

TYPED_TEST(SslHelpBaseTest, OperatorConstTPtr_ReturnsRawPointer)
{
    const TypeParam ssl(88);
    const SslMock *raw = static_cast<const SslMock *>(ssl);
    ASSERT_NE(raw, nullptr);
    EXPECT_EQ(raw->i, 88);
}

// =============================================================================
// Move semantics
// =============================================================================

TYPED_TEST(SslHelpBaseTest, MoveConstruct_TransfersOwnership)
{
    TypeParam ssl(21);
    EXPECT_EQ(SslMock::instanceCnt, 1);

    TypeParam moved(std::move(ssl));
    EXPECT_EQ(SslMock::instanceCnt, 1); // still exactly one instance
    EXPECT_EQ(moved.Get()->i, 21);
    EXPECT_EQ(ssl.Get(), nullptr); // NOLINT: known moved-from state
}

TYPED_TEST(SslHelpBaseTest, MoveAssign_TransfersAndFreesOld)
{
    TypeParam a(10);
    TypeParam b(20);
    EXPECT_EQ(SslMock::instanceCnt, 2);

    b = std::move(a);
    EXPECT_EQ(SslMock::instanceCnt, 1); // b's old instance freed
    EXPECT_EQ(b.Get()->i, 10);
}
