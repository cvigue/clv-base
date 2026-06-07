// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "HelpSslHmac.h"

#include <cstdint>
#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <vector>
#include <array>
#include <string>

using namespace clv::OpenSSL;

// ================================================================================================
// Typed Test Configuration - Parameterize tests across SHA-256 and SHA-512
// ================================================================================================

template <typename Traits>
struct HmacConfig
{
    using traits_type = Traits;
    static constexpr std::size_t output_size = Traits::output_size;
    static constexpr const char *name = Traits::digest_name;
};

using HmacSha256Config = HmacConfig<HmacSha256Traits>;
using HmacSha512Config = HmacConfig<HmacSha512Traits>;

// ================================================================================================
// Typed Test Fixture
// ================================================================================================

template <typename T>
class HmacTest : public ::testing::Test
{
  protected:
    using Config = T;
    using Traits = typename T::traits_type;
    static constexpr std::size_t output_size = T::output_size;
};

using HmacTypes = ::testing::Types<HmacSha256Config, HmacSha512Config>;
TYPED_TEST_SUITE(HmacTest, HmacTypes);

// ================================================================================================
// Typed Tests - Run for both SHA-256 and SHA-512
// ================================================================================================

TYPED_TEST(HmacTest, BasicComputation)
{
    using Traits = typename TestFixture::Traits;

    // Test vector from RFC 4231
    std::vector<std::uint8_t> key(20, 0x0b);
    std::string data = "Hi There";
    std::vector<std::uint8_t> data_vec(data.begin(), data.end());

    auto result = SslHmacCtx<Traits>::Hmac(key, data_vec);

    EXPECT_EQ(result.size(), TestFixture::output_size);

    // SHA-256 expected: b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
    // SHA-512 expected: 87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854
    if constexpr (TestFixture::output_size == 32)
    {
        std::array<std::uint8_t, 32> expected = {
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7};
        EXPECT_EQ(result, expected);
    }
    else if constexpr (TestFixture::output_size == 64)
    {
        std::array<std::uint8_t, 64> expected = {
            0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d, 0x4f, 0xf0, 0xb4, 0x24, 0x1a, 0x1d, 0x6c, 0xb0, 0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78, 0x7a, 0xd0, 0xb3, 0x05, 0x45, 0xe1, 0x7c, 0xde, 0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02, 0x03, 0x8b, 0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4, 0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70, 0x2e, 0x69, 0x6c, 0x20, 0x3a, 0x12, 0x68, 0x54};
        EXPECT_EQ(result, expected);
    }
}

TYPED_TEST(HmacTest, EmptyData)
{
    using Traits = typename TestFixture::Traits;

    std::vector<std::uint8_t> key = {0x01, 0x02, 0x03, 0x04};
    std::vector<std::uint8_t> data;

    EXPECT_NO_THROW({
        auto result = SslHmacCtx<Traits>::Hmac(key, data);
        EXPECT_EQ(result.size(), TestFixture::output_size);
    });
}

TYPED_TEST(HmacTest, LargeData)
{
    using Traits = typename TestFixture::Traits;

    std::vector<std::uint8_t> key = {0xaa, 0xbb, 0xcc, 0xdd};
    std::vector<std::uint8_t> data(10000, 0x55); // 10KB

    EXPECT_NO_THROW({
        auto result = SslHmacCtx<Traits>::Hmac(key, data);
        EXPECT_EQ(result.size(), TestFixture::output_size);
    });
}

TYPED_TEST(HmacTest, IncrementalHmac)
{
    using Traits = typename TestFixture::Traits;

    std::vector<std::uint8_t> key = {0x01, 0x02, 0x03, 0x04};
    std::vector<std::uint8_t> data1 = {0x11, 0x22, 0x33};
    std::vector<std::uint8_t> data2 = {0x44, 0x55, 0x66};
    std::vector<std::uint8_t> data_full = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

    // Compute in one shot
    auto result_one_shot = SslHmacCtx<Traits>::Hmac(key, data_full);

    // Compute incrementally
    SslHmacCtx<Traits> ctx(nullptr); // Start with empty context, Init() will create it
    ctx.Init(key);
    ctx.Update(data1);
    ctx.Update(data2);
    auto result_incremental = ctx.Final();

    EXPECT_EQ(result_one_shot, result_incremental);
}

TYPED_TEST(HmacTest, FreeFunctionConsistency)
{
    using Traits = typename TestFixture::Traits;

    std::vector<std::uint8_t> key = {0x01, 0x02, 0x03};
    std::vector<std::uint8_t> data = {0xaa, 0xbb, 0xcc};

    auto result_templated = SslHmacCtx<Traits>::Hmac(key, data);

    // Verify consistency with free functions
    if constexpr (TestFixture::output_size == 32)
    {
        auto result_free = HmacSha256(key, data);
        EXPECT_EQ(result_templated, result_free);
    }
    else if constexpr (TestFixture::output_size == 64)
    {
        auto result_free = HmacSha512(key, data);
        EXPECT_EQ(result_templated, result_free);
    }
}

TYPED_TEST(HmacTest, Determinism)
{
    using Traits = typename TestFixture::Traits;

    std::vector<std::uint8_t> key = {0x12, 0x34, 0x56, 0x78};
    std::vector<std::uint8_t> data = {0x9a, 0xbc, 0xde, 0xf0};

    auto result1 = SslHmacCtx<Traits>::Hmac(key, data);
    auto result2 = SslHmacCtx<Traits>::Hmac(key, data);

    EXPECT_EQ(result1, result2);
}

TYPED_TEST(HmacTest, KeySensitivity)
{
    using Traits = typename TestFixture::Traits;

    std::vector<std::uint8_t> key1 = {0x01, 0x02, 0x03};
    std::vector<std::uint8_t> key2 = {0x01, 0x02, 0x04}; // Different key
    std::vector<std::uint8_t> data = {0xaa, 0xbb, 0xcc};

    auto result1 = SslHmacCtx<Traits>::Hmac(key1, data);
    auto result2 = SslHmacCtx<Traits>::Hmac(key2, data);

    EXPECT_NE(result1, result2);
}

TYPED_TEST(HmacTest, DataSensitivity)
{
    using Traits = typename TestFixture::Traits;

    std::vector<std::uint8_t> key = {0x01, 0x02, 0x03};
    std::vector<std::uint8_t> data1 = {0xaa, 0xbb, 0xcc};
    std::vector<std::uint8_t> data2 = {0xaa, 0xbb, 0xcd}; // Different data

    auto result1 = SslHmacCtx<Traits>::Hmac(key, data1);
    auto result2 = SslHmacCtx<Traits>::Hmac(key, data2);

    EXPECT_NE(result1, result2);
}

// ================================================================================================
// Non-Typed Tests - Algorithm-specific or edge cases
// ================================================================================================

TEST(SslHmacCtx, HmacSha256_LongKey)
{
    // RFC 4231 test case 5: key longer than block size (SHA-256 specific)
    std::vector<std::uint8_t> key(131, 0xaa);
    std::string data = "Test Using Larger Than Block-Size Key - Hash Key First";
    std::vector<std::uint8_t> data_vec(data.begin(), data.end());

    auto result = HmacSha256(key, data_vec);

    // Expected: 60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54
    std::array<std::uint8_t, 32> expected = {
        0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5, 0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54};

    EXPECT_EQ(result, expected);
}

TEST(SslHmacCtx, IncrementalHmac_EmptyUpdates)
{
    // Edge case: empty update calls
    std::vector<std::uint8_t> key = {0x01};
    std::vector<std::uint8_t> empty;

    SslHmacCtx<HmacSha256Traits> ctx(nullptr);
    ctx.Init(key);
    ctx.Update(empty); // Empty update should be fine
    auto result = ctx.Final();

    EXPECT_EQ(result.size(), 32);
}

// ================================================================================================
// Constant-Time Comparison Tests - Algorithm-independent
// ================================================================================================

TEST(SslHmacCtx, ConstantTimeCompare_Equal)
{
    std::vector<std::uint8_t> a = {0x01, 0x02, 0x03, 0x04};
    std::vector<std::uint8_t> b = {0x01, 0x02, 0x03, 0x04};

    EXPECT_TRUE(SslHmacCtx<>::ConstantTimeCompare(a, b));
}

TEST(SslHmacCtx, ConstantTimeCompare_NotEqual)
{
    std::vector<std::uint8_t> a = {0x01, 0x02, 0x03, 0x04};
    std::vector<std::uint8_t> b = {0x01, 0x02, 0x03, 0x05}; // Last byte differs

    EXPECT_FALSE(SslHmacCtx<>::ConstantTimeCompare(a, b));
}

TEST(SslHmacCtx, ConstantTimeCompare_DifferentLengths)
{
    std::vector<std::uint8_t> a = {0x01, 0x02, 0x03, 0x04};
    std::vector<std::uint8_t> b = {0x01, 0x02, 0x03};

    EXPECT_FALSE(SslHmacCtx<>::ConstantTimeCompare(a, b));
}

TEST(SslHmacCtx, ConstantTimeCompare_Empty)
{
    std::vector<std::uint8_t> a;
    std::vector<std::uint8_t> b;

    EXPECT_TRUE(SslHmacCtx<>::ConstantTimeCompare(a, b));
}

TEST(SslHmacCtx, ConstantTimeCompare_OneBitDifference)
{
    std::vector<std::uint8_t> a = {0b10101010};
    std::vector<std::uint8_t> b = {0b10101011}; // Single bit flip

    EXPECT_FALSE(SslHmacCtx<>::ConstantTimeCompare(a, b));
}
