// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "gtest/gtest.h"

#include <array>
#include <span>
#include <vector>

#include <HelpSslEvpPkeyCtx.h>
#include <HelpSslException.h>

using namespace clv::OpenSSL;

// Test basic HKDF-Extract functionality
TEST(SslEvpPkeyCtxTests, HkdfExtract_Basic)
{
    // Simple extract: PRK = HKDF-Extract(salt, IKM)
    std::array<std::uint8_t, 16> salt{};
    std::array<std::uint8_t, 16> ikm{};
    std::array<std::uint8_t, 32> prk{};

    std::fill(salt.begin(), salt.end(), 0x01);
    std::fill(ikm.begin(), ikm.end(), 0x02);

    auto ctx = SslEvpPkeyCtx::CreateHkdf();
    ctx.InitDerivation();
    ctx.SetHkdfMd(EVP_sha256());
    ctx.SetHkdfMode(EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY);
    ctx.SetHkdfSalt(salt);
    ctx.SetHkdfKey(ikm);
    ctx.Derive(SslEvpPkeyCtx::Output(prk.data(), prk.size()));

    // Verify output is non-zero
    bool all_zero = std::all_of(prk.begin(), prk.end(), [](auto b)
    { return b == 0; });
    EXPECT_FALSE(all_zero) << "PRK should not be all zeros";
}

// Test basic HKDF-Expand functionality
TEST(SslEvpPkeyCtxTests, HkdfExpand_Basic)
{
    // Create a PRK first
    std::array<std::uint8_t, 32> prk{};
    std::fill(prk.begin(), prk.end(), 0x42);

    // Expand: OKM = HKDF-Expand(PRK, info, L)
    std::array<std::uint8_t, 8> info = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    std::array<std::uint8_t, 16> okm{};

    auto ctx = SslEvpPkeyCtx::CreateHkdf();
    ctx.InitDerivation();
    ctx.SetHkdfMd(EVP_sha256());
    ctx.SetHkdfMode(EVP_PKEY_HKDEF_MODE_EXPAND_ONLY);
    ctx.SetHkdfKey(prk);
    ctx.AddHkdfInfo(info);
    ctx.Derive(SslEvpPkeyCtx::Output(okm.data(), okm.size()));

    // Verify output is non-zero
    bool all_zero = std::all_of(okm.begin(), okm.end(), [](auto b)
    { return b == 0; });
    EXPECT_FALSE(all_zero) << "OKM should not be all zeros";
}

// Test HKDF-Extract-and-Expand (full HKDF)
TEST(SslEvpPkeyCtxTests, HkdfExtractAndExpand_Full)
{
    std::array<std::uint8_t, 16> salt{};
    std::array<std::uint8_t, 16> ikm{};
    std::array<std::uint8_t, 8> info{};
    std::array<std::uint8_t, 32> okm{};

    std::fill(salt.begin(), salt.end(), 0x01);
    std::fill(ikm.begin(), ikm.end(), 0x02);
    std::fill(info.begin(), info.end(), 0x03);

    auto ctx = SslEvpPkeyCtx::CreateHkdf();
    ctx.InitDerivation();
    ctx.SetHkdfMd(EVP_sha256());
    ctx.SetHkdfMode(EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND);
    ctx.SetHkdfSalt(salt);
    ctx.SetHkdfKey(ikm);
    ctx.AddHkdfInfo(info);
    ctx.Derive(SslEvpPkeyCtx::Output(okm.data(), okm.size()));

    // Verify output is non-zero
    bool all_zero = std::all_of(okm.begin(), okm.end(), [](auto b)
    { return b == 0; });
    EXPECT_FALSE(all_zero) << "OKM should not be all zeros";
}

// Test that same inputs produce same outputs (deterministic)
TEST(SslEvpPkeyCtxTests, HkdfDeterministic)
{
    std::array<std::uint8_t, 16> salt{};
    std::array<std::uint8_t, 16> ikm{};
    std::array<std::uint8_t, 32> prk1{};
    std::array<std::uint8_t, 32> prk2{};

    std::fill(salt.begin(), salt.end(), 0xAA);
    std::fill(ikm.begin(), ikm.end(), 0xBB);

    // First derivation
    {
        auto ctx = SslEvpPkeyCtx::CreateHkdf();
        ctx.InitDerivation();
        ctx.SetHkdfMd(EVP_sha256());
        ctx.SetHkdfMode(EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY);
        ctx.SetHkdfSalt(salt);
        ctx.SetHkdfKey(ikm);
        ctx.Derive(SslEvpPkeyCtx::Output(prk1.data(), prk1.size()));
    }

    // Second derivation (same inputs)
    {
        auto ctx = SslEvpPkeyCtx::CreateHkdf();
        ctx.InitDerivation();
        ctx.SetHkdfMd(EVP_sha256());
        ctx.SetHkdfMode(EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY);
        ctx.SetHkdfSalt(salt);
        ctx.SetHkdfKey(ikm);
        ctx.Derive(SslEvpPkeyCtx::Output(prk2.data(), prk2.size()));
    }

    EXPECT_EQ(prk1, prk2) << "Same inputs should produce same output";
}

// Test that different salts produce different outputs
TEST(SslEvpPkeyCtxTests, HkdfDifferentSalts)
{
    std::array<std::uint8_t, 16> salt1{};
    std::array<std::uint8_t, 16> salt2{};
    std::array<std::uint8_t, 16> ikm{};
    std::array<std::uint8_t, 32> prk1{};
    std::array<std::uint8_t, 32> prk2{};

    std::fill(salt1.begin(), salt1.end(), 0x01);
    std::fill(salt2.begin(), salt2.end(), 0x02);
    std::fill(ikm.begin(), ikm.end(), 0x42);

    // Extract with salt1
    {
        auto ctx = SslEvpPkeyCtx::CreateHkdf();
        ctx.InitDerivation();
        ctx.SetHkdfMd(EVP_sha256());
        ctx.SetHkdfMode(EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY);
        ctx.SetHkdfSalt(SslEvpPkeyCtx::Salt(salt1.data(), salt1.size()));
        ctx.SetHkdfKey(SslEvpPkeyCtx::Key(ikm.data(), ikm.size()));
        ctx.Derive(SslEvpPkeyCtx::Output(prk1.data(), prk1.size()));
    }

    // Extract with salt2
    {
        auto ctx = SslEvpPkeyCtx::CreateHkdf();
        ctx.InitDerivation();
        ctx.SetHkdfMd(EVP_sha256());
        ctx.SetHkdfMode(EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY);
        ctx.SetHkdfSalt(salt2);
        ctx.SetHkdfKey(ikm);
        ctx.Derive(SslEvpPkeyCtx::Output(prk2.data(), prk2.size()));
    }

    EXPECT_NE(prk1, prk2) << "Different salts should produce different outputs";
}

// Test that different info produces different outputs
TEST(SslEvpPkeyCtxTests, HkdfDifferentInfo)
{
    std::array<std::uint8_t, 32> prk{};
    std::array<std::uint8_t, 8> info1{};
    std::array<std::uint8_t, 8> info2{};
    std::array<std::uint8_t, 16> okm1{};
    std::array<std::uint8_t, 16> okm2{};

    std::fill(prk.begin(), prk.end(), 0x42);
    std::fill(info1.begin(), info1.end(), 0x01);
    std::fill(info2.begin(), info2.end(), 0x02);

    // Expand with info1
    {
        auto ctx = SslEvpPkeyCtx::CreateHkdf();
        ctx.InitDerivation();
        ctx.SetHkdfMd(EVP_sha256());
        ctx.SetHkdfMode(EVP_PKEY_HKDEF_MODE_EXPAND_ONLY);
        ctx.SetHkdfKey(prk);
        ctx.AddHkdfInfo(info1);
        ctx.Derive(SslEvpPkeyCtx::Output(okm1.data(), okm1.size()));
    }

    // Expand with info2
    {
        auto ctx = SslEvpPkeyCtx::CreateHkdf();
        ctx.InitDerivation();
        ctx.SetHkdfMd(EVP_sha256());
        ctx.SetHkdfMode(EVP_PKEY_HKDEF_MODE_EXPAND_ONLY);
        ctx.SetHkdfKey(prk);
        ctx.AddHkdfInfo(info2);
        ctx.Derive(SslEvpPkeyCtx::Output(okm2.data(), okm2.size()));
    }

    EXPECT_NE(okm1, okm2) << "Different info should produce different outputs";
}

// Test variable output lengths
TEST(SslEvpPkeyCtxTests, HkdfVariableOutputLengths)
{
    std::array<std::uint8_t, 32> prk{};
    std::fill(prk.begin(), prk.end(), 0x42);

    std::array<std::uint8_t, 4> info = {0x01, 0x02, 0x03, 0x04};

    // Test different output lengths
    for (std::size_t len : {1, 16, 32, 64, 128})
    {
        std::vector<std::uint8_t> okm(len);

        auto ctx = SslEvpPkeyCtx::CreateHkdf();
        ctx.InitDerivation();
        ctx.SetHkdfMd(EVP_sha256());
        ctx.SetHkdfMode(EVP_PKEY_HKDEF_MODE_EXPAND_ONLY);
        ctx.SetHkdfKey(prk);
        ctx.AddHkdfInfo(info);
        ctx.Derive(SslEvpPkeyCtx::Output(okm.data(), okm.size()));

        EXPECT_EQ(okm.size(), len) << "Output should be requested length";

        bool all_zero = std::all_of(okm.begin(), okm.end(), [](auto b)
        { return b == 0; });
        EXPECT_FALSE(all_zero) << "Output should not be all zeros for length " << len;
    }
}

// Test exception on uninitialized context
TEST(SslEvpPkeyCtxTests, ThrowsOnUninitialized)
{
    auto ctx = SslEvpPkeyCtx::CreateHkdf();
    // Don't call InitDerivation()

    // Should throw because we didn't initialize
    EXPECT_THROW(ctx.SetHkdfMode(EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY), SslException);
}

// Test exception on missing key
TEST(SslEvpPkeyCtxTests, ThrowsOnMissingKey)
{
    auto ctx = SslEvpPkeyCtx::CreateHkdf();
    ctx.InitDerivation();
    ctx.SetHkdfMd(EVP_sha256());
    ctx.SetHkdfMode(EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY);
    // Don't set key

    std::array<std::uint8_t, 32> output{};
    EXPECT_THROW(ctx.Derive(SslEvpPkeyCtx::Output(output.data(), output.size())), SslException);
}

// Test exception on empty key
TEST(SslEvpPkeyCtxTests, ThrowsOnEmptyKey)
{
    auto ctx = SslEvpPkeyCtx::CreateHkdf();
    ctx.InitDerivation();
    ctx.SetHkdfMd(EVP_sha256());
    ctx.SetHkdfMode(EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY);

    std::span<const std::uint8_t> empty_key;
    EXPECT_THROW(ctx.SetHkdfKey(SslEvpPkeyCtx::Key(empty_key.data(), empty_key.size())), SslException);
}

// Test exception on excessive output length
TEST(SslEvpPkeyCtxTests, ThrowsOnExcessiveLength)
{
    std::array<std::uint8_t, 32> prk{};
    std::fill(prk.begin(), prk.end(), 0x42);

    // HKDF-Expand with SHA-256 can output up to 255 * 32 = 8160 bytes
    std::vector<std::uint8_t> huge_output(10000);

    auto ctx = SslEvpPkeyCtx::CreateHkdf();
    ctx.InitDerivation();
    ctx.SetHkdfMd(EVP_sha256());
    ctx.SetHkdfMode(EVP_PKEY_HKDEF_MODE_EXPAND_ONLY);
    ctx.SetHkdfKey(SslEvpPkeyCtx::Key(prk.data(), prk.size()));

    EXPECT_THROW(ctx.Derive(SslEvpPkeyCtx::Output(huge_output.data(), huge_output.size())), SslException);
}

// Test RAII cleanup (context should auto-free)
TEST(SslEvpPkeyCtxTests, RaiiCleanup)
{
    // Create context in inner scope
    {
        auto ctx = SslEvpPkeyCtx::CreateHkdf();
        ctx.InitDerivation();
        // Context should be freed when it goes out of scope
    }

    // If RAII works correctly, no memory leak
    // This is mainly tested by running under valgrind/ASAN
    SUCCEED() << "Context cleaned up successfully";
}

// Test move semantics
TEST(SslEvpPkeyCtxTests, MoveSemantics)
{
    auto ctx1 = SslEvpPkeyCtx::CreateHkdf();
    ctx1.InitDerivation();
    ctx1.SetHkdfMd(EVP_sha256());

    // Move construct
    auto ctx2 = std::move(ctx1);

    // ctx2 should be usable
    ctx2.SetHkdfMode(EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY);

    std::array<std::uint8_t, 16> salt{};
    std::array<std::uint8_t, 16> ikm{};
    std::array<std::uint8_t, 32> prk{};

    std::fill(salt.begin(), salt.end(), 0x01);
    std::fill(ikm.begin(), ikm.end(), 0x02);

    ctx2.SetHkdfSalt(salt);
    ctx2.SetHkdfKey(ikm);
    ctx2.Derive(SslEvpPkeyCtx::Output(prk.data(), prk.size()));

    bool all_zero = std::all_of(prk.begin(), prk.end(), [](auto b)
    { return b == 0; });
    EXPECT_FALSE(all_zero) << "Moved context should still work";
}

// Test that empty salt is allowed (RFC 5869 allows it)
TEST(SslEvpPkeyCtxTests, EmptySaltAllowed)
{
    std::span<const std::uint8_t> empty_salt;
    std::array<std::uint8_t, 16> ikm{};
    std::array<std::uint8_t, 32> prk{};

    std::fill(ikm.begin(), ikm.end(), 0x42);

    auto ctx = SslEvpPkeyCtx::CreateHkdf();
    ctx.InitDerivation();
    ctx.SetHkdfMd(EVP_sha256());
    ctx.SetHkdfMode(EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY);
    ctx.SetHkdfSalt(SslEvpPkeyCtx::Salt(empty_salt.data(), empty_salt.size())); // Empty salt should be OK
    ctx.SetHkdfKey(SslEvpPkeyCtx::Key(ikm.data(), ikm.size()));

    EXPECT_NO_THROW(ctx.Derive(SslEvpPkeyCtx::Output(prk.data(), prk.size())));

    bool all_zero = std::all_of(prk.begin(), prk.end(), [](auto b)
    { return b == 0; });
    EXPECT_FALSE(all_zero) << "PRK should not be all zeros even with empty salt";
}

// ================================================================================================
// Static Extract/Expand convenience method tests
// ================================================================================================

TEST(SslEvpPkeyCtxTests, StaticExtractHkdf_Basic)
{
    std::array<std::uint8_t, 16> salt{};
    std::array<std::uint8_t, 16> ikm{};

    std::fill(salt.begin(), salt.end(), 0x01);
    std::fill(ikm.begin(), ikm.end(), 0x02);

    auto prk = SslEvpPkeyCtx::ExtractHkdf(EVP_sha256(),
                                          SslEvpPkeyCtx::Key(ikm),
                                          SslEvpPkeyCtx::Salt(salt));

    EXPECT_EQ(prk.size(), 32) << "SHA-256 PRK should be 32 bytes";

    bool all_zero = std::all_of(prk.begin(), prk.end(), [](auto b)
    { return b == 0; });
    EXPECT_FALSE(all_zero) << "PRK should not be all zeros";
}

TEST(SslEvpPkeyCtxTests, StaticExtractHkdf_EmptySalt)
{
    std::array<std::uint8_t, 16> ikm{};
    std::fill(ikm.begin(), ikm.end(), 0x42);

    std::array<std::uint8_t, 0> empty_salt{};

    auto prk = SslEvpPkeyCtx::ExtractHkdf(EVP_sha256(),
                                          SslEvpPkeyCtx::Key(ikm),
                                          SslEvpPkeyCtx::Salt(empty_salt));

    EXPECT_EQ(prk.size(), 32);
    bool all_zero = std::all_of(prk.begin(), prk.end(), [](auto b)
    { return b == 0; });
    EXPECT_FALSE(all_zero);
}

TEST(SslEvpPkeyCtxTests, StaticExtractHkdf_Deterministic)
{
    std::array<std::uint8_t, 16> salt{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    std::array<std::uint8_t, 16> ikm{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00};

    auto prk1 = SslEvpPkeyCtx::ExtractHkdf(EVP_sha256(),
                                           SslEvpPkeyCtx::Key(ikm),
                                           SslEvpPkeyCtx::Salt(salt));

    auto prk2 = SslEvpPkeyCtx::ExtractHkdf(EVP_sha256(),
                                           SslEvpPkeyCtx::Key(ikm),
                                           SslEvpPkeyCtx::Salt(salt));

    EXPECT_EQ(prk1, prk2) << "Same inputs should produce same PRK";
}

TEST(SslEvpPkeyCtxTests, StaticExpandHkdf_Basic)
{
    std::array<std::uint8_t, 32> prk{};
    std::fill(prk.begin(), prk.end(), 0x42);

    std::array<std::uint8_t, 8> info{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    auto okm = SslEvpPkeyCtx::ExpandHkdf(EVP_sha256(),
                                         SslEvpPkeyCtx::Key(prk),
                                         SslEvpPkeyCtx::Info(info),
                                         16);

    EXPECT_EQ(okm.size(), 16) << "OKM should be requested length";

    bool all_zero = std::all_of(okm.begin(), okm.end(), [](auto b)
    { return b == 0; });
    EXPECT_FALSE(all_zero) << "OKM should not be all zeros";
}

TEST(SslEvpPkeyCtxTests, StaticExpandHkdf_FixedSize)
{
    std::array<std::uint8_t, 32> prk{};
    std::fill(prk.begin(), prk.end(), 0x42);

    std::array<std::uint8_t, 8> info{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    // Template version returns std::array
    auto okm = SslEvpPkeyCtx::ExpandHkdf<16>(EVP_sha256(),
                                             SslEvpPkeyCtx::Key(prk),
                                             SslEvpPkeyCtx::Info(info));

    EXPECT_EQ(okm.size(), 16) << "OKM should be compile-time size";

    bool all_zero = std::all_of(okm.begin(), okm.end(), [](auto b)
    { return b == 0; });
    EXPECT_FALSE(all_zero) << "OKM should not be all zeros";
}

TEST(SslEvpPkeyCtxTests, StaticExpandHkdf_FixedVsRuntime)
{
    std::array<std::uint8_t, 32> prk{};
    std::fill(prk.begin(), prk.end(), 0x42);

    std::array<std::uint8_t, 8> info{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    // Both versions should produce identical output
    auto okm_fixed = SslEvpPkeyCtx::ExpandHkdf<32>(EVP_sha256(),
                                                   SslEvpPkeyCtx::Key(prk),
                                                   SslEvpPkeyCtx::Info(info));

    auto okm_runtime = SslEvpPkeyCtx::ExpandHkdf(EVP_sha256(),
                                                 SslEvpPkeyCtx::Key(prk),
                                                 SslEvpPkeyCtx::Info(info),
                                                 32);

    EXPECT_TRUE(std::equal(okm_fixed.begin(), okm_fixed.end(), okm_runtime.begin()))
        << "Fixed-size and runtime-size versions should produce identical output";
}

TEST(SslEvpPkeyCtxTests, StaticExpandHkdf_CommonSizes)
{
    std::array<std::uint8_t, 32> prk{};
    std::fill(prk.begin(), prk.end(), 0x42);

    std::array<std::uint8_t, 0> empty_info{};

    // Test common QUIC/TLS sizes
    auto okm_12 = SslEvpPkeyCtx::ExpandHkdf<12>(EVP_sha256(),
                                                SslEvpPkeyCtx::Key(prk),
                                                SslEvpPkeyCtx::Info(empty_info));
    EXPECT_EQ(okm_12.size(), 12);

    auto okm_16 = SslEvpPkeyCtx::ExpandHkdf<16>(EVP_sha256(),
                                                SslEvpPkeyCtx::Key(prk),
                                                SslEvpPkeyCtx::Info(empty_info));
    EXPECT_EQ(okm_16.size(), 16);

    auto okm_32 = SslEvpPkeyCtx::ExpandHkdf<32>(EVP_sha256(),
                                                SslEvpPkeyCtx::Key(prk),
                                                SslEvpPkeyCtx::Info(empty_info));
    EXPECT_EQ(okm_32.size(), 32);
}

TEST(SslEvpPkeyCtxTests, StaticExpandHkdf_VariableLengths)
{
    std::array<std::uint8_t, 32> prk{};
    std::fill(prk.begin(), prk.end(), 0x99);

    std::array<std::uint8_t, 4> info{0xAA, 0xBB, 0xCC, 0xDD};

    // Test various output lengths
    for (std::size_t len : {16, 32, 48, 64, 128})
    {
        auto okm = SslEvpPkeyCtx::ExpandHkdf(EVP_sha256(),
                                             SslEvpPkeyCtx::Key(prk),
                                             SslEvpPkeyCtx::Info(info),
                                             len);

        EXPECT_EQ(okm.size(), len) << "OKM should be exactly " << len << " bytes";
    }
}

TEST(SslEvpPkeyCtxTests, StaticExpandHkdf_EmptyInfo)
{
    std::array<std::uint8_t, 32> prk{};
    std::fill(prk.begin(), prk.end(), 0x55);

    std::array<std::uint8_t, 0> empty_info{};

    auto okm = SslEvpPkeyCtx::ExpandHkdf(EVP_sha256(),
                                         SslEvpPkeyCtx::Key(prk),
                                         SslEvpPkeyCtx::Info(empty_info),
                                         32);

    EXPECT_EQ(okm.size(), 32);
    bool all_zero = std::all_of(okm.begin(), okm.end(), [](auto b)
    { return b == 0; });
    EXPECT_FALSE(all_zero);
}

TEST(SslEvpPkeyCtxTests, StaticExpandHkdf_Deterministic)
{
    std::array<std::uint8_t, 32> prk{};
    std::fill(prk.begin(), prk.end(), 0x88);

    std::array<std::uint8_t, 10> info{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A};

    auto okm1 = SslEvpPkeyCtx::ExpandHkdf(EVP_sha256(),
                                          SslEvpPkeyCtx::Key(prk),
                                          SslEvpPkeyCtx::Info(info),
                                          24);

    auto okm2 = SslEvpPkeyCtx::ExpandHkdf(EVP_sha256(),
                                          SslEvpPkeyCtx::Key(prk),
                                          SslEvpPkeyCtx::Info(info),
                                          24);

    EXPECT_EQ(okm1, okm2) << "Same inputs should produce same OKM";
}

TEST(SslEvpPkeyCtxTests, StaticExpandHkdf_DifferentInfoDifferentOutput)
{
    std::array<std::uint8_t, 32> prk{};
    std::fill(prk.begin(), prk.end(), 0x77);

    std::array<std::uint8_t, 4> info1{0x01, 0x02, 0x03, 0x04};
    std::array<std::uint8_t, 4> info2{0x05, 0x06, 0x07, 0x08};

    auto okm1 = SslEvpPkeyCtx::ExpandHkdf(EVP_sha256(),
                                          SslEvpPkeyCtx::Key(prk),
                                          SslEvpPkeyCtx::Info(info1),
                                          16);

    auto okm2 = SslEvpPkeyCtx::ExpandHkdf(EVP_sha256(),
                                          SslEvpPkeyCtx::Key(prk),
                                          SslEvpPkeyCtx::Info(info2),
                                          16);

    EXPECT_NE(okm1, okm2) << "Different info should produce different OKM";
}

TEST(SslEvpPkeyCtxTests, StaticExpandHkdf_ExcessiveLengthThrows)
{
    std::array<std::uint8_t, 32> prk{};
    std::fill(prk.begin(), prk.end(), 0x33);

    std::array<std::uint8_t, 4> info{0xAA, 0xBB, 0xCC, 0xDD};

    // SHA-256 max output is 255 * 32 = 8160 bytes
    EXPECT_THROW(
        SslEvpPkeyCtx::ExpandHkdf(EVP_sha256(),
                                  SslEvpPkeyCtx::Key(prk),
                                  SslEvpPkeyCtx::Info(info),
                                  8200),
        SslException)
        << "Should throw when output length exceeds maximum";
}

TEST(SslEvpPkeyCtxTests, StaticExtractThenExpand_FullWorkflow)
{
    // Simulate full HKDF workflow: Extract then Expand
    std::array<std::uint8_t, 16> salt{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    std::array<std::uint8_t, 32> ikm{};
    std::fill(ikm.begin(), ikm.end(), 0x0B);

    // Extract phase
    auto prk = SslEvpPkeyCtx::ExtractHkdf(EVP_sha256(),
                                          SslEvpPkeyCtx::Key(ikm),
                                          SslEvpPkeyCtx::Salt(salt));

    EXPECT_EQ(prk.size(), 32);

    // Expand phase
    std::array<std::uint8_t, 10> info{0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9};
    auto okm = SslEvpPkeyCtx::ExpandHkdf(EVP_sha256(),
                                         SslEvpPkeyCtx::Key(prk),
                                         SslEvpPkeyCtx::Info(info),
                                         42);

    EXPECT_EQ(okm.size(), 42);

    bool all_zero = std::all_of(okm.begin(), okm.end(), [](auto b)
    { return b == 0; });
    EXPECT_FALSE(all_zero) << "Final OKM should not be all zeros";
}

TEST(SslEvpPkeyCtxTests, StaticExtractHkdf_SHA384)
{
    std::array<std::uint8_t, 16> salt{};
    std::array<std::uint8_t, 16> ikm{};

    std::fill(salt.begin(), salt.end(), 0xAA);
    std::fill(ikm.begin(), ikm.end(), 0xBB);

    auto prk = SslEvpPkeyCtx::ExtractHkdf(EVP_sha384(),
                                          SslEvpPkeyCtx::Key(ikm),
                                          SslEvpPkeyCtx::Salt(salt));

    EXPECT_EQ(prk.size(), 48) << "SHA-384 PRK should be 48 bytes";

    bool all_zero = std::all_of(prk.begin(), prk.end(), [](auto b)
    { return b == 0; });
    EXPECT_FALSE(all_zero) << "PRK should not be all zeros";
}

TEST(SslEvpPkeyCtxTests, StaticExtractHkdf_SHA512)
{
    std::array<std::uint8_t, 16> salt{};
    std::array<std::uint8_t, 16> ikm{};

    std::fill(salt.begin(), salt.end(), 0xCC);
    std::fill(ikm.begin(), ikm.end(), 0xDD);

    auto prk = SslEvpPkeyCtx::ExtractHkdf(EVP_sha512(),
                                          SslEvpPkeyCtx::Key(ikm),
                                          SslEvpPkeyCtx::Salt(salt));

    EXPECT_EQ(prk.size(), 64) << "SHA-512 PRK should be 64 bytes";

    bool all_zero = std::all_of(prk.begin(), prk.end(), [](auto b)
    { return b == 0; });
    EXPECT_FALSE(all_zero) << "PRK should not be all zeros";
}

TEST(SslEvpPkeyCtxTests, StaticExtractHkdf_DifferentDigests_DifferentSizes)
{
    std::array<std::uint8_t, 16> salt{};
    std::array<std::uint8_t, 16> ikm{};
    std::fill(salt.begin(), salt.end(), 0x11);
    std::fill(ikm.begin(), ikm.end(), 0x22);

    auto prk256 = SslEvpPkeyCtx::ExtractHkdf(EVP_sha256(),
                                             SslEvpPkeyCtx::Key(ikm),
                                             SslEvpPkeyCtx::Salt(salt));

    auto prk384 = SslEvpPkeyCtx::ExtractHkdf(EVP_sha384(),
                                             SslEvpPkeyCtx::Key(ikm),
                                             SslEvpPkeyCtx::Salt(salt));

    auto prk512 = SslEvpPkeyCtx::ExtractHkdf(EVP_sha512(),
                                             SslEvpPkeyCtx::Key(ikm),
                                             SslEvpPkeyCtx::Salt(salt));

    EXPECT_EQ(prk256.size(), 32);
    EXPECT_EQ(prk384.size(), 48);
    EXPECT_EQ(prk512.size(), 64);

    // All should produce different outputs
    EXPECT_NE(std::vector<uint8_t>(prk256.begin(), prk256.begin() + 32),
              std::vector<uint8_t>(prk384.begin(), prk384.begin() + 32));
    EXPECT_NE(std::vector<uint8_t>(prk256.begin(), prk256.begin() + 32),
              std::vector<uint8_t>(prk512.begin(), prk512.begin() + 32));
}
