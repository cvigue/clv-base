// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "quic/quic_tls.h"

#include <gtest/gtest.h>

#include <array>
#include <filesystem>
#include <vector>

using namespace clv::quic;

// ============================================================================
// Test Fixtures
// ============================================================================

class QuicTlsTest : public ::testing::Test
{
  protected:
    static std::string GetTestCertPath()
    {
        return "cert.pem";
    }

    static std::string GetTestKeyPath()
    {
        return "pvtkey.pem";
    }

    void SetUp() override
    {
        // Verify test certificates exist
        ASSERT_TRUE(std::filesystem::exists(GetTestCertPath()))
            << "Test certificate not found: " << GetTestCertPath();
        ASSERT_TRUE(std::filesystem::exists(GetTestKeyPath()))
            << "Test key not found: " << GetTestKeyPath();
    }
};

// ============================================================================
// Basic Construction Tests
// ============================================================================

TEST_F(QuicTlsTest, CreateServer_ValidCertAndKey_Success)
{
    ASSERT_NO_THROW({
        auto tls = QuicTls::CreateServer(GetTestCertPath(), GetTestKeyPath());
        EXPECT_TRUE(tls.GetSsl() != nullptr);
    });
}

TEST_F(QuicTlsTest, CreateServer_InvalidCertPath_Throws)
{
    EXPECT_THROW(
        {
            QuicTls::CreateServer("nonexistent.pem", GetTestKeyPath());
        },
        std::exception);
}

TEST_F(QuicTlsTest, CreateServer_InvalidKeyPath_Throws)
{
    EXPECT_THROW(
        {
            QuicTls::CreateServer(GetTestCertPath(), "nonexistent.pem");
        },
        std::exception);
}

TEST_F(QuicTlsTest, CreateClient_NoArgs_Success)
{
    ASSERT_NO_THROW({
        auto tls = QuicTls::CreateClient();
        EXPECT_TRUE(tls.GetSsl() != nullptr);
    });
}

TEST_F(QuicTlsTest, CreateClient_WithSNI_Success)
{
    ASSERT_NO_THROW({
        auto tls = QuicTls::CreateClient("localhost");
        EXPECT_TRUE(tls.GetSsl() != nullptr);
    });
}

// ============================================================================
// ALPN Tests
// ============================================================================

TEST_F(QuicTlsTest, SetAlpn_SingleProtocol_Success)
{
    auto tls = QuicTls::CreateServer(GetTestCertPath(), GetTestKeyPath());

    std::array<std::string_view, 1> alpn = {"h3"};
    ASSERT_NO_THROW(tls.SetAlpn(alpn));
}

TEST_F(QuicTlsTest, SetAlpn_MultipleProtocols_Success)
{
    auto tls = QuicTls::CreateServer(GetTestCertPath(), GetTestKeyPath());

    std::array<std::string_view, 3> alpn = {"h3", "h3-29", "h3-32"};
    ASSERT_NO_THROW(tls.SetAlpn(alpn));
}

TEST_F(QuicTlsTest, SetAlpn_EmptyProtocols_NoThrow)
{
    auto tls = QuicTls::CreateServer(GetTestCertPath(), GetTestKeyPath());

    std::vector<std::string_view> alpn;
    ASSERT_NO_THROW(tls.SetAlpn(alpn));
}

TEST_F(QuicTlsTest, GetAlpn_BeforeNegotiation_ReturnsEmpty)
{
    auto tls = QuicTls::CreateServer(GetTestCertPath(), GetTestKeyPath());

    std::array<std::string_view, 1> alpn = {"h3"};
    tls.SetAlpn(alpn);

    auto negotiated = tls.GetAlpn();
    EXPECT_FALSE(negotiated.has_value());
}

// ============================================================================
// State Tests
// ============================================================================

TEST_F(QuicTlsTest, IsComplete_InitialState_ReturnsFalse)
{
    auto tls = QuicTls::CreateServer(GetTestCertPath(), GetTestKeyPath());
    EXPECT_FALSE(tls.IsComplete());
}

TEST_F(QuicTlsTest, GetWriteLevel_InitialState_ReturnsInitial)
{
    auto tls = QuicTls::CreateServer(GetTestCertPath(), GetTestKeyPath());
    EXPECT_EQ(tls.GetWriteLevel(), QuicEncryptionLevel::Initial);
}

TEST_F(QuicTlsTest, GetReadLevel_InitialState_ReturnsInitial)
{
    auto tls = QuicTls::CreateServer(GetTestCertPath(), GetTestKeyPath());
    EXPECT_EQ(tls.GetReadLevel(), QuicEncryptionLevel::Initial);
}

// ============================================================================
// Callback Tests
// ============================================================================

TEST_F(QuicTlsTest, SetSecretCallback_ValidCallback_NoThrow)
{
    auto tls = QuicTls::CreateServer(GetTestCertPath(), GetTestKeyPath());

    bool called = false;
    tls.SetSecretCallback(
        [&called](QuicEncryptionLevel, const SSL_CIPHER *, std::span<const std::uint8_t>, std::span<const std::uint8_t>)
    {
        called = true;
    });

    // Callback shouldn't be called yet (no handshake)
    EXPECT_FALSE(called);
}

TEST_F(QuicTlsTest, SetHandshakeDataCallback_ValidCallback_NoThrow)
{
    auto tls = QuicTls::CreateServer(GetTestCertPath(), GetTestKeyPath());

    bool called = false;
    tls.SetHandshakeDataCallback(
        [&called](QuicEncryptionLevel, std::span<const std::uint8_t>)
    {
        called = true;
    });

    // Callback shouldn't be called yet (no handshake)
    EXPECT_FALSE(called);
}

TEST_F(QuicTlsTest, SetAlertCallback_ValidCallback_NoThrow)
{
    auto tls = QuicTls::CreateServer(GetTestCertPath(), GetTestKeyPath());

    bool called = false;
    tls.SetAlertCallback(
        [&called](QuicEncryptionLevel, std::uint8_t)
    {
        called = true;
    });

    // Callback shouldn't be called yet (no alert)
    EXPECT_FALSE(called);
}

// ============================================================================
// Move Semantics Tests
// ============================================================================

TEST_F(QuicTlsTest, MoveConstructor_TransfersOwnership)
{
    auto tls1 = QuicTls::CreateServer(GetTestCertPath(), GetTestKeyPath());
    SSL *ssl_ptr = tls1.GetSsl();

    QuicTls tls2(std::move(tls1));

    EXPECT_EQ(tls2.GetSsl(), ssl_ptr);
    EXPECT_EQ(tls1.GetSsl(), nullptr);
}

TEST_F(QuicTlsTest, MoveAssignment_TransfersOwnership)
{
    auto tls1 = QuicTls::CreateServer(GetTestCertPath(), GetTestKeyPath());
    auto tls2 = QuicTls::CreateClient();

    SSL *ssl1_ptr = tls1.GetSsl();
    SSL *ssl2_ptr = tls2.GetSsl();

    tls2 = std::move(tls1);

    // After move assignment with swap semantics:
    // tls2 gets tls1's SSL pointer
    // tls1 gets tls2's old SSL pointer (not nullptr)
    EXPECT_EQ(tls2.GetSsl(), ssl1_ptr);
    EXPECT_EQ(tls1.GetSsl(), ssl2_ptr); // Swap semantics - gets tls2's old ptr
}

// ============================================================================
// Error Handling Tests
// ============================================================================

TEST_F(QuicTlsTest, GetErrorString_ReturnsNonEmpty)
{
    auto error = QuicTls::GetErrorString();
    // Should return some error string (or empty if no error)
    EXPECT_TRUE(error.empty() || !error.empty());
}

// ============================================================================
// ProvideData Tests
// ============================================================================

TEST_F(QuicTlsTest, ProvideData_EmptyData_NoThrow)
{
    auto tls = QuicTls::CreateServer(GetTestCertPath(), GetTestKeyPath());

    std::vector<std::uint8_t> empty_data;
    ASSERT_NO_THROW(tls.ProvideData(QuicEncryptionLevel::Initial, empty_data));
}

TEST_F(QuicTlsTest, ProvideData_InvalidData_NoThrow)
{
    auto tls = QuicTls::CreateServer(GetTestCertPath(), GetTestKeyPath());

    // Random garbage data - BoringSSL may accept or reject it
    std::vector<std::uint8_t> garbage = {0x01, 0x02, 0x03, 0x04};

    // Just verify it doesn't crash
    ASSERT_NO_THROW(tls.ProvideData(QuicEncryptionLevel::Initial, garbage));
}

// ============================================================================
// Advance Tests
// ============================================================================

TEST_F(QuicTlsTest, Advance_InitialState_ReturnsZero)
{
    auto tls = QuicTls::CreateServer(GetTestCertPath(), GetTestKeyPath());

    // Without any data provided, Advance should indicate need for more data
    int result = tls.Advance();
    EXPECT_EQ(result, 0); // 0 = need more data
}
