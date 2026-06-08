// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>

#include "HelpSslException.h"
#include "HelpSslX509.h"
#include "HelpSslX509Crl.h"

#include <openssl/x509.h>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

using namespace clv::OpenSSL;

// ================================================================================================
// Construction from PEM string
// ================================================================================================

// Minimal valid PEM CRL generated from the test CA (cert.pem / key.pem).
static constexpr std::string_view kCrlPem = "-----BEGIN X509 CRL-----\n"
                                            "MIIB3TCBxgIBATANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCVVMxEzARBgNV\n"
                                            "BAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xGjAYBgNVBAoM\n"
                                            "EVRlc3QgT3JnYW5pemF0aW9uMRAwDgYDVQQLDAdUZXN0aW5nMRkwFwYDVQQDDBB0\n"
                                            "ZXN0LmV4YW1wbGUuY29tFw0yNjA0MTUwOTM4MzVaFw0zNjA0MTIwOTM4MzVaoA4w\n"
                                            "DDAKBgNVHRQEAwIBATANBgkqhkiG9w0BAQsFAAOCAQEARMcIqXCcCkpnB0x+XJXa\n"
                                            "BTxtRGlgSOSFxaQ/NQy/DjziHEtQCe694voWpYtgH+h7EnA64PbOPodCEaVJR4zy\n"
                                            "IgV6qlzWWc5WT+vhbmZqajg5M4mKqx1kjgnK/hpPVOgjA2aTeMl6g/e3PcH34oBQ\n"
                                            "cFaf7PbG75cycfBLqBq3zcQJc1bczuVUW/XHqwQqsz6iNmvNpsCpN2u+VXCQzBzj\n"
                                            "6LYKWlNpd1fszoRu4vMO7rw4xgM28GuDCyv553jMpGY102Y1y94jlWN/j8js0QdD\n"
                                            "wQFtlIC6NQ8l8XAMMLRM7s83pS9q7g8M3Ut144eMR+qKgWXEaz0jaIZzm4gcmE23\n"
                                            "DA==\n"
                                            "-----END X509 CRL-----\n";

TEST(SslX509CrlTest, ConstructFromPemString)
{
    EXPECT_NO_THROW(SslX509Crl{kCrlPem});
}

TEST(SslX509CrlTest, GetIsNotNull)
{
    SslX509Crl crl{kCrlPem};
    EXPECT_NE(crl.Get(), nullptr);
}

// ================================================================================================
// Construction from stream
// ================================================================================================

TEST(SslX509CrlTest, ConstructFromStream)
{
    std::istringstream ss{std::string(kCrlPem)};
    EXPECT_NO_THROW(SslX509Crl{std::move(ss)});
}

TEST(SslX509CrlTest, ConstructFromStreamGetNotNull)
{
    std::istringstream ss{std::string(kCrlPem)};
    SslX509Crl crl(std::move(ss));
    EXPECT_NE(crl.Get(), nullptr);
}

// ================================================================================================
// Construction from file
// ================================================================================================

TEST(SslX509CrlTest, ConstructFromFile)
{
    EXPECT_NO_THROW(SslX509Crl{std::filesystem::path{"crl.pem"}});
}

TEST(SslX509CrlTest, ConstructFromMissingFileThrows)
{
    EXPECT_THROW(SslX509Crl{std::filesystem::path{"nonexistent.crl"}}, SslException);
}

// ================================================================================================
// Invalid PEM
// ================================================================================================

TEST(SslX509CrlTest, ConstructFromInvalidPemThrows)
{
    // PEM-framed but garbage content — OpenSSL can't parse it
    EXPECT_THROW(SslX509Crl{std::string_view{"-----BEGIN X509 CRL-----\ngarbage\n-----END X509 CRL-----\n"}},
                 SslException);
}

// ================================================================================================
// Reference counting (SslWithRc copy semantics)
// ================================================================================================

TEST(SslX509CrlTest, CopySharesPointer)
{
    SslX509Crl crl1{kCrlPem};
    SslX509Crl crl2(crl1); // copy — increments refcount
    EXPECT_NE(crl2.Get(), nullptr);
}

TEST(SslX509CrlTest, MoveTransfersOwnership)
{
    SslX509Crl crl1{kCrlPem};
    X509_CRL *raw = crl1.Get();
    SslX509Crl crl2(std::move(crl1));
    EXPECT_EQ(crl2.Get(), raw);
}

TEST(SslX509CrlTest, LastUpdateUnix)
{
    SslX509Crl crl{kCrlPem};
    const auto ts = crl.LastUpdateUnix();
    ASSERT_TRUE(ts.has_value());
    EXPECT_EQ(1776245915, *ts);
}

TEST(SslX509CrlTest, VerifyIssuerWithCa)
{
    SslX509Crl crl{kCrlPem};
    auto chain = SslX509::LoadChainFromFile("cert.pem");
    ASSERT_FALSE(chain.empty());
    EXPECT_TRUE(crl.VerifyIssuer(chain.front()));
}

TEST(SslX509CrlTest, TryFromBytesPemAndDer)
{
    const std::vector<std::uint8_t> pem_bytes(kCrlPem.begin(), kCrlPem.end());
    const auto from_pem = SslX509Crl::TryFromBytes(pem_bytes);
    ASSERT_TRUE(from_pem.has_value());

    SslX509Crl crl{kCrlPem};
    const int der_len = i2d_X509_CRL(crl.Get(), nullptr);
    ASSERT_GT(der_len, 0);
    std::vector<std::uint8_t> der(static_cast<std::size_t>(der_len));
    std::uint8_t *p = der.data();
    ASSERT_GT(i2d_X509_CRL(crl.Get(), &p), 0);

    const auto from_der = SslX509Crl::TryFromBytes(der);
    ASSERT_TRUE(from_der.has_value());
    auto chain = SslX509::LoadChainFromFile("cert.pem");
    ASSERT_FALSE(chain.empty());
    EXPECT_TRUE(from_der->VerifyIssuer(chain.front()));
}

TEST(SslX509CrlTest, TryFromBytesRejectsGarbage)
{
    const std::vector<std::uint8_t> garbage{0x30, 0x03, 0x01, 0x02, 0x03};
    EXPECT_FALSE(SslX509Crl::TryFromBytes(garbage).has_value());
    EXPECT_FALSE(SslX509Crl::TryFromBytes(std::span<const std::uint8_t>{}).has_value());
}
