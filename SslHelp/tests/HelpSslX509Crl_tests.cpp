// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>

#include "HelpSslException.h"
#include "HelpSslX509Crl.h"

#include <sstream>
#include <string_view>

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
