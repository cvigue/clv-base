// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>

#include "HelpSslX509.h"
#include "HelpSslX509Crl.h"
#include "HelpSslX509Store.h"

#include <fstream>
#include <string_view>

using namespace clv::OpenSSL;

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

// ================================================================================================
// Basic construction
// ================================================================================================

TEST(SslX509StoreTest, DefaultConstruct)
{
    SslX509Store store;
    EXPECT_NE(store.Get(), nullptr);
}

TEST(SslX509StoreTest, MoveConstruct)
{
    SslX509Store store1;
    X509_STORE *raw = store1.Get();
    SslX509Store store2(std::move(store1));
    EXPECT_EQ(store2.Get(), raw);
}

// ================================================================================================
// AddCert
// ================================================================================================

TEST(SslX509StoreTest, AddCertFromSslX509)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    SslX509Store store;
    EXPECT_NO_THROW(store.AddCert(cert));
}

TEST(SslX509StoreTest, AddCertRawPtr)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    SslX509Store store;
    EXPECT_NO_THROW(store.AddCert(const_cast<X509 *>(cert.Get())));
}

// ================================================================================================
// AddCrl
// ================================================================================================

TEST(SslX509StoreTest, AddCrl)
{
    SslX509Crl crl{kCrlPem};

    SslX509Store store;
    EXPECT_NO_THROW(store.AddCrl(crl));
}

TEST(SslX509StoreTest, AddCrlAndSetCrlFlag)
{
    SslX509Crl crl{kCrlPem};

    SslX509Store store;
    EXPECT_NO_THROW(store.AddCrl(crl));
    EXPECT_NO_THROW(store.SetFlags(X509_V_FLAG_CRL_CHECK));
}

// ================================================================================================
// SetFlags
// ================================================================================================

TEST(SslX509StoreTest, SetFlagsDoesNotThrow)
{
    SslX509Store store;
    EXPECT_NO_THROW(store.SetFlags(X509_V_FLAG_X509_STRICT));
}

TEST(SslX509StoreTest, AddCertDuplicateIsIdempotent)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    SslX509Store store;
    EXPECT_NO_THROW(store.AddCert(cert));
    EXPECT_NO_THROW(store.AddCert(cert));
}

TEST(SslX509StoreTest, AddCertsFromPem)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    const std::string pem((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    SslX509Store store;
    EXPECT_NO_THROW(store.AddCertsFromPem(pem));
}

TEST(SslX509StoreTest, AddCertsFromPemEmptyThrows)
{
    SslX509Store store;
    EXPECT_THROW(store.AddCertsFromPem(""), SslException);
}

TEST(SslX509StoreTest, AddCrlsFromPem)
{
    SslX509Store store;
    EXPECT_NO_THROW(store.AddCrlsFromPem(kCrlPem));
}

TEST(SslX509StoreTest, LoadCertsFromFile)
{
    SslX509Store store;
    EXPECT_NO_THROW(store.LoadCertsFromFile("cert.pem"));
}

// ================================================================================================
// Chain validation via X509_STORE (integration with SslX509StoreCtx)
// ================================================================================================

TEST(SslX509StoreTest, ValidateSelfSignedViaStore)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    // Add cert as trusted root
    SslX509Store store;
    store.AddCert(cert);

    // Verify via X509_STORE_CTX
    SslX509StoreCtx ctx;
    ASSERT_TRUE(ctx.Init(store.Get(), const_cast<X509 *>(cert.Get())));
    EXPECT_EQ(ctx.Verify(), 1);
    EXPECT_EQ(ctx.Error(), X509_V_OK);
}

TEST(SslX509StoreTest, ValidateUntrustedFails)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    // Empty store — cert not trusted
    SslX509Store store;

    SslX509StoreCtx ctx;
    ASSERT_TRUE(ctx.Init(store.Get(), const_cast<X509 *>(cert.Get())));
    EXPECT_NE(ctx.Verify(), 1);
    EXPECT_NE(ctx.Error(), X509_V_OK);
}
