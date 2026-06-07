// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>
#include <fstream>
#include <string>
#include <utility>

#include "HelpSslTrustStore.h"
#include "HelpSslX509.h"
#include "HelpSslCertValidator.h"

using namespace clv::OpenSSL;

// ================================================================================================
// SslX509 — cert-level queries using the test cert
// (cert.pem is a self-signed CA: CN=test.example.com, CA:TRUE, KeyUsage=DS+KE+CertSign)
// ================================================================================================

TEST(SslX509Test, CertificateValidityCheck)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    // The test cert is valid for 100 years
    EXPECT_TRUE(cert.IsValidAtTime());
}

TEST(SslX509Test, CommonNameExtraction)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    auto cn = cert.GetCommonName();
    EXPECT_EQ(cn, "test.example.com");
}

TEST(SslX509Test, FingerprintCalculation)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    std::string fp = cert.GetFingerprint();
    EXPECT_FALSE(fp.empty());
    // SHA-256 fingerprint is 64 hex chars (no separators) or 95 with colons
    EXPECT_GE(fp.size(), 32u);
}

// ================================================================================================
// SslTrustStore — fingerprint management
// ================================================================================================

TEST(SslTrustStoreTest, AddTrustedFingerprint)
{
    SslTrustStore store;

    const std::string fp = "a1b2c3d4e5f6";
    store.AddTrustedFingerprint(fp);

    EXPECT_TRUE(store.IsFingerprintTrusted(fp));
    EXPECT_FALSE(store.IsFingerprintTrusted("invalid"));

    store.ClearTrustedFingerprints();
    EXPECT_FALSE(store.IsFingerprintTrusted(fp));
}

TEST(SslTrustStoreTest, MoveSemantics)
{
    SslTrustStore store1;
    store1.AddTrustedFingerprint("test123");

    SslTrustStore store2 = std::move(store1);
    EXPECT_TRUE(store2.IsFingerprintTrusted("test123"));
}

// ================================================================================================
// SslCertValidator — real chain validation using test cert
// ================================================================================================

TEST(SslCertValidatorTest, ValidateChainTrusted)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    SslTrustStore store;
    store.AddTrustedCA(cert);

    SslCertValidator validator(store);
    auto result = validator.ValidateChain(cert);

    EXPECT_TRUE(result.valid) << result.errorMessage;
    EXPECT_EQ(result.errorCode, 0);
}

TEST(SslCertValidatorTest, ValidateChainUntrusted)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    SslTrustStore store; // empty — cert not trusted
    SslCertValidator validator(store);
    auto result = validator.ValidateChain(cert);

    EXPECT_FALSE(result.valid);
    EXPECT_NE(result.errorCode, 0);
}

TEST(SslCertValidatorTest, FingerprintBypassWorks)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    std::string fp = cert.GetFingerprint();

    SslTrustStore store;
    store.AddTrustedFingerprint(fp);

    SslCertValidator validator(store);
    auto result = validator.ValidateChain(cert);

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.errorMessage, "Certificate trusted via fingerprint pinning");
}
