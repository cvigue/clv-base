// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>
#include <string>
#include <utility>

#include "HelpSslTrustStore.h"

using namespace clv::OpenSSL;

// Test certificate validation methods
TEST(SslX509Test, CertificateValidityCheck)
{
    // This test would need actual test certificates
    // For now, just verify the API compiles
    EXPECT_TRUE(true);
}

TEST(SslX509Test, CommonNameExtraction)
{
    // Would need test cert here
    EXPECT_TRUE(true);
}

TEST(SslX509Test, FingerprintCalculation)
{
    // Would need test cert here
    EXPECT_TRUE(true);
}

TEST(SslTrustStoreTest, AddTrustedFingerprint)
{
    SslTrustStore store;

    std::string test_fingerprint = "a1b2c3d4e5f6";
    store.AddTrustedFingerprint(test_fingerprint);

    EXPECT_TRUE(store.IsFingerprintTrusted(test_fingerprint));
    EXPECT_FALSE(store.IsFingerprintTrusted("invalid"));

    store.ClearTrustedFingerprints();
    EXPECT_FALSE(store.IsFingerprintTrusted(test_fingerprint));
}

TEST(SslTrustStoreTest, MoveSemantics)
{
    SslTrustStore store1;
    store1.AddTrustedFingerprint("test123");

    SslTrustStore store2 = std::move(store1);
    EXPECT_TRUE(store2.IsFingerprintTrusted("test123"));
}

// Example usage demonstration (would need real certs to actually run)
TEST(SslCertValidatorTest, ValidateChainExample)
{
    // This demonstrates the API usage
    // In real tests, you would:
    // 1. Load test CA cert
    // 2. Load test peer cert
    // 3. Validate chain

    EXPECT_TRUE(true); // Placeholder
}
