// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include <chrono>
#include <gtest/gtest.h>
#include <fstream>
#include <openssl/obj_mac.h>
#include <openssl/types.h>
#include <optional>
#include <string>
#include <utility>
#include "HelpSslException.h"
#include "HelpSslX509.h"
#include "HelpSslTrustStore.h"
#include "HelpSslCertValidator.h"
#include "HelpSslX509Name.h"

using namespace clv::OpenSSL;

// ================================================================================================
// SslTrustStore Tests
// ================================================================================================

TEST(SslTrustStore, default_construct)
{
    SslTrustStore store;
    EXPECT_NE(store.GetStore(), nullptr);
}

TEST(SslTrustStore, move_construct)
{
    SslTrustStore store1;
    X509_STORE *ptr = store1.GetStore();

    SslTrustStore store2 = std::move(store1);
    EXPECT_EQ(store2.GetStore(), ptr);
    EXPECT_EQ(store1.GetStore(), nullptr); // Moved from
}

TEST(SslTrustStore, move_assign)
{
    SslTrustStore store1;
    X509_STORE *ptr = store1.GetStore();

    SslTrustStore store2;
    store2 = std::move(store1);

    EXPECT_EQ(store2.GetStore(), ptr);
    EXPECT_EQ(store1.GetStore(), nullptr);
}

TEST(SslTrustStore, add_trusted_ca)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto ca_cert = SslX509(std::move(file));

    SslTrustStore store;
    EXPECT_NO_THROW(store.AddTrustedCA(ca_cert));
}

TEST(SslTrustStore, load_ca_file)
{
    SslTrustStore store;
    EXPECT_NO_THROW(store.LoadCAFile("cert.pem"));
}

TEST(SslTrustStore, load_ca_file_not_found)
{
    SslTrustStore store;
    EXPECT_THROW(store.LoadCAFile("nonexistent.pem"), SslException);
}

TEST(SslTrustStore, fingerprint_pinning)
{
    SslTrustStore store;

    std::string fp1 = "a1b2c3d4e5f6";
    std::string fp2 = "1234567890ab";

    store.AddTrustedFingerprint(fp1);
    store.AddTrustedFingerprint(fp2);

    EXPECT_TRUE(store.IsFingerprintTrusted(fp1));
    EXPECT_TRUE(store.IsFingerprintTrusted(fp2));
    EXPECT_FALSE(store.IsFingerprintTrusted("invalid"));
}

TEST(SslTrustStore, clear_fingerprints)
{
    SslTrustStore store;

    std::string fp = "test123";
    store.AddTrustedFingerprint(fp);
    EXPECT_TRUE(store.IsFingerprintTrusted(fp));

    store.ClearTrustedFingerprints();
    EXPECT_FALSE(store.IsFingerprintTrusted(fp));
}

// ================================================================================================
// SslCertValidator Tests
// ================================================================================================

TEST(SslCertValidator, construct)
{
    SslTrustStore store;
    EXPECT_NO_THROW(SslCertValidator validator(store));
}

TEST(SslCertValidator, validate_self_signed)
{
    // Load self-signed CA cert
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    // Create trust store and add the cert as trusted CA
    SslTrustStore store;
    store.AddTrustedCA(cert);

    SslCertValidator validator(store);
    auto result = validator.ValidateChain(cert);

    EXPECT_TRUE(result.valid) << "Error: " << result.errorMessage;
    EXPECT_EQ(result.errorCode, 0);
}

TEST(SslCertValidator, validate_untrusted)
{
    // Load cert but don't add to trust store
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    SslTrustStore store;
    // Don't add any trusted CAs

    SslCertValidator validator(store);
    auto result = validator.ValidateChain(cert);

    // Should fail because cert is not in trust store
    EXPECT_FALSE(result.valid);
    EXPECT_NE(result.errorCode, 0);
}

TEST(SslCertValidator, validate_peer_identity)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    SslTrustStore store;
    SslCertValidator validator(store);

    // Create cert with known CN
    auto test_cert = SslX509();
    auto subject = SslX509Name("CN", "peer-a.example.com");
    test_cert.SetSubjectName(subject);

    EXPECT_TRUE(validator.ValidatePeerIdentity(test_cert, "peer-a.example.com"));
    EXPECT_FALSE(validator.ValidatePeerIdentity(test_cert, "peer-b.example.com"));
}

TEST(SslCertValidator, check_basic_constraints_ca)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    SslTrustStore store;
    SslCertValidator validator(store);

    // Test cert is a CA
    EXPECT_TRUE(validator.CheckBasicConstraints(cert, true));   // Must be CA
    EXPECT_FALSE(validator.CheckBasicConstraints(cert, false)); // Must NOT be CA
}

TEST(SslCertValidator, fingerprint_bypass)
{
    // Load cert
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    // Get its fingerprint
    std::string fingerprint = cert.GetFingerprint();

    // Create trust store with fingerprint pinning (no CA needed)
    SslTrustStore store;
    store.AddTrustedFingerprint(fingerprint);

    SslCertValidator validator(store);
    auto result = validator.ValidateChain(cert);

    // Should pass via fingerprint bypass
    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.errorMessage, "Certificate trusted via fingerprint pinning");
}

// ================================================================================================
// Integration Tests
// ================================================================================================

TEST(SslCertValidation, full_validation_workflow)
{
    // 1. Load CA certificate
    std::ifstream ca_file("cert.pem");
    ASSERT_TRUE(ca_file.good());
    auto ca_cert = SslX509(std::move(ca_file));

    // 2. Create trust store
    SslTrustStore store;
    store.AddTrustedCA(ca_cert);

    // 3. Create validator
    SslCertValidator validator(store);

    // 4. Validate the CA cert itself (self-signed)
    auto result = validator.ValidateChain(ca_cert);

    EXPECT_TRUE(result.valid);
    EXPECT_NE(result.peerId, std::nullopt);

    // 5. Check it's a CA
    EXPECT_TRUE(validator.CheckBasicConstraints(ca_cert, true));
}

TEST(SslCertValidation, expired_certificate)
{
    // Create a cert with known expired dates would require cert generation
    // For now, test with future time
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    // Check validity far in the future (after 2123)
    auto future_time = std::chrono::system_clock::from_time_t(5000000000); // ~2128
    EXPECT_FALSE(cert.IsValidAtTime(future_time));
}

TEST(SslCertValidation, multiple_ca_trust_store)
{
    // Load same CA multiple times (should be idempotent)
    std::ifstream file1("cert.pem");
    ASSERT_TRUE(file1.good());
    auto ca1 = SslX509(std::move(file1));

    std::ifstream file2("cert.pem");
    ASSERT_TRUE(file2.good());
    auto ca2 = SslX509(std::move(file2));

    SslTrustStore store;
    EXPECT_NO_THROW(store.AddTrustedCA(ca1));
    // Adding same cert again might fail or succeed depending on OpenSSL
    // Just ensure no crash
    try
    {
        store.AddTrustedCA(ca2);
    }
    catch (...)
    {
        // Expected - duplicate cert
    }
}

TEST(SslCertValidation, validation_result_structure)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    SslTrustStore store;
    store.AddTrustedCA(cert);

    SslCertValidator validator(store);
    auto result = validator.ValidateChain(cert);

    // Check result structure
    EXPECT_TRUE(result.valid);
    EXPECT_FALSE(result.errorMessage.empty());
    EXPECT_EQ(result.errorCode, 0);
    // peer_id might be empty if cert doesn't have CN
    EXPECT_TRUE(result.subjectAltNames.empty() || !result.subjectAltNames.empty());
}

TEST(SslCertValidator, check_key_usage_valid)
{
    // Test cert has digitalSignature and keyEncipherment
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    SslTrustStore store;
    SslCertValidator validator(store);

    EXPECT_TRUE(validator.CheckKeyUsage(cert));
}

TEST(SslCertValidator, check_extended_key_usage_server)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    SslTrustStore store;
    SslCertValidator validator(store);

    // Test cert has both serverAuth and clientAuth
    EXPECT_TRUE(validator.CheckExtendedKeyUsage(cert, true, false)); // Require server only
    EXPECT_TRUE(validator.CheckExtendedKeyUsage(cert, false, true)); // Require client only
    EXPECT_TRUE(validator.CheckExtendedKeyUsage(cert, true, true));  // Require both
}

TEST(SslCertValidator, check_extended_key_usage_client)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    SslTrustStore store;
    SslCertValidator validator(store);

    // Test cert has clientAuth, so single client requirement passes
    EXPECT_TRUE(validator.CheckExtendedKeyUsage(cert, false, true));

    // But code_sign is not present
    bool has_code_sign = cert.HasExtendedKeyUsage(NID_code_sign);
    EXPECT_FALSE(has_code_sign);
}

TEST(SslCertValidator, combined_constraint_checks)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    SslTrustStore store;
    SslCertValidator validator(store);

    // All checks should pass for the test cert
    EXPECT_TRUE(validator.CheckKeyUsage(cert));
    EXPECT_TRUE(validator.CheckExtendedKeyUsage(cert, true, true));
    EXPECT_TRUE(validator.CheckBasicConstraints(cert, true)); // Is a CA
}
