// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#include "gtest/gtest.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <fstream>

#include <HelpSslX509.h>
#include <HelpSslX509Name.h>
#include <HelpSslAsn1.h>
#include <iterator>
#include <openssl/obj_mac.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <string>
#include <utility>

using namespace clv::OpenSSL;

TEST(HelpSslX509, default_construct)
{
    auto cert = SslX509();
    EXPECT_NE(cert.Get(), nullptr);
}

TEST(HelpSslX509, from_pem_file)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());

    auto cert = SslX509(std::move(file));
    EXPECT_NE(cert.Get(), nullptr);
}

TEST(HelpSslX509, from_pem_string)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());

    std::string pem_data((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());

    auto cert = SslX509(pem_data);
    EXPECT_NE(cert.Get(), nullptr);
}

TEST(HelpSslX509, get_pem)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());

    auto cert = SslX509(std::move(file));
    std::string pem = cert.GetPEM();

    EXPECT_FALSE(pem.empty());
    EXPECT_NE(pem.find("-----BEGIN CERTIFICATE-----"), std::string::npos);
    EXPECT_NE(pem.find("-----END CERTIFICATE-----"), std::string::npos);
}

TEST(HelpSslX509, serial_number)
{
    auto cert = SslX509();

    // Set serial number
    auto serial = SslAsn1Integer(uint64_t(12345));
    cert.SetSerialNumber(std::move(serial));

    // Get serial number back
    auto retrieved = cert.GetSerialNumber();
    EXPECT_EQ(retrieved.AsUint(), 12345u);
}

TEST(HelpSslX509, issuer_name)
{
    auto cert = SslX509();

    auto issuer = SslX509Name("CN", "Test CA");
    issuer.AddEntry("O", "Test Organization");

    cert.SetIssuerName(issuer);

    auto retrieved = cert.GetIssuerName();
    EXPECT_NE(retrieved.Get(), nullptr);
}

TEST(HelpSslX509, subject_name)
{
    auto cert = SslX509();

    auto subject = SslX509Name("CN", "Test Subject");
    subject.AddEntry("O", "Test Org");

    cert.SetSubjectName(subject);

    auto retrieved = cert.GetSubjectName();
    EXPECT_NE(retrieved.Get(), nullptr);
}

// ================================================================================================
// New validation tests
// ================================================================================================

TEST(HelpSslX509, is_valid_at_time)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    // Certificate should be valid now (cert expires in 2123!)
    EXPECT_TRUE(cert.IsValidAtTime());

    // Check with explicit time (e.g., year 2020 before cert was created)
    auto past_time = std::chrono::system_clock::from_time_t(1577836800); // 2020-01-01
    EXPECT_FALSE(cert.IsValidAtTime(past_time));
}

TEST(HelpSslX509, get_common_name)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    std::string cn = cert.GetCommonName();
    EXPECT_FALSE(cn.empty());
    EXPECT_EQ(cn, "test.example.com");
}

TEST(HelpSslX509, get_common_name_from_cert_without_cn)
{
    // Create a certificate without CN
    auto cert = SslX509();
    cert.SetSubjectName(SslX509Name("O", "Test Organization")); // No CN

    std::string cn = cert.GetCommonName();
    EXPECT_TRUE(cn.empty()); // Should return empty string, not throw
}

TEST(HelpSslX509, get_subject_name)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    auto subject = cert.GetSubjectName();
    EXPECT_NE(subject.Get(), nullptr);
    // Verify we can extract CN from the returned name
    int pos = X509_NAME_get_index_by_NID(subject.Get(), NID_commonName, -1);
    EXPECT_NE(pos, -1); // CN should be found
}

TEST(HelpSslX509, get_issuer_name)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    auto issuer = cert.GetIssuerName();
    EXPECT_NE(issuer.Get(), nullptr);
    // Verify we can extract CN from the returned name
    int pos = X509_NAME_get_index_by_NID(issuer.Get(), NID_commonName, -1);
    EXPECT_NE(pos, -1); // CN should be found in issuer
}

TEST(HelpSslX509, get_subject_name_null_safe)
{
    // Create a minimal cert
    auto cert = SslX509();
    auto subject = cert.GetSubjectName();
    EXPECT_NE(subject.Get(), nullptr); // Should be a valid (possibly empty) X509_NAME
}

TEST(HelpSslX509, get_issuer_name_null_safe)
{
    // Create a minimal cert
    auto cert = SslX509();
    auto issuer = cert.GetIssuerName();
    EXPECT_NE(issuer.Get(), nullptr); // Should be a valid (possibly empty) X509_NAME
}

TEST(HelpSslX509, get_fingerprint)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    std::string fingerprint = cert.GetFingerprint();
    EXPECT_EQ(fingerprint.length(), 64u); // SHA256 produces 32 bytes = 64 hex chars

    // Fingerprint should be lowercase hex
    for (char c : fingerprint)
    {
        EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }
}

TEST(HelpSslX509, is_ca)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    // Test cert is a CA (has basicConstraints CA:TRUE)
    EXPECT_TRUE(cert.IsCA());
}

TEST(HelpSslX509, get_subject_alternative_names)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    auto sans = cert.GetSubjectAlternativeNames();
    EXPECT_EQ(sans.size(), 3);
    EXPECT_NE(std::find(sans.begin(), sans.end(), "test.example.com"), sans.end());
    EXPECT_NE(std::find(sans.begin(), sans.end(), "*.test.example.com"), sans.end());
    EXPECT_NE(std::find(sans.begin(), sans.end(), "peer-a.mesh.local"), sans.end());
}

TEST(HelpSslX509, match_peer_identity)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    // Should match CN
    EXPECT_TRUE(cert.MatchesPeerIdentity("test.example.com"));
    // Should match wildcard SAN
    EXPECT_TRUE(cert.MatchesPeerIdentity("foo.test.example.com"));
    // Should match specific SAN
    EXPECT_TRUE(cert.MatchesPeerIdentity("peer-a.mesh.local"));
    // Should NOT match unrelated name
    EXPECT_FALSE(cert.MatchesPeerIdentity("peer-b.example.com"));
}

TEST(HelpSslX509, has_key_usage)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    // Certificate has digitalSignature, keyEncipherment, keyCertSign
    EXPECT_TRUE(cert.HasKeyUsage(0));  // Digital Signature
    EXPECT_TRUE(cert.HasKeyUsage(2));  // Key Encipherment
    EXPECT_TRUE(cert.HasKeyUsage(5));  // Key Cert Sign
    EXPECT_FALSE(cert.HasKeyUsage(3)); // Data Encipherment (not set)
}

TEST(HelpSslX509, has_extended_key_usage)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    // Certificate has serverAuth and clientAuth
    EXPECT_TRUE(cert.HasExtendedKeyUsage(NID_server_auth));
    EXPECT_TRUE(cert.HasExtendedKeyUsage(NID_client_auth));
    EXPECT_FALSE(cert.HasExtendedKeyUsage(NID_code_sign));
}

TEST(HelpSslX509, verify_signature_self_signed)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto cert = SslX509(std::move(file));

    // Test cert is self-signed, so it should verify against itself
    EXPECT_TRUE(cert.VerifySignature(cert));
}

TEST(HelpSslX509, copy_construct)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());

    auto cert1 = SslX509(std::move(file));
    auto cert2 = cert1; // Copy

    EXPECT_EQ(cert1.Get(), cert2.Get()); // Same underlying pointer (ref counted)
}

TEST(HelpSslX509, move_construct)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());

    auto cert1 = SslX509(std::move(file));
    X509 *ptr = cert1.Get();

    auto cert2 = std::move(cert1);

    EXPECT_EQ(cert2.Get(), ptr);
}

TEST(HelpSslX509, roundtrip_pem)
{
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());

    auto cert1 = SslX509(std::move(file));
    std::string pem1 = cert1.GetPEM();

    // Create new cert from PEM
    auto cert2 = SslX509(pem1);
    std::string pem2 = cert2.GetPEM();

    // Should be able to roundtrip
    EXPECT_EQ(pem1, pem2);
}

TEST(HelpSslX509, invalid_pem)
{
    EXPECT_ANY_THROW(SslX509("not a valid pem"));
}
