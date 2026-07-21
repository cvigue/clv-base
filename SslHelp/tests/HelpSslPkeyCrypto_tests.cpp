// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "HelpSslPkeyCrypto.h"
#include "HelpSslX509.h"

#include <openssl/err.h>
#include <openssl/evp.h>

#include <gtest/gtest.h>

#include <array>
#include <cstring>
#include <string>
#include <vector>

using namespace clv::OpenSSL;

TEST(SslPkeyCrypto, RandomBytes)
{
    auto a = RandomBytes<16>();
    auto b = RandomBytes<16>();
    EXPECT_NE(0, std::memcmp(a.data(), b.data(), a.size()));
}

TEST(SslPkeyCrypto, ExportImportPublicKeyDer)
{
    const SslEvpKey key(2048);
    const auto der = ExportPublicKeyDer(key);
    const auto imported = ImportPublicKeyDer(der);
    EXPECT_EQ(EVP_PKEY_RSA, imported.BaseId());
}

TEST(SslPkeyCrypto, BorrowPublicKeyFromCertMatchesOwningExtract)
{
    auto chain = SslX509::LoadChainFromFile("cert.pem");
    ASSERT_FALSE(chain.empty());
    const SslX509 &cert = chain.front();
    const auto borrowed_der = ExportPublicKeyDer(BorrowPublicKeyFromCert(cert));
    const auto owning_der = ExportPublicKeyDer(PublicKeyFromCert(cert));
    EXPECT_EQ(borrowed_der, owning_der);
}

TEST(SslPkeyCrypto, BorrowPublicKeyFromCertOutlivesCertificate)
{
    std::vector<std::uint8_t> borrowed_der;
    {
        auto chain = SslX509::LoadChainFromFile("cert.pem");
        ASSERT_FALSE(chain.empty());
        const auto borrowed = BorrowPublicKeyFromCert(chain.front());
        borrowed_der = ExportPublicKeyDer(borrowed);
    }
    auto chain = SslX509::LoadChainFromFile("cert.pem");
    ASSERT_FALSE(chain.empty());
    EXPECT_EQ(borrowed_der, ExportPublicKeyDer(PublicKeyFromCert(chain.front())));
}

TEST(SslPkeyCrypto, BorrowPublicKeyFromCertSupportsKeyInspection)
{
    auto chain = SslX509::LoadChainFromFile("cert.pem");
    ASSERT_FALSE(chain.empty());
    const auto borrowed = BorrowPublicKeyFromCert(chain.front());
    EXPECT_EQ(EVP_PKEY_RSA, borrowed.BaseId());
    EXPECT_GE(borrowed.BitLength(), 2048);
}

TEST(SslPkeyCrypto, RsaOaepSha256Roundtrip)
{
    const SslEvpKey key(2048);
    const auto cek = RandomBytes<32>();
    const auto wrapped = RsaOaepSha256Encrypt(key, cek);
    const auto unwrapped = RsaOaepSha256Decrypt(key, wrapped);
    ASSERT_EQ(cek.size(), unwrapped.size());
    EXPECT_EQ(0, std::memcmp(cek.data(), unwrapped.data(), cek.size()));
}

TEST(SslPkeyCrypto, TryRsaOaepSha256RoundtripAndCorruptFails)
{
    const SslEvpKey key(2048);
    const auto cek = RandomBytes<32>();
    auto wrapped = TryRsaOaepSha256Encrypt(key, cek);
    ASSERT_TRUE(wrapped.has_value());
    auto unwrapped = TryRsaOaepSha256Decrypt(key, *wrapped);
    ASSERT_TRUE(unwrapped.has_value());
    ASSERT_EQ(cek.size(), unwrapped->size());
    EXPECT_EQ(0, std::memcmp(cek.data(), unwrapped->data(), cek.size()));

    (*wrapped)[0] ^= 0x5a;
    auto bad = TryRsaOaepSha256Decrypt(key, *wrapped);
    EXPECT_FALSE(bad.has_value());
    EXPECT_EQ(ERR_peek_error(), 0u);
}

TEST(SslPkeyCrypto, EcdhP256HkdfRoundtrip)
{
    constexpr std::array<std::uint8_t, 13> info{'m', 'e', 's', 'h', 'c', 'o', 'r', 'e', '-', 't', 'e', 's', 't'};

    auto alice = GenerateEphemeralEcP256();
    auto bob = GenerateEphemeralEcP256();

    const auto alice_pub = ImportPublicKeyDer(ExportPublicKeyDer(alice));
    const auto bob_pub = ImportPublicKeyDer(ExportPublicKeyDer(bob));

    const auto alice_key = DeriveKeyEcdhP256Hkdf<32>(alice, bob_pub, info);
    const auto bob_key = DeriveKeyEcdhP256Hkdf<32>(bob, alice_pub, info);
    EXPECT_EQ(0, std::memcmp(alice_key.data(), bob_key.data(), alice_key.size()));
}

TEST(SslPkeyCrypto, DigestSignVerifySha256RsaPss)
{
    const SslEvpKey key(2048);
    const auto pubkey = ImportPublicKeyDer(ExportPublicKeyDer(key));
    const std::vector<std::uint8_t> message{'h', 'e', 'l', 'l', 'o'};

    const auto signature = DigestSignSha256(key, message);
    EXPECT_TRUE(DigestVerifySha256(pubkey, message, signature));
    EXPECT_FALSE(DigestVerifySha256(pubkey, std::vector<std::uint8_t>{'w', 'o', 'r', 'l', 'd'}, signature));
}
