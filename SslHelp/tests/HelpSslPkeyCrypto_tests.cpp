// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "HelpSslPkeyCrypto.h"

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

TEST(SslPkeyCrypto, RsaOaepSha256Roundtrip)
{
    const SslEvpKey key(2048);
    const auto cek = RandomBytes<32>();
    const auto wrapped = RsaOaepSha256Encrypt(key, cek);
    const auto unwrapped = RsaOaepSha256Decrypt(key, wrapped);
    ASSERT_EQ(cek.size(), unwrapped.size());
    EXPECT_EQ(0, std::memcmp(cek.data(), unwrapped.data(), cek.size()));
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
