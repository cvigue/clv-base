// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "HelpSslCipher.h"
#include "HelpSslException.h"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <vector>

using namespace clv::OpenSSL;

// ================================================================================================
// Cipher Trait Wrapper for Typed Tests
// ================================================================================================

template <const AeadCipherTraits &Traits, std::size_t KeySize>
struct CipherConfig
{
    static constexpr const AeadCipherTraits &traits = Traits;
    static constexpr std::size_t key_size = KeySize;

    using KeyArray = std::array<std::uint8_t, KeySize>;

    static KeyArray MakeKey(std::uint8_t fill_value = 0x42)
    {
        KeyArray key{};
        std::fill(key.begin(), key.end(), fill_value);
        return key;
    }
};

// Define cipher configurations
using Aes128GcmConfig = CipherConfig<AES_128_GCM_TRAITS, 16>;
using Aes256GcmConfig = CipherConfig<AES_256_GCM_TRAITS, 32>;
using ChaCha20Poly1305Config = CipherConfig<CHACHA20_POLY1305_TRAITS, 32>;

// ================================================================================================
// Typed Tests for AEAD Ciphers
// ================================================================================================

template <typename T>
class AeadCipherTest : public ::testing::Test
{
  protected:
    using Config = T;
    static constexpr const AeadCipherTraits &Traits = Config::traits;

    typename Config::KeyArray MakeKey(std::uint8_t fill_value = 0x42)
    {
        return Config::MakeKey(fill_value);
    }

    std::array<std::uint8_t, 12> MakeNonce(std::uint8_t fill_value = 0x01)
    {
        std::array<std::uint8_t, 12> nonce{};
        std::fill(nonce.begin(), nonce.end(), fill_value);
        return nonce;
    }
};

using AeadCipherTypes = ::testing::Types<Aes128GcmConfig, Aes256GcmConfig, ChaCha20Poly1305Config>;
TYPED_TEST_SUITE(AeadCipherTest, AeadCipherTypes);

TYPED_TEST(AeadCipherTest, EncryptDecrypt_Basic)
{
    auto key = this->MakeKey();
    auto nonce = this->MakeNonce();

    std::vector<std::uint8_t> plaintext(128);
    std::fill(plaintext.begin(), plaintext.end(), 0xAA);

    std::vector<std::uint8_t> aad(10);
    std::fill(aad.begin(), aad.end(), 0xFF);

    auto ciphertext = EncryptAead(TestFixture::Traits, key, nonce, plaintext, aad);

    EXPECT_EQ(ciphertext.size(), plaintext.size() + 16) << "Ciphertext should include 16-byte tag";

    auto decrypted = DecryptAead(TestFixture::Traits, key, nonce, ciphertext, aad);

    EXPECT_EQ(decrypted, plaintext) << "Decrypted plaintext should match original";
}

TYPED_TEST(AeadCipherTest, EncryptDecrypt_EmptyPlaintext)
{
    auto key = this->MakeKey();
    auto nonce = this->MakeNonce();
    std::vector<std::uint8_t> plaintext;
    std::vector<std::uint8_t> aad;

    auto ciphertext = EncryptAead(TestFixture::Traits, key, nonce, plaintext, aad);

    EXPECT_EQ(ciphertext.size(), 16) << "Empty plaintext should produce only tag";

    auto decrypted = DecryptAead(TestFixture::Traits, key, nonce, ciphertext, aad);

    EXPECT_TRUE(decrypted.empty()) << "Decrypted should be empty";
}

TYPED_TEST(AeadCipherTest, EncryptDecrypt_NoAAD)
{
    auto key = this->MakeKey(0x33);
    auto nonce = this->MakeNonce(0x99);

    std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<std::uint8_t> empty_aad;

    auto ciphertext = EncryptAead(TestFixture::Traits, key, nonce, plaintext, empty_aad);
    auto decrypted = DecryptAead(TestFixture::Traits, key, nonce, ciphertext, empty_aad);

    EXPECT_EQ(decrypted, plaintext);
}

TYPED_TEST(AeadCipherTest, Decrypt_TamperedTag)
{
    auto key = this->MakeKey();
    auto nonce = this->MakeNonce();
    std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04};
    std::vector<std::uint8_t> aad;

    auto ciphertext = EncryptAead(TestFixture::Traits, key, nonce, plaintext, aad);

    // Tamper with the tag
    ciphertext.back() ^= 0x01;

    EXPECT_THROW(DecryptAead(TestFixture::Traits, key, nonce, ciphertext, aad), SslException);
}

TYPED_TEST(AeadCipherTest, Decrypt_WrongKey)
{
    auto key1 = this->MakeKey(0x42);
    auto key2 = this->MakeKey(0x43); // Different key
    auto nonce = this->MakeNonce();

    std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03};
    std::vector<std::uint8_t> aad;

    auto ciphertext = EncryptAead(TestFixture::Traits, key1, nonce, plaintext, aad);

    EXPECT_THROW(DecryptAead(TestFixture::Traits, key2, nonce, ciphertext, aad), SslException)
        << "Should throw on authentication failure with wrong key";
}

TYPED_TEST(AeadCipherTest, Decrypt_WrongAAD)
{
    auto key = this->MakeKey();
    auto nonce = this->MakeNonce();
    std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03};
    std::vector<std::uint8_t> aad1 = {0xAA, 0xBB};
    std::vector<std::uint8_t> aad2 = {0xCC, 0xDD}; // Different AAD

    auto ciphertext = EncryptAead(TestFixture::Traits, key, nonce, plaintext, aad1);

    EXPECT_THROW(DecryptAead(TestFixture::Traits, key, nonce, ciphertext, aad2), SslException)
        << "Should throw on AAD mismatch";
}

TYPED_TEST(AeadCipherTest, Decrypt_CorruptedCiphertext)
{
    auto key = this->MakeKey();
    auto nonce = this->MakeNonce();
    std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03};
    std::vector<std::uint8_t> aad;

    auto ciphertext = EncryptAead(TestFixture::Traits, key, nonce, plaintext, aad);

    // Corrupt a byte in the ciphertext portion
    ciphertext[0] ^= 0xFF;

    EXPECT_THROW(DecryptAead(TestFixture::Traits, key, nonce, ciphertext, aad), SslException)
        << "Should throw on corrupted ciphertext";
}

TYPED_TEST(AeadCipherTest, Decrypt_TooShortCiphertext)
{
    auto key = this->MakeKey();
    auto nonce = this->MakeNonce();
    std::vector<std::uint8_t> short_ciphertext = {0x01, 0x02}; // < 16 bytes
    std::vector<std::uint8_t> aad;

    EXPECT_THROW(DecryptAead(TestFixture::Traits, key, nonce, short_ciphertext, aad), SslException)
        << "Should throw when ciphertext is too short";
}

TYPED_TEST(AeadCipherTest, EncryptDecrypt_DifferentNonces)
{
    auto key = this->MakeKey();
    auto nonce1 = this->MakeNonce(0x01);
    auto nonce2 = this->MakeNonce(0x02);

    std::vector<std::uint8_t> plaintext = {0xAA, 0xBB, 0xCC};
    std::vector<std::uint8_t> aad;

    auto ct1 = EncryptAead(TestFixture::Traits, key, nonce1, plaintext, aad);
    auto ct2 = EncryptAead(TestFixture::Traits, key, nonce2, plaintext, aad);

    EXPECT_NE(ct1, ct2) << "Different nonces should produce different ciphertexts";
}

TYPED_TEST(AeadCipherTest, EncryptDecrypt_Deterministic)
{
    auto key = this->MakeKey();
    auto nonce = this->MakeNonce();

    std::vector<std::uint8_t> plaintext = {0xAA, 0xBB, 0xCC};
    std::vector<std::uint8_t> aad = {0x11, 0x22};

    auto ct1 = EncryptAead(TestFixture::Traits, key, nonce, plaintext, aad);
    auto ct2 = EncryptAead(TestFixture::Traits, key, nonce, plaintext, aad);

    EXPECT_EQ(ct1, ct2) << "Same inputs should produce same ciphertext";
}

TYPED_TEST(AeadCipherTest, LargePlaintext)
{
    auto key = this->MakeKey(0xAB);
    auto nonce = this->MakeNonce(0x12);

    std::vector<std::uint8_t> plaintext(1024 * 1024); // 1MB
    for (size_t i = 0; i < plaintext.size(); ++i)
        plaintext[i] = static_cast<std::uint8_t>(i & 0xFF);

    std::vector<std::uint8_t> aad = {0x01, 0x02, 0x03};

    auto ciphertext = EncryptAead(TestFixture::Traits, key, nonce, plaintext, aad);
    auto decrypted = DecryptAead(TestFixture::Traits, key, nonce, ciphertext, aad);

    EXPECT_EQ(decrypted, plaintext);
}

// ================================================================================================
// ECB Tests (AES-128 and AES-256)
// ================================================================================================

TEST(SslCipherCtxTests, Aes128EcbEncrypt_Basic)
{
    std::array<std::uint8_t, 16> key{};
    std::fill(key.begin(), key.end(), 0x42);

    std::array<std::uint8_t, 16> sample{};
    std::fill(sample.begin(), sample.end(), 0xAA);

    auto mask = EncryptEcb(AES_128_ECB_TRAITS, key, sample);

    EXPECT_EQ(mask.size(), 16);

    // Verify it's not all zeros or the input
    bool all_zero = std::all_of(mask.begin(), mask.end(), [](auto b)
    { return b == 0; });
    EXPECT_FALSE(all_zero);
    EXPECT_NE(mask, sample);
}

TEST(SslCipherCtxTests, Aes128EcbEncrypt_Deterministic)
{
    std::array<std::uint8_t, 16> key{};
    std::fill(key.begin(), key.end(), 0x33);

    std::array<std::uint8_t, 16> sample{};
    std::fill(sample.begin(), sample.end(), 0x99);

    auto mask1 = EncryptEcb(AES_128_ECB_TRAITS, key, sample);
    auto mask2 = EncryptEcb(AES_128_ECB_TRAITS, key, sample);

    EXPECT_EQ(mask1, mask2) << "Same inputs should produce same mask";
}

TEST(SslCipherCtxTests, Aes128EcbEncrypt_DifferentKeys)
{
    std::array<std::uint8_t, 16> key1{};
    std::fill(key1.begin(), key1.end(), 0x11);

    std::array<std::uint8_t, 16> key2{};
    std::fill(key2.begin(), key2.end(), 0x22);

    std::array<std::uint8_t, 16> sample{};
    std::fill(sample.begin(), sample.end(), 0xAA);

    auto mask1 = EncryptEcb(AES_128_ECB_TRAITS, key1, sample);
    auto mask2 = EncryptEcb(AES_128_ECB_TRAITS, key2, sample);

    EXPECT_NE(mask1, mask2) << "Different keys should produce different masks";
}

TEST(SslCipherCtxTests, Aes128EcbEncrypt_DifferentSamples)
{
    std::array<std::uint8_t, 16> key{};
    std::fill(key.begin(), key.end(), 0x42);

    std::array<std::uint8_t, 16> sample1{};
    std::fill(sample1.begin(), sample1.end(), 0x11);

    std::array<std::uint8_t, 16> sample2{};
    std::fill(sample2.begin(), sample2.end(), 0x22);

    auto mask1 = EncryptEcb(AES_128_ECB_TRAITS, key, sample1);
    auto mask2 = EncryptEcb(AES_128_ECB_TRAITS, key, sample2);

    EXPECT_NE(mask1, mask2) << "Different samples should produce different masks";
}

// ================================================================================================
// Context Reuse Tests
// ================================================================================================

TEST(SslCipherCtxTests, ContextReuse_EncryptMultiple)
{
    std::array<std::uint8_t, 16> key{};
    std::fill(key.begin(), key.end(), 0x42);

    std::array<std::uint8_t, 12> nonce1{}, nonce2{}, nonce3{};
    std::fill(nonce1.begin(), nonce1.end(), 0x01);
    std::fill(nonce2.begin(), nonce2.end(), 0x02);
    std::fill(nonce3.begin(), nonce3.end(), 0x03);

    std::vector<std::uint8_t> plaintext1 = {0x11, 0x22, 0x33};
    std::vector<std::uint8_t> plaintext2 = {0x44, 0x55, 0x66, 0x77};
    std::vector<std::uint8_t> plaintext3 = {0x88};
    std::vector<std::uint8_t> aad;

    // Reuse context for multiple encryptions
    SslCipherCtx ctx;
    ctx.InitAeadEncrypt(AES_128_GCM_TRAITS);

    auto ct1 = ctx.EncryptAead(AES_128_GCM_TRAITS, key, nonce1, plaintext1, aad);
    auto ct2 = ctx.EncryptAead(AES_128_GCM_TRAITS, key, nonce2, plaintext2, aad);
    auto ct3 = ctx.EncryptAead(AES_128_GCM_TRAITS, key, nonce3, plaintext3, aad);

    EXPECT_EQ(ct1.size(), plaintext1.size() + 16);
    EXPECT_EQ(ct2.size(), plaintext2.size() + 16);
    EXPECT_EQ(ct3.size(), plaintext3.size() + 16);

    // Verify decryption works with separate context
    SslCipherCtx decrypt_ctx;
    decrypt_ctx.InitAeadDecrypt(AES_128_GCM_TRAITS);

    auto pt1 = decrypt_ctx.DecryptAead(AES_128_GCM_TRAITS, key, nonce1, ct1, aad);
    auto pt2 = decrypt_ctx.DecryptAead(AES_128_GCM_TRAITS, key, nonce2, ct2, aad);
    auto pt3 = decrypt_ctx.DecryptAead(AES_128_GCM_TRAITS, key, nonce3, ct3, aad);

    EXPECT_EQ(pt1, plaintext1);
    EXPECT_EQ(pt2, plaintext2);
    EXPECT_EQ(pt3, plaintext3);
}

TEST(SslCipherCtxTests, ContextReuse_MatchesStaticMethods)
{
    std::array<std::uint8_t, 16> key{};
    std::fill(key.begin(), key.end(), 0x99);

    std::array<std::uint8_t, 12> nonce{};
    std::fill(nonce.begin(), nonce.end(), 0x55);

    std::vector<std::uint8_t> plaintext = {0xAA, 0xBB, 0xCC, 0xDD};
    std::vector<std::uint8_t> aad = {0x11};

    // Free function (one-shot)
    auto ct_free = EncryptAead(AES_128_GCM_TRAITS, key, nonce, plaintext, aad);

    // Instance method (context reuse)
    SslCipherCtx ctx;
    ctx.InitAeadEncrypt(AES_128_GCM_TRAITS);
    auto ct_instance = ctx.EncryptAead(AES_128_GCM_TRAITS, key, nonce, plaintext, aad);

    EXPECT_EQ(ct_free, ct_instance) << "Free function and instance method should produce identical output";
}

TEST(SslCipherCtxTests, ContextReuse_EcbMultiple)
{
    std::array<std::uint8_t, 16> key{};
    std::fill(key.begin(), key.end(), 0x42);

    std::array<std::uint8_t, 16> sample1{}, sample2{}, sample3{};
    std::fill(sample1.begin(), sample1.end(), 0x11);
    std::fill(sample2.begin(), sample2.end(), 0x22);
    std::fill(sample3.begin(), sample3.end(), 0x33);

    auto mask1 = EncryptEcb(AES_128_ECB_TRAITS, key, sample1);
    auto mask2 = EncryptEcb(AES_128_ECB_TRAITS, key, sample2);
    auto mask3 = EncryptEcb(AES_128_ECB_TRAITS, key, sample3);

    // All should produce different masks
    EXPECT_NE(mask1, mask2);
    EXPECT_NE(mask2, mask3);
    EXPECT_NE(mask1, mask3);

    // Should be deterministic
    auto mask1_again = EncryptEcb(AES_128_ECB_TRAITS, key, sample1);
    EXPECT_EQ(mask1, mask1_again);
}

// ================================================================================================
// Cross-Cipher Comparison Tests
// ================================================================================================

TEST(SslCipherCtxTests, DifferentCiphers_SamePlaintext)
{
    // Same key material (but different interpretations)
    std::array<std::uint8_t, 32> key256{};
    std::fill(key256.begin(), key256.end(), 0x55);

    std::array<std::uint8_t, 16> key128{};
    std::copy_n(key256.begin(), 16, key128.begin());

    std::array<std::uint8_t, 12> nonce{};
    std::fill(nonce.begin(), nonce.end(), 0x33);

    std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<std::uint8_t> aad;

    // Encrypt with all three ciphers
    auto ct_aes128 = EncryptAead(AES_128_GCM_TRAITS, key128, nonce, plaintext, aad);
    auto ct_aes256 = EncryptAead(AES_256_GCM_TRAITS, key256, nonce, plaintext, aad);
    auto ct_chacha = EncryptAead(CHACHA20_POLY1305_TRAITS, key256, nonce, plaintext, aad);

    // All should produce different ciphertexts (different algorithms)
    EXPECT_NE(ct_aes128, ct_aes256);
    EXPECT_NE(ct_aes256, ct_chacha);
    EXPECT_NE(ct_aes128, ct_chacha);

    // But all should decrypt to same plaintext
    auto pt_aes128 = DecryptAead(AES_128_GCM_TRAITS, key128, nonce, ct_aes128, aad);
    auto pt_aes256 = DecryptAead(AES_256_GCM_TRAITS, key256, nonce, ct_aes256, aad);
    auto pt_chacha = DecryptAead(CHACHA20_POLY1305_TRAITS, key256, nonce, ct_chacha, aad);

    EXPECT_EQ(pt_aes128, plaintext);
    EXPECT_EQ(pt_aes256, plaintext);
    EXPECT_EQ(pt_chacha, plaintext);
}
