// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "HelpSslStreamCipher.h"
#include "HelpSslException.h"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <numeric>
#include <vector>

using namespace clv::OpenSSL;

// ================================================================================================
// Cipher Trait Wrapper for Typed Tests
// ================================================================================================

template <const StreamCipherTraits &Traits, std::size_t KeySize, std::size_t IvSize>
struct StreamCipherConfig
{
    static constexpr const StreamCipherTraits &traits = Traits;
    static constexpr std::size_t key_size = KeySize;
    static constexpr std::size_t iv_size = IvSize;

    using KeyArray = std::array<std::uint8_t, KeySize>;
    using IvArray = std::array<std::uint8_t, IvSize>;

    static KeyArray MakeKey(std::uint8_t fill_value = 0x42)
    {
        KeyArray key{};
        std::fill(key.begin(), key.end(), fill_value);
        return key;
    }

    static IvArray MakeIv(std::uint8_t fill_value = 0x01)
    {
        IvArray iv{};
        std::fill(iv.begin(), iv.end(), fill_value);
        return iv;
    }
};

// Stream cipher configs (CTR, CFB, OFB — no padding)
using Aes256CtrConfig = StreamCipherConfig<AES_256_CTR_TRAITS, 32, 16>;
using Aes128CtrConfig = StreamCipherConfig<AES_128_CTR_TRAITS, 16, 16>;
using Aes256CfbConfig = StreamCipherConfig<AES_256_CFB_TRAITS, 32, 16>;
using Aes256OfbConfig = StreamCipherConfig<AES_256_OFB_TRAITS, 32, 16>;

// Block cipher configs (CBC — with padding)
using Aes256CbcConfig = StreamCipherConfig<AES_256_CBC_TRAITS, 32, 16>;
using Aes128CbcConfig = StreamCipherConfig<AES_128_CBC_TRAITS, 16, 16>;

// ================================================================================================
// Typed Tests — Stream Ciphers (no padding)
// ================================================================================================

template <typename T>
class StreamCipherTest : public ::testing::Test
{
  protected:
    using Config = T;
    static constexpr const StreamCipherTraits &Traits = Config::traits;

    typename Config::KeyArray MakeKey(std::uint8_t fill_value = 0x42)
    {
        return Config::MakeKey(fill_value);
    }

    typename Config::IvArray MakeIv(std::uint8_t fill_value = 0x01)
    {
        return Config::MakeIv(fill_value);
    }
};

using StreamCipherTypes = ::testing::Types<Aes256CtrConfig, Aes128CtrConfig, Aes256CfbConfig, Aes256OfbConfig>;
TYPED_TEST_SUITE(StreamCipherTest, StreamCipherTypes);

TYPED_TEST(StreamCipherTest, EncryptDecrypt_Basic)
{
    auto key = this->MakeKey();
    auto iv = this->MakeIv();

    std::vector<std::uint8_t> plaintext(128);
    std::iota(plaintext.begin(), plaintext.end(), static_cast<std::uint8_t>(0));

    auto ciphertext = Encrypt<TestFixture::Traits>(key, iv, plaintext);
    ASSERT_EQ(ciphertext.size(), plaintext.size()); // No padding for stream ciphers
    EXPECT_NE(ciphertext, plaintext);

    auto decrypted = Decrypt<TestFixture::Traits>(key, iv, ciphertext);
    EXPECT_EQ(decrypted, plaintext);
}

TYPED_TEST(StreamCipherTest, EncryptDecrypt_EmptyPlaintext)
{
    auto key = this->MakeKey();
    auto iv = this->MakeIv();

    std::vector<std::uint8_t> plaintext;

    auto ciphertext = Encrypt<TestFixture::Traits>(key, iv, plaintext);
    EXPECT_TRUE(ciphertext.empty());

    auto decrypted = Decrypt<TestFixture::Traits>(key, iv, ciphertext);
    EXPECT_TRUE(decrypted.empty());
}

TYPED_TEST(StreamCipherTest, EncryptDecrypt_SingleByte)
{
    auto key = this->MakeKey();
    auto iv = this->MakeIv();

    std::vector<std::uint8_t> plaintext = {0xAB};

    auto ciphertext = Encrypt<TestFixture::Traits>(key, iv, plaintext);
    auto decrypted = Decrypt<TestFixture::Traits>(key, iv, ciphertext);
    EXPECT_EQ(decrypted, plaintext);
}

TYPED_TEST(StreamCipherTest, EncryptDecrypt_LargeData)
{
    auto key = this->MakeKey();
    auto iv = this->MakeIv();

    std::vector<std::uint8_t> plaintext(64 * 1024);
    std::iota(plaintext.begin(), plaintext.end(), static_cast<std::uint8_t>(0));

    auto ciphertext = Encrypt<TestFixture::Traits>(key, iv, plaintext);
    auto decrypted = Decrypt<TestFixture::Traits>(key, iv, ciphertext);
    EXPECT_EQ(decrypted, plaintext);
}

TYPED_TEST(StreamCipherTest, DifferentKeysProduceDifferentCiphertext)
{
    auto key1 = this->MakeKey(0x42);
    auto key2 = this->MakeKey(0x43);
    auto iv = this->MakeIv();

    std::vector<std::uint8_t> plaintext(64);
    std::fill(plaintext.begin(), plaintext.end(), static_cast<std::uint8_t>(0xAA));

    auto ct1 = Encrypt<TestFixture::Traits>(key1, iv, plaintext);
    auto ct2 = Encrypt<TestFixture::Traits>(key2, iv, plaintext);
    EXPECT_NE(ct1, ct2);
}

TYPED_TEST(StreamCipherTest, DifferentIvsProduceDifferentCiphertext)
{
    auto key = this->MakeKey();
    auto iv1 = this->MakeIv(0x01);
    auto iv2 = this->MakeIv(0x02);

    std::vector<std::uint8_t> plaintext(64);
    std::fill(plaintext.begin(), plaintext.end(), static_cast<std::uint8_t>(0xBB));

    auto ct1 = Encrypt<TestFixture::Traits>(key, iv1, plaintext);
    auto ct2 = Encrypt<TestFixture::Traits>(key, iv2, plaintext);
    EXPECT_NE(ct1, ct2);
}

TYPED_TEST(StreamCipherTest, WrongKeyFailsToDecrypt)
{
    auto key1 = this->MakeKey(0x42);
    auto key2 = this->MakeKey(0x43);
    auto iv = this->MakeIv();

    std::vector<std::uint8_t> plaintext(64);
    std::iota(plaintext.begin(), plaintext.end(), static_cast<std::uint8_t>(0));

    auto ciphertext = Encrypt<TestFixture::Traits>(key1, iv, plaintext);
    // CTR/CFB/OFB won't throw — they'll just produce wrong data
    auto bad_decrypt = Decrypt<TestFixture::Traits>(key2, iv, ciphertext);
    EXPECT_NE(bad_decrypt, plaintext);
}

TYPED_TEST(StreamCipherTest, StreamingEncryptDecrypt)
{
    auto key = this->MakeKey();
    auto iv = this->MakeIv();

    std::vector<std::uint8_t> data1(50);
    std::fill(data1.begin(), data1.end(), static_cast<std::uint8_t>(0xAA));
    std::vector<std::uint8_t> data2(70);
    std::fill(data2.begin(), data2.end(), static_cast<std::uint8_t>(0xBB));

    // Encrypt in chunks
    SslStreamCipherCtx<TestFixture::Traits> enc_ctx;
    enc_ctx.InitEncrypt(key, iv);
    auto ct1 = enc_ctx.UpdateEncrypt(data1);
    auto ct2 = enc_ctx.UpdateEncrypt(data2);
    auto ct_final = enc_ctx.FinalizeEncrypt();

    std::vector<std::uint8_t> ciphertext;
    ciphertext.insert(ciphertext.end(), ct1.begin(), ct1.end());
    ciphertext.insert(ciphertext.end(), ct2.begin(), ct2.end());
    ciphertext.insert(ciphertext.end(), ct_final.begin(), ct_final.end());

    // Decrypt in one shot should match
    std::vector<std::uint8_t> full_plaintext;
    full_plaintext.insert(full_plaintext.end(), data1.begin(), data1.end());
    full_plaintext.insert(full_plaintext.end(), data2.begin(), data2.end());

    auto decrypted = Decrypt<TestFixture::Traits>(key, iv, ciphertext);
    EXPECT_EQ(decrypted, full_plaintext);
}

TYPED_TEST(StreamCipherTest, MemberOneShot_MatchesFreeFunction)
{
    auto key = this->MakeKey();
    auto iv = this->MakeIv();

    std::vector<std::uint8_t> plaintext(100);
    std::iota(plaintext.begin(), plaintext.end(), static_cast<std::uint8_t>(0));

    // Free function
    auto ct_free = Encrypt<TestFixture::Traits>(key, iv, plaintext);

    // Member function
    SslStreamCipherCtx<TestFixture::Traits> ctx;
    auto ct_member = ctx.Encrypt(key, iv, plaintext);

    EXPECT_EQ(ct_free, ct_member);
}

// ================================================================================================
// Typed Tests — Block Ciphers with Padding (CBC)
// ================================================================================================

template <typename T>
class BlockCipherTest : public ::testing::Test
{
  protected:
    using Config = T;
    static constexpr const StreamCipherTraits &Traits = Config::traits;

    typename Config::KeyArray MakeKey(std::uint8_t fill_value = 0x42)
    {
        return Config::MakeKey(fill_value);
    }

    typename Config::IvArray MakeIv(std::uint8_t fill_value = 0x01)
    {
        return Config::MakeIv(fill_value);
    }
};

using BlockCipherTypes = ::testing::Types<Aes256CbcConfig, Aes128CbcConfig>;
TYPED_TEST_SUITE(BlockCipherTest, BlockCipherTypes);

TYPED_TEST(BlockCipherTest, EncryptDecrypt_Basic)
{
    auto key = this->MakeKey();
    auto iv = this->MakeIv();

    std::vector<std::uint8_t> plaintext(100); // Not block-aligned
    std::iota(plaintext.begin(), plaintext.end(), static_cast<std::uint8_t>(0));

    auto ciphertext = Encrypt<TestFixture::Traits>(key, iv, plaintext);
    // CBC with padding: ciphertext is padded to block boundary
    EXPECT_GT(ciphertext.size(), plaintext.size());
    EXPECT_EQ(ciphertext.size() % 16, 0u); // Block-aligned

    auto decrypted = Decrypt<TestFixture::Traits>(key, iv, ciphertext);
    EXPECT_EQ(decrypted, plaintext);
}

TYPED_TEST(BlockCipherTest, EncryptDecrypt_BlockAligned)
{
    auto key = this->MakeKey();
    auto iv = this->MakeIv();

    std::vector<std::uint8_t> plaintext(64); // Already block-aligned
    std::iota(plaintext.begin(), plaintext.end(), static_cast<std::uint8_t>(0));

    auto ciphertext = Encrypt<TestFixture::Traits>(key, iv, plaintext);
    // PKCS#7 adds a full block of padding when input is block-aligned
    EXPECT_EQ(ciphertext.size(), plaintext.size() + 16);

    auto decrypted = Decrypt<TestFixture::Traits>(key, iv, ciphertext);
    EXPECT_EQ(decrypted, plaintext);
}

TYPED_TEST(BlockCipherTest, WrongKeyFailsToDecrypt)
{
    auto key1 = this->MakeKey(0x42);
    auto key2 = this->MakeKey(0x43);
    auto iv = this->MakeIv();

    std::vector<std::uint8_t> plaintext(64);
    std::iota(plaintext.begin(), plaintext.end(), static_cast<std::uint8_t>(0));

    auto ciphertext = Encrypt<TestFixture::Traits>(key1, iv, plaintext);
    // CBC with wrong key should fail during finalize (bad padding)
    EXPECT_THROW(Decrypt<TestFixture::Traits>(key2, iv, ciphertext), SslException);
}

// ================================================================================================
// AES-256-CTR Specific Tests (tls-crypt use case)
// ================================================================================================

TEST(Aes256CtrTest, KnownAnswer_RoundTrip)
{
    // Simulate tls-crypt scenario: key from key material, IV from HMAC prefix
    std::array<std::uint8_t, 32> key{};
    std::iota(key.begin(), key.end(), static_cast<std::uint8_t>(0));

    std::array<std::uint8_t, 16> iv{};
    std::fill(iv.begin(), iv.end(), static_cast<std::uint8_t>(0xDE));

    std::vector<std::uint8_t> payload(200);
    std::iota(payload.begin(), payload.end(), static_cast<std::uint8_t>(0x80));

    auto ct = Encrypt<AES_256_CTR_TRAITS>(key, iv, payload);
    ASSERT_EQ(ct.size(), payload.size());
    EXPECT_NE(ct, payload);

    auto pt = Decrypt<AES_256_CTR_TRAITS>(key, iv, ct);
    EXPECT_EQ(pt, payload);
}

TEST(Aes256CtrTest, ContextReuse)
{
    // Verify that a single SslStreamCipherCtx can be reused for multiple operations
    std::array<std::uint8_t, 32> key{};
    std::fill(key.begin(), key.end(), static_cast<std::uint8_t>(0x42));

    std::array<std::uint8_t, 16> iv1{};
    std::fill(iv1.begin(), iv1.end(), static_cast<std::uint8_t>(0x01));

    std::array<std::uint8_t, 16> iv2{};
    std::fill(iv2.begin(), iv2.end(), static_cast<std::uint8_t>(0x02));

    std::vector<std::uint8_t> plaintext(64, 0xAA);

    SslStreamCipherCtx<AES_256_CTR_TRAITS> ctx;

    auto ct1 = ctx.Encrypt(key, iv1, plaintext);
    auto ct2 = ctx.Encrypt(key, iv2, plaintext);
    EXPECT_NE(ct1, ct2); // Different IVs → different ciphertext

    auto pt1 = ctx.Decrypt(key, iv1, ct1);
    auto pt2 = ctx.Decrypt(key, iv2, ct2);
    EXPECT_EQ(pt1, plaintext);
    EXPECT_EQ(pt2, plaintext);
}
