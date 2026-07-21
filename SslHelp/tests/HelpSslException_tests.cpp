// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include "gtest/gtest.h"

#include "HelpSslCipher.h"
#include "HelpSslException.h"
#include "HelpSslHmac.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <vector>

using namespace clv::OpenSSL;

namespace {

void PushSyntheticError(int lib, int reason)
{
    ERR_put_error(lib, 0, reason, "HelpSslException_tests.cpp", __LINE__);
}

} // namespace

TEST(SslExceptionTest, EmptyQueueMessageEqualsContext)
{
    ERR_clear_error();
    const SslError err = SslError::capture("no openssl error");
    EXPECT_EQ(err.size(), 0u);
    EXPECT_EQ(err.message(), "no openssl error");
    EXPECT_EQ(err.kind(), SslErrorKind::None);

    SslException ex("no openssl error");
    EXPECT_STREQ(ex.what(), "no openssl error");
    EXPECT_EQ(ex.kind(), SslErrorKind::None);
}

TEST(SslExceptionTest, StringCtorDrainsQueue)
{
    ERR_clear_error();
    PushSyntheticError(ERR_LIB_SSL, SSL_R_CERTIFICATE_VERIFY_FAILED);
    PushSyntheticError(ERR_LIB_SSL, SSL_R_UNSUPPORTED_PROTOCOL);

    SslException ex(std::string("load failed"));
    EXPECT_EQ(ERR_peek_error(), 0u);
    EXPECT_GE(ex.error().size(), 1u);
    EXPECT_NE(std::string(ex.what()).find("load failed"), std::string::npos);
}

TEST(SslExceptionTest, MultiErrorDrainRetainsUpToEightAndClearsQueue)
{
    ERR_clear_error();
    for (int i = 0; i < 10; ++i)
        PushSyntheticError(ERR_LIB_SSL, SSL_R_CERTIFICATE_VERIFY_FAILED);

    const SslError err = SslError::capture("stacked");
    EXPECT_EQ(err.size(), kSslMaxErrors);
    EXPECT_EQ(ERR_peek_error(), 0u);
    EXPECT_EQ(err.kind(), SslErrorKind::CertVerify);
    EXPECT_NE(err.message().find(" / "), std::string::npos);
}

TEST(SslExceptionTest, AlertDecodeSetsTlsAlertKind)
{
    ERR_clear_error();
    PushSyntheticError(ERR_LIB_SSL, SSL_AD_REASON_OFFSET + SSL_AD_HANDSHAKE_FAILURE);

    const SslError err = SslError::capture("alert");
    EXPECT_EQ(err.kind(), SslErrorKind::TlsAlert);
    EXPECT_EQ(err.alert(), SSL_AD_HANDSHAKE_FAILURE);
    EXPECT_NE(err.message().find("handshake failure"), std::string::npos);
}

TEST(SslExceptionTest, AuthTagKind)
{
    ERR_clear_error();
    PushSyntheticError(ERR_LIB_SSL, SSL_R_CERTIFICATE_VERIFY_FAILED);
    const SslError err = SslError::auth_tag("tag mismatch");
    EXPECT_EQ(err.kind(), SslErrorKind::AuthTag);
    EXPECT_EQ(ERR_peek_error(), 0u);
    EXPECT_EQ(err.message(), "tag mismatch");
}

TEST(SslExceptionTest, LocationOverloadAppendsToWhat)
{
    ERR_clear_error();
    const auto loc = std::source_location::current();
    SslException ex(SslError::capture("field failure"), loc);
    const std::string what = ex.what();
    EXPECT_NE(what.find("field failure"), std::string::npos);
    EXPECT_NE(what.find("(at "), std::string::npos);
    EXPECT_NE(what.find(std::to_string(loc.line())), std::string::npos);
    EXPECT_TRUE(ex.error().has_location());
}

TEST(SslExceptionTest, ThrowSslWithoutLocationHasNoSuffix)
{
    ERR_clear_error();
    try
    {
        ThrowSsl("plain");
        FAIL() << "expected throw";
    }
    catch (const SslException &e)
    {
        EXPECT_EQ(std::string(e.what()), "plain");
        EXPECT_FALSE(e.error().has_location());
    }
}

TEST(SslExceptionTest, TryDecryptAeadTagMismatchReturnsAuthTag)
{
    ERR_clear_error();
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 12> nonce{};
    std::vector<std::uint8_t> plaintext = {1, 2, 3, 4};
    std::vector<std::uint8_t> aad = {9};

    auto ct = TryEncryptAead(AES_256_GCM_TRAITS, key, nonce, plaintext, aad);
    ASSERT_TRUE(ct.has_value());
    (*ct)[0] ^= 0x01; // corrupt ciphertext

    auto pt = TryDecryptAead(AES_256_GCM_TRAITS, key, nonce, *ct, aad);
    ASSERT_FALSE(pt.has_value());
    EXPECT_EQ(pt.error().kind(), SslErrorKind::AuthTag);
    EXPECT_EQ(ERR_peek_error(), 0u);

    EXPECT_THROW(DecryptAead(AES_256_GCM_TRAITS, key, nonce, *ct, aad), SslException);
}

TEST(SslExceptionTest, TryHmacSha256RoundTrip)
{
    ERR_clear_error();
    std::array<std::uint8_t, 16> key{};
    std::vector<std::uint8_t> data = {1, 2, 3};

    auto r = TryHmacSha256(key, data);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->size(), 32u);
    EXPECT_EQ(HmacSha256(key, data), *r);
}

TEST(SslExceptionTest, TryEncryptDecryptInPlace_PreKeyedRoundTrip)
{
    ERR_clear_error();
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 12> nonce1{};
    std::array<std::uint8_t, 12> nonce2{};
    std::fill(nonce1.begin(), nonce1.end(), 0x11);
    std::fill(nonce2.begin(), nonce2.end(), 0x22);

    std::vector<std::uint8_t> plaintext = {1, 2, 3, 4, 5, 6, 7, 8};
    std::vector<std::uint8_t> aad = {0xAA, 0xBB};
    std::array<std::uint8_t, 12> dummy_nonce{};

    SslCipherCtx enc;
    enc.InitAeadEncrypt(AES_256_GCM_TRAITS);
    enc.SetEncryptKeyAndNonce(key, dummy_nonce);

    std::vector<std::uint8_t> buf = plaintext;
    auto tag = enc.TryEncryptInPlace(nonce1, buf, aad);
    ASSERT_TRUE(tag.has_value());
    EXPECT_NE(buf, plaintext);

    // Second packet on the same keyed context (nonce-only refresh).
    std::vector<std::uint8_t> buf2 = plaintext;
    auto tag2 = enc.TryEncryptInPlace(nonce2, buf2, aad);
    ASSERT_TRUE(tag2.has_value());
    EXPECT_NE(buf, buf2);

    SslCipherCtx dec;
    dec.InitAeadDecrypt(AES_256_GCM_TRAITS);
    dec.SetDecryptKeyAndNonce(key, dummy_nonce);

    EXPECT_TRUE(dec.TryDecryptInPlace(nonce1, buf, *tag, aad).has_value());
    EXPECT_EQ(buf, plaintext);

    EXPECT_TRUE(dec.TryDecryptInPlace(nonce2, buf2, *tag2, aad).has_value());
    EXPECT_EQ(buf2, plaintext);
}

TEST(SslExceptionTest, TryDecryptInPlace_TagMismatchReturnsAuthTag)
{
    ERR_clear_error();
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 12> nonce{};
    std::fill(nonce.begin(), nonce.end(), 0x33);
    std::vector<std::uint8_t> plaintext = {9, 8, 7, 6};
    std::vector<std::uint8_t> aad = {1};
    std::array<std::uint8_t, 12> dummy_nonce{};

    SslCipherCtx enc;
    enc.InitAeadEncrypt(AES_256_GCM_TRAITS);
    enc.SetEncryptKeyAndNonce(key, dummy_nonce);
    std::vector<std::uint8_t> buf = plaintext;
    auto tag = enc.TryEncryptInPlace(nonce, buf, aad);
    ASSERT_TRUE(tag.has_value());
    (*tag)[0] ^= 0xFF;

    SslCipherCtx dec;
    dec.InitAeadDecrypt(AES_256_GCM_TRAITS);
    dec.SetDecryptKeyAndNonce(key, dummy_nonce);

    auto r = dec.TryDecryptInPlace(nonce, buf, *tag, aad);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().kind(), SslErrorKind::AuthTag);
    EXPECT_EQ(ERR_peek_error(), 0u);
}
