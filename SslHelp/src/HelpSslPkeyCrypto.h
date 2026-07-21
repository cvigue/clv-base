// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_SSLHELP_SSL_PKEY_CRYPTO_H
#define CLV_SSLHELP_SSL_PKEY_CRYPTO_H

#include "HelpSslEvpPkey.h"
#include "HelpSslEvpPkeyCtx.h"
#include "HelpSslException.h"
#include "HelpSslNoRc.h"
#include "HelpSslX509.h"
#include "openssl/crypto.h"
#include "openssl/obj_mac.h"
#include "openssl/x509.h"

#include <expected>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace clv::OpenSSL {

struct SslEvpMdCtx : SslNoRc<EVP_MD_CTX, EVP_MD_CTX_new, EVP_MD_CTX_free>
{
    using SslNoRc<EVP_MD_CTX, EVP_MD_CTX_new, EVP_MD_CTX_free>::SslNoRc;
};

/**
 * @brief Fill @p out with cryptographically strong random bytes.
 */
inline void RandomBytes(std::span<std::uint8_t> out)
{
    if (out.empty())
        return;
    if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1)
        ThrowSsl("RAND_bytes failed");
}

template <std::size_t N>
[[nodiscard]] inline std::array<std::uint8_t, N> RandomBytes()
{
    std::array<std::uint8_t, N> out{};
    RandomBytes(std::span<std::uint8_t>(out.data(), out.size()));
    return out;
}

/**
 * @brief Extract the certificate public key as an owning @c SslEvpKey.
 * @details Uses @c X509_get_pubkey (allocates). Prefer @c BorrowPublicKeyFromCert when the
 *          certificate outlives the key handle or only a short-lived @c SslEvpKey is needed.
 */
inline SslEvpKey PublicKeyFromCert(const SslX509 &cert)
{
    EVP_PKEY *pkey = X509_get_pubkey(const_cast<X509 *>(cert.Get()));
    if (!pkey)
        ThrowSsl("X509_get_pubkey failed");
    return SslEvpKey(pkey);
}

/**
 * @brief Borrow the certificate embedded public key as an @c SslEvpKey (non-throwing).
 * @param cert Certificate whose embedded public key is borrowed
 * @return Owning @c SslEvpKey (via up-ref), or SslError if the cert has no public key
 * @note Uses @c X509_get0_pubkey plus @c EVP_PKEY_up_ref.
 * @note Primary implementation; BorrowPublicKeyFromCert is a thin throwing wrapper.
 */
[[nodiscard]] inline SslExpected<SslEvpKey> TryBorrowPublicKeyFromCert(const SslX509 &cert)
{
    EVP_PKEY *pkey = X509_get0_pubkey(const_cast<X509 *>(cert.Get()));
    if (!pkey)
        return std::unexpected(SslError::capture("X509_get0_pubkey failed"));
    return SslEvpKey::Borrow(pkey);
}

/**
 * @brief Borrow the certificate embedded public key as an @c SslEvpKey.
 * @param cert Certificate whose embedded public key is borrowed
 * @return Owning @c SslEvpKey (via up-ref); remains valid after @p cert is destroyed
 * @throws SslException if the certificate has no public key
 * @details Uses @c X509_get0_pubkey plus @c EVP_PKEY_up_ref.
 */
inline SslEvpKey BorrowPublicKeyFromCert(const SslX509 &cert)
{
    if (auto r = TryBorrowPublicKeyFromCert(cert); r.has_value())
        return *std::move(r);
    else
        throw SslException(std::move(r.error()));
}

/**
 * @brief Export an EVP public key as SPKI DER.
 */
inline std::vector<std::uint8_t> ExportPublicKeyDer(const SslEvpKey &key)
{
    const int der_len = i2d_PUBKEY(const_cast<EVP_PKEY *>(key.Get()), nullptr);
    if (der_len <= 0)
        ThrowSsl("i2d_PUBKEY size query failed");

    std::vector<std::uint8_t> der(static_cast<std::size_t>(der_len));
    std::uint8_t *p = der.data();
    if (i2d_PUBKEY(const_cast<EVP_PKEY *>(key.Get()), &p) <= 0)
        ThrowSsl("i2d_PUBKEY failed");
    return der;
}

/**
 * @brief Import an SPKI DER blob as an @c SslEvpKey (public key only, non-throwing).
 * @param der SubjectPublicKeyInfo DER encoding
 * @return Imported public key, or SslError on parse failure
 * @note Primary implementation; ImportPublicKeyDer is a thin throwing wrapper.
 */
[[nodiscard]] inline SslExpected<SslEvpKey> TryImportPublicKeyDer(std::span<const std::uint8_t> der)
{
    const std::uint8_t *p = der.data();
    EVP_PKEY *pkey = d2i_PUBKEY(nullptr, &p, static_cast<long>(der.size()));
    if (!pkey)
        return std::unexpected(SslError::capture("d2i_PUBKEY failed"));
    return SslEvpKey(pkey);
}

/**
 * @brief Import an SPKI DER blob as an @c SslEvpKey (public key only).
 * @param der SubjectPublicKeyInfo DER encoding
 * @return Imported public key
 * @throws SslException on parse failure
 */
inline SslEvpKey ImportPublicKeyDer(std::span<const std::uint8_t> der)
{
    if (auto r = TryImportPublicKeyDer(der); r.has_value())
        return *std::move(r);
    else
        throw SslException(std::move(r.error()));
}

/**
 * @brief One-shot SHA-256 digest of a byte span.
 */
[[nodiscard]] inline std::array<std::uint8_t, 32> Sha256(std::span<const std::uint8_t> data)
{
    std::array<std::uint8_t, 32> digest{};
    SHA256(data.data(), data.size(), digest.data());
    return digest;
}

/**
 * @brief Configure an @c EVP_PKEY_CTX for RSA-OAEP with SHA-256 (non-throwing).
 * @param ctx Context already associated with an RSA key
 * @return Empty success, or SslError if padding / OAEP MD / MGF1 MD setup fails
 * @note Sets PKCS#1 OAEP padding, OAEP MD = SHA-256, MGF1 MD = SHA-256.
 */
inline SslExpected<void> TryConfigureRsaOaepSha256(EVP_PKEY_CTX *ctx)
{
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        return std::unexpected(SslError::capture("EVP_PKEY_CTX_set_rsa_padding failed"));
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0)
        return std::unexpected(SslError::capture("EVP_PKEY_CTX_set_rsa_oaep_md failed"));
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0)
        return std::unexpected(SslError::capture("EVP_PKEY_CTX_set_rsa_mgf1_md failed"));
    return {};
}

/**
 * @brief Configure an @c EVP_PKEY_CTX for RSA-OAEP with SHA-256.
 * @param ctx Context already associated with an RSA key
 * @throws SslException if padding / OAEP MD / MGF1 MD setup fails
 */
inline void ConfigureRsaOaepSha256(EVP_PKEY_CTX *ctx)
{
    if (auto r = TryConfigureRsaOaepSha256(ctx); r.has_value())
        return;
    else
        throw SslException(std::move(r.error()));
}

/**
 * @brief RSA-OAEP-SHA256 encrypt (non-throwing).
 * @param public_key Recipient RSA public key
 * @param plaintext Small plaintext (typically key material)
 * @return Ciphertext, or SslError on failure
 * @note Primary implementation; RsaOaepSha256Encrypt is a thin throwing wrapper.
 */
[[nodiscard]] inline SslExpected<std::vector<std::uint8_t>>
TryRsaOaepSha256Encrypt(const SslEvpKey &public_key, std::span<const std::uint8_t> plaintext)
{
    auto ctx = SslEvpPkeyCtx(EVP_PKEY_CTX_new(const_cast<EVP_PKEY *>(public_key.Get()), nullptr));
    if (EVP_PKEY_encrypt_init(ctx) <= 0)
        return std::unexpected(SslError::capture("EVP_PKEY_encrypt_init failed"));
    if (auto cfg = TryConfigureRsaOaepSha256(ctx); !cfg)
        return std::unexpected(std::move(cfg.error()));

    std::size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, plaintext.data(), plaintext.size()) <= 0)
        return std::unexpected(SslError::capture("EVP_PKEY_encrypt size query failed"));

    std::vector<std::uint8_t> ciphertext(outlen);
    if (EVP_PKEY_encrypt(ctx, ciphertext.data(), &outlen, plaintext.data(), plaintext.size()) <= 0)
        return std::unexpected(SslError::capture("EVP_PKEY_encrypt failed"));
    ciphertext.resize(outlen);
    return ciphertext;
}

/**
 * @brief RSA-OAEP-SHA256 encrypt (typically used for small key material).
 * @param public_key Recipient RSA public key
 * @param plaintext Small plaintext (typically key material)
 * @return Ciphertext
 * @throws SslException on failure
 */
inline std::vector<std::uint8_t> RsaOaepSha256Encrypt(const SslEvpKey &public_key,
                                                      std::span<const std::uint8_t> plaintext)
{
    if (auto r = TryRsaOaepSha256Encrypt(public_key, plaintext); r.has_value())
        return *std::move(r);
    else
        throw SslException(std::move(r.error()));
}

/**
 * @brief RSA-OAEP-SHA256 decrypt (non-throwing).
 * @param private_key Recipient RSA private key
 * @param ciphertext OAEP ciphertext from @c TryRsaOaepSha256Encrypt / @c RsaOaepSha256Encrypt
 * @return Plaintext, or SslError on failure (including wrong key / corrupt ciphertext)
 * @note Primary implementation; RsaOaepSha256Decrypt is a thin throwing wrapper.
 */
[[nodiscard]] inline SslExpected<std::vector<std::uint8_t>>
TryRsaOaepSha256Decrypt(const SslEvpKey &private_key, std::span<const std::uint8_t> ciphertext)
{
    auto ctx = SslEvpPkeyCtx(EVP_PKEY_CTX_new(const_cast<EVP_PKEY *>(private_key.Get()), nullptr));
    if (EVP_PKEY_decrypt_init(ctx) <= 0)
        return std::unexpected(SslError::capture("EVP_PKEY_decrypt_init failed"));
    if (auto cfg = TryConfigureRsaOaepSha256(ctx); !cfg)
        return std::unexpected(std::move(cfg.error()));

    std::size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, ciphertext.data(), ciphertext.size()) <= 0)
        return std::unexpected(SslError::capture("EVP_PKEY_decrypt size query failed"));

    std::vector<std::uint8_t> plaintext(outlen);
    if (EVP_PKEY_decrypt(ctx, plaintext.data(), &outlen, ciphertext.data(), ciphertext.size()) <= 0)
        return std::unexpected(SslError::capture("EVP_PKEY_decrypt failed"));
    plaintext.resize(outlen);
    return plaintext;
}

/**
 * @brief RSA-OAEP-SHA256 decrypt.
 * @param private_key Recipient RSA private key
 * @param ciphertext OAEP ciphertext from @c RsaOaepSha256Encrypt
 * @return Plaintext
 * @throws SslException on failure (including wrong key / corrupt ciphertext)
 */
inline std::vector<std::uint8_t> RsaOaepSha256Decrypt(const SslEvpKey &private_key,
                                                      std::span<const std::uint8_t> ciphertext)
{
    if (auto r = TryRsaOaepSha256Decrypt(private_key, ciphertext); r.has_value())
        return *std::move(r);
    else
        throw SslException(std::move(r.error()));
}

/**
 * @brief Generate an ephemeral EC P-256 key pair.
 */
inline SslEvpKey GenerateEphemeralEcP256()
{
    auto ctx = SslEvpPkeyCtx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    if (EVP_PKEY_keygen_init(ctx) <= 0
        || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0)
        ThrowSsl("EC P-256 keygen init failed");

    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        ThrowSsl("EC P-256 keygen failed");
    return SslEvpKey(pkey);
}

/**
 * @brief ECDH P-256 shared secret → HKDF-SHA256 → fixed-size key.
 */
template <std::size_t OutLength>
[[nodiscard]] inline std::array<std::uint8_t, OutLength> DeriveKeyEcdhP256Hkdf(
    const SslEvpKey &private_key,
    const SslEvpKey &peer_public_key,
    std::span<const std::uint8_t> info)
{
    auto ctx = SslEvpPkeyCtx(EVP_PKEY_CTX_new(const_cast<EVP_PKEY *>(private_key.Get()), nullptr));
    if (EVP_PKEY_derive_init(ctx) <= 0)
        ThrowSsl("EVP_PKEY_derive_init failed");
    if (EVP_PKEY_derive_set_peer(ctx, const_cast<EVP_PKEY *>(peer_public_key.Get())) <= 0)
        ThrowSsl("EVP_PKEY_derive_set_peer failed");

    std::size_t secret_len = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0)
        ThrowSsl("EVP_PKEY_derive size query failed");

    std::vector<std::uint8_t> secret(secret_len);
    if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) <= 0)
        ThrowSsl("EVP_PKEY_derive failed");
    secret.resize(secret_len);

    const SslEvpPkeyCtx::Salt empty_salt{};
    const auto prk = SslEvpPkeyCtx::ExtractHkdf(
        EVP_sha256(),
        SslEvpPkeyCtx::Key(secret),
        empty_salt);

    const SslEvpPkeyCtx::Info hkdf_info{info.data(), info.size()};
    return SslEvpPkeyCtx::ExpandHkdf<OutLength>(
        EVP_sha256(),
        SslEvpPkeyCtx::Key(prk),
        hkdf_info);
}

inline void ConfigureRsaPssSha256(EVP_MD_CTX *ctx)
{
    EVP_PKEY_CTX *pctx = EVP_MD_CTX_get_pkey_ctx(ctx);
    if (!pctx)
        ThrowSsl("EVP_MD_CTX_get_pkey_ctx failed");
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1)
        ThrowSsl("EVP_PKEY_CTX_set_rsa_padding failed");
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) != 1)
        ThrowSsl("EVP_PKEY_CTX_set_rsa_pss_saltlen failed");
}

/**
 * @brief SHA-256 digest sign (RSA uses PSS with salt length = digest size).
 */
inline std::vector<std::uint8_t> DigestSignSha256(const SslEvpKey &private_key,
                                                  std::span<const std::uint8_t> message)
{
    auto ctx = SslEvpMdCtx();
    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, const_cast<EVP_PKEY *>(private_key.Get())) != 1)
        ThrowSsl("EVP_DigestSignInit failed");
    if (private_key.BaseId() == EVP_PKEY_RSA)
        ConfigureRsaPssSha256(ctx);

    std::size_t siglen = 0;
    if (EVP_DigestSign(ctx, nullptr, &siglen, message.data(), message.size()) != 1)
        ThrowSsl("EVP_DigestSign size query failed");

    std::vector<std::uint8_t> signature(siglen);
    if (EVP_DigestSign(ctx, signature.data(), &siglen, message.data(), message.size()) != 1)
        ThrowSsl("EVP_DigestSign failed");
    signature.resize(siglen);
    return signature;
}

/**
 * @brief SHA-256 digest verify (RSA uses PSS with salt length = digest size).
 */
inline bool DigestVerifySha256(const SslEvpKey &public_key,
                               std::span<const std::uint8_t> message,
                               std::span<const std::uint8_t> signature)
{
    auto ctx = SslEvpMdCtx();
    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, const_cast<EVP_PKEY *>(public_key.Get())) != 1)
        return false;
    if (public_key.BaseId() == EVP_PKEY_RSA)
    {
        try
        {
            ConfigureRsaPssSha256(ctx);
        }
        catch (...)
        {
            return false;
        }
    }

    return EVP_DigestVerify(ctx, signature.data(), signature.size(), message.data(), message.size()) == 1;
}

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_SSL_PKEY_CRYPTO_H
