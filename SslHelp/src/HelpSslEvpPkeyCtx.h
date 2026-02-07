// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLV_SSLHELP_SSL_EVP_PKEY_CTX_H
#define CLV_SSLHELP_SSL_EVP_PKEY_CTX_H

#include "HelpSslException.h"
#include "HelpSslNoRc.h"

#include <array>
#include <cstddef>
#include <openssl/types.h>
#include <span>
#include <vector>
#include <cstdint>
#include <openssl/evp.h>
#include <openssl/kdf.h>

namespace clv::OpenSSL {

/**
 * @brief RAII wrapper for OpenSSL EVP_PKEY_CTX with HKDF helper methods
 * @class SslEvpPkeyCtx
 * @details SslEvpPkeyCtx provides a safe wrapper around EVP_PKEY_CTX with convenience
 *          methods for common operations like HKDF key derivation. All methods throw
 *          SslException on OpenSSL errors rather than requiring manual error checking.
 * @see \c SslNoRc
 */
struct SslEvpPkeyCtx : SslNoRc<EVP_PKEY_CTX, EVP_PKEY_CTX_new, EVP_PKEY_CTX_free>
{
    using SslNoRc<EVP_PKEY_CTX, EVP_PKEY_CTX_new, EVP_PKEY_CTX_free>::SslNoRc;


    /// @brief Strong type for HKDF key material (IKM for extract, PRK for expand)
    struct Key : std::span<const std::uint8_t>
    {
        using std::span<const std::uint8_t>::span;
    };

    /// @brief Strong type for HKDF salt
    struct Salt : std::span<const std::uint8_t>
    {
        using std::span<const std::uint8_t>::span;
    };

    /// @brief Strong type for HKDF info (context/application-specific data)
    struct Info : std::span<const std::uint8_t>
    {
        using std::span<const std::uint8_t>::span;
    };

    /// @brief Strong type for derived output
    struct Output : std::span<std::uint8_t>
    {
        using std::span<std::uint8_t>::span;
    };

    /**
     * @brief Create a new SslEvpPkeyCtx initialized for HKDF
     * @return SslEvpPkeyCtx instance initialized for HKDF
     * @throws SslException if context creation fails
     */
    static SslEvpPkeyCtx CreateHkdf();

    /**
     * @brief Create a new SslEvpPkeyCtx initialized for TLS 1.0 PRF
     * @return SslEvpPkeyCtx instance initialized for TLS 1.0 PRF
     * @throws SslException if context creation fails
     */
    static SslEvpPkeyCtx CreateTls1Prf();

    /**
     * @brief Perform TLS 1.0 PRF key derivation
     * @param secret The master secret
     * @param seed The seed (typically label || client_random || server_random)
     * @param length Desired output length in bytes
     * @return Derived key material
     * @throws SslException on failure
     *
     * @note Uses EVP_md5_sha1() as required by TLS 1.0/1.1 PRF.
     *       This is the P_MD5 XOR P_SHA-1 construction from RFC 2246.
     */
    static std::vector<std::uint8_t> DeriveTls1Prf(Key secret,
                                                   std::span<const std::uint8_t> seed,
                                                   std::size_t length);

    /**
     * @brief Perform TLS 1.0 PRF key derivation (fixed-size output)
     * @tparam N Output size in bytes (known at compile time)
     * @param secret The master secret
     * @param seed The seed (typically label || client_random || server_random)
     * @return Fixed-size derived key material as std::array
     * @throws SslException on failure
     */
    template <std::size_t N>
    static std::array<std::uint8_t, N> DeriveTls1Prf(Key secret,
                                                     std::span<const std::uint8_t> seed);

    /**
     * @brief Perform HKDF-Extract to derive a PRK from IKM and salt
     * @param md Message digest algorithm (e.g., EVP_sha256(), EVP_sha384(), EVP_sha512())
     * @param ikm Input keying material
     * @param salt Salt value (can be empty)
     * @return PRK sized according to the hash function output (e.g., 32 bytes for SHA-256,
     *         48 bytes for SHA-384, 64 bytes for SHA-512)
     * @throws SslException on failure
     */
    static std::vector<std::uint8_t> ExtractHkdf(const EVP_MD *md,
                                                 Key ikm,
                                                 Salt salt);

    /**
     * @brief Perform HKDF-Expand to derive OKM from PRK and info
     * @param md Message digest algorithm (e.g., EVP_sha256())
     * @param prk Pseudo-random key from Extract phase
     * @param info Context and application-specific information
     * @param length Desired output length in bytes
     * @return Variable-length OKM (heap-allocated)
     * @throws SslException on failure or if length exceeds 255 * hash_length
     *
     * @note Use this version when the output size is determined at runtime.
     *       For compile-time known sizes, prefer the template version for
     *       stack allocation and zero overhead.
     */
    static std::vector<std::uint8_t> ExpandHkdf(const EVP_MD *md,
                                                Key prk,
                                                Info info,
                                                std::size_t length);

    /**
     * @brief Perform HKDF-Expand to derive fixed-size OKM from PRK and info
     * @tparam N Output size in bytes (known at compile time)
     * @param md Message digest algorithm (e.g., EVP_sha256())
     * @param prk Pseudo-random key from Extract phase
     * @param info Context and application-specific information
     * @return Fixed-size OKM as std::array (stack-allocated, no heap allocation)
     * @throws SslException on failure or if N exceeds 255 * hash_length
     *
     * @note Use this version when the output size is known at compile time.
     *       Provides stack allocation and cleaner API for common fixed sizes.
     * @code
     *   // QUIC key derivation example (compile-time sizes)
     *   auto key = ExpandHkdf<16>(EVP_sha256(), prk, info);  // std::array<uint8_t, 16>
     *   auto iv  = ExpandHkdf<12>(EVP_sha256(), prk, info);  // std::array<uint8_t, 12>
     *   auto hp  = ExpandHkdf<16>(EVP_sha256(), prk, info);  // std::array<uint8_t, 16>
     * @endcode
     */
    template <std::size_t N>
    static std::array<std::uint8_t, N> ExpandHkdf(const EVP_MD *md,
                                                  Key prk,
                                                  Info info);

    /**
     * @brief Initialize the context for key derivation
     * @throws SslException if initialization fails
     */
    void InitDerivation();

    /**
     * @brief Set HKDF mode (EXTRACT_ONLY, EXPAND_ONLY, or EXTRACT_AND_EXPAND)
     * @param mode One of EVP_PKEY_HKDEF_MODE_* constants
     * @throws SslException on failure
     */
    void SetHkdfMode(int mode);

    /**
     * @brief Set HKDF hash algorithm
     * @param md Message digest (e.g., EVP_sha256())
     * @throws SslException on failure
     */
    void SetHkdfMd(const EVP_MD *md);

    /**
     * @brief Set HKDF salt
     * @param salt Salt bytes
     * @throws SslException on failure
     */
    void SetHkdfSalt(Salt salt);

    /**
     * @brief Set HKDF key (IKM for extract, PRK for expand)
     * @param key Key material
     * @throws SslException on failure
     */
    void SetHkdfKey(Key key);

    /**
     * @brief Add HKDF info (context data for expand)
     * @param info Info bytes
     * @throws SslException on failure
     */
    void AddHkdfInfo(Info info);

    /**
     * @brief Derive key material into output buffer
     * @param output Output buffer to receive derived key material
     * @throws SslException on failure
     */
    void Derive(Output output);

  private: // Private helper overloads for CreateHkdf
    /**
     * @brief Create and initialize an HKDF context with mode, hash, and key
     * @param mode HKDF mode (EVP_PKEY_HKDEF_MODE_*)
     * @param md Message digest algorithm (e.g., EVP_sha256())
     * @param key Key material (IKM for extract, PRK for expand)
     * @return Initialized SslEvpPkeyCtx ready for Derive()
     * @throws SslException on failure
     */
    static SslEvpPkeyCtx CreateHkdf(int mode, const EVP_MD *md, Key key);

    /**
     * @brief Create and initialize an HKDF context with mode, hash, key, and salt
     * @param mode HKDF mode (EVP_PKEY_HKDEF_MODE_*)
     * @param md Message digest algorithm (e.g., EVP_sha256())
     * @param key Key material (IKM for extract, PRK for expand)
     * @param salt Salt bytes
     * @return Initialized SslEvpPkeyCtx ready for Derive()
     * @throws SslException on failure
     */
    static SslEvpPkeyCtx CreateHkdf(int mode, const EVP_MD *md,
                                    Key key,
                                    Salt salt);

    /**
     * @brief Create and initialize an HKDF context with mode, hash, key, and info (no salt)
     * @param mode HKDF mode (EVP_PKEY_HKDEF_MODE_*)
     * @param md Message digest algorithm (e.g., EVP_sha256())
     * @param key Key material (IKM for extract, PRK for expand)
     * @param info Context/application-specific info
     * @return Initialized SslEvpPkeyCtx ready for Derive()
     * @throws SslException on failure
     */
    static SslEvpPkeyCtx CreateHkdf(int mode, const EVP_MD *md,
                                    Key key,
                                    Info info);

    /**
     * @brief Create and initialize an HKDF context with all common parameters
     * @param mode HKDF mode (EVP_PKEY_HKDEF_MODE_*)
     * @param md Message digest algorithm (e.g., EVP_sha256())
     * @param key Key material (IKM for extract, PRK for expand)
     * @param salt Salt bytes
     * @param info Context/application-specific info
     * @return Initialized SslEvpPkeyCtx ready for Derive()
     * @throws SslException on failure
     */
    static SslEvpPkeyCtx CreateHkdf(int mode, const EVP_MD *md,
                                    Key key,
                                    Salt salt,
                                    Info info);
};

// ================================================================================================
//  Implementation
// ================================================================================================

inline SslEvpPkeyCtx SslEvpPkeyCtx::CreateHkdf()
{
    return SslEvpPkeyCtx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    ;
}

inline SslEvpPkeyCtx SslEvpPkeyCtx::CreateTls1Prf()
{
    return SslEvpPkeyCtx(EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, nullptr));
}

inline std::vector<std::uint8_t> SslEvpPkeyCtx::DeriveTls1Prf(Key secret,
                                                              std::span<const std::uint8_t> seed,
                                                              std::size_t length)
{
    auto ctx = CreateTls1Prf();
    ctx.InitDerivation();

    if (EVP_PKEY_CTX_set_tls1_prf_md(ctx, EVP_md5_sha1()) <= 0)
        throw SslException("EVP_PKEY_CTX_set_tls1_prf_md failed");

    if (EVP_PKEY_CTX_set1_tls1_prf_secret(ctx, secret.data(), static_cast<int>(secret.size())) <= 0)
        throw SslException("EVP_PKEY_CTX_set1_tls1_prf_secret failed");

    if (EVP_PKEY_CTX_add1_tls1_prf_seed(ctx, seed.data(), static_cast<int>(seed.size())) <= 0)
        throw SslException("EVP_PKEY_CTX_add1_tls1_prf_seed failed");

    std::vector<std::uint8_t> output(length);
    ctx.Derive(Output(output.data(), output.size()));
    return output;
}

template <std::size_t N>
inline std::array<std::uint8_t, N> SslEvpPkeyCtx::DeriveTls1Prf(Key secret,
                                                                std::span<const std::uint8_t> seed)
{
    auto ctx = CreateTls1Prf();
    ctx.InitDerivation();

    if (EVP_PKEY_CTX_set_tls1_prf_md(ctx, EVP_md5_sha1()) <= 0)
        throw SslException("EVP_PKEY_CTX_set_tls1_prf_md failed");

    if (EVP_PKEY_CTX_set1_tls1_prf_secret(ctx, secret.data(), static_cast<int>(secret.size())) <= 0)
        throw SslException("EVP_PKEY_CTX_set1_tls1_prf_secret failed");

    if (EVP_PKEY_CTX_add1_tls1_prf_seed(ctx, seed.data(), static_cast<int>(seed.size())) <= 0)
        throw SslException("EVP_PKEY_CTX_add1_tls1_prf_seed failed");

    std::array<std::uint8_t, N> output;
    ctx.Derive(Output(output.data(), output.size()));
    return output;
}

inline SslEvpPkeyCtx SslEvpPkeyCtx::CreateHkdf(int mode, const EVP_MD *md, Key key)
{
    auto ctx = CreateHkdf();
    ctx.InitDerivation();
    ctx.SetHkdfMode(mode);
    ctx.SetHkdfMd(md);
    ctx.SetHkdfKey(key);
    return ctx;
}

inline SslEvpPkeyCtx SslEvpPkeyCtx::CreateHkdf(int mode, const EVP_MD *md,
                                               Key key,
                                               Salt salt)
{
    auto ctx = CreateHkdf();
    ctx.InitDerivation();
    ctx.SetHkdfMode(mode);
    ctx.SetHkdfMd(md);
    ctx.SetHkdfSalt(salt);
    ctx.SetHkdfKey(key);
    return ctx;
}

inline SslEvpPkeyCtx SslEvpPkeyCtx::CreateHkdf(int mode, const EVP_MD *md,
                                               Key key,
                                               Info info)
{
    auto ctx = CreateHkdf();
    ctx.InitDerivation();
    ctx.SetHkdfMode(mode);
    ctx.SetHkdfMd(md);
    ctx.SetHkdfKey(key);
    ctx.AddHkdfInfo(info);
    return ctx;
}

inline SslEvpPkeyCtx SslEvpPkeyCtx::CreateHkdf(int mode, const EVP_MD *md,
                                               Key key,
                                               Salt salt,
                                               Info info)
{
    auto ctx = CreateHkdf();
    ctx.InitDerivation();
    ctx.SetHkdfMode(mode);
    ctx.SetHkdfMd(md);
    ctx.SetHkdfSalt(salt);
    ctx.SetHkdfKey(key);
    ctx.AddHkdfInfo(info);
    return ctx;
}

inline std::vector<std::uint8_t> SslEvpPkeyCtx::ExtractHkdf(const EVP_MD *md,
                                                            Key ikm,
                                                            Salt salt)
{
    if (!md)
        throw SslException("ExtractHkdf: md cannot be null");

    const int digest_size = EVP_MD_size(md);
    if (digest_size <= 0)
        throw SslException("ExtractHkdf: invalid digest size");

    std::vector<std::uint8_t> prk(static_cast<std::size_t>(digest_size));

    auto ctx = CreateHkdf(EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY, md, ikm, salt);
    ctx.Derive(Output(prk.data(), prk.size()));

    return prk;
}

inline std::vector<std::uint8_t> SslEvpPkeyCtx::ExpandHkdf(const EVP_MD *md,
                                                           Key prk,
                                                           Info info,
                                                           std::size_t length)
{
    std::vector<std::uint8_t> okm(length);

    auto ctx = CreateHkdf(EVP_PKEY_HKDEF_MODE_EXPAND_ONLY, md, prk, info);
    ctx.Derive(Output(okm.data(), okm.size()));

    return okm;
}

template <std::size_t N>
inline std::array<std::uint8_t, N> SslEvpPkeyCtx::ExpandHkdf(const EVP_MD *md,
                                                             Key prk,
                                                             Info info)
{
    std::array<std::uint8_t, N> okm;

    auto ctx = CreateHkdf(EVP_PKEY_HKDEF_MODE_EXPAND_ONLY, md, prk, info);
    ctx.Derive(Output(okm.data(), okm.size()));

    return okm;
}

inline void SslEvpPkeyCtx::InitDerivation()
{
    if (EVP_PKEY_derive_init(*this) <= 0)
        throw SslException("EVP_PKEY_derive_init failed");
}

inline void SslEvpPkeyCtx::SetHkdfMode(int mode)
{
    if (EVP_PKEY_CTX_hkdf_mode(*this, mode) <= 0)
        throw SslException("EVP_PKEY_CTX_hkdf_mode failed");
}

inline void SslEvpPkeyCtx::SetHkdfMd(const EVP_MD *md)
{
    if (EVP_PKEY_CTX_set_hkdf_md(*this, md) <= 0)
        throw SslException("EVP_PKEY_CTX_set_hkdf_md failed");
}

inline void SslEvpPkeyCtx::SetHkdfSalt(Salt salt)
{
    if (salt.empty())
        return; // RFC 5869: empty salt is valid; OpenSSL uses a default of HashLen zeros
    if (EVP_PKEY_CTX_set1_hkdf_salt(*this, salt.data(), static_cast<int>(salt.size())) <= 0)
        throw SslException("EVP_PKEY_CTX_set1_hkdf_salt failed");
}

inline void SslEvpPkeyCtx::SetHkdfKey(Key key)
{
    if (EVP_PKEY_CTX_set1_hkdf_key(*this, key.data(), static_cast<int>(key.size())) <= 0)
        throw SslException("EVP_PKEY_CTX_set1_hkdf_key failed");
}

inline void SslEvpPkeyCtx::AddHkdfInfo(Info info)
{
    if (EVP_PKEY_CTX_add1_hkdf_info(*this, info.data(), static_cast<int>(info.size())) <= 0)
        throw SslException("EVP_PKEY_CTX_add1_hkdf_info failed");
}

inline void SslEvpPkeyCtx::Derive(Output output)
{
    std::size_t outlen = output.size();
    if (EVP_PKEY_derive(*this, output.data(), &outlen) <= 0 || outlen != output.size())
        throw SslException("EVP_PKEY_derive failed");
}

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_SSL_EVP_PKEY_CTX_H