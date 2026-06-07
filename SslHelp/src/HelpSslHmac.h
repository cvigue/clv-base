// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_SSLHELP_SSL_HMAC_H
#define CLV_SSLHELP_SSL_HMAC_H

#include "HelpSslException.h"
#include "HelpSslNoRc.h"

#include <array>
#include <cstddef>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/types.h>
#include <span>
#include <cstdint>
#include <openssl/evp.h>

namespace clv::OpenSSL {

// ================================================================================================
// HMAC Traits - Define properties for different hash algorithms
// ================================================================================================

/**
 * @brief Traits for HMAC-SHA256
 */
struct HmacSha256Traits
{
    static constexpr std::size_t output_size = 32;
    static constexpr const char *digest_name = "SHA256";
    static const EVP_MD *evp_md()
    {
        return EVP_sha256();
    }
};

/**
 * @brief Traits for HMAC-SHA512
 */
struct HmacSha512Traits
{
    static constexpr std::size_t output_size = 64;
    static constexpr const char *digest_name = "SHA512";
    static const EVP_MD *evp_md()
    {
        return EVP_sha512();
    }
};

/**
 * @brief Traits for HMAC-MD5 (required for TLS 1.0 PRF)
 */
struct HmacMd5Traits
{
    static constexpr std::size_t output_size = 16;
    static constexpr const char *digest_name = "MD5";
    static const EVP_MD *evp_md()
    {
        return EVP_md5();
    }
};

/**
 * @brief Traits for HMAC-SHA1 (required for TLS 1.0 PRF)
 */
struct HmacSha1Traits
{
    static constexpr std::size_t output_size = 20;
    static constexpr const char *digest_name = "SHA1";
    static const EVP_MD *evp_md()
    {
        return EVP_sha1();
    }
};

// ================================================================================================
// SslHmacCtx - Type-safe HMAC context
// ================================================================================================

/**
 * @brief RAII wrapper for OpenSSL EVP_MAC_CTX with common HMAC operations
 * @tparam DefaultTraits Default HMAC traits to use (e.g., HmacSha256Traits)
 * @class SslHmacCtx
 * @details Provides a safe wrapper around EVP_MAC_CTX for message authentication.
 *          Supports SHA-256, SHA-512, and other hash algorithms using the modern EVP_MAC API.
 *          Template parameter provides type safety while method templates allow override.
 * @see \c SslNoRc
 */
template <typename DefaultTraits = HmacSha256Traits>
struct SslHmacCtx : SslNoRc<EVP_MAC_CTX, EVP_MAC_CTX_new, EVP_MAC_CTX_free>
{
    using SslNoRc<EVP_MAC_CTX, EVP_MAC_CTX_new, EVP_MAC_CTX_free>::SslNoRc;

    /**
     * @brief Compute HMAC in a single operation
     * @tparam Traits HMAC traits defining the hash algorithm
     * @param key Secret key for HMAC
     * @param data Data to authenticate
     * @return HMAC result (size determined by traits)
     * @throws SslException on failure
     */
    template <typename Traits = DefaultTraits>
    static std::array<std::uint8_t, Traits::output_size>
    Hmac(std::span<const std::uint8_t> key,
         std::span<const std::uint8_t> data);

    /**
     * @brief Constant-time comparison for HMAC verification
     * @param computed Computed HMAC value
     * @param expected Expected HMAC value
     * @return true if equal, false otherwise (timing-safe)
     */
    static bool ConstantTimeCompare(std::span<const std::uint8_t> computed,
                                    std::span<const std::uint8_t> expected);

    // ============================================================================================
    // Instance methods for incremental HMAC computation (streaming)
    // ============================================================================================

    /**
     * @brief Initialize context for HMAC computation
     * @tparam Traits HMAC traits defining the hash algorithm
     * @param key Secret key for HMAC
     * @throws SslException on failure
     * @note Call this once, then use Update() multiple times, then Final()
     */
    template <typename Traits = DefaultTraits>
    void Init(std::span<const std::uint8_t> key);

    /**
     * @brief Update HMAC with additional data (streaming)
     * @param data Data chunk to add to HMAC computation
     * @throws SslException on failure
     * @note Can be called multiple times after Init()
     */
    void Update(std::span<const std::uint8_t> data);

    /**
     * @brief Finalize HMAC computation and get result
     * @tparam Traits HMAC traits defining the hash algorithm
     * @return HMAC result (size determined by traits)
     * @throws SslException on failure
     * @note Must call Init() and optionally Update() before this
     */
    template <typename Traits = DefaultTraits>
    std::array<std::uint8_t, Traits::output_size> Final();
};

// ================================================================================================
//  Implementation - Static methods
// ================================================================================================

template <typename DefaultTraits>
template <typename Traits>
inline std::array<std::uint8_t, Traits::output_size>
SslHmacCtx<DefaultTraits>::Hmac(std::span<const std::uint8_t> key,
                                std::span<const std::uint8_t> data)
{
    std::array<std::uint8_t, Traits::output_size> result;
    size_t out_len = result.size();

    if (EVP_Q_mac(nullptr,
                  "HMAC",
                  nullptr,
                  Traits::digest_name,
                  nullptr,
                  key.data(),
                  key.size(),
                  data.data(),
                  data.size(),
                  result.data(),
                  result.size(),
                  &out_len)
        == nullptr)
    {
        throw SslException("Hmac: EVP_Q_mac computation failed");
    }

    if (out_len != Traits::output_size)
        throw SslException("Hmac: Unexpected output length");

    return result;
}

template <typename DefaultTraits>
inline bool SslHmacCtx<DefaultTraits>::ConstantTimeCompare(std::span<const std::uint8_t> computed,
                                                           std::span<const std::uint8_t> expected)
{
    if (computed.size() != expected.size())
        return false;

    return CRYPTO_memcmp(computed.data(), expected.data(), computed.size()) == 0;
}

// ================================================================================================
//  Implementation - Instance methods (streaming/incremental)
// ================================================================================================

template <typename DefaultTraits>
template <typename Traits>
inline void SslHmacCtx<DefaultTraits>::Init(std::span<const std::uint8_t> key)
{
    EVP_MAC *mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (!mac)
        throw SslException("Init: EVP_MAC_fetch failed");

    // Reset context to use the fetched MAC
    this->Reset(EVP_MAC_CTX_new(mac));
    EVP_MAC_free(mac);

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", const_cast<char *>(Traits::digest_name), 0),
        OSSL_PARAM_construct_end()};

    if (EVP_MAC_init(*this, key.data(), key.size(), params) != 1)
        throw SslException("Init: EVP_MAC_init failed");
}

template <typename DefaultTraits>
inline void SslHmacCtx<DefaultTraits>::Update(std::span<const std::uint8_t> data)
{
    if (EVP_MAC_update(*this, data.data(), data.size()) != 1)
        throw SslException("Update: EVP_MAC_update failed");
}

template <typename DefaultTraits>
template <typename Traits>
inline std::array<std::uint8_t, Traits::output_size> SslHmacCtx<DefaultTraits>::Final()
{
    std::array<std::uint8_t, Traits::output_size> result;
    size_t out_len = 0;

    if (EVP_MAC_final(*this, result.data(), &out_len, result.size()) != 1)
        throw SslException("Final: EVP_MAC_final failed");

    if (out_len != Traits::output_size)
        throw SslException("Final: Unexpected output length");

    return result;
}

// ================================================================================================
// Free functions for convenience
// ================================================================================================

/**
 * @brief Compute HMAC-SHA256 in a single operation (free function)
 * @param key Secret key for HMAC
 * @param data Data to authenticate
 * @return 32-byte HMAC-SHA256 result
 * @throws SslException on failure
 */
inline std::array<std::uint8_t, 32>
HmacSha256(std::span<const std::uint8_t> key,
           std::span<const std::uint8_t> data)
{
    return SslHmacCtx<HmacSha256Traits>::Hmac(key, data);
}

/**
 * @brief Compute HMAC-SHA512 in a single operation (free function)
 * @param key Secret key for HMAC
 * @param data Data to authenticate
 * @return 64-byte HMAC-SHA512 result
 * @throws SslException on failure
 */
inline std::array<std::uint8_t, 64>
HmacSha512(std::span<const std::uint8_t> key,
           std::span<const std::uint8_t> data)
{
    return SslHmacCtx<HmacSha512Traits>::Hmac(key, data);
}

/**
 * @brief Compute HMAC-MD5 in a single operation (free function)
 * @param key Secret key for HMAC
 * @param data Data to authenticate
 * @return 16-byte HMAC-MD5 result
 * @throws SslException on failure
 */
inline std::array<std::uint8_t, 16>
HmacMd5(std::span<const std::uint8_t> key,
        std::span<const std::uint8_t> data)
{
    return SslHmacCtx<HmacMd5Traits>::Hmac(key, data);
}

/**
 * @brief Compute HMAC-SHA1 in a single operation (free function)
 * @param key Secret key for HMAC
 * @param data Data to authenticate
 * @return 20-byte HMAC-SHA1 result
 * @throws SslException on failure
 */
inline std::array<std::uint8_t, 20>
HmacSha1(std::span<const std::uint8_t> key,
         std::span<const std::uint8_t> data)
{
    return SslHmacCtx<HmacSha1Traits>::Hmac(key, data);
}

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_SSL_HMAC_H
