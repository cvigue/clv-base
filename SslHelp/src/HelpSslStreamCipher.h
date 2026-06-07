// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_SSLHELP_SSL_STREAM_CIPHER_H
#define CLV_SSLHELP_SSL_STREAM_CIPHER_H

#include "HelpSslException.h"
#include "HelpSslNoRc.h"

#include <cstddef>
#include <cstdint>
#include <openssl/evp.h>
#include <openssl/types.h>
#include <span>
#include <string>
#include <vector>

namespace clv::OpenSSL {

// ================================================================================================
//  Stream / Non-AEAD Cipher Traits
// ================================================================================================

/**
 * @brief Cipher traits for non-AEAD symmetric ciphers (CTR, CFB, OFB, CBC)
 * @details Unlike AeadCipherTraits, these ciphers produce no authentication tag.
 *          Authentication (if needed) must be handled separately (e.g., via HMAC).
 */
struct StreamCipherTraits
{
    const EVP_CIPHER *(*cipher_fn)(); ///< Function returning the EVP_CIPHER for this algorithm
    const char *name;                 ///< Human-readable cipher name for error messages
    std::size_t key_size;             ///< Expected key size in bytes
    std::size_t iv_size;              ///< Expected IV size in bytes (0 if none)
    bool uses_padding;                ///< Whether PKCS#7 padding applies (false for CTR/CFB/OFB)
};

// ----- Pre-defined stream cipher traits -----

/**
 * @brief Traits for AES-256-CTR
 */
constexpr StreamCipherTraits AES_256_CTR_TRAITS{
    EVP_aes_256_ctr,
    "AES-256-CTR",
    32,    // 256-bit key
    16,    // 128-bit IV
    false, // CTR mode: no padding
};

/**
 * @brief Traits for AES-128-CTR
 */
constexpr StreamCipherTraits AES_128_CTR_TRAITS{
    EVP_aes_128_ctr,
    "AES-128-CTR",
    16,    // 128-bit key
    16,    // 128-bit IV
    false, // CTR mode: no padding
};

/**
 * @brief Traits for AES-256-CBC
 */
constexpr StreamCipherTraits AES_256_CBC_TRAITS{
    EVP_aes_256_cbc,
    "AES-256-CBC",
    32,   // 256-bit key
    16,   // 128-bit IV
    true, // CBC mode: PKCS#7 padding by default
};

/**
 * @brief Traits for AES-128-CBC
 */
constexpr StreamCipherTraits AES_128_CBC_TRAITS{
    EVP_aes_128_cbc,
    "AES-128-CBC",
    16,   // 128-bit key
    16,   // 128-bit IV
    true, // CBC mode: PKCS#7 padding by default
};

/**
 * @brief Traits for AES-256-CFB
 */
constexpr StreamCipherTraits AES_256_CFB_TRAITS{
    EVP_aes_256_cfb128,
    "AES-256-CFB",
    32,    // 256-bit key
    16,    // 128-bit IV
    false, // CFB: no padding
};

/**
 * @brief Traits for AES-256-OFB
 */
constexpr StreamCipherTraits AES_256_OFB_TRAITS{
    EVP_aes_256_ofb,
    "AES-256-OFB",
    32,    // 256-bit key
    16,    // 128-bit IV
    false, // OFB: no padding
};

// ================================================================================================
//  SslStreamCipherCtx — RAII wrapper for non-AEAD symmetric ciphers
// ================================================================================================

/**
 * @brief RAII wrapper for OpenSSL EVP_CIPHER_CTX with non-AEAD symmetric cipher operations
 * @tparam DefaultTraits Default cipher algorithm for this context (can be overridden per method)
 * @details Provides a safe wrapper around EVP_CIPHER_CTX for stream and block ciphers that
 *          do NOT produce an authentication tag (CTR, CFB, OFB, CBC). Authentication must be
 *          handled separately (e.g., via SslHmacCtx) when using these ciphers.
 *
 * Usage (one-shot):
 * @code
 *   auto ct = Encrypt<AES_256_CTR_TRAITS>(key, iv, plaintext);
 *   auto pt = Decrypt<AES_256_CTR_TRAITS>(key, iv, ct);
 * @endcode
 *
 * Usage (streaming):
 * @code
 *   SslStreamCipherCtx<AES_256_CTR_TRAITS> ctx;
 *   ctx.InitEncrypt(key, iv);
 *   auto chunk1 = ctx.UpdateEncrypt(data1);
 *   auto chunk2 = ctx.UpdateEncrypt(data2);
 *   auto final  = ctx.FinalizeEncrypt();
 * @endcode
 *
 * @see SslNoRc, SslCipherCtx (for AEAD ciphers)
 */
template <const StreamCipherTraits &DefaultTraits>
struct SslStreamCipherCtx : SslNoRc<EVP_CIPHER_CTX, EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_free>
{
    using SslNoRc<EVP_CIPHER_CTX, EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_free>::SslNoRc;

    // ========================================================================================
    //  Streaming API
    // ========================================================================================

    /**
     * @brief Initialize cipher for encryption with key and IV
     * @tparam Traits Cipher traits specifying the algorithm (defaults to DefaultTraits)
     * @param key Encryption key (must match Traits::key_size)
     * @param iv Initialization vector (must match Traits::iv_size)
     * @throws SslException on failure
     */
    template <const StreamCipherTraits &Traits = DefaultTraits>
    void InitEncrypt(std::span<const std::uint8_t> key,
                     std::span<const std::uint8_t> iv);

    /**
     * @brief Initialize cipher for decryption with key and IV
     * @tparam Traits Cipher traits specifying the algorithm (defaults to DefaultTraits)
     * @param key Decryption key (must match Traits::key_size)
     * @param iv Initialization vector (must match Traits::iv_size)
     * @throws SslException on failure
     */
    template <const StreamCipherTraits &Traits = DefaultTraits>
    void InitDecrypt(std::span<const std::uint8_t> key,
                     std::span<const std::uint8_t> iv);

    /**
     * @brief Encrypt a chunk of plaintext
     * @tparam Traits Cipher traits (defaults to DefaultTraits)
     * @param plaintext Data to encrypt
     * @return Ciphertext chunk
     * @throws SslException on failure
     * @note Call after InitEncrypt. Can be called multiple times for streaming.
     */
    template <const StreamCipherTraits &Traits = DefaultTraits>
    std::vector<std::uint8_t> UpdateEncrypt(std::span<const std::uint8_t> plaintext);

    /**
     * @brief Decrypt a chunk of ciphertext
     * @tparam Traits Cipher traits (defaults to DefaultTraits)
     * @param ciphertext Data to decrypt
     * @return Plaintext chunk
     * @throws SslException on failure
     * @note Call after InitDecrypt. Can be called multiple times for streaming.
     */
    template <const StreamCipherTraits &Traits = DefaultTraits>
    std::vector<std::uint8_t> UpdateDecrypt(std::span<const std::uint8_t> ciphertext);

    /**
     * @brief Finalize encryption and flush any remaining bytes
     * @tparam Traits Cipher traits (defaults to DefaultTraits)
     * @return Final ciphertext bytes (may be empty for stream ciphers like CTR)
     * @throws SslException on failure
     */
    template <const StreamCipherTraits &Traits = DefaultTraits>
    std::vector<std::uint8_t> FinalizeEncrypt();

    /**
     * @brief Finalize decryption and flush any remaining bytes
     * @tparam Traits Cipher traits (defaults to DefaultTraits)
     * @return Final plaintext bytes (may be empty for stream ciphers like CTR)
     * @throws SslException on failure
     */
    template <const StreamCipherTraits &Traits = DefaultTraits>
    std::vector<std::uint8_t> FinalizeDecrypt();

    // ========================================================================================
    //  One-shot API (convenience)
    // ========================================================================================

    /**
     * @brief One-shot encryption
     * @tparam Traits Cipher traits (defaults to DefaultTraits)
     * @param key Encryption key
     * @param iv Initialization vector
     * @param plaintext Data to encrypt
     * @return Ciphertext
     * @throws SslException on failure
     */
    template <const StreamCipherTraits &Traits = DefaultTraits>
    std::vector<std::uint8_t> Encrypt(std::span<const std::uint8_t> key,
                                      std::span<const std::uint8_t> iv,
                                      std::span<const std::uint8_t> plaintext);

    /**
     * @brief One-shot decryption
     * @tparam Traits Cipher traits (defaults to DefaultTraits)
     * @param key Decryption key
     * @param iv Initialization vector
     * @param ciphertext Data to decrypt
     * @return Plaintext
     * @throws SslException on failure
     */
    template <const StreamCipherTraits &Traits = DefaultTraits>
    std::vector<std::uint8_t> Decrypt(std::span<const std::uint8_t> key,
                                      std::span<const std::uint8_t> iv,
                                      std::span<const std::uint8_t> ciphertext);
};

// ================================================================================================
//  Free Function Operations (one-shot convenience)
// ================================================================================================

/**
 * @brief One-shot stream cipher encryption (creates its own context)
 * @tparam Traits Cipher traits specifying the algorithm
 * @param key Encryption key
 * @param iv Initialization vector
 * @param plaintext Data to encrypt
 * @return Ciphertext
 * @throws SslException on failure
 * @note Example: Encrypt<AES_256_CTR_TRAITS>(key, iv, plaintext)
 */
template <const StreamCipherTraits &Traits>
std::vector<std::uint8_t>
Encrypt(std::span<const std::uint8_t> key,
        std::span<const std::uint8_t> iv,
        std::span<const std::uint8_t> plaintext);

/**
 * @brief One-shot stream cipher decryption (creates its own context)
 * @tparam Traits Cipher traits specifying the algorithm
 * @param key Decryption key
 * @param iv Initialization vector
 * @param ciphertext Data to decrypt
 * @return Plaintext
 * @throws SslException on failure
 * @note Example: Decrypt<AES_256_CTR_TRAITS>(key, iv, ciphertext)
 */
template <const StreamCipherTraits &Traits>
std::vector<std::uint8_t>
Decrypt(std::span<const std::uint8_t> key,
        std::span<const std::uint8_t> iv,
        std::span<const std::uint8_t> ciphertext);

// ================================================================================================
//  SslStreamCipherCtx member method implementations
// ================================================================================================

template <const StreamCipherTraits &DefaultTraits>
template <const StreamCipherTraits &Traits>
inline void SslStreamCipherCtx<DefaultTraits>::InitEncrypt(std::span<const std::uint8_t> key,
                                                           std::span<const std::uint8_t> iv)
{
    if (EVP_EncryptInit_ex(*this, Traits.cipher_fn(), nullptr, key.data(), iv.data()) != 1)
        throw SslException(std::string(Traits.name) + " encrypt init failed");

    if (!Traits.uses_padding)
        EVP_CIPHER_CTX_set_padding(*this, 0);
}

template <const StreamCipherTraits &DefaultTraits>
template <const StreamCipherTraits &Traits>
inline void SslStreamCipherCtx<DefaultTraits>::InitDecrypt(std::span<const std::uint8_t> key,
                                                           std::span<const std::uint8_t> iv)
{
    if (EVP_DecryptInit_ex(*this, Traits.cipher_fn(), nullptr, key.data(), iv.data()) != 1)
        throw SslException(std::string(Traits.name) + " decrypt init failed");

    if (!Traits.uses_padding)
        EVP_CIPHER_CTX_set_padding(*this, 0);
}

template <const StreamCipherTraits &DefaultTraits>
template <const StreamCipherTraits &Traits>
inline std::vector<std::uint8_t>
SslStreamCipherCtx<DefaultTraits>::UpdateEncrypt(std::span<const std::uint8_t> plaintext)
{
    if (plaintext.empty())
        return {};

    // For block ciphers with padding, output can be up to plaintext.size() + block_size
    std::vector<std::uint8_t> ciphertext(plaintext.size() + EVP_CIPHER_CTX_block_size(*this));
    int outlen = 0;

    if (EVP_EncryptUpdate(*this, ciphertext.data(), &outlen, plaintext.data(), static_cast<int>(plaintext.size())) != 1)
        throw SslException(std::string(Traits.name) + " encryption failed");

    ciphertext.resize(static_cast<std::size_t>(outlen));
    return ciphertext;
}

template <const StreamCipherTraits &DefaultTraits>
template <const StreamCipherTraits &Traits>
inline std::vector<std::uint8_t>
SslStreamCipherCtx<DefaultTraits>::UpdateDecrypt(std::span<const std::uint8_t> ciphertext)
{
    if (ciphertext.empty())
        return {};

    // For block ciphers with padding, output can be up to ciphertext.size() + block_size
    std::vector<std::uint8_t> plaintext(ciphertext.size() + EVP_CIPHER_CTX_block_size(*this));
    int outlen = 0;

    if (EVP_DecryptUpdate(*this, plaintext.data(), &outlen, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1)
        throw SslException(std::string(Traits.name) + " decryption failed");

    plaintext.resize(static_cast<std::size_t>(outlen));
    return plaintext;
}

template <const StreamCipherTraits &DefaultTraits>
template <const StreamCipherTraits &Traits>
inline std::vector<std::uint8_t>
SslStreamCipherCtx<DefaultTraits>::FinalizeEncrypt()
{
    // block_size bytes is the maximum Final can produce
    std::vector<std::uint8_t> final_data(EVP_CIPHER_CTX_block_size(*this));
    int outlen = 0;

    if (EVP_EncryptFinal_ex(*this, final_data.data(), &outlen) != 1)
        throw SslException(std::string(Traits.name) + " encrypt finalization failed");

    final_data.resize(static_cast<std::size_t>(outlen));
    return final_data;
}

template <const StreamCipherTraits &DefaultTraits>
template <const StreamCipherTraits &Traits>
inline std::vector<std::uint8_t>
SslStreamCipherCtx<DefaultTraits>::FinalizeDecrypt()
{
    std::vector<std::uint8_t> final_data(EVP_CIPHER_CTX_block_size(*this));
    int outlen = 0;

    if (EVP_DecryptFinal_ex(*this, final_data.data(), &outlen) != 1)
        throw SslException(std::string(Traits.name) + " decrypt finalization failed");

    final_data.resize(static_cast<std::size_t>(outlen));
    return final_data;
}

// One-shot member methods

template <const StreamCipherTraits &DefaultTraits>
template <const StreamCipherTraits &Traits>
inline std::vector<std::uint8_t>
SslStreamCipherCtx<DefaultTraits>::Encrypt(std::span<const std::uint8_t> key,
                                           std::span<const std::uint8_t> iv,
                                           std::span<const std::uint8_t> plaintext)
{
    InitEncrypt<Traits>(key, iv);
    auto ciphertext = UpdateEncrypt<Traits>(plaintext);
    auto final_bytes = FinalizeEncrypt<Traits>();
    ciphertext.insert(ciphertext.end(), final_bytes.begin(), final_bytes.end());
    return ciphertext;
}

template <const StreamCipherTraits &DefaultTraits>
template <const StreamCipherTraits &Traits>
inline std::vector<std::uint8_t>
SslStreamCipherCtx<DefaultTraits>::Decrypt(std::span<const std::uint8_t> key,
                                           std::span<const std::uint8_t> iv,
                                           std::span<const std::uint8_t> ciphertext)
{
    InitDecrypt<Traits>(key, iv);
    auto plaintext = UpdateDecrypt<Traits>(ciphertext);
    auto final_bytes = FinalizeDecrypt<Traits>();
    plaintext.insert(plaintext.end(), final_bytes.begin(), final_bytes.end());
    return plaintext;
}

// ================================================================================================
//  Free function implementations
// ================================================================================================

template <const StreamCipherTraits &Traits>
inline std::vector<std::uint8_t>
Encrypt(std::span<const std::uint8_t> key,
        std::span<const std::uint8_t> iv,
        std::span<const std::uint8_t> plaintext)
{
    SslStreamCipherCtx<Traits> ctx;
    return ctx.Encrypt(key, iv, plaintext);
}

template <const StreamCipherTraits &Traits>
inline std::vector<std::uint8_t>
Decrypt(std::span<const std::uint8_t> key,
        std::span<const std::uint8_t> iv,
        std::span<const std::uint8_t> ciphertext)
{
    SslStreamCipherCtx<Traits> ctx;
    return ctx.Decrypt(key, iv, ciphertext);
}

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_SSL_STREAM_CIPHER_H
