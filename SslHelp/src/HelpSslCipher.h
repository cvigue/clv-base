// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_SSLHELP_SSL_CIPHER_H
#define CLV_SSLHELP_SSL_CIPHER_H

#include "HelpSslException.h"
#include "HelpSslNoRc.h"
#include "HelpSslNoRcCopy.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <openssl/types.h>
#include <span>
#include <string>
#include <vector>
#include <cstdint>
#include <openssl/evp.h>

namespace clv::OpenSSL {

// ================================================================================================
//  AEAD Constants
// ================================================================================================

/**
 * @brief Standard AEAD authentication tag length (128 bits)
 */
constexpr std::size_t AEAD_TAG_LENGTH = 16;

/**
 * @brief Standard AEAD nonce/IV length for GCM and ChaCha20-Poly1305 (96 bits)
 */
constexpr std::size_t AEAD_DEFAULT_NONCE_LENGTH = 12;

// ================================================================================================
//  Forward Declarations
// ================================================================================================

struct AeadCipherTraits;

/**
 * @brief RAII wrapper for OpenSSL EVP_CIPHER_CTX with AEAD cipher operations
 * @details Provides a safe wrapper around EVP_CIPHER_CTX for authenticated encryption
 *          with associated data (AEAD). Supports AES-GCM and ChaCha20-Poly1305.
 *          Cipher algorithm is selected at runtime via AeadCipherTraits passed to
 *          initialization methods.
 * @see \c SslNoRcCopy
 */
struct SslCipherCtx : SslNoRcCopy<SslCipherCtx, EVP_CIPHER_CTX,
                                  EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_free,
                                  SslCopyCloner<EVP_CIPHER_CTX, EVP_CIPHER_CTX_new,
                                                EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_copy>>
{
    using SslNoRcCopy::SslNoRcCopy;
    // Clone() inherited from SslNoRcCopy — returns SslCipherCtx

    // ========================================================================================
    // Low-level cipher context operations
    // ========================================================================================

    /**
     * @brief Initialize cipher context for encryption
     * @param traits Cipher traits specifying the algorithm
     * @param engine Optional ENGINE to use (nullptr for default)
     * @param key Optional key to set immediately (nullptr to set later)
     * @param iv Optional IV to set immediately (nullptr to set later)
     * @throws SslException on failure
     * @note This only initializes the cipher, does not set IV length for AEAD ciphers.
     * @note For AEAD ciphers, call SetIvLength() after this.
     */
    void InitEncrypt(const AeadCipherTraits &traits,
                     ENGINE *engine = nullptr,
                     const unsigned char *key = nullptr,
                     const unsigned char *iv = nullptr);

    /**
     * @brief Initialize cipher context for decryption
     * @param traits Cipher traits specifying the algorithm
     * @param engine Optional ENGINE to use (nullptr for default)
     * @param key Optional key to set immediately (nullptr to set later)
     * @param iv Optional IV to set immediately (nullptr to set later)
     * @throws SslException on failure
     * @note This only initializes the cipher, does not set IV length for AEAD ciphers.
     * @note For AEAD ciphers, call SetIvLength() after this.
     */
    void InitDecrypt(const AeadCipherTraits &traits,
                     ENGINE *engine = nullptr,
                     const unsigned char *key = nullptr,
                     const unsigned char *iv = nullptr);

    /**
     * @brief Set IV length for AEAD cipher
     * @param ivLen Length of IV in bytes
     * @throws SslException on failure
     * @note Call after InitEncrypt or InitDecrypt for AEAD ciphers.
     * @note Not needed for ECB mode (no IV).
     */
    void SetIvLength(int ivLen);

    // ========================================================================================
    // High-level AEAD methods
    // ========================================================================================

    /**
     * @brief Initialize AEAD cipher for encryption (convenience wrapper)
     * @param traits Cipher traits specifying the algorithm
     * @throws SslException on failure
     * @note Calls InitEncrypt() then SetIvLength(12).
     */
    void InitAeadEncrypt(const AeadCipherTraits &traits);

    /**
     * @brief Initialize AEAD cipher for decryption (convenience wrapper)
     * @param traits Cipher traits specifying the algorithm
     * @throws SslException on failure
     * @note Calls InitDecrypt() then SetIvLength(12).
     */
    void InitAeadDecrypt(const AeadCipherTraits &traits);

    /**
     * @brief Set key and nonce for encryption (streaming API)
     * @param key Encryption key
     * @param nonce Nonce/IV (must be unique per message for encryption)
     * @throws SslException on failure
     * @note Call after InitAeadEncrypt.
     * @note Must be called before UpdateEncryptAad or UpdateEncrypt.
     */
    void SetEncryptKeyAndNonce(std::span<const std::uint8_t> key,
                               std::span<const std::uint8_t> nonce);

    /**
     * @brief Set key and nonce for decryption (streaming API)
     * @param key Decryption key
     * @param nonce Nonce/IV
     * @throws SslException on failure
     * @note Call after InitAeadDecrypt.
     * @note Must be called before UpdateDecryptAad or UpdateDecrypt.
     */
    void SetDecryptKeyAndNonce(std::span<const std::uint8_t> key,
                               std::span<const std::uint8_t> nonce);

    /**
     * @brief Update only the nonce for an already-keyed encryption context
     * @param nonce New nonce/IV for the next message
     * @throws SslException on failure
     * @note Call on a persistent context after an initial SetEncryptKeyAndNonce.
     *       Reuses the cached key schedule (~10-20ns vs ~100-150ns for full key
     *       setup), eliminating the dominant per-packet overhead.
     */
    void SetEncryptNonce(std::span<const std::uint8_t> nonce);

    /**
     * @brief Update only the nonce for an already-keyed decryption context
     * @param nonce New nonce/IV for the next message
     * @throws SslException on failure
     * @note Call on a persistent context after an initial SetDecryptKeyAndNonce.
     *       Reuses the cached key schedule.
     */
    void SetDecryptNonce(std::span<const std::uint8_t> nonce);

    /**
     * @brief Add additional authenticated data for encryption (streaming API)
     * @param aad Additional authenticated data
     * @throws SslException on failure
     * @note Call after SetEncryptKeyAndNonce, before UpdateEncrypt.
     * @note Can be called multiple times to add AAD in chunks.
     * @note All AAD must be added before any plaintext processing.
     */
    void UpdateEncryptAad(std::span<const std::uint8_t> aad);

    /**
     * @brief Add additional authenticated data for decryption (streaming API)
     * @param aad Additional authenticated data
     * @throws SslException on failure
     * @note Call after SetDecryptKeyAndNonce, before UpdateDecrypt.
     * @note Can be called multiple times to add AAD in chunks.
     * @note All AAD must be added before any ciphertext processing.
     */
    void UpdateDecryptAad(std::span<const std::uint8_t> aad);

    /**
     * @brief Encrypt a chunk of plaintext (streaming API)
     * @param plaintext Plaintext chunk to encrypt
     * @return Ciphertext chunk
     * @throws SslException on failure
     * @note Call after SetEncryptKeyAndNonce (and optional UpdateEncryptAad calls).
     * @note Can be called multiple times for streaming encryption.
     */
    std::vector<std::uint8_t>
    UpdateEncrypt(std::span<const std::uint8_t> plaintext);

    /**
     * @brief Encrypt data in-place (streaming API, zero-copy)
     * @param data Buffer to encrypt in-place (ciphertext overwrites plaintext)
     * @throws SslException on failure
     * @note OpenSSL GCM/ChaCha20 support overlapping in/out buffers.
     * @note Call after SetEncryptKeyAndNonce (and optional UpdateEncryptAad calls).
     */
    void UpdateEncryptInPlace(std::span<std::uint8_t> data);

    /**
     * @brief Finalize encryption and extract authentication tag (streaming API)
     * @return Final ciphertext bytes (if any) followed by 16-byte authentication tag
     * @throws SslException on failure
     * @note Call after all UpdateEncrypt calls to get the authentication tag.
     */
    std::vector<std::uint8_t> FinalizeEncrypt();

    /**
     * @brief Finalize encryption and return only the authentication tag (zero-copy)
     * @return 16-byte authentication tag
     * @throws SslException on failure
     * @note Call after UpdateEncryptInPlace. Returns tag without heap allocation.
     */
    std::array<std::uint8_t, AEAD_TAG_LENGTH> FinalizeEncryptTag();

    /**
     * @brief Decrypt a chunk of ciphertext (streaming API)
     * @param ciphertext Ciphertext chunk to decrypt (without tag)
     * @return Plaintext chunk
     * @throws SslException on failure
     * @note Call after SetDecryptKeyAndNonce (and optional UpdateDecryptAad calls).
     * @note Can be called multiple times for streaming decryption.
     * @note Do not include the tag in ciphertext chunks.
     */
    std::vector<std::uint8_t>
    UpdateDecrypt(std::span<const std::uint8_t> ciphertext);

    /**
     * @brief Decrypt data in-place (streaming API, zero-copy)
     * @param data Buffer to decrypt in-place (plaintext overwrites ciphertext)
     * @throws SslException on failure
     * @note OpenSSL GCM/ChaCha20 support overlapping in/out buffers.
     * @note Call after SetDecryptKeyAndNonce (and optional UpdateDecryptAad calls).
     * @note Do not include the tag in the data buffer.
     */
    void UpdateDecryptInPlace(std::span<std::uint8_t> data);

    /**
     * @brief Finalize decryption and verify authentication tag (streaming API)
     * @param tag Authentication tag to verify (AEAD_TAG_LENGTH bytes)
     * @return Final plaintext bytes (if any)
     * @throws SslException on authentication failure or other errors
     * @note Call after all UpdateDecrypt calls with the authentication tag.
     */
    std::vector<std::uint8_t>
    FinalizeDecrypt(std::span<const std::uint8_t, AEAD_TAG_LENGTH> tag);

    /**
     * @brief Finalize decryption and verify authentication tag (zero-copy)
     * @param tag Authentication tag to verify (AEAD_TAG_LENGTH bytes)
     * @return true if tag verification succeeded, false on authentication failure
     * @note Call after UpdateDecryptInPlace. No heap allocation.
     * @note Unlike FinalizeDecrypt, returns false instead of throwing on tag mismatch.
     */
    bool FinalizeDecryptCheck(std::span<const std::uint8_t, AEAD_TAG_LENGTH> tag);

    // ========================================================================================
    // One-shot AEAD methods (convenience wrappers that reinitialize the context)
    // ========================================================================================

    /**
     * @brief One-shot AEAD encryption using this context
     * @param traits Cipher traits specifying the algorithm
     * @param key Encryption key (length depends on cipher)
     * @param nonce 12-byte nonce/IV (must be unique per message)
     * @param plaintext Data to encrypt
     * @param aad Additional authenticated data
     * @return Ciphertext with 16-byte authentication tag appended
     * @throws SslException on failure
     */
    std::vector<std::uint8_t>
    EncryptAead(const AeadCipherTraits &traits,
                std::span<const std::uint8_t> key,
                std::span<const std::uint8_t> nonce,
                std::span<const std::uint8_t> plaintext,
                std::span<const std::uint8_t> aad);

    /**
     * @brief One-shot AEAD decryption using this context
     * @param traits Cipher traits specifying the algorithm
     * @param key Decryption key (length depends on cipher)
     * @param nonce 12-byte nonce/IV
     * @param ciphertext Data to decrypt (includes 16-byte tag)
     * @param aad Additional authenticated data (must match encryption)
     * @return Plaintext data
     * @throws SslException on authentication failure or decryption error
     */
    std::vector<std::uint8_t>
    DecryptAead(const AeadCipherTraits &traits,
                std::span<const std::uint8_t> key,
                std::span<const std::uint8_t> nonce,
                std::span<const std::uint8_t> ciphertext,
                std::span<const std::uint8_t> aad);

    /**
     * @brief Encrypt data in-place with AEAD, returning only the tag
     * @param traits Cipher traits specifying the algorithm
     * @param key Encryption key
     * @param nonce 12-byte nonce/IV (must be unique per message)
     * @param data Data buffer to encrypt in-place (ciphertext overwrites plaintext)
     * @param aad Additional authenticated data
     * @return 16-byte authentication tag
     * @throws SslException on failure
     * @note Zero heap allocations. Caller manages the buffer.
     */
    std::array<std::uint8_t, AEAD_TAG_LENGTH>
    EncryptAeadInPlace(const AeadCipherTraits &traits,
                       std::span<const std::uint8_t> key,
                       std::span<const std::uint8_t> nonce,
                       std::span<std::uint8_t> data,
                       std::span<const std::uint8_t> aad);

    /**
     * @brief Decrypt data in-place with AEAD, verifying the tag
     * @param traits Cipher traits specifying the algorithm
     * @param key Decryption key
     * @param nonce 12-byte nonce/IV
     * @param data Data buffer to decrypt in-place (plaintext overwrites ciphertext)
     * @param tag 16-byte authentication tag to verify
     * @param aad Additional authenticated data (must match encryption)
     * @return true if decryption and tag verification succeeded
     * @note Zero heap allocations. Returns false instead of throwing on tag mismatch.
     */
    bool DecryptAeadInPlace(const AeadCipherTraits &traits,
                            std::span<const std::uint8_t> key,
                            std::span<const std::uint8_t> nonce,
                            std::span<std::uint8_t> data,
                            std::span<const std::uint8_t, AEAD_TAG_LENGTH> tag,
                            std::span<const std::uint8_t> aad);

  private:
    /// Query the cipher name from the initialized OpenSSL context (for error messages)
    const char *CipherName() const;
};

// ================================================================================================
//  Free Function AEAD Operations (one-shot convenience)
// ================================================================================================

/**
 * @brief One-shot AEAD encryption
 * @param traits Cipher traits specifying the algorithm (AES_128_GCM_TRAITS, etc.)
 * @param key Encryption key (length depends on cipher)
 * @param nonce 12-byte nonce/IV
 * @param plaintext Data to encrypt
 * @param aad Additional authenticated data
 * @return Ciphertext with 16-byte authentication tag appended
 * @throws SslException on failure
 * @note Example: EncryptAead(AES_256_GCM_TRAITS, key32, nonce, plaintext, aad)
 */
std::vector<std::uint8_t>
EncryptAead(const AeadCipherTraits &traits,
            std::span<const std::uint8_t> key,
            std::span<const std::uint8_t> nonce,
            std::span<const std::uint8_t> plaintext,
            std::span<const std::uint8_t> aad);

/**
 * @brief One-shot AEAD decryption
 * @param traits Cipher traits specifying the algorithm (AES_128_GCM_TRAITS, etc.)
 * @param key Decryption key (length depends on cipher)
 * @param nonce 12-byte nonce/IV
 * @param ciphertext Data to decrypt (includes 16-byte tag)
 * @param aad Additional authenticated data (must match encryption)
 * @return Plaintext data
 * @throws SslException on authentication failure or decryption error
 * @note Example: DecryptAead(AES_256_GCM_TRAITS, key32, nonce, ciphertext, aad)
 */
std::vector<std::uint8_t>
DecryptAead(const AeadCipherTraits &traits,
            std::span<const std::uint8_t> key,
            std::span<const std::uint8_t> nonce,
            std::span<const std::uint8_t> ciphertext,
            std::span<const std::uint8_t> aad);

/**
 * @brief One-shot in-place AEAD encryption (zero-copy)
 * @param traits Cipher traits specifying the algorithm (AES_128_GCM_TRAITS, etc.)
 * @param key Encryption key
 * @param nonce 12-byte nonce/IV (must be unique per message)
 * @param data Data buffer to encrypt in-place
 * @param aad Additional authenticated data
 * @return 16-byte authentication tag
 * @throws SslException on failure
 */
std::array<std::uint8_t, AEAD_TAG_LENGTH>
EncryptAeadInPlace(const AeadCipherTraits &traits,
                   std::span<const std::uint8_t> key,
                   std::span<const std::uint8_t> nonce,
                   std::span<std::uint8_t> data,
                   std::span<const std::uint8_t> aad);

/**
 * @brief One-shot in-place AEAD decryption (zero-copy)
 * @param traits Cipher traits specifying the algorithm (AES_128_GCM_TRAITS, etc.)
 * @param key Decryption key
 * @param nonce 12-byte nonce/IV
 * @param data Data buffer to decrypt in-place
 * @param tag 16-byte authentication tag to verify
 * @param aad Additional authenticated data (must match encryption)
 * @return true if decryption and tag verification succeeded
 */
bool DecryptAeadInPlace(const AeadCipherTraits &traits,
                        std::span<const std::uint8_t> key,
                        std::span<const std::uint8_t> nonce,
                        std::span<std::uint8_t> data,
                        std::span<const std::uint8_t, AEAD_TAG_LENGTH> tag,
                        std::span<const std::uint8_t> aad);

/**
 * @brief One-shot ECB encryption (single block)
 * @param traits Cipher traits specifying the algorithm (AES_128_ECB_TRAITS, AES_256_ECB_TRAITS)
 * @param key Encryption key (length depends on cipher: 16 bytes for AES-128, 32 for AES-256)
 * @param block 16-byte input block
 * @return 16-byte encrypted output
 * @throws SslException on failure
 * @note Example: EncryptEcb(AES_128_ECB_TRAITS, key, block)
 * @note ECB mode is typically used for header protection in protocols like QUIC
 */
std::array<std::uint8_t, 16>
EncryptEcb(const AeadCipherTraits &traits,
           std::span<const std::uint8_t> key,
           std::span<const std::uint8_t, 16> block);

// ================================================================================================
//  Cipher Traits Definitions
// ================================================================================================

/**
 * @brief Cipher algorithm traits for AEAD and ECB operations
 * @details Encapsulates the algorithm-specific information needed for encryption/decryption:
 *          the OpenSSL cipher factory function and a human-readable name for diagnostics.
 *          All AEAD control codes (IV length, tag get/set) use the generic EVP_CTRL_AEAD_*
 *          constants which work across all AEAD cipher families.
 */
struct AeadCipherTraits
{
    const EVP_CIPHER *(*cipher_fn)(); ///< Function returning the EVP_CIPHER for this algorithm
    const char *name;                 ///< Human-readable cipher name for error messages
};

/**
 * @brief Traits for AES-128-GCM
 */
constexpr AeadCipherTraits AES_128_GCM_TRAITS{
    EVP_aes_128_gcm,
    "AES-128-GCM",
};

/**
 * @brief Traits for AES-256-GCM
 */
constexpr AeadCipherTraits AES_256_GCM_TRAITS{
    EVP_aes_256_gcm,
    "AES-256-GCM",
};

/**
 * @brief Traits for ChaCha20-Poly1305
 */
constexpr AeadCipherTraits CHACHA20_POLY1305_TRAITS{
    EVP_chacha20_poly1305,
    "ChaCha20-Poly1305",
};

/**
 * @brief Traits for AES-128-ECB (for header protection, etc.)
 */
constexpr AeadCipherTraits AES_128_ECB_TRAITS{
    EVP_aes_128_ecb,
    "AES-128-ECB",
};

/**
 * @brief Traits for AES-256-ECB
 */
constexpr AeadCipherTraits AES_256_ECB_TRAITS{
    EVP_aes_256_ecb,
    "AES-256-ECB",
};

// ================================================================================================
//  SslCipherCtx member method implementations
// ================================================================================================

// Private helper: query cipher name from initialized context

inline const char *SslCipherCtx::CipherName() const
{
    const EVP_CIPHER *c = EVP_CIPHER_CTX_get0_cipher(*this);
    return c ? EVP_CIPHER_get0_name(c) : "cipher";
}

// Low-level initialization methods

inline void SslCipherCtx::InitEncrypt(const AeadCipherTraits &traits,
                                      ENGINE *engine,
                                      const unsigned char *key,
                                      const unsigned char *iv)
{
    if (EVP_EncryptInit_ex(*this, traits.cipher_fn(), engine, key, iv) != 1)
        throw SslException(std::string(traits.name) + " encrypt init failed");
}

inline void SslCipherCtx::InitDecrypt(const AeadCipherTraits &traits,
                                      ENGINE *engine,
                                      const unsigned char *key,
                                      const unsigned char *iv)
{
    if (EVP_DecryptInit_ex(*this, traits.cipher_fn(), engine, key, iv) != 1)
        throw SslException(std::string(traits.name) + " decrypt init failed");
}

inline void SslCipherCtx::SetIvLength(int ivLen)
{
    if (EVP_CIPHER_CTX_ctrl(*this, EVP_CTRL_AEAD_SET_IVLEN, ivLen, nullptr) != 1)
        throw SslException(std::string(CipherName()) + " IV length setup failed");
}

// High-level AEAD methods

inline void SslCipherCtx::InitAeadEncrypt(const AeadCipherTraits &traits)
{
    InitEncrypt(traits);
    SetIvLength(AEAD_DEFAULT_NONCE_LENGTH);
}

inline void SslCipherCtx::InitAeadDecrypt(const AeadCipherTraits &traits)
{
    InitDecrypt(traits);
    SetIvLength(AEAD_DEFAULT_NONCE_LENGTH);
}

inline void SslCipherCtx::SetEncryptKeyAndNonce(std::span<const std::uint8_t> key,
                                                std::span<const std::uint8_t> nonce)
{
    // Set key and nonce for encryption (cipher already set by InitAeadEncrypt)
    if (EVP_EncryptInit_ex(*this, nullptr, nullptr, key.data(), nonce.data()) != 1)
        throw SslException(std::string(CipherName()) + " key/nonce setup failed");
}

inline void SslCipherCtx::SetDecryptKeyAndNonce(std::span<const std::uint8_t> key,
                                                std::span<const std::uint8_t> nonce)
{
    // Set key and nonce for decryption (cipher already set by InitAeadDecrypt)
    if (EVP_DecryptInit_ex(*this, nullptr, nullptr, key.data(), nonce.data()) != 1)
        throw SslException(std::string(CipherName()) + " key/nonce setup failed");
}

inline void SslCipherCtx::SetEncryptNonce(std::span<const std::uint8_t> nonce)
{
    // Pass NULL for cipher & key — reuses the cached key schedule from the initial
    // SetEncryptKeyAndNonce call.  Only the nonce/IV is updated.
    if (EVP_EncryptInit_ex(*this, nullptr, nullptr, nullptr, nonce.data()) != 1)
        throw SslException("encrypt nonce update failed");
}

inline void SslCipherCtx::SetDecryptNonce(std::span<const std::uint8_t> nonce)
{
    // Pass NULL for cipher & key — reuses the cached key schedule.
    if (EVP_DecryptInit_ex(*this, nullptr, nullptr, nullptr, nonce.data()) != 1)
        throw SslException("decrypt nonce update failed");
}

inline void SslCipherCtx::UpdateEncryptAad(std::span<const std::uint8_t> aad)
{
    if (aad.empty())
        return;

    int outlen = 0;
    if (EVP_EncryptUpdate(*this, nullptr, &outlen, aad.data(), static_cast<int>(aad.size())) != 1)
        throw SslException(std::string(CipherName()) + " AAD processing failed");
}

inline void SslCipherCtx::UpdateDecryptAad(std::span<const std::uint8_t> aad)
{
    if (aad.empty())
        return;

    int outlen = 0;
    if (EVP_DecryptUpdate(*this, nullptr, &outlen, aad.data(), static_cast<int>(aad.size())) != 1)
        throw SslException(std::string(CipherName()) + " AAD processing failed");
}

inline std::vector<std::uint8_t>
SslCipherCtx::UpdateEncrypt(std::span<const std::uint8_t> plaintext)
{
    if (plaintext.empty())
        return {};

    std::vector<std::uint8_t> ciphertext(plaintext.size());
    int outlen = 0;
    if (EVP_EncryptUpdate(*this, ciphertext.data(), &outlen, plaintext.data(), static_cast<int>(plaintext.size())) != 1)
        throw SslException(std::string(CipherName()) + " encryption failed");

    ciphertext.resize(outlen);
    return ciphertext;
}

inline void SslCipherCtx::UpdateEncryptInPlace(std::span<std::uint8_t> data)
{
    if (data.empty())
        return;

    int outlen = 0;
    // OpenSSL GCM/ChaCha20-Poly1305 support in-place encryption (out == in)
    if (EVP_EncryptUpdate(*this, data.data(), &outlen, data.data(), static_cast<int>(data.size())) != 1)
        throw SslException(std::string(CipherName()) + " in-place encryption failed");
}

inline std::vector<std::uint8_t> SslCipherCtx::FinalizeEncrypt()
{
    std::vector<std::uint8_t> final_data(AEAD_TAG_LENGTH); // Space for any final bytes + tag
    int outlen = 0;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(*this, final_data.data(), &outlen) != 1)
        throw SslException(std::string(CipherName()) + " finalization failed");

    // Extract authentication tag
    if (EVP_CIPHER_CTX_ctrl(*this, EVP_CTRL_AEAD_GET_TAG, AEAD_TAG_LENGTH, final_data.data() + outlen) != 1)
        throw SslException(std::string(CipherName()) + " tag extraction failed");

    final_data.resize(outlen + AEAD_TAG_LENGTH);
    return final_data;
}

inline std::array<std::uint8_t, AEAD_TAG_LENGTH> SslCipherCtx::FinalizeEncryptTag()
{
    // For GCM/ChaCha20, EVP_EncryptFinal_ex produces 0 final bytes
    int outlen = 0;
    std::uint8_t dummy = 0;
    if (EVP_EncryptFinal_ex(*this, &dummy, &outlen) != 1)
        throw SslException(std::string(CipherName()) + " finalization failed");

    // Extract authentication tag directly into array (no heap allocation)
    std::array<std::uint8_t, AEAD_TAG_LENGTH> tag;
    if (EVP_CIPHER_CTX_ctrl(*this, EVP_CTRL_AEAD_GET_TAG, AEAD_TAG_LENGTH, tag.data()) != 1)
        throw SslException(std::string(CipherName()) + " tag extraction failed");

    return tag;
}

inline std::vector<std::uint8_t>
SslCipherCtx::UpdateDecrypt(std::span<const std::uint8_t> ciphertext)
{
    if (ciphertext.empty())
        return {};

    std::vector<std::uint8_t> plaintext(ciphertext.size());
    int outlen = 0;
    if (EVP_DecryptUpdate(*this, plaintext.data(), &outlen, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1)
        throw SslException(std::string(CipherName()) + " decryption failed");

    plaintext.resize(outlen);
    return plaintext;
}

inline void SslCipherCtx::UpdateDecryptInPlace(std::span<std::uint8_t> data)
{
    if (data.empty())
        return;

    int outlen = 0;
    // OpenSSL GCM/ChaCha20-Poly1305 support in-place decryption (out == in)
    if (EVP_DecryptUpdate(*this, data.data(), &outlen, data.data(), static_cast<int>(data.size())) != 1)
        throw SslException(std::string(CipherName()) + " in-place decryption failed");
}

inline std::vector<std::uint8_t>
SslCipherCtx::FinalizeDecrypt(std::span<const std::uint8_t, AEAD_TAG_LENGTH> tag)
{
    // Set expected tag value for verification
    if (EVP_CIPHER_CTX_ctrl(*this, EVP_CTRL_AEAD_SET_TAG, tag.size(), const_cast<std::uint8_t *>(tag.data())) != 1)
        throw SslException(std::string(CipherName()) + " tag setup failed");

    std::vector<std::uint8_t> final_data(AEAD_TAG_LENGTH); // Space for any final bytes
    int outlen = 0;

    // Finalize and verify tag
    if (EVP_DecryptFinal_ex(*this, final_data.data(), &outlen) != 1)
        throw SslException(std::string(CipherName()) + " authentication failed (tag mismatch)");

    final_data.resize(outlen);
    return final_data;
}

inline bool SslCipherCtx::FinalizeDecryptCheck(std::span<const std::uint8_t, AEAD_TAG_LENGTH> tag)
{
    // Set expected tag value for verification
    if (EVP_CIPHER_CTX_ctrl(*this, EVP_CTRL_AEAD_SET_TAG, tag.size(), const_cast<std::uint8_t *>(tag.data())) != 1)
        throw SslException(std::string(CipherName()) + " tag setup failed");

    // For GCM/ChaCha20, EVP_DecryptFinal_ex produces 0 final bytes
    int outlen = 0;
    std::uint8_t dummy = 0;

    // Returns 0 on tag mismatch (authentication failure) — not an exception
    return EVP_DecryptFinal_ex(*this, &dummy, &outlen) == 1;
}

// ================================================================================================
// One-shot member method implementations
// ================================================================================================

inline std::vector<std::uint8_t>
SslCipherCtx::EncryptAead(const AeadCipherTraits &traits,
                          std::span<const std::uint8_t> key,
                          std::span<const std::uint8_t> nonce,
                          std::span<const std::uint8_t> plaintext,
                          std::span<const std::uint8_t> aad)
{
    // Reinitialize cipher (context may have been used before)
    InitEncrypt(traits);
    SetIvLength(static_cast<int>(nonce.size()));
    SetEncryptKeyAndNonce(key, nonce);
    UpdateEncryptAad(aad);

    auto ciphertext = UpdateEncrypt(plaintext);
    auto final_and_tag = FinalizeEncrypt();

    // Combine ciphertext and final bytes + tag
    ciphertext.insert(ciphertext.end(), final_and_tag.begin(), final_and_tag.end());
    return ciphertext;
}

inline std::vector<std::uint8_t>
SslCipherCtx::DecryptAead(const AeadCipherTraits &traits,
                          std::span<const std::uint8_t> key,
                          std::span<const std::uint8_t> nonce,
                          std::span<const std::uint8_t> ciphertext,
                          std::span<const std::uint8_t> aad)
{
    if (ciphertext.size() < AEAD_TAG_LENGTH)
        throw SslException(std::string(traits.name) + " ciphertext too short (missing tag)");

    // Reinitialize cipher (context may have been used before)
    InitDecrypt(traits);
    SetIvLength(static_cast<int>(nonce.size()));
    SetDecryptKeyAndNonce(key, nonce);
    UpdateDecryptAad(aad);

    // Split ciphertext and tag
    const std::size_t ct_len = ciphertext.size() - AEAD_TAG_LENGTH;
    auto ct_data = ciphertext.subspan(0, ct_len);
    std::array<std::uint8_t, AEAD_TAG_LENGTH> tag;
    std::copy_n(ciphertext.data() + ct_len, AEAD_TAG_LENGTH, tag.begin());

    auto plaintext = UpdateDecrypt(ct_data);
    auto final_bytes = FinalizeDecrypt(tag);

    // Combine plaintext and final bytes
    plaintext.insert(plaintext.end(), final_bytes.begin(), final_bytes.end());
    return plaintext;
}

inline std::array<std::uint8_t, AEAD_TAG_LENGTH>
SslCipherCtx::EncryptAeadInPlace(const AeadCipherTraits &traits,
                                 std::span<const std::uint8_t> key,
                                 std::span<const std::uint8_t> nonce,
                                 std::span<std::uint8_t> data,
                                 std::span<const std::uint8_t> aad)
{
    InitEncrypt(traits);
    SetIvLength(static_cast<int>(nonce.size()));
    SetEncryptKeyAndNonce(key, nonce);
    UpdateEncryptAad(aad);
    UpdateEncryptInPlace(data);
    return FinalizeEncryptTag();
}

inline bool
SslCipherCtx::DecryptAeadInPlace(const AeadCipherTraits &traits,
                                 std::span<const std::uint8_t> key,
                                 std::span<const std::uint8_t> nonce,
                                 std::span<std::uint8_t> data,
                                 std::span<const std::uint8_t, AEAD_TAG_LENGTH> tag,
                                 std::span<const std::uint8_t> aad)
{
    InitDecrypt(traits);
    SetIvLength(static_cast<int>(nonce.size()));
    SetDecryptKeyAndNonce(key, nonce);
    UpdateDecryptAad(aad);
    UpdateDecryptInPlace(data);
    return FinalizeDecryptCheck(tag);
}

// ================================================================================================
//  Free function implementations
// ================================================================================================

inline std::vector<std::uint8_t>
EncryptAead(const AeadCipherTraits &traits,
            std::span<const std::uint8_t> key,
            std::span<const std::uint8_t> nonce,
            std::span<const std::uint8_t> plaintext,
            std::span<const std::uint8_t> aad)
{
    SslCipherCtx ctx;
    return ctx.EncryptAead(traits, key, nonce, plaintext, aad);
}

inline std::vector<std::uint8_t>
DecryptAead(const AeadCipherTraits &traits,
            std::span<const std::uint8_t> key,
            std::span<const std::uint8_t> nonce,
            std::span<const std::uint8_t> ciphertext,
            std::span<const std::uint8_t> aad)
{
    SslCipherCtx ctx;
    return ctx.DecryptAead(traits, key, nonce, ciphertext, aad);
}

inline std::array<std::uint8_t, AEAD_TAG_LENGTH>
EncryptAeadInPlace(const AeadCipherTraits &traits,
                   std::span<const std::uint8_t> key,
                   std::span<const std::uint8_t> nonce,
                   std::span<std::uint8_t> data,
                   std::span<const std::uint8_t> aad)
{
    SslCipherCtx ctx;
    return ctx.EncryptAeadInPlace(traits, key, nonce, data, aad);
}

inline bool
DecryptAeadInPlace(const AeadCipherTraits &traits,
                   std::span<const std::uint8_t> key,
                   std::span<const std::uint8_t> nonce,
                   std::span<std::uint8_t> data,
                   std::span<const std::uint8_t, AEAD_TAG_LENGTH> tag,
                   std::span<const std::uint8_t> aad)
{
    SslCipherCtx ctx;
    return ctx.DecryptAeadInPlace(traits, key, nonce, data, tag, aad);
}

inline std::array<std::uint8_t, 16>
EncryptEcb(const AeadCipherTraits &traits,
           std::span<const std::uint8_t> key,
           std::span<const std::uint8_t, 16> block)
{
    SslCipherCtx ctx;

    // Initialize encryption with specified ECB cipher
    if (EVP_EncryptInit_ex(ctx, traits.cipher_fn(), nullptr, key.data(), nullptr) != 1)
        throw SslException(std::string(traits.name) + " encrypt init failed");

    // Disable padding (we're encrypting exactly one block)
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // Encrypt the block (single 16-byte block)
    std::array<std::uint8_t, 16> output;
    int outlen = 0;
    if (EVP_EncryptUpdate(ctx, output.data(), &outlen, block.data(), 16) != 1)
        throw SslException(std::string(traits.name) + " encryption failed");

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, output.data() + outlen, &final_len) != 1)
        throw SslException(std::string(traits.name) + " finalization failed");

    return output;
}

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_SSL_CIPHER_H
