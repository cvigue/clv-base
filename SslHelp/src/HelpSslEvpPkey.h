// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLV_SSLHELP_SSL_EVP_PKEY_H
#define CLV_SSLHELP_SSL_EVP_PKEY_H

#include <istream>
#include <iterator>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/types.h>
#include <string>
#include <string_view>

#include "HelpSslException.h"
#include "HelpSslWithRc.h"
#include "HelpSslBio.h"
#include "HelpSslEvpPkeyCtx.h"

#include <openssl/evp.h>
#include <openssl/pem.h>

namespace clv::OpenSSL {

/**
    @brief SslEvpKey is a class that represents an OpenSSL EVP_PKEY object
    @class SslEvpKey

    SslEvpKey is a class that represents an OpenSSL EVP_PKEY object, which is a
    data structure used to store and manage cryptographic keys. The class provides
    several constructors that allow creating an EVP_PKEY object in different ways.

    The purpose of this code is to provide a convenient way to create and manage
    EVP_PKEY objects, which are essential for various cryptographic operations in
    OpenSSL, such as encryption, decryption, signing, and verification. The class
    encapsulates the low-level OpenSSL functions and provides a more user-friendly
    interface for working with cryptographic keys.
*/
struct SslEvpKey : SslWithRc<EVP_PKEY, EVP_PKEY_new, EVP_PKEY_free, EVP_PKEY_up_ref>
{
    using SslWithRc<EVP_PKEY, EVP_PKEY_new, EVP_PKEY_free, EVP_PKEY_up_ref>::SslWithRc;
    explicit SslEvpKey(int bits);
    explicit SslEvpKey(std::string_view buffer);
    explicit SslEvpKey(std::istream &s);

  private:
    static EVP_PKEY *EvpPkeyFromPem(std::string_view buffer);
    static EVP_PKEY *EvpPkeyCreateRsa(int bits);
};

/**
    @brief Try to create an EVP_PKEY of the specified width
    @param bits Desired key width
    @param prime Optional prime number
    @details
    SslEvpKey(int bits), creates a new EVP_PKEY object that contains an RSA key pair. The
    bits parameter specifies the desired key length (in bits).
*/
inline SslEvpKey::SslEvpKey(int bits)
    : SslWithRc(EvpPkeyCreateRsa(bits)) {};
/**
    @brief Try to create an EVP_PKEY from the given PEM formatted text buffer.
    @param buffer PEM formatted text that converts to a key.
    @details
    SslEvpKey(std::string_view buffer), creates a new EVP_PKEY object from a
    PEM-formatted text buffer. The buffer parameter is a string view that contains
    the PEM-encoded key data.
*/
inline SslEvpKey::SslEvpKey(std::string_view buffer)
    : SslWithRc(EvpPkeyFromPem(buffer)) {};
/**
    @brief Try to create an EVP_PKEY from the given PEM formatted data stream.
    @param buffer PEM formatted stream that converts to a key.
    @details
    SslEvpKey(std::istream &&s), creates a new EVP_PKEY object from a PEM-formatted data
    stream. The s parameter is an input stream that provides the PEM-encoded key data.
*/
inline SslEvpKey::SslEvpKey(std::istream &s)
    : SslEvpKey(std::string(std::istreambuf_iterator<char>(s), {})) {};
/**
    @brief Helper: creates EVP_PKEY * from PEM buffer
    @param buffer PEM encoded key
    @return EVP_PKEY * resulting EVP_PKEY *
*/
inline EVP_PKEY *SslEvpKey::EvpPkeyFromPem(std::string_view buffer)
{
    auto bio = SslBio(BIO_new_mem_buf(buffer.data(), -1));
    return PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
}
/**
    @brief Helper: creates RSA EVP_PKEY * of given width
    @param bits Desired key width
    @return EVP_PKEY * resulting EVP_PKEY *
*/
inline EVP_PKEY *SslEvpKey::EvpPkeyCreateRsa(int bits)
{
    auto ctx = SslEvpPkeyCtx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    if (EVP_PKEY_keygen_init(ctx) <= 0)
        throw SslException("EVP_PKEY_keygen_init failed");
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
        throw SslException("EVP_PKEY_CTX_set_rsa_keygen_bits failed");
    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        throw SslException("EVP_PKEY_keygen failed");
    return pkey;
}

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_SSL_EVP_PKEY_H