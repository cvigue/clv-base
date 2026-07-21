// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLV_SSLHELP_SSL_EVP_PKEY_H
#define CLV_SSLHELP_SSL_EVP_PKEY_H

#include <istream>
#include <iterator>
#include <optional>
#include <openssl/bio.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/types.h>
#include <string>
#include <string_view>

#include "HelpSslException.h"
#include "HelpSslWithRc.h"
#include "HelpSslBio.h"
#include "HelpSslEvpPkeyCtx.h"
#include "openssl/opensslv.h"

#include <openssl/ec.h>
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

    /** @brief OpenSSL key type (e.g. EVP_PKEY_RSA, EVP_PKEY_EC); wraps EVP_PKEY_base_id. */
    [[nodiscard]] int BaseId() const noexcept
    {
        return EVP_PKEY_base_id(Get());
    }

    /** @brief Public-key strength in bits (RSA modulus or EC field size). */
    [[nodiscard]] int BitLength() const
    {
        if (Get() == nullptr)
            ThrowSslApp("SslEvpKey: null key");
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        return EVP_PKEY_get_bits(Get());
#else
        switch (EVP_PKEY_base_id(Get()))
        {
        case EVP_PKEY_RSA:
            {
                const RSA *rsa = EVP_PKEY_get0_RSA(Get());
                if (rsa == nullptr)
                    ThrowSslApp("SslEvpKey: invalid RSA key");
                return RSA_bits(rsa);
            }
        case EVP_PKEY_EC:
            {
                const EC_KEY *ec = EVP_PKEY_get0_EC_KEY(Get());
                if (ec == nullptr)
                    ThrowSslApp("SslEvpKey: invalid EC key");
                return EC_GROUP_get_degree(EC_KEY_get0_group(ec));
            }
        default:
            ThrowSslApp("SslEvpKey: BitLength unsupported for key type");
        }
#endif
    }

    /** @brief Share an external @c EVP_PKEY (increments refcount). */
    static SslEvpKey Borrow(EVP_PKEY *pkey)
    {
        return SslWithRc::BorrowRef<SslEvpKey>(pkey);
    }

    /** @brief Elliptic-curve NID when this is an EC key; otherwise @c std::nullopt. */
    [[nodiscard]] std::optional<int> EcCurveNid() const noexcept
    {
        if (Get() == nullptr || EVP_PKEY_base_id(Get()) != EVP_PKEY_EC)
            return std::nullopt;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        char gname[80];
        if (EVP_PKEY_get_group_name(Get(), gname, sizeof(gname), nullptr) <= 0)
            return std::nullopt;
        const int nid = OBJ_sn2nid(gname);
        return nid == NID_undef ? OBJ_txt2nid(gname) : nid;
#else
        const EC_KEY *ec = EVP_PKEY_get0_EC_KEY(Get());
        if (ec == nullptr)
            return std::nullopt;
        return EC_GROUP_get_curve_name(EC_KEY_get0_group(ec));
#endif
    }

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
        ThrowSsl("EVP_PKEY_keygen_init failed");
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
        ThrowSsl("EVP_PKEY_CTX_set_rsa_keygen_bits failed");
    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        ThrowSsl("EVP_PKEY_keygen failed");
    return pkey;
}

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_SSL_EVP_PKEY_H