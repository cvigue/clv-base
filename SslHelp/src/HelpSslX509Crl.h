// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_SSLHELP_X509CRL_H
#define CLV_SSLHELP_X509CRL_H

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <istream>
#include <iterator>
#include <memory>
#include <optional>
#include <span>
#include <openssl/bio.h>
#include <openssl/types.h>
#include <string>
#include <string_view>

#include "HelpSslAsn1.h"
#include "HelpSslBio.h"
#include "HelpSslException.h"
#include "HelpSslWithRc.h"
#include "HelpSslFileUtils.h"
#include "HelpSslX509.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

namespace clv::OpenSSL {

/**
    @brief RAII wrapper for OpenSSL X509_CRL (Certificate Revocation List)
    @details Provides automatic memory management for CRL objects
*/
struct SslX509Crl : SslWithRc<X509_CRL, &X509_CRL_new, &X509_CRL_free, &X509_CRL_up_ref>
{
    using SslWithRc<X509_CRL, &X509_CRL_new, &X509_CRL_free, &X509_CRL_up_ref>::SslWithRc;

    // Load from file
    explicit SslX509Crl(const std::filesystem::path &crl_file);

    // Load from stream
    explicit SslX509Crl(std::istream &&stream);

    // Load from PEM string
    explicit SslX509Crl(std::string_view pem_data);

    /** @brief Parse PEM or DER CRL bytes without throwing. */
    [[nodiscard]] static std::optional<SslX509Crl> TryFromBytes(std::span<const std::uint8_t> bytes) noexcept;

    /** @brief Verify issuer DN matches @p ca and CRL signature verifies with CA public key. */
    [[nodiscard]] bool VerifyIssuer(const SslX509 &ca) const noexcept;

    /** @brief CRL @c thisUpdate as Unix epoch seconds (UTC). */
    [[nodiscard]] std::optional<std::int64_t> LastUpdateUnix() const noexcept
    {
        return Asn1TimeToUnixSeconds(X509_CRL_get0_lastUpdate(Get()));
    }

  private:
    static X509_CRL *LoadFromDer(std::span<const std::uint8_t> der);
    static X509_CRL *LoadFromFile(const std::filesystem::path &crl_file);
    static X509_CRL *LoadFromStream(std::istream &stream);
    static X509_CRL *LoadFromString(std::string_view pem_data);
};

// ================================================================================================
// Implementation
// ================================================================================================

/**
    @brief Load CRL from file (helper)
    @param crl_file Path to PEM-encoded CRL file
    @return Raw X509_CRL pointer (caller takes ownership)
*/
inline X509_CRL *SslX509Crl::LoadFromFile(const std::filesystem::path &crl_file)
{
    if (!std::filesystem::exists(crl_file))
        throw SslException("CRL file not found: " + crl_file.string());

    std::unique_ptr<FILE, decltype(&FileDeleter)> fp(fopen(crl_file.string().c_str(), "r"), &FileDeleter);
    if (!fp)
        throw SslException("Failed to open CRL file: " + crl_file.string());

    X509_CRL *crl = PEM_read_X509_CRL(fp.get(), nullptr, nullptr, nullptr);

    if (!crl)
        throw SslException("Failed to read CRL from file");

    return crl;
}

/**
    @brief Load CRL from stream (helper)
    @param stream Input stream containing PEM-encoded CRL
    @return Raw X509_CRL pointer (caller takes ownership)
*/
inline X509_CRL *SslX509Crl::LoadFromStream(std::istream &stream)
{
    std::string pem_data((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    return LoadFromString(pem_data);
}

/**
    @brief Load CRL from PEM string (helper)
    @param pem_data PEM-encoded CRL data
    @return Raw X509_CRL pointer (caller takes ownership)
*/
inline X509_CRL *SslX509Crl::LoadFromString(std::string_view pem_data)
{
    auto bio = SslBio(BIO_new_mem_buf(pem_data.data(), static_cast<int>(pem_data.size())));
    return PEM_read_bio_X509_CRL(bio, nullptr, nullptr, nullptr);
}

/**
    @brief Load CRL from file
    @param crl_file Path to PEM-encoded CRL file
*/
inline SslX509Crl::SslX509Crl(const std::filesystem::path &crl_file)
    : SslWithRc(LoadFromFile(crl_file))
{
}

/**
    @brief Load CRL from input stream
    @param stream Input stream containing PEM-encoded CRL
*/
inline SslX509Crl::SslX509Crl(std::istream &&stream)
    : SslWithRc(LoadFromStream(stream))
{
}

/**
    @brief Load CRL from PEM string
    @param pem_data PEM-encoded CRL data
*/
inline SslX509Crl::SslX509Crl(std::string_view pem_data)
    : SslWithRc(LoadFromString(pem_data))
{
}

inline X509_CRL *SslX509Crl::LoadFromDer(std::span<const std::uint8_t> der)
{
    const std::uint8_t *p = der.data();
    return d2i_X509_CRL(nullptr, &p, static_cast<long>(der.size()));
}

inline std::optional<SslX509Crl> SslX509Crl::TryFromBytes(std::span<const std::uint8_t> bytes) noexcept
{
    if (bytes.empty())
        return std::nullopt;

    const std::string_view view(reinterpret_cast<const char *>(bytes.data()), bytes.size());
    if (view.find("-----BEGIN") != std::string_view::npos)
    {
        try
        {
            return SslX509Crl(view);
        }
        catch (const std::exception &)
        {
            return std::nullopt;
        }
    }

    X509_CRL *raw = LoadFromDer(bytes);
    if (raw == nullptr)
        return std::nullopt;

    return SslX509Crl(raw);
}

inline bool SslX509Crl::VerifyIssuer(const SslX509 &ca) const noexcept
{
    if (Get() == nullptr || ca.Get() == nullptr)
        return false;

    if (X509_NAME_cmp(X509_CRL_get_issuer(Get()), X509_get_subject_name(ca.Get())) != 0)
        return false;

    EVP_PKEY *pkey = X509_get_pubkey(const_cast<X509 *>(ca.Get()));
    if (pkey == nullptr)
        return false;

    const int ok = X509_CRL_verify(const_cast<X509_CRL *>(Get()), pkey);
    EVP_PKEY_free(pkey);
    return ok == 1;
}

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_X509CRL_H
