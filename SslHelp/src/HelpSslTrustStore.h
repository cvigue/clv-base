// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_SSLHELP_SSLTRUSTSTORE_H
#define CLV_SSLHELP_SSLTRUSTSTORE_H

#include <cstdio>
#include <filesystem>
#include <memory>
#include <set>
#include <string>
#include <utility>

#include <openssl/pem.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "HelpSslException.h"
#include "HelpSslFileUtils.h"
#include "HelpSslX509.h"
#include "HelpSslX509Crl.h"
#include "HelpSslX509Store.h"
#include "HelpSslX509StoreCtx.h"

namespace clv::OpenSSL {

/**
    @brief Manages trusted CA certificates and certificate revocation lists (CRL)
    @details Wraps OpenSSL X509_STORE to provide certificate chain validation
*/
class SslTrustStore
{
  public:
    SslTrustStore() = default;
    ~SslTrustStore() = default;

    // Prevent copying (X509_STORE is reference counted internally)
    SslTrustStore(const SslTrustStore &) = delete;
    SslTrustStore &operator=(const SslTrustStore &) = delete;

    // Allow moving
    SslTrustStore(SslTrustStore &&other) noexcept;
    SslTrustStore &operator=(SslTrustStore &&other) noexcept;

    // Load trusted CAs
    void AddTrustedCA(const SslX509 &ca_cert);
    void LoadCAFile(const std::filesystem::path &ca_file);
    void LoadCADirectory(const std::filesystem::path &ca_dir);
    void SetDefaultVerifyPaths();

    // CRL management
    void LoadCRL(const std::filesystem::path &crl_file);
    void EnableCRLCheck(bool check_all = false);
    bool IsRevoked(const SslX509 &cert) const;

    // Certificate pinning (fingerprint-based trust)
    void AddTrustedFingerprint(const std::string &fingerprint_hex);
    bool IsFingerprintTrusted(const std::string &fingerprint_hex) const;
    void ClearTrustedFingerprints();

    // Get underlying X509_STORE for OpenSSL integration
    X509_STORE *GetStore()
    {
        return store_.Get();
    }
    const X509_STORE *GetStore() const
    {
        return store_.Get();
    }

  private:
    SslX509Store store_;
    std::set<std::string> trusted_fingerprints_;
};

// ================================================================================================
// Implementation
// ================================================================================================

inline SslTrustStore::SslTrustStore(SslTrustStore &&other) noexcept
    : store_(std::move(other.store_)), trusted_fingerprints_(std::move(other.trusted_fingerprints_))
{
    other.store_ = SslX509Store(nullptr);
}

inline SslTrustStore &SslTrustStore::operator=(SslTrustStore &&other) noexcept
{
    if (this != &other)
    {
        store_ = std::move(other.store_);
        trusted_fingerprints_ = std::move(other.trusted_fingerprints_);
        other.store_ = SslX509Store(nullptr);
    }
    return *this;
}

/**
    @brief Add a trusted CA certificate to the store
    @param ca_cert CA certificate to trust
*/
inline void SslTrustStore::AddTrustedCA(const SslX509 &ca_cert)
{
    store_.AddCert(ca_cert);
}

/**
    @brief Load trusted CA certificate(s) from PEM file
    @param ca_file Path to PEM file containing one or more CA certificates
*/
inline void SslTrustStore::LoadCAFile(const std::filesystem::path &ca_file)
{
    if (!std::filesystem::exists(ca_file))
        throw SslException("CA file not found: " + ca_file.string());

    std::unique_ptr<FILE, decltype(&FileDeleter)> fp(fopen(ca_file.string().c_str(), "r"), &FileDeleter);
    if (!fp)
        throw SslException("Failed to open CA file: " + ca_file.string());

    X509 *cert = nullptr;
    int count = 0;
    while ((cert = PEM_read_X509(fp.get(), nullptr, nullptr, nullptr)) != nullptr)
    {
        store_.AddCert(cert);
        count++;
        X509_free(cert);
    }

    if (count == 0)
        throw SslException("No valid CA certificates found in file");
}

/**
    @brief Load trusted CA certificates from directory
    @param ca_dir Path to directory containing CA certificate files
*/
inline void SslTrustStore::LoadCADirectory(const std::filesystem::path &ca_dir)
{
    store_.LoadDirectory(ca_dir);
}

/**
    @brief Load system default CA certificates
*/
inline void SslTrustStore::SetDefaultVerifyPaths()
{
    store_.SetDefaultPaths();
}

/**
    @brief Load CRL from file
    @param crl_file Path to CRL file in PEM format
*/
inline void SslTrustStore::LoadCRL(const std::filesystem::path &crl_file)
{
    SslX509Crl crl(crl_file);
    store_.AddCrl(crl);
}

/**
    @brief Enable CRL checking
    @param check_all If true, check entire chain; if false, only check end entity cert
*/
inline void SslTrustStore::EnableCRLCheck(bool check_all)
{
    unsigned long flags = X509_V_FLAG_CRL_CHECK;
    if (check_all)
        flags |= X509_V_FLAG_CRL_CHECK_ALL;

    store_.SetFlags(flags);
}

/**
    @brief Check if certificate is revoked
    @param cert Certificate to check
    @return true if certificate is revoked
*/
inline bool SslTrustStore::IsRevoked(const SslX509 &cert) const
{
    SslX509StoreCtx ctx;

    auto store_ptr = const_cast<X509_STORE *>(store_.Get());
    if (!ctx.Init(store_ptr, const_cast<X509 *>(cert.Get()), nullptr))
        return false;

    // We just trigger error population here
    [[maybe_unused]] int result = ctx.Verify();

    return (ctx.Error() == X509_V_ERR_CERT_REVOKED);
}

/**
    @brief Add trusted certificate fingerprint for pinning
    @param fingerprint_hex SHA256 fingerprint in hex format
*/
inline void SslTrustStore::AddTrustedFingerprint(const std::string &fingerprint_hex)
{
    trusted_fingerprints_.insert(fingerprint_hex);
}

/**
    @brief Check if fingerprint is trusted
    @param fingerprint_hex SHA256 fingerprint in hex format
    @return true if fingerprint is in trusted set
*/
inline bool SslTrustStore::IsFingerprintTrusted(const std::string &fingerprint_hex) const
{
    return trusted_fingerprints_.find(fingerprint_hex) != trusted_fingerprints_.end();
}

/**
    @brief Clear all trusted fingerprints
*/
inline void SslTrustStore::ClearTrustedFingerprints()
{
    trusted_fingerprints_.clear();
}

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_SSLTRUSTSTORE_H
