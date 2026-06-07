// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_SSLHELP_CERTVALIDATOR_H
#define CLV_SSLHELP_CERTVALIDATOR_H

#include <openssl/obj_mac.h>
#include <openssl/safestack.h>
#include <openssl/types.h>
#include <string>
#include <vector>
#include <optional>

#include "HelpSslX509.h"
#include "HelpSslTrustStore.h"
#include "HelpSslX509StoreCtx.h"

#include <openssl/x509_vfy.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

namespace clv::OpenSSL {

/**
    @brief Certificate validation results
*/
struct CertValidationResult
{
    bool valid;
    std::string errorMessage;
    int errorCode;                     // OpenSSL verification error code
    std::optional<std::string> peerId; // CN or SAN
    std::vector<std::string> subjectAltNames;
};

/**
    @brief Certificate chain validator
    @details Provides high-level certificate validation with custom checks for mesh VPN
*/
class SslCertValidator
{
  public:
    explicit SslCertValidator(SslTrustStore &trust_store);

    // Validate certificate chain
    CertValidationResult ValidateChain(
        const SslX509 &peer_cert,
        const std::vector<SslX509> &chain = {}) const;

    // Validate specific peer identity
    bool ValidatePeerIdentity(
        const SslX509 &cert,
        const std::string &expected_peerId) const;

    // Custom validation checks
    bool CheckKeyUsage(const SslX509 &cert) const;
    bool CheckExtendedKeyUsage(const SslX509 &cert, bool require_server, bool require_client) const;
    bool CheckBasicConstraints(const SslX509 &cert, bool must_be_ca) const;

  private:
    SslTrustStore &trustStore_;
};

// ================================================================================================
// Implementation
// ================================================================================================

inline SslCertValidator::SslCertValidator(SslTrustStore &trust_store)
    : trustStore_(trust_store)
{
}

/**
    @brief Validate certificate chain
    @param peer_cert End entity certificate
    @param chain Intermediate certificates (optional)
    @return Validation result with details
*/
inline CertValidationResult SslCertValidator::ValidateChain(
    const SslX509 &peer_cert,
    const std::vector<SslX509> &chain) const
{
    CertValidationResult result;
    result.valid = false;
    result.errorCode = 0;

    // Extract peer identity
    result.peerId = peer_cert.GetCommonName();
    result.subjectAltNames = peer_cert.GetSubjectAlternativeNames();

    // Check if certificate is currently valid
    if (!peer_cert.IsValidAtTime())
    {
        result.errorMessage = "Certificate is not valid (expired or not yet valid)";
        result.errorCode = X509_V_ERR_CERT_HAS_EXPIRED;
        return result;
    }

    // Check fingerprint pinning first (if configured)
    auto fingerprint = peer_cert.GetFingerprint();
    if (trustStore_.IsFingerprintTrusted(fingerprint))
    {
        result.valid = true;
        result.errorMessage = "Certificate trusted via fingerprint pinning";
        return result;
    }

    // Perform full chain validation
    SslX509StoreCtx ctx;
    std::optional<SslX509Stack> chain_stack;
    STACK_OF(X509) *chain_ptr = nullptr;

    if (!chain.empty())
    {
        chain_stack.emplace();
        for (const auto &intermediate : chain)
        {
            X509 *cert_ptr = const_cast<X509 *>(intermediate.Get());
            chain_stack->Push(cert_ptr);
        }
        chain_ptr = chain_stack->Raw();
    }

    if (!ctx.Init(trustStore_.GetStore(), const_cast<X509 *>(peer_cert.Get()), chain_ptr))
    {
        result.errorMessage = "Failed to initialize verification context";
        return result;
    }

    int verify_result = ctx.Verify();

    if (verify_result == 1)
    {
        result.valid = true;
        result.errorMessage = "Certificate chain is valid";
    }
    else
    {
        result.errorCode = ctx.Error();
        result.errorMessage = X509_verify_cert_error_string(result.errorCode);
    }
    return result;
}

/**
    @brief Validate peer identity matches expected value
    @param cert Certificate to check
    @param expected_peerId Expected CN or SAN
    @return true if identity matches
*/
inline bool SslCertValidator::ValidatePeerIdentity(
    const SslX509 &cert,
    const std::string &expected_peerId) const
{
    return cert.MatchesPeerIdentity(expected_peerId);
}

/**
    @brief Check key usage extension
    @param cert Certificate to check
    @return true if has Digital Signature and Key Encipherment
*/
inline bool SslCertValidator::CheckKeyUsage(const SslX509 &cert) const
{
    // For VPN usage, we typically need Digital Signature and Key Encipherment
    return cert.HasKeyUsage(0) && // Digital Signature (bit 0)
           cert.HasKeyUsage(2);   // Key Encipherment (bit 2)
}

/**
    @brief Check extended key usage
    @param cert Certificate to check
    @param require_server Require TLS Server Authentication
    @param require_client Require TLS Client Authentication
    @return true if requirements met
*/
inline bool SslCertValidator::CheckExtendedKeyUsage(
    const SslX509 &cert,
    bool require_server,
    bool require_client) const
{
    bool has_server = cert.HasExtendedKeyUsage(NID_server_auth);
    bool has_client = cert.HasExtendedKeyUsage(NID_client_auth);

    if (require_server && !has_server)
        return false;
    if (require_client && !has_client)
        return false;

    return true;
}

/**
    @brief Check basic constraints
    @param cert Certificate to check
    @param must_be_ca If true, cert must be a CA
    @return true if constraints are satisfied
*/
inline bool SslCertValidator::CheckBasicConstraints(
    const SslX509 &cert,
    bool must_be_ca) const
{
    bool is_ca = cert.IsCA();

    if (must_be_ca && !is_ca)
        return false;
    if (!must_be_ca && is_ca)
        return false; // End entity cert should not be a CA

    return true;
}

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_CERTVALIDATOR_H
