// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_SSLHELP_VERIFYHELPER_H
#define CLV_SSLHELP_VERIFYHELPER_H

#include <functional>
#include <openssl/obj_mac.h>
#include <openssl/types.h>
#include <string>

#include "HelpSslX509.h"
#include "HelpSslX509StoreCtx.h"
#include "HelpSslTrustStore.h"
#include "HelpSslContext.h"

#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <utility>

#include <scope_guard.h>

namespace clv::OpenSSL {

/**
    @brief Custom verification callback for TLS connections
    @details Used to implement OpenVPN-style tls-verify functionality
*/
using VerifyCallback = std::function<bool(const SslX509 &cert, int depth, int preverify_ok)>;

/**
    @brief Helper for setting up custom certificate verification
    @details Integrates SslTrustStore and custom verification logic with SSL_CTX
*/
class SslVerifyHelper
{
  public:
    explicit SslVerifyHelper(SslContext &ctx, SslTrustStore &trust_store);

    // Set custom verification callback (called after OpenSSL verification)
    void SetVerifyCallback(VerifyCallback callback);

    // Set expected peer identity (CN or SAN)
    void SetExpectedPeerIdentity(const std::string &peer_id);

    // Require specific extended key usages
    void RequireExtendedKeyUsage(bool require_server, bool require_client);

    // Enable strict verification mode
    void SetStrictMode(bool strict);

  private:
    static int OpenSSLVerifyCallback(int preverify_ok, X509_STORE_CTX *ctx);
    static SslVerifyHelper *GetHelperFromStoreCtx(X509_STORE_CTX *ctx);

    SslContext &sslCtx_;
    SslTrustStore &trustStore_;
    VerifyCallback customCallback_;
    std::string expectedPeerId_;
    bool requireServerAuth_ = false;
    bool requireClientAuth_ = false;
    bool strictMode_ = false;
};

// ================================================================================================
// Implementation
// ================================================================================================

inline SslVerifyHelper::SslVerifyHelper(SslContext &ctx, SslTrustStore &trust_store)
    : sslCtx_(ctx), trustStore_(trust_store)
{
    // Set up SSL_CTX to use our trust store
    SSL_CTX_set_cert_store(ctx.Get(), trust_store.GetStore());
    X509_STORE_up_ref(trust_store.GetStore()); // SSL_CTX takes ownership, add ref

    // Set verify mode
    SSL_CTX_set_verify(ctx.Get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, OpenSSLVerifyCallback);

    // Store pointer to this helper in SSL_CTX ex_data
    SSL_CTX_set_ex_data(ctx.Get(), 0, this);
}

/**
    @brief Set custom verification callback
    @param callback Function called for each certificate in chain
*/
inline void SslVerifyHelper::SetVerifyCallback(VerifyCallback callback)
{
    customCallback_ = std::move(callback);
}

/**
    @brief Set expected peer identity for validation
    @param peer_id Expected CN or SAN value
*/
inline void SslVerifyHelper::SetExpectedPeerIdentity(const std::string &peer_id)
{
    expectedPeerId_ = peer_id;
}

/**
    @brief Require extended key usage validation
    @param require_server Require TLS Server Auth
    @param require_client Require TLS Client Auth
*/
inline void SslVerifyHelper::RequireExtendedKeyUsage(bool require_server, bool require_client)
{
    requireServerAuth_ = require_server;
    requireClientAuth_ = require_client;
}

/**
    @brief Enable strict verification mode
    @param strict If true, fail on any custom check failure
*/
inline void SslVerifyHelper::SetStrictMode(bool strict)
{
    strictMode_ = strict;
}

/**
    @brief OpenSSL verification callback (static)
    @param preverify_ok Result of OpenSSL's built-in verification
    @param ctx X509_STORE_CTX with certificate information
    @return 1 if verification passes, 0 if it fails
*/
inline int SslVerifyHelper::OpenSSLVerifyCallback(int preverify_ok, X509_STORE_CTX *ctx)
{
    // Get SSL context
    SSL *ssl = static_cast<SSL *>(
        X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));
    if (!ssl)
        return preverify_ok;

    SSL_CTX *ssl_ctx = SSL_get_SSL_CTX(ssl);
    if (!ssl_ctx)
        return preverify_ok;

    // Get our helper
    SslVerifyHelper *helper = static_cast<SslVerifyHelper *>(
        SSL_CTX_get_ex_data(ssl_ctx, 0));
    if (!helper)
        return preverify_ok;

    // Non-owning wrap: ctx is owned by OpenSSL's verification machinery.
    // Release() prevents our RAII destructor from calling X509_STORE_CTX_free.
    SslX509StoreCtx store_ctx(ctx);
    auto releaseGuard = clv::scope_exit([&]
    { (void)store_ctx.Release(); });

    X509 *cert = store_ctx.GetCurrentCert();
    if (!cert)
        return 0;

    int depth = store_ctx.GetErrorDepth();

    // Borrow certificate reference (increments refcount)
    SslX509 ssl_cert = SslX509::Borrow(cert);

    // For end-entity cert (depth 0), perform additional checks
    if (depth == 0)
    {
        // Check expected peer identity
        if (!helper->expectedPeerId_.empty())
        {
            if (!ssl_cert.MatchesPeerIdentity(helper->expectedPeerId_))
            {
                store_ctx.SetError(X509_V_ERR_APPLICATION_VERIFICATION);
                return 0;
            }
        }

        // Check extended key usage
        if (helper->requireServerAuth_ || helper->requireClientAuth_)
        {
            bool has_server = ssl_cert.HasExtendedKeyUsage(NID_server_auth);
            bool has_client = ssl_cert.HasExtendedKeyUsage(NID_client_auth);

            if (helper->requireServerAuth_ && !has_server)
            {
                store_ctx.SetError(X509_V_ERR_INVALID_PURPOSE);
                return 0;
            }
            if (helper->requireClientAuth_ && !has_client)
            {
                store_ctx.SetError(X509_V_ERR_INVALID_PURPOSE);
                return 0;
            }
        }
    }

    // Call custom callback if set
    if (helper->customCallback_)
    {
        bool custom_result = helper->customCallback_(ssl_cert, depth, preverify_ok);

        if (!custom_result)
        {
            if (helper->strictMode_)
            {
                store_ctx.SetError(X509_V_ERR_APPLICATION_VERIFICATION);
                return 0;
            }
            // In non-strict mode, log but don't fail
        }
    }

    return preverify_ok;
}

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_VERIFYHELPER_H
