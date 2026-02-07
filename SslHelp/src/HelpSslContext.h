// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLV_SSLHELP_SSL_CONTEXT_H
#define CLV_SSLHELP_SSL_CONTEXT_H


#include "HelpSslException.h"
#include "HelpSslWithRc.h"
#include "HelpSslX509.h"
#include "HelpSslEvpPkey.h"

#include <openssl/types.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

// QUIC TLS support is enabled via CMake when linking against quictls
// Define CLV_HAS_QUIC_TLS in your build system when using quictls

namespace clv::OpenSSL {

// ================================================================================================
/**
  @brief wrapper for OpenSSL SSL_CTX
  @note Provides a RAII wrapper for OpenSSL SSL_CTX objects. The class is a template
        that uses the SslWithRc template to manage the SSL_CTX object. The class
        provides a constructor that creates a new SSL_CTX object and a destructor
        that frees the resources associated with the SSL_CTX object. The class also
        provides a Get method that returns a pointer to the SSL_CTX object and a
        conversion operator for places that expect SSL_CTX *.
*/
struct SslContext : SslWithRc<SSL_CTX, SSL_CTX_new, SSL_CTX_free, SSL_CTX_up_ref>
{
    using SslWithRc<SSL_CTX, SSL_CTX_new, SSL_CTX_free, SSL_CTX_up_ref>::SslWithRc;

    void SetOptions(long options)
    {
        if (SSL_CTX_set_options(Get(), options) == 0)
            throw SslException("SSL_CTX_set_options failed");
    }
    void ClearOptions(long options)
    {
        if (SSL_CTX_clear_options(Get(), options) == 0)
            throw SslException("SSL_CTX_clear_options failed");
    }
    void SetCipherList(const std::string &ciphers)
    {
        if (SSL_CTX_set_cipher_list(Get(), ciphers.c_str()) == 0)
            throw SslException("SSL_CTX_set_cipher_list failed");
    }
    void SetCurvesList(const std::string &curves)
    {
        if (SSL_CTX_set1_curves_list(Get(), curves.c_str()) == 0)
            throw SslException("SSL_CTX_set1_curves_list failed");
    }
    void SetVerifyMode(int mode, int (*callback)(int, X509_STORE_CTX *) = nullptr) noexcept
    {
        SSL_CTX_set_verify(Get(), mode, callback);
    }
    void SetVerifyDepth(int depth) noexcept
    {
        SSL_CTX_set_verify_depth(Get(), depth);
    }
    void SetDefaultVerifyPaths()
    {
        if (SSL_CTX_set_default_verify_paths(Get()) == 0)
            throw SslException("SSL_CTX_set_default_verify_paths failed");
    }
    void UsePrivateKeyFile(const std::filesystem::path &pvtKeyFile)
    {
        if (SSL_CTX_use_PrivateKey_file(Get(), pvtKeyFile.string().c_str(), SSL_FILETYPE_PEM) == 0)
            throw SslException("SSL_CTX_use_PrivateKey_file failed");
    }
    void UseCertificateChainFile(const std::filesystem::path &certFile)
    {
        if (SSL_CTX_use_certificate_chain_file(Get(), certFile.string().c_str()) == 0)
            throw SslException("SSL_CTX_use_certificate_chain_file failed");
    }

    /// Load certificate from X509 object
    void UseCertificate(SslX509 &cert)
    {
        if (SSL_CTX_use_certificate(Get(), cert.Get()) != 1)
            throw SslException("SSL_CTX_use_certificate failed");
    }

    /// Load certificate from PEM string
    void UseCertificatePem(std::string_view pem)
    {
        SslX509 cert(pem);
        UseCertificate(cert);
    }

    /// Load private key from EVP_PKEY object
    void UsePrivateKey(SslEvpKey &pkey)
    {
        if (SSL_CTX_use_PrivateKey(Get(), pkey.Get()) != 1)
            throw SslException("SSL_CTX_use_PrivateKey failed");
    }

    /// Load private key from PEM string
    void UsePrivateKeyPem(std::string_view pem)
    {
        SslEvpKey pkey(pem);
        UsePrivateKey(pkey);
    }

    void LoadVerifyFile(const std::filesystem::path &caFile)
    {
        if (SSL_CTX_load_verify_file(Get(), caFile.string().c_str()) == 0)
            throw SslException("SSL_CTX_load_verify_file failed");
    }

    /// Load CA certificate from PEM string for verification
    void LoadVerifyPem(std::string_view pem)
    {
        SslX509 ca_cert(pem);
        X509_STORE *store = SSL_CTX_get_cert_store(Get());
        if (!store)
            throw SslException("SSL_CTX_get_cert_store returned null");
        if (X509_STORE_add_cert(store, ca_cert.Get()) != 1)
            throw SslException("X509_STORE_add_cert failed for CA PEM");
    }
    void SetMinProtoVersion(int version)
    {
        if (SSL_CTX_set_min_proto_version(Get(), version) == 0)
            throw SslException("SSL_CTX_set_min_proto_version failed");
    }
    void SetMaxProtoVersion(int version)
    {
        if (SSL_CTX_set_max_proto_version(Get(), version) == 0)
            throw SslException("SSL_CTX_set_max_proto_version failed");
    }
    bool SetCipherListNoEx(const char *ciphers)
    {
        return (SSL_CTX_set_cipher_list(Get(), ciphers) == 1);
    }
    void SetCipherList(const char *ciphers)
    {
        if (!SetCipherListNoEx(ciphers))
            throw SslException("SSL_CTX_set_cipher_list failed");
    }
    bool SetMaxSendFragmentNoEx(size_t fragment_size)
    {
        return (SSL_CTX_set_max_send_fragment(Get(), fragment_size) == 1);
    }
    void SetMaxSendFragment(size_t fragment_size)
    {
        if (!SetMaxSendFragmentNoEx(fragment_size))
            throw SslException("SSL_CTX_set_max_send_fragment failed");
    }

    // ========================================================================================
    // QUIC TLS Support (requires quictls/openssl)
    // ========================================================================================
#ifdef CLV_HAS_QUIC_TLS
    /**
     * @brief Set ALPN protocols for QUIC (client-side)
     * @param protos Wire-format ALPN list (length-prefixed strings)
     */
    void SetAlpnProtos(std::span<const std::uint8_t> protos)
    {
        // SSL_CTX_set_alpn_protos returns 0 on success (unlike most OpenSSL functions!)
        if (SSL_CTX_set_alpn_protos(Get(), protos.data(), static_cast<unsigned int>(protos.size())) != 0)
            throw SslException("SSL_CTX_set_alpn_protos failed");
    }

    /// ALPN selection callback type
    using AlpnSelectCb = int (*)(SSL *, const unsigned char **, unsigned char *,
                                 const unsigned char *, unsigned int, void *);

    /**
     * @brief Set ALPN selection callback (server-side)
     * @param cb Callback function to select ALPN protocol
     * @param arg User data passed to callback
     */
    void SetAlpnSelectCb(AlpnSelectCb cb, void *arg) noexcept
    {
        SSL_CTX_set_alpn_select_cb(Get(), cb, arg);
    }
#endif // CLV_HAS_QUIC_TLS
};



// ================================================================================================
//  Helpers
// ================================================================================================

/**
    @brief Create a new basic SSL_CTX object for a server
    @param method The SSL_METHOD to use, often something like SSLv23_method() but can be customized
    @param pemFile The path to the PEM file containing the server certificate
    @param pvtKeyFile The path to the PEM file containing the server private key
    @return SslContext A new SSL_CTX object for a server
*/
inline SslContext MakeSslServerContext(const SSL_METHOD *method,
                                       std::filesystem::path pemFile,
                                       std::optional<std::filesystem::path> pvtKeyFile = std::nullopt)
{
    auto server = SslContext(method);

    server.UseCertificateChainFile(pemFile);
    if (pvtKeyFile)
        server.UsePrivateKeyFile(*pvtKeyFile);

    return server;
}

/**
    @brief Create a new basic SSL_CTX object for a client
    @param method The SSL_METHOD to use, often something like SSLv23_method() but can be customized
    @param pemFile The path to the PEM file containing the CA certificate
    @param pvtKeyFile The path to the PEM file containing the client private key
    @return SslContext A new SSL_CTX object for a client
*/
inline SslContext MakeSslClientContext(const SSL_METHOD *method,
                                       std::filesystem::path pemFile,
                                       std::optional<std::filesystem::path> pvtKeyFile = std::nullopt)
{
    auto client = SslContext(method);

    client.LoadVerifyFile(pemFile);
    if (pvtKeyFile)
        client.UsePrivateKeyFile(*pvtKeyFile);

    return client;
}

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_SSL_CONTEXT_H