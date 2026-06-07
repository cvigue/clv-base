// Copyright (c) 2025- Charlie Vigue. All rights reserved.
//
// QUIC TLS Helper Header
// Provides convenience types and functions for QUIC TLS using quictls/openssl.

#ifndef CLV_SSLHELP_QUIC_H
#define CLV_SSLHELP_QUIC_H

// SslHelp core headers
#include "HelpSslContext.h"
#include <openssl/prov_ssl.h>
#include <openssl/ssl.h>

namespace clv::OpenSSL {

// ============================================================================
// Helper Functions for QUIC TLS
// ============================================================================

/**
 * @brief Create a server SSL_CTX for QUIC (TLS 1.3 only)
 * @param minVer Minimum TLS version (default TLS 1.3)
 * @param maxVer Maximum TLS version (default TLS 1.3)
 * @return SslContext configured for QUIC server use
 *
 */
inline SslContext CreateServerContext(int minVer = TLS1_3_VERSION, int maxVer = TLS1_3_VERSION)
{
    SslContext ctx(TLS_server_method());
    ctx.SetMinProtoVersion(minVer);
    ctx.SetMaxProtoVersion(maxVer);
    return ctx;
}

/**
 * @brief Create a client SSL_CTX for QUIC (TLS 1.3 only)
 * @param minVer Minimum TLS version (default TLS 1.3)
 * @param maxVer Maximum TLS version (default TLS 1.3)
 * @return SslContext configured for QUIC client use
 *
 */
inline SslContext CreateClientContext(int minVer = TLS1_3_VERSION, int maxVer = TLS1_3_VERSION)
{
    SslContext ctx(TLS_client_method());
    ctx.SetMinProtoVersion(minVer);
    ctx.SetMaxProtoVersion(maxVer);
    return ctx;
}

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_QUIC_H
