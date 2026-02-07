// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLV_SSLHELP_SSL_SSL_H
#define CLV_SSLHELP_SSL_SSL_H

#include "HelpSslWithRc.h"
#include "HelpSslContext.h"
#include "HelpSslException.h"

#include <openssl/prov_ssl.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/types.h>
#include <string>
#include <string_view>

namespace clv::OpenSSL {

/**
    @brief Simple RAII wrapper for OpenSSL SSL * with reference counting
    @details Use this when you need basic SSL lifecycle management without
             owning the BIOs. For SSL with owned BIOs, use SslSsl<> instead.
*/
struct SslSsl : SslWithRc<SSL, SSL_new, SSL_free, SSL_up_ref>
{
    using SslWithRc<SSL, SSL_new, SSL_free, SSL_up_ref>::SslWithRc;

    /// Create from SslContext
    explicit SslSsl(SslContext &ctx) : SslWithRc(SSL_new(ctx.Get()))
    {
    }

    /// Get error code for last operation
    [[nodiscard]] int GetError(int ret) const
    {
        return SSL_get_error(Get(), ret);
    }

    // ========================================================================================
    // QUIC TLS Support (requires quictls/openssl)
    // ========================================================================================
#ifdef CLV_HAS_QUIC_TLS
    /**
     * @brief Set QUIC transport parameters
     * @param params Encoded transport parameters
     */
    void SetTransportParameters(std::span<const std::uint8_t> params)
    {
        if (SSL_set_quic_transport_params(Get(), params.data(), params.size()) != 1)
            throw SslException("SSL_set_quic_transport_params failed");
    }

    /**
     * @brief Set QUIC method callbacks for TLS handshake integration
     * @param method Pointer to SSL_QUIC_METHOD structure with callbacks
     */
    void SetQuicMethod(const SSL_QUIC_METHOD *method)
    {
        if (SSL_set_quic_method(Get(), method) != 1)
            throw SslException("SSL_set_quic_method failed");
    }

    /**
     * @brief Provide QUIC handshake data received from peer
     * @param level Encryption level for this data
     * @param data Handshake data bytes
     * @return 1 on success, 0 on failure
     */
    int ProvideQuicData(OSSL_ENCRYPTION_LEVEL level, std::span<const std::uint8_t> data)
    {
        return SSL_provide_quic_data(Get(), level, data.data(), data.size());
    }

    /**
     * @brief Get current QUIC read encryption level
     */
    [[nodiscard]] OSSL_ENCRYPTION_LEVEL QuicReadLevel() const noexcept
    {
        return SSL_quic_read_level(Get());
    }

    /**
     * @brief Get current QUIC write encryption level
     */
    [[nodiscard]] OSSL_ENCRYPTION_LEVEL QuicWriteLevel() const noexcept
    {
        return SSL_quic_write_level(Get());
    }
#endif // CLV_HAS_QUIC_TLS

    /**
     * @brief Store user data in SSL object
     */
    void SetExData(int idx, void *data)
    {
        if (SSL_set_ex_data(Get(), idx, data) != 1)
            throw SslException("SSL_set_ex_data failed");
    }

    /**
     * @brief Retrieve user data from SSL object
     */
    template <typename T>
    T *GetExData(int idx) const
    {
        return static_cast<T *>(SSL_get_ex_data(Get(), idx));
    }

    /**
     * @brief Perform TLS handshake (non-blocking)
     */
    int DoHandshake()
    {
        return SSL_do_handshake(Get());
    }

    /**
     * @brief Set SSL to server mode (accept incoming connections)
     */
    void SetAcceptState() noexcept
    {
        SSL_set_accept_state(Get());
    }

    /**
     * @brief Set SSL to client mode (initiate outgoing connections)
     */
    void SetConnectState() noexcept
    {
        SSL_set_connect_state(Get());
    }

    /**
     * @brief Set TLS Server Name Indication (SNI)
     * @param sni Server hostname
     */
    void SetTlsSni(std::string_view sni)
    {
        if (SSL_set_tlsext_host_name(Get(), std::string(sni).c_str()) != 1)
            throw SslException("SSL_set_tlsext_host_name failed");
    }

    /**
     * @brief Get the negotiated ALPN protocol
     * @return Selected ALPN protocol, or empty string_view if none
     */
    [[nodiscard]] std::string_view GetAlpnSelected() const noexcept
    {
        const unsigned char *data = nullptr;
        unsigned int len = 0;
        SSL_get0_alpn_selected(Get(), &data, &len);
        return data ? std::string_view(reinterpret_cast<const char *>(data), len) : std::string_view{};
    }
};

/**
    @brief wrapper for OpenSSL SSL * with owned BIOs
    @details
*/
template <typename BIO_IN, typename BIO_OUT>
struct SslSslBio : SslSsl
{
    // Use the base boilerplate here
    using SslSsl::SslSsl;

    // Add this constructor - unwraps the wrapper and passes it on
    SslSslBio(SslContext ctx, BIO_IN &&in, BIO_OUT &&out);

    // API
    int Connect();
    int Accept();

  private:
    BIO_IN mIn;
    BIO_OUT mOut;
};

/**
     @brief Constructor for SslSsl class
     @param ctx The SSL context object
     @throws None
     @details This constructor initializes a new SslSsl object using the provided SslContext.
*/
template <typename BIO_IN, typename BIO_OUT>
inline SslSslBio<BIO_IN, BIO_OUT>::SslSslBio(SslContext ctx, BIO_IN &&in, BIO_OUT &&out)
    : SslSsl(ctx), mIn(std::move(in)), mOut(std::move(out))
{
    SSL_set_bio(Get(), mIn.Copy(), mOut.Copy());
}
/**
     @brief Establishes an SSL/TLS connection on the underlying socket.
     @return The return value from SSL_connect(). 0 on success, or a negative error code on failure.
     @throws Exceptions may be thrown by the underlying SSL_connect() call.
     @details This function attempts to establish an SSL/TLS connection on the underlying socket.
              It must be called after setting up the SSL context and performing any required
              handshake steps.
*/
template <typename BIO_IN, typename BIO_OUT>
inline int SslSslBio<BIO_IN, BIO_OUT>::Connect()
{
    return SSL_connect(Get());
}
/**
     @brief Performs the SSL/TLS handshake on the underlying socket.
     @return The return value from SSL_accept(). 0 on success, or a negative error code on failure.
     @throws std::runtime_error if the SSL_accept() call fails.
     @details This function attempts to perform the SSL/TLS handshake on the underlying socket.
              It must be called after setting up the SSL context and setting the underlying socket.
              If the handshake is successful, the connection is ready for data transfer.
*/
template <typename BIO_IN, typename BIO_OUT>
inline int SslSslBio<BIO_IN, BIO_OUT>::Accept()
{
    return SSL_accept(Get());
}

// ================================================================================================
//  Helpers
// ================================================================================================

/**
 * @brief Create server SSL from context
 */
inline SslSsl CreateServerSsl(SslContext &ctx)
{
    SslSsl ssl(ctx);
    ssl.SetAcceptState();
    return ssl;
}

/**
 * @brief Create client SSL from context
 * @param ctx SSL context
 * @param sni Optional Server Name Indication hostname
 */
inline SslSsl CreateClientSsl(SslContext &ctx, const char *sni = nullptr)
{
    SslSsl ssl(ctx);
    ssl.SetConnectState();
    if (sni)
        ssl.SetTlsSni(sni);
    return ssl;
}

/**
 * @brief Create a server SSL_CTX for QUIC (TLS 1.3 only)
 */
inline SslContext CreateQuicServerContext()
{
    SslContext ctx(TLS_server_method());
    ctx.SetMinProtoVersion(TLS1_3_VERSION);
    ctx.SetMaxProtoVersion(TLS1_3_VERSION);
    return ctx;
}

/**
 * @brief Create a client SSL_CTX for QUIC (TLS 1.3 only)
 */
inline SslContext CreateQuicClientContext()
{
    SslContext ctx(TLS_client_method());
    ctx.SetMinProtoVersion(TLS1_3_VERSION);
    ctx.SetMaxProtoVersion(TLS1_3_VERSION);
    return ctx;
}

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_SSL_SSL_H