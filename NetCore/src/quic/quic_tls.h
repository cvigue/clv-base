// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_QUIC_TLS_H
#define CLV_QUIC_TLS_H

// Use SslHelp QUIC-compatible wrappers (works with quictls/openssl)
#include "HelpSslContext.h"
#include "HelpSslSsl.h"
#include "HelpSslException.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <openssl/tls1.h>
#include <optional>
#include <span>
#include <spdlog/spdlog.h>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// OpenSSL/quictls headers
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

namespace clv::quic {

using clv::OpenSSL::SslContext;
using clv::OpenSSL::SslException;
using clv::OpenSSL::SslSsl;

/**
 * @brief QUIC encryption level (matches quictls/openssl's ssl_encryption_level_t)
 */
enum class QuicEncryptionLevel : int
{
    Initial = 0,    // ssl_encryption_initial
    EarlyData = 1,  // ssl_encryption_early_data (0-RTT)
    Handshake = 2,  // ssl_encryption_handshake
    Application = 3 // ssl_encryption_application (1-RTT)
};

constexpr int QuicEncryptionLevelCount = 4;

/**
 * @brief QUIC TLS implementation using quictls/openssl's QUIC API
 *
 * This class provides TLS 1.3 handshake support for QUIC using the
 * SSL_set_quic_method() API, which properly separates handshake data by
 * encryption level. Uses quictls/openssl.
 *
 * Usage:
 *   1. Create with CreateServer() or CreateClient()
 *   2. Set callbacks with SetSecretCallback() and SetHandshakeDataCallback()
 *   3. Call ProvideData() with incoming CRYPTO frame data at the appropriate level
 *   4. Call Advance() to run TLS state machine
 *   5. Callbacks will be invoked with secrets and outgoing handshake data
 *   6. Repeat until IsComplete() returns true
 */
class QuicTls
{
  public:
    /// Callback for when TLS secrets become available
    /// @param level The encryption level for these secrets
    /// @param cipher The cipher suite (for key derivation info)
    /// @param read_secret Secret for decrypting (client→server for server, vice versa)
    /// @param write_secret Secret for encrypting (server→client for server, vice versa)
    using SecretCallback = std::function<void(QuicEncryptionLevel level,
                                              const SSL_CIPHER *cipher,
                                              std::span<const std::uint8_t> read_secret,
                                              std::span<const std::uint8_t> write_secret)>;

    /// Callback for outgoing handshake data (CRYPTO frame payload)
    /// @param level The encryption level to send this data at
    /// @param data The TLS handshake message data
    using HandshakeDataCallback = std::function<void(QuicEncryptionLevel level,
                                                     std::span<const std::uint8_t> data)>;

    /// Callback for TLS alerts
    using AlertCallback = std::function<void(QuicEncryptionLevel level,
                                             std::uint8_t alert)>;

    /// Create server-side TLS from file paths
    static QuicTls CreateServer(std::string_view cert_path, std::string_view key_path);

    /// Create server-side TLS from PEM strings
    static QuicTls CreateServerFromPem(std::string_view cert_pem, std::string_view key_pem);

    /// Create client-side TLS
    static QuicTls CreateClient(std::string_view sni = {});

    /// Create client-side TLS with client certificate (for mutual TLS)
    static QuicTls CreateClientFromPem(std::string_view cert_pem, std::string_view key_pem, std::string_view sni = {});

    ~QuicTls();

    // Move-only
    QuicTls(const QuicTls &) = delete;
    QuicTls &operator=(const QuicTls &) = delete;
    QuicTls(QuicTls &&other) noexcept;
    QuicTls &operator=(QuicTls &&other) noexcept;

    /// Set callback for when secrets become available
    void SetSecretCallback(SecretCallback cb);

    /// Set callback for outgoing handshake data
    void SetHandshakeDataCallback(HandshakeDataCallback cb);

    /// Set callback for TLS alerts
    void SetAlertCallback(AlertCallback cb);

    /// Set ALPN protocols for negotiation
    void SetAlpn(std::span<const std::string_view> protocols);

    /// Get negotiated ALPN after handshake
    [[nodiscard]] std::optional<std::string> GetAlpn() const;

    /// Set QUIC transport parameters (must be called before Advance())
    /// @param params Encoded transport parameters
    /// @return true on success, false on error
    void SetTransportParameters(std::span<const std::uint8_t> params);

    /// Provide incoming CRYPTO frame data at a specific encryption level
    /// @return true on success, false on error
    bool ProvideData(QuicEncryptionLevel level, std::span<const std::uint8_t> data);

    /// Run TLS state machine (SSL_do_handshake)
    /// @return 1=complete, 0=need more data, -1=error
    int Advance();

    /// Check if handshake is complete
    [[nodiscard]] bool IsComplete() const noexcept;

    /// Get error string for last error
    [[nodiscard]] static std::string GetErrorString();

    /// Get the current write encryption level
    [[nodiscard]] QuicEncryptionLevel GetWriteLevel() const;

    /// Get the current read encryption level
    [[nodiscard]] QuicEncryptionLevel GetReadLevel() const;

    /// Get the raw SSL pointer (for advanced use)
    [[nodiscard]] SSL *GetSsl() noexcept
    {
        return mSsl.Get();
    }

    /// Get peer certificate after handshake completes (server: client cert, client: server cert)
    /// @return PEM-encoded certificate, or nullopt if not available
    [[nodiscard]] std::optional<std::string> GetPeerCertificatePem() const;

  private: // Internal functions
    QuicTls(SslContext ctx, SslSsl ssl, bool isServer);

    // QUIC method callbacks (static, use SSL ex_data to get 'this')
    // quictls uses set_encryption_secrets which provides both read and write secrets at once
    static int SetEncryptionSecretsCb(SSL *ssl, ssl_encryption_level_t level,
                                      const uint8_t *read_secret, const uint8_t *write_secret,
                                      size_t secret_len);
    static int AddHandshakeDataCb(SSL *ssl, ssl_encryption_level_t level,
                                  const uint8_t *data, size_t len);
    static int FlushFlightCb(SSL *ssl);
    static int SendAlertCb(SSL *ssl, ssl_encryption_level_t level, uint8_t alert);

    // Convert between our enum and OpenSSL's
    static QuicEncryptionLevel FromSsl(ssl_encryption_level_t level);

    static ssl_encryption_level_t ToSsl(QuicEncryptionLevel level);

  private: // Data members
    SslContext mCtx;
    SslSsl mSsl;
    bool mIsServer = false;
    bool mComplete = false;

    SecretCallback mSecretCallback;
    HandshakeDataCallback mHandshakeDataCallback;
    AlertCallback mAlertCallback;
};

// ============================================================================
// Implementation
// ============================================================================

inline QuicTls::QuicTls(SslContext ctx, SslSsl ssl, bool isServer)
    : mCtx(std::move(ctx)), mSsl(std::move(ssl)), mIsServer(isServer)
{
    // Store 'this' pointer in SSL ex_data for callbacks
    mSsl.SetExData(0, this);

    // Set up QUIC method callbacks
    // quictls uses set_encryption_secrets (combined read/write) instead of separate callbacks
    static const SSL_QUIC_METHOD quic_method = {
        SetEncryptionSecretsCb,
        AddHandshakeDataCb,
        FlushFlightCb,
        SendAlertCb};

    mSsl.SetQuicMethod(&quic_method);
}

inline QuicTls::~QuicTls() = default;

inline QuicTls::QuicTls(QuicTls &&other) noexcept
    : mCtx(std::move(other.mCtx)), mSsl(std::move(other.mSsl)), mIsServer(other.mIsServer),
      mComplete(other.mComplete), mSecretCallback(std::move(other.mSecretCallback)),
      mHandshakeDataCallback(std::move(other.mHandshakeDataCallback)),
      mAlertCallback(std::move(other.mAlertCallback))
{
    mSsl.SetExData(0, this);
}

inline QuicTls &QuicTls::operator=(QuicTls &&other) noexcept
{
    if (this != &other)
    {
        mCtx = std::move(other.mCtx);
        mSsl = std::move(other.mSsl);
        mIsServer = other.mIsServer;
        mComplete = other.mComplete;
        mSecretCallback = std::move(other.mSecretCallback);
        mHandshakeDataCallback = std::move(other.mHandshakeDataCallback);
        mAlertCallback = std::move(other.mAlertCallback);

        if (mSsl)
            mSsl.SetExData(0, this);
    }
    return *this;
}

inline QuicTls QuicTls::CreateServer(std::string_view cert_path, std::string_view key_path)
{
    auto ctx = OpenSSL::CreateQuicServerContext();
    ctx.UseCertificateChainFile(cert_path);
    ctx.UsePrivateKeyFile(key_path);

    SslSsl ssl(ctx);
    ssl.SetAcceptState();

    return QuicTls(std::move(ctx), std::move(ssl), true);
}

inline QuicTls QuicTls::CreateServerFromPem(std::string_view cert_pem, std::string_view key_pem)
{
    auto ctx = OpenSSL::CreateQuicServerContext();
    ctx.UseCertificatePem(cert_pem);
    ctx.UsePrivateKeyPem(key_pem);

    // Request client certificate for peer identification (mutual TLS)
    // Use a custom verify callback that always succeeds - we extract peer identity from cert
    // but don't validate against a CA (self-signed mesh network)
    ctx.SetVerifyMode(SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                      [](int /* preverify_ok */, X509_STORE_CTX * /* ctx */) -> int
    {
        // Always accept - we just want the certificate for identity
        return 1;
    });

    SslSsl ssl(ctx);
    ssl.SetAcceptState();

    return QuicTls(std::move(ctx), std::move(ssl), true);
}

inline QuicTls QuicTls::CreateClient(std::string_view sni)
{
    auto ctx = OpenSSL::CreateQuicClientContext();

    SslSsl ssl(ctx);
    ssl.SetConnectState();

    if (!sni.empty())
        ssl.SetTlsSni(sni);

    return QuicTls(std::move(ctx), std::move(ssl), false);
}

inline QuicTls QuicTls::CreateClientFromPem(std::string_view cert_pem, std::string_view key_pem, std::string_view sni)
{
    auto ctx = OpenSSL::CreateQuicClientContext();

    // Load client certificate and key for mutual TLS
    ctx.UseCertificatePem(cert_pem);
    ctx.UsePrivateKeyPem(key_pem);

    // Accept server certificate for peer identification
    // Use a custom verify callback that always succeeds - we extract peer identity from cert
    // but don't validate against a CA (self-signed mesh network)
    ctx.SetVerifyMode(SSL_VERIFY_PEER,
                      [](int /* preverify_ok */, X509_STORE_CTX * /* ctx */) -> int
    {
        // Always accept - we just want the certificate for identity
        return 1;
    });

    SslSsl ssl(ctx);
    ssl.SetConnectState();

    if (!sni.empty())
        ssl.SetTlsSni(sni);

    return QuicTls(std::move(ctx), std::move(ssl), false);
}

inline void QuicTls::SetSecretCallback(SecretCallback cb)
{
    mSecretCallback = std::move(cb);
}

inline void QuicTls::SetHandshakeDataCallback(HandshakeDataCallback cb)
{
    mHandshakeDataCallback = std::move(cb);
}

inline void QuicTls::SetAlertCallback(AlertCallback cb)
{
    mAlertCallback = std::move(cb);
}

inline void QuicTls::SetAlpn(std::span<const std::string_view> protocols)
{
    if (protocols.empty())
        return;

    // Build ALPN wire format: length-prefixed strings
    std::vector<unsigned char> alpn;
    for (const auto &p : protocols)
    {
        if (p.size() > 255)
            continue;
        alpn.push_back(static_cast<unsigned char>(p.size()));
        alpn.insert(alpn.end(), p.begin(), p.end());
    }

    if (mIsServer)
    {
        // Server: use callback to select protocol
        auto cb = [](SSL *, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *) -> int
        {
            // Select "h3" if offered
            const unsigned char *p = in;
            while (p < in + inlen)
            {
                unsigned char len = *p++;
                if (p + len > in + inlen)
                    break;
                if (len == 2 && p[0] == 'h' && p[1] == '3')
                {
                    *out = p;
                    *outlen = len;
                    return SSL_TLSEXT_ERR_OK;
                }
                p += len;
            }
            return SSL_TLSEXT_ERR_NOACK;
        };
        mCtx.SetAlpnSelectCb(cb, nullptr);
    }
    else
    {
        // Client: propose protocols
        SSL_set_alpn_protos(mSsl.Get(), alpn.data(), static_cast<unsigned>(alpn.size()));
    }
}

inline void QuicTls::SetTransportParameters(std::span<const std::uint8_t> params)
{
    mSsl.SetTransportParameters(params);
}

inline std::optional<std::string> QuicTls::GetAlpn() const
{
    auto alpn = mSsl.GetAlpnSelected();
    return !alpn.empty() ? std::optional<std::string>(alpn) : std::nullopt;
}

inline bool QuicTls::ProvideData(QuicEncryptionLevel level, std::span<const std::uint8_t> data)
{
    if (data.empty())
        return true;

    int ret = SSL_provide_quic_data(mSsl.Get(), ToSsl(level), data.data(), data.size());
    return ret == 1;
}

inline int QuicTls::Advance()
{
    // Log state BEFORE handshake
    const char *state_before = SSL_state_string_long(mSsl.Get());

    int ret = mSsl.DoHandshake();

    // Log state AFTER handshake
    const char *state_after = SSL_state_string_long(mSsl.Get());

    if (ret == 1)
    {
        spdlog::debug("QuicTls::Advance: Handshake COMPLETE! is_server={}", mIsServer);
        mComplete = true;
        return 1;
    }

    int err = SSL_get_error(mSsl.Get(), ret);
    spdlog::debug("QuicTls::Advance: DoHandshake returned {}, SSL_get_error={}, is_server={}, state: {} -> {}",
                  ret,
                  err,
                  mIsServer,
                  state_before,
                  state_after);

    if (err == SSL_ERROR_WANT_READ)
    {
        spdlog::debug("QuicTls::Advance: SSL_ERROR_WANT_READ (need more incoming data)");
        return 0;
    }
    if (err == SSL_ERROR_WANT_WRITE)
    {
        spdlog::debug("QuicTls::Advance: SSL_ERROR_WANT_WRITE (should have called handshake callback)");
        return 0;
    }

    // Log the actual error
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    spdlog::error("QuicTls::Advance: TLS error {}: {}", err, buf);

    return -1; // Error
}

inline bool QuicTls::IsComplete() const noexcept
{
    return mComplete;
}

inline std::string QuicTls::GetErrorString()
{
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return std::string(buf);
}

inline QuicEncryptionLevel QuicTls::GetWriteLevel() const
{
    return FromSsl(SSL_quic_write_level(mSsl.Get()));
}

inline QuicEncryptionLevel QuicTls::GetReadLevel() const
{
    return FromSsl(SSL_quic_read_level(mSsl.Get()));
}

inline std::optional<std::string> QuicTls::GetPeerCertificatePem() const
{
    X509 *cert = SSL_get_peer_certificate(mSsl.Get());
    if (!cert)
        return std::nullopt;

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
    {
        X509_free(cert);
        return std::nullopt;
    }

    if (PEM_write_bio_X509(bio, cert) != 1)
    {
        BIO_free(bio);
        X509_free(cert);
        return std::nullopt;
    }

    char *data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string pem(data, static_cast<std::size_t>(len));

    BIO_free(bio);
    X509_free(cert);

    return pem;
}

// ============================================================================
// Static callback implementations
// ============================================================================

inline int QuicTls::SetEncryptionSecretsCb(SSL *ssl, ssl_encryption_level_t level,
                                           const uint8_t *read_secret, const uint8_t *write_secret,
                                           size_t secret_len)
{
    auto *self = static_cast<QuicTls *>(SSL_get_ex_data(ssl, 0));
    if (!self)
        return 0;

    // quictls provides both read and write secrets in one callback
    // Get the cipher from the SSL connection
    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);

    if (self->mSecretCallback)
    {
        std::span<const std::uint8_t> read_span(read_secret, secret_len);
        std::span<const std::uint8_t> write_span(write_secret, secret_len);
        self->mSecretCallback(FromSsl(level), cipher, read_span, write_span);
    }

    return 1;
}

inline int QuicTls::AddHandshakeDataCb(SSL *ssl, ssl_encryption_level_t level, const uint8_t *data, size_t len)
{
    auto *self = static_cast<QuicTls *>(SSL_get_ex_data(ssl, 0));
    if (!self)
        return 0;

    if (self->mHandshakeDataCallback)
    {
        self->mHandshakeDataCallback(FromSsl(level),
                                     std::span<const std::uint8_t>(data, len));
    }

    return 1;
}

inline int QuicTls::FlushFlightCb(SSL * /*ssl*/)
{
    // Called when quictls/openssl wants us to flush queued handshake data
    // We send immediately via callback, so nothing to do here
    return 1;
}

inline int QuicTls::SendAlertCb(SSL *ssl, ssl_encryption_level_t level, uint8_t alert)
{
    auto *self = static_cast<QuicTls *>(SSL_get_ex_data(ssl, 0));
    if (!self)
        return 0;

    if (self->mAlertCallback)
    {
        self->mAlertCallback(FromSsl(level), alert);
    }

    return 1;
}

// ============================================================================
// Conversion functions
// ============================================================================

inline QuicEncryptionLevel QuicTls::FromSsl(ssl_encryption_level_t level)
{
    return static_cast<QuicEncryptionLevel>(level);
}

inline ssl_encryption_level_t QuicTls::ToSsl(QuicEncryptionLevel level)
{
    return static_cast<ssl_encryption_level_t>(level);
}

} // namespace clv::quic

#endif // CLV_QUIC_TLS_H
