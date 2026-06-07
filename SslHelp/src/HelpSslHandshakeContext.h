// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_SSLHELP_SSL_HANDSHAKE_CONTEXT_H
#define CLV_SSLHELP_SSL_HANDSHAKE_CONTEXT_H

#include "HelpSslContext.h"
#include "HelpSslException.h"
#include "HelpSslMemBio.h"
#include "HelpSslSsl.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <openssl/tls1.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace clv::OpenSSL {

/**
 * @brief Manages TLS handshake state using memory BIOs
 *
 * Encapsulates the complete TLS handshake process with manual data flow control.
 * Abstracts away raw OpenSSL API calls (SSL_do_handshake, SSL_get_error, etc).
 *
 * Usage:
 *   SslHandshakeContext handshake(ctx, true);  // true = server
 *   while (!handshake.IsComplete()) {
 *       auto response = handshake.ProcessIncomingData(peer_data);
 *       SendToPeer(response);
 *   }
 *   auto key_material = handshake.ExportKeyMaterial("label", 32);
 */
class SslHandshakeContext
{
  public:
    enum class Result
    {
        WantMoreData,  ///< Handshake needs more input data
        HasDataToSend, ///< Handshake produced data to send
        Complete,      ///< Handshake completed successfully
        Failed         ///< Handshake encountered fatal error
    };

  private:
    SslSsl ssl_;
    SslMemBio bios_;
    bool handshakeComplete_ = false;
    int lastError_ = 0;

    // Common initialization for both constructors
    void InitializeHandshake(bool is_server);

    // Process handshake and capture errors
    Result AdvanceHandshake();

    /** @brief Silently drain OpenSSL error queue (non-fatal paths) */
    void DiscardErrors();

    /** @brief Drain OpenSSL error queue and throw SslException (fatal paths) */
    [[noreturn]] void ThrowSslErrors(std::string_view context);

  public:
    /**
     * @brief Create a handshake context
     * @param ctx SSL context (server or client)
     * @param is_server true for server mode, false for client
     * @throws SslException on initialization failure
     */
    SslHandshakeContext(SslContext &ctx, bool is_server)
        : ssl_(ctx)
    {
        ssl_.ThrowIfNull("SslHandshakeContext & constructor received null SslContext");
        InitializeHandshake(is_server);
    }

    /**
     * @brief Create a handshake context (move semantics)
     * @param ctx SSL context (server or client) - moved
     * @param is_server true for server mode, false for client
     * @throws SslException on initialization failure
     */
    SslHandshakeContext(SslContext &&ctx, bool is_server)
        : ssl_(std::move(ctx))
    {
        ssl_.ThrowIfNull("SslHandshakeContext && constructor received null SslContext");
        InitializeHandshake(is_server);
    }

    ~SslHandshakeContext() = default;

    // Non-copyable, movable
    SslHandshakeContext(const SslHandshakeContext &) = delete;
    SslHandshakeContext &operator=(const SslHandshakeContext &) = delete;
    SslHandshakeContext(SslHandshakeContext &&) = default;
    SslHandshakeContext &operator=(SslHandshakeContext &&) = default;

    /**
     * @brief Process incoming TLS data and advance handshake
     * @param data TLS record/handshake data from peer
     * @return Result indicating handshake state
     */
    Result ProcessIncomingData(std::span<const std::uint8_t> data)
    {
        if (handshakeComplete_)
            return Result::Complete;

        if (HasError())
            return Result::Failed;

        // Feed data to input BIO
        if (data.size() > 0)
        {
            int written = bios_.WriteInput(data);
            if (written < 0)
            {
                lastError_ = SSL_ERROR_SYSCALL;
                ThrowSslErrors("BIO write failed");
            }
        }

        return AdvanceHandshake();
    }

    /**
     * @brief Get all pending output data to send to peer
     * @return Vector containing TLS records to transmit
     */
    std::vector<std::uint8_t> GetPendingOutput()
    {
        return bios_.ReadOutput();
    }

    /**
     * @brief Check if handshake is complete
     */
    bool IsComplete() const
    {
        return handshakeComplete_;
    }

    /**
     * @brief Check if handshake failed
     */
    bool HasError() const
    {
        return lastError_ != SSL_ERROR_NONE && lastError_ != SSL_ERROR_WANT_READ && lastError_ != SSL_ERROR_WANT_WRITE;
    }

    /**
     * @brief Get the last SSL error code
     */
    int GetLastError() const
    {
        return lastError_;
    }

    /**
     * @brief Get human-readable error message
     */
    std::string GetErrorString() const
    {
        if (lastError_ == 0)
            return "No error";

        const char *err_string = nullptr;

        switch (lastError_)
        {
        case SSL_ERROR_ZERO_RETURN:
            err_string = "Connection closed cleanly";
            break;
        case SSL_ERROR_WANT_READ:
            err_string = "Need more input data";
            break;
        case SSL_ERROR_WANT_WRITE:
            err_string = "Need to send pending data";
            break;
        case SSL_ERROR_WANT_CONNECT:
            err_string = "Connection pending";
            break;
        case SSL_ERROR_WANT_ACCEPT:
            err_string = "Accept pending";
            break;
        case SSL_ERROR_WANT_X509_LOOKUP:
            err_string = "X.509 lookup pending";
            break;
        case SSL_ERROR_SYSCALL:
            err_string = "System error";
            break;
        case SSL_ERROR_SSL:
            err_string = "SSL protocol error";
            break;
        default:
            err_string = "Unknown error";
        }

        return std::string(err_string) + " (code=" + std::to_string(lastError_) + ")";
    }

    /**
     * @brief Get the negotiated cipher suite name
     * @return Cipher name (e.g., "TLS_AES_256_GCM_SHA384"), or empty if handshake not complete
     */
    std::string GetCipherName() const
    {
        if (!handshakeComplete_)
            return "";
        const char *name = SSL_get_cipher_name(ssl_.Get());
        return name ? name : "";
    }

    /**
     * @brief Export keying material from TLS session using RFC 5705
     * @param label PRF label (e.g., "EXPORTER-OpenVPN-datakeys")
     * @param context Optional context data for key derivation
     * @param length Bytes to export
     * @return Key material, or nullopt if handshake not complete
     */
    std::optional<std::vector<std::uint8_t>>
    ExportKeyMaterial(std::string_view label,
                      std::span<const std::uint8_t> context,
                      size_t length) const
    {
        if (!handshakeComplete_)
            return std::nullopt;

        std::vector<std::uint8_t> result(length);

        // Use TLS exporter (RFC 5705)
        // Note: label must be null-terminated, which string_view doesn't guarantee
        std::string label_str(label);

        // const_cast: SSL_export_keying_material is logically const (read-only derivation
        // from the completed TLS session) but OpenSSL's API lacks const-correctness.
        // Safe because ssl_ is a non-const member; a const method only makes it a const
        // reference, not originally-declared-const storage.
        int rc = SSL_export_keying_material(const_cast<SSL *>(ssl_.Get()),
                                            result.data(),
                                            length,
                                            label_str.c_str(),
                                            label_str.size(),
                                            context.data(),
                                            context.size(),
                                            context.empty() ? 0 : 1 // use_context flag
        );

        if (rc != 1)
            return std::nullopt;

        return result;
    }

    /**
     * @brief Write application data to TLS tunnel (encrypt)
     * @param data Plaintext data to encrypt and send
     * @return Number of bytes written, or -1 on error
     *
     * After calling this, use GetPendingOutput() to get encrypted TLS records.
     */
    int WriteAppData(std::span<const std::uint8_t> data)
    {
        if (!handshakeComplete_)
            return -1;

        int written = SSL_write(ssl_.Get(), data.data(), static_cast<int>(data.size()));
        if (written <= 0)
        {
            lastError_ = ssl_.GetError(written);
            if (lastError_ != SSL_ERROR_WANT_WRITE)
                ThrowSslErrors("SSL_write failed");
            return -1;
        }
        return written;
    }

    /**
     * @brief Read decrypted application data from TLS tunnel
     * @return Decrypted plaintext, or empty vector if no data/error
     *
     * Call this after feeding encrypted data via ProcessIncomingData().
     */
    std::vector<std::uint8_t> ReadAppData()
    {
        if (!handshakeComplete_)
            return {};

        std::vector<std::uint8_t> result;
        std::array<std::uint8_t, 4096> buffer;

        while (true)
        {
            int read = SSL_read(ssl_.Get(), buffer.data(), static_cast<int>(buffer.size()));
            if (read > 0)
            {
                result.insert(result.end(), buffer.begin(), buffer.begin() + read);
            }
            else
            {
                lastError_ = ssl_.GetError(read);
                if (lastError_ != SSL_ERROR_WANT_READ)
                    ThrowSslErrors("SSL_read failed");
                break;
            }
        }
        return result;
    }

    /**
     * @brief Feed incoming encrypted TLS data after handshake complete
     * @param data Encrypted TLS records from peer
     * @return true if data was written to input BIO successfully
     *
     * After calling this, use ReadAppData() to get decrypted plaintext.
     */
    bool FeedEncryptedData(std::span<const std::uint8_t> data)
    {
        if (!handshakeComplete_)
            return false;

        if (data.empty())
            return true;

        int written = bios_.WriteInput(data);
        return written >= 0;
    }
};

// ================================ INLINE IMPLEMENTATIONS ================================

inline void SslHandshakeContext::InitializeHandshake(bool is_server)
{
    // Attach memory BIOs to SSL object
    bios_.AttachToSSL(ssl_);

    // Set handshake state
    if (is_server)
    {
        SSL_set_accept_state(ssl_.Get());
    }
    else
    {
        SSL_set_connect_state(ssl_.Get());
    }

    // Configure for manual I/O control
    SSL_set_mode(ssl_.Get(), SSL_MODE_AUTO_RETRY | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
}

inline SslHandshakeContext::Result SslHandshakeContext::AdvanceHandshake()
{
    int ret = SSL_do_handshake(ssl_.Get());

    if (ret == 1)
    {
        // Handshake complete
        handshakeComplete_ = true;
        return Result::Complete;
    }

    if (ret <= 0)
    {
        lastError_ = ssl_.GetError(ret);

        if (lastError_ == SSL_ERROR_WANT_READ || lastError_ == SSL_ERROR_WANT_WRITE)
        {
            // Non-fatal, handshake needs more data
            DiscardErrors();
            return Result::WantMoreData;
        }

        // Fatal error
        ThrowSslErrors("TLS handshake failed");
    }

    // Handshake produced output
    DiscardErrors();
    return Result::HasDataToSend;
}

inline void SslHandshakeContext::DiscardErrors()
{
    while (ERR_get_error() != 0)
    {
    }
}

inline void SslHandshakeContext::ThrowSslErrors(std::string_view context)
{
    std::string detail;
    char buf[256];
    unsigned long err;
    while ((err = ERR_get_error()) != 0)
    {
        ERR_error_string_n(err, buf, sizeof(buf));
        if (!detail.empty())
            detail += "; ";
        detail += buf;
    }
    if (detail.empty())
        throw SslException(std::string(context));
    throw SslException(std::string(context) + ": " + detail);
}

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_SSL_HANDSHAKE_CONTEXT_H
