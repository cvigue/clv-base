// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_SSLHELP_SSL_EXCEPTION_H
#define CLV_SSLHELP_SSL_EXCEPTION_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <source_location>
#include <string>
#include <string_view>
#include <utility>

#include <openssl/err.h>
#include <openssl/pemerr.h>
#include <openssl/ssl.h>
#include <stdexcept>

namespace clv::OpenSSL {

/** @brief Maximum OpenSSL packed codes retained on @c SslError (queue still drains past this). */
inline constexpr std::size_t kSslMaxErrors = 8;

/**
 * @brief Library-level OpenSSL / quictls error buckets.
 * @details Not a VPN/product policy enum — consumers map further onto their own policy.
 */
enum class SslErrorKind : std::uint8_t
{
    None = 0,    ///< Empty / unclassified (e.g. capture with empty ERR queue)
    App,         ///< Message-only / precondition (no ERR / no SSL_get_error)
    Library,     ///< Generic OpenSSL library error
    Syscall,     ///< SSL_ERROR_SYSCALL
    WantIo,      ///< WANT_READ / WANT_WRITE / …
    CertVerify,  ///< SSL_R_CERTIFICATE_VERIFY_FAILED
    PemPassword, ///< PEM_R_BAD_PASSWORD_READ / BAD_DECRYPT
    TlsVersion,  ///< SSL_R_UNSUPPORTED_PROTOCOL
    TlsAlert,    ///< reason >= SSL_AD_REASON_OFFSET (incl. named alerts)
    AuthTag,     ///< AEAD tag mismatch (app-tagged; may have empty ERR queue)
};

/**
 * @brief Structured OpenSSL / quictls error snapshot (non-throwing primary type).
 * @details Construct only via @c capture / @c app / @c auth_tag. Factories that touch the
 *          ERR queue drain it to empty (type invariant). Owns copied codes + formatted message;
 *          not an RAII guard of OpenSSL state after construction.
 */
class SslError
{
    // Use the factories below to construct SslError objects.
    SslError() = default;

  public:
    /**
     * @brief Capture the current thread-local ERR queue after an OpenSSL API failure.
     * @param context Call-site description prepended to the formatted message
     * @param ssl_error Optional @c SSL_get_error value (-1 = none)
     * @return Snapshot with retained codes (≤ @c kSslMaxErrors), kind, and message
     * @note Drains the ERR queue to empty (keeps draining past @c kSslMaxErrors).
     */
    static SslError capture(std::string_view context, int ssl_error = -1);

    /**
     * @brief Build an application / precondition failure (not an OpenSSL API report).
     * @param context Call-site description (becomes the message body)
     * @param kind Error kind (default @c SslErrorKind::App)
     * @param drain_stale If true, discard any stale ERR entries without retaining them
     * @return Snapshot with the given kind; typically no retained OpenSSL codes
     * @note Soft-fail paths that need the ERR queue should clear with @c ERR_clear_error
     *       instead of relying on this factory.
     */
    static SslError app(std::string_view context,
                        SslErrorKind kind = SslErrorKind::App,
                        bool drain_stale = true);

    /**
     * @brief AEAD authentication-tag mismatch (app-tagged failure).
     * @param context Call-site description
     * @return Snapshot with @c SslErrorKind::AuthTag (stale ERR discarded)
     */
    static SslError auth_tag(std::string_view context);

    /** @brief Classified error kind. */
    [[nodiscard]] SslErrorKind kind() const noexcept;
    /** @brief Stored @c SSL_get_error value, or -1 if none. */
    [[nodiscard]] int ssl_error() const noexcept;
    /** @brief TLS alert description code, or -1 if none. */
    [[nodiscard]] int alert() const noexcept;
    /** @brief Number of retained OpenSSL packed codes. */
    [[nodiscard]] std::size_t size() const noexcept;
    /**
     * @brief Packed OpenSSL error code at index @p i.
     * @return Code, or 0 if @p i is out of range
     */
    [[nodiscard]] unsigned long code(std::size_t i) const noexcept;
    /** @brief Original context string passed to the factory. */
    [[nodiscard]] std::string_view context() const noexcept;
    /** @brief Formatted diagnostic message (used by @c SslException::what). */
    [[nodiscard]] const std::string &message() const noexcept;
    /** @brief True if @c with_location was applied. */
    [[nodiscard]] bool has_location() const noexcept;
    /** @brief Call-site location when @c has_location() is true. */
    [[nodiscard]] const std::source_location &location() const noexcept;
    /** @brief True if this represents a failure (non-None kind, codes, or ssl_error). */
    [[nodiscard]] explicit operator bool() const noexcept;

    /**
     * @brief Attach call-site location and append it to @c message() (release builds).
     * @param loc Explicit @c std::source_location::current() from the call site (no default)
     * @return @c *this
     */
    SslError &with_location(std::source_location loc);

  private:
    void discard_queue() noexcept;
    void drain_queue() noexcept;
    void classify_from_codes() noexcept;
    void format();
    static const char *ssl_error_text(int ssl_error) noexcept;

    std::string context_{};
    std::string message_;
    std::array<unsigned long, kSslMaxErrors> codes_{};
    std::size_t n_ = 0;
    int ssl_error_ = -1;
    int alert_ = -1;
    SslErrorKind kind_ = SslErrorKind::None;
    bool has_location_ = false;
    std::source_location location_{};
};

/**
 * @brief Throwable OpenSSL / quictls error holding a structured @c SslError.
 * @details Inherits @c std::runtime_error so catch-by-base still works. Construction always
 *          goes through @c SslError (no inherited string-ctor drain hole).
 */
class SslException : public std::runtime_error
{
  public:
    /**
     * @brief Capture the ERR queue and throw with @p what_arg as context.
     * @param what_arg Context string (null treated as "SslException")
     */
    explicit SslException(const char *what_arg);
    /** @brief Capture the ERR queue with @p what_arg as context. */
    explicit SslException(std::string_view what_arg);
    /** @brief Capture the ERR queue with @p what_arg as context. */
    explicit SslException(std::string what_arg);
    /**
     * @brief Wrap an existing @c SslError (message becomes @c what()).
     * @param error Pre-built structured error (moved)
     */
    explicit SslException(SslError error);

    /**
     * @brief Wrap @p error and attach an explicit call-site location.
     * @param error Pre-built structured error
     * @param loc Must be passed explicitly (no default) — typically @c current()
     */
    SslException(SslError error, std::source_location loc);
    /**
     * @brief Capture ERR queue with an @c SSL_get_error value.
     * @param what_arg Context string
     * @param ssl_error Result of @c SSL_get_error
     */
    SslException(std::string_view what_arg, int ssl_error);
    /**
     * @brief Capture ERR queue and attach an explicit call-site location.
     * @param what_arg Context string
     * @param loc Must be passed explicitly (no default)
     */
    SslException(std::string_view what_arg, std::source_location loc);

    /** @brief Embedded structured error. */
    [[nodiscard]] const SslError &error() const noexcept;
    /** @brief Convenience for @c error().kind(). */
    [[nodiscard]] SslErrorKind kind() const noexcept;

  private:
    SslError error_;
};

inline SslError SslError::capture(std::string_view context, int ssl_error)
{
    SslError e;
    e.context_.assign(context.data(), context.size());
    e.ssl_error_ = ssl_error;
    e.drain_queue();
    e.classify_from_codes();
    if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE
        || ssl_error == SSL_ERROR_WANT_CONNECT || ssl_error == SSL_ERROR_WANT_ACCEPT
        || ssl_error == SSL_ERROR_WANT_X509_LOOKUP)
        e.kind_ = SslErrorKind::WantIo;
    else if (ssl_error == SSL_ERROR_SYSCALL)
        e.kind_ = SslErrorKind::Syscall;
    e.format();
    return e;
}

inline SslError SslError::app(std::string_view context, SslErrorKind kind, bool drain_stale)
{
    SslError e;
    e.context_.assign(context.data(), context.size());
    e.kind_ = kind;
    if (drain_stale)
        e.discard_queue();
    e.format();
    return e;
}

inline SslError SslError::auth_tag(std::string_view context)
{
    return app(context, SslErrorKind::AuthTag, /*drain_stale=*/true);
}

inline SslErrorKind SslError::kind() const noexcept
{
    return kind_;
}

inline int SslError::ssl_error() const noexcept
{
    return ssl_error_;
}

inline int SslError::alert() const noexcept
{
    return alert_;
}

inline std::size_t SslError::size() const noexcept
{
    return n_;
}

inline unsigned long SslError::code(std::size_t i) const noexcept
{
    return i < n_ ? codes_[i] : 0;
}

inline std::string_view SslError::context() const noexcept
{
    return context_;
}

inline const std::string &SslError::message() const noexcept
{
    return message_;
}

inline bool SslError::has_location() const noexcept
{
    return has_location_;
}

inline const std::source_location &SslError::location() const noexcept
{
    return location_;
}

inline SslError::operator bool() const noexcept
{
    return kind_ != SslErrorKind::None || n_ != 0 || ssl_error_ != -1;
}

inline SslError &SslError::with_location(std::source_location loc)
{
    location_ = loc;
    has_location_ = true;
    message_.append(" (at ");
    message_.append(loc.file_name());
    message_.append(":");
    message_.append(std::to_string(loc.line()));
    message_.append(" ");
    message_.append(loc.function_name());
    message_.append(")");
    return *this;
}

inline void SslError::discard_queue() noexcept
{
    while (ERR_get_error() != 0)
    {
    }
}

inline void SslError::drain_queue() noexcept
{
    n_ = 0;
    while (unsigned long err = ERR_get_error())
    {
        if (n_ < kSslMaxErrors)
            codes_[n_++] = err;
        // keep draining past kSslMaxErrors
    }
}

inline void SslError::classify_from_codes() noexcept
{
    kind_ = n_ ? SslErrorKind::Library : SslErrorKind::None;
    for (std::size_t i = 0; i < n_; ++i)
    {
        const int reason = ERR_GET_REASON(codes_[i]);
        if (reason >= SSL_AD_REASON_OFFSET)
        {
            kind_ = SslErrorKind::TlsAlert;
            alert_ = reason - SSL_AD_REASON_OFFSET;
        }
        switch (reason)
        {
        case SSL_R_CERTIFICATE_VERIFY_FAILED:
            kind_ = SslErrorKind::CertVerify;
            break;
        case PEM_R_BAD_PASSWORD_READ:
        case PEM_R_BAD_DECRYPT:
            kind_ = SslErrorKind::PemPassword;
            break;
        case SSL_R_UNSUPPORTED_PROTOCOL:
            kind_ = SslErrorKind::TlsVersion;
            break;
        default:
            break;
        }
    }
}

inline void SslError::format()
{
    message_ = context_;
    const char *sep = ": ";
    char buf[256];
    for (std::size_t i = 0; i < n_; ++i)
    {
        ERR_error_string_n(codes_[i], buf, sizeof(buf));
        message_.append(sep);
        message_.append(buf);
        const int reason = ERR_GET_REASON(codes_[i]);
        if (reason >= SSL_AD_REASON_OFFSET)
        {
            message_.append("[");
            message_.append(SSL_alert_desc_string_long(reason - SSL_AD_REASON_OFFSET));
            message_.append("]");
        }
        sep = " / ";
    }
    if (ssl_error_ >= 0)
    {
        message_.append(" (");
        message_.append(ssl_error_text(ssl_error_));
        message_.append(")");
    }
    if (message_.empty())
        message_ = "SslError";
}

inline const char *SslError::ssl_error_text(int ssl_error) noexcept
{
    switch (ssl_error)
    {
    case SSL_ERROR_NONE:
        return "SSL_ERROR_NONE";
    case SSL_ERROR_SSL:
        return "SSL_ERROR_SSL";
    case SSL_ERROR_WANT_READ:
        return "SSL_ERROR_WANT_READ";
    case SSL_ERROR_WANT_WRITE:
        return "SSL_ERROR_WANT_WRITE";
    case SSL_ERROR_WANT_X509_LOOKUP:
        return "SSL_ERROR_WANT_X509_LOOKUP";
    case SSL_ERROR_SYSCALL:
        return "SSL_ERROR_SYSCALL";
    case SSL_ERROR_ZERO_RETURN:
        return "SSL_ERROR_ZERO_RETURN";
    case SSL_ERROR_WANT_CONNECT:
        return "SSL_ERROR_WANT_CONNECT";
    case SSL_ERROR_WANT_ACCEPT:
        return "SSL_ERROR_WANT_ACCEPT";
    default:
        return "SSL_ERROR_unknown";
    }
}

inline SslException::SslException(const char *what_arg)
    : SslException(SslError::capture(what_arg ? what_arg : "SslException"))
{
}

inline SslException::SslException(std::string_view what_arg)
    : SslException(SslError::capture(what_arg))
{
}

inline SslException::SslException(std::string what_arg)
    : SslException(std::string_view{what_arg})
{
}

inline SslException::SslException(SslError error)
    : std::runtime_error(error.message()), error_(std::move(error))
{
}

inline SslException::SslException(SslError error, std::source_location loc)
    : SslException(std::move(error.with_location(loc)))
{
}

inline SslException::SslException(std::string_view what_arg, int ssl_error)
    : SslException(SslError::capture(what_arg, ssl_error))
{
}

inline SslException::SslException(std::string_view what_arg, std::source_location loc)
    : SslException(SslError::capture(what_arg), loc)
{
}

inline const SslError &SslException::error() const noexcept
{
    return error_;
}

inline SslErrorKind SslException::kind() const noexcept
{
    return error_.kind();
}

/**
 * @brief @c std::expected with @c SslError as the error type.
 * @tparam T Success value type
 */
template <class T>
using SslExpected = std::expected<T, SslError>;

/**
 * @brief Throw after capturing the OpenSSL ERR queue (@c SslError::capture).
 * @param ctx Context string for the exception message
 * @throws SslException
 */
[[noreturn]] inline void ThrowSsl(std::string_view ctx)
{
    throw SslException(SslError::capture(ctx));
}
/**
 * @brief Throw after capturing the ERR queue, with an explicit call-site location.
 * @param ctx Context string
 * @param loc Must be passed explicitly (typically @c std::source_location::current())
 * @throws SslException
 */
[[noreturn]] inline void ThrowSsl(std::string_view ctx, std::source_location loc)
{
    throw SslException(SslError::capture(ctx), loc);
}
/**
 * @brief Throw an application / precondition failure (@c SslError::app).
 * @param ctx Context string
 * @throws SslException
 */
[[noreturn]] inline void ThrowSslApp(std::string_view ctx)
{
    throw SslException(SslError::app(ctx));
}
/**
 * @brief Throw an application failure with an explicit call-site location.
 * @param ctx Context string
 * @param loc Must be passed explicitly (typically @c std::source_location::current())
 * @throws SslException
 */
[[noreturn]] inline void ThrowSslApp(std::string_view ctx, std::source_location loc)
{
    throw SslException(SslError::app(ctx), loc);
}

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_SSL_EXCEPTION_H
