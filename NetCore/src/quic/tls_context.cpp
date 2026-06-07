// Copyright (c) 2026- Charlie Vigue. All rights reserved.
//
// clv::quic TlsContext implementation. Hides OpenSSL/quictls and
// ngtcp2_crypto_quictls behind a pImpl so the header stays clean.

#include "quic/tls_context.h"

#include <ngtcp2/ngtcp2_crypto_quictls.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <cstring>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>

namespace clv::quic {

namespace {

// ngtcp2_crypto_quictls_init() must be called once per process before
// any quictls-backed connection is opened (recommended for quictls >= 3.0).
// std::call_once gives us thread-safe lazy initialization without a
// mandatory global ctor.
void EnsureCryptoInit()
{
    static std::once_flag flag;
    static int init_rc = 0;
    std::call_once(flag, []()
    { init_rc = ngtcp2_crypto_quictls_init(); });
    if (init_rc != 0)
    {
        throw std::runtime_error("ngtcp2_crypto_quictls_init failed");
    }
}

// Encode an AlpnList into the wire format SSL_CTX_set_alpn_protos
// expects: a flat byte stream where each protocol id is prefixed by its
// 1-byte length.
std::vector<std::uint8_t> EncodeAlpn(const AlpnList &alpns)
{
    std::vector<std::uint8_t> out;
    out.reserve(alpns.size() * 8);
    for (const auto &id : alpns)
    {
        if (id.empty() || id.size() > 255)
        {
            throw std::runtime_error(
                "TlsContext: ALPN id must be 1..255 bytes (RFC 7301): '" + id + "'");
        }
        out.push_back(static_cast<std::uint8_t>(id.size()));
        out.insert(out.end(), id.begin(), id.end());
    }
    return out;
}

// Server-side ALPN selection callback. Picks the first protocol the
// client offered that we also advertise. Returns SSL_TLSEXT_ERR_OK
// on match, SSL_TLSEXT_ERR_NOACK otherwise (lets the handshake fail).
int AlpnSelectCb(SSL * /*ssl*/, const unsigned char **out, unsigned char *outlen,
                 const unsigned char *in, unsigned int inlen, void *arg)
{
    const auto *encoded = static_cast<const std::vector<std::uint8_t> *>(arg);
    // SSL_select_next_proto's signature wants non-const for the server
    // list; the contents are not mutated.
    auto *server_list = const_cast<unsigned char *>(encoded->data());
    const unsigned int server_len = static_cast<unsigned int>(encoded->size());

    if (SSL_select_next_proto(const_cast<unsigned char **>(out), outlen, server_list, server_len, in, inlen) == OPENSSL_NPN_NEGOTIATED)
    {
        return SSL_TLSEXT_ERR_OK;
    }
    return SSL_TLSEXT_ERR_NOACK;
}

// Pull the current OpenSSL error queue into a string for diagnostics.
std::string DrainOpenSslError(const char *prefix)
{
    std::string msg = prefix;
    while (unsigned long e = ERR_get_error())
    {
        char buf[256];
        ERR_error_string_n(e, buf, sizeof(buf));
        msg.append(": ").append(buf);
    }
    return msg;
}

// Load a PEM-encoded certificate chain + private key from in-memory
// strings into an SSL_CTX. Mirrors what SSL_CTX_use_certificate_chain_file
// and SSL_CTX_use_PrivateKey_file do for on-disk files: the first
// certificate in `cert_pem` becomes the leaf, any additional certs in
// the bundle become intermediate chain entries.
void LoadCertChainAndKeyFromPem(SSL_CTX *ctx, std::string_view cert_pem,
                                std::string_view key_pem)
{
    if (cert_pem.empty() || key_pem.empty())
    {
        throw std::runtime_error("TlsContext: cert/key PEM is empty");
    }

    BIO *cbio = BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size()));
    if (cbio == nullptr)
    {
        throw std::runtime_error(DrainOpenSslError("BIO_new_mem_buf(cert)"));
    }

    X509 *leaf = PEM_read_bio_X509(cbio, nullptr, nullptr, nullptr);
    if (leaf == nullptr)
    {
        BIO_free(cbio);
        throw std::runtime_error(DrainOpenSslError("PEM_read_bio_X509(leaf)"));
    }
    if (SSL_CTX_use_certificate(ctx, leaf) != 1)
    {
        X509_free(leaf);
        BIO_free(cbio);
        throw std::runtime_error(DrainOpenSslError("SSL_CTX_use_certificate"));
    }
    X509_free(leaf);

    // Drop any prior chain (for repeated calls) and append intermediates.
    SSL_CTX_clear_chain_certs(ctx);
    while (true)
    {
        X509 *ca = PEM_read_bio_X509(cbio, nullptr, nullptr, nullptr);
        if (ca == nullptr)
        {
            ERR_clear_error();
            break;
        }
        if (SSL_CTX_add0_chain_cert(ctx, ca) != 1)
        {
            X509_free(ca);
            BIO_free(cbio);
            throw std::runtime_error(DrainOpenSslError("SSL_CTX_add0_chain_cert"));
        }
        // add0 took ownership of ca; do NOT free.
    }
    BIO_free(cbio);

    BIO *kbio = BIO_new_mem_buf(key_pem.data(), static_cast<int>(key_pem.size()));
    if (kbio == nullptr)
    {
        throw std::runtime_error(DrainOpenSslError("BIO_new_mem_buf(key)"));
    }
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(kbio, nullptr, nullptr, nullptr);
    BIO_free(kbio);
    if (pkey == nullptr)
    {
        throw std::runtime_error(DrainOpenSslError("PEM_read_bio_PrivateKey"));
    }
    if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1)
    {
        EVP_PKEY_free(pkey);
        throw std::runtime_error(DrainOpenSslError("SSL_CTX_use_PrivateKey"));
    }
    EVP_PKEY_free(pkey);

    if (SSL_CTX_check_private_key(ctx) != 1)
    {
        throw std::runtime_error(DrainOpenSslError("SSL_CTX_check_private_key"));
    }
}

} // namespace

struct TlsContext::Impl
{
    SSL_CTX *mCtx{nullptr};
    Role mRole{};
    AlpnList mAlpns;
    std::vector<std::uint8_t> mAlpnEncoded;

    ~Impl()
    {
        if (mCtx != nullptr)
        {
            SSL_CTX_free(mCtx);
        }
    }
};

TlsContext::TlsContext(std::unique_ptr<Impl> impl) noexcept : mImpl(std::move(impl))
{
}
TlsContext::TlsContext(TlsContext &&) noexcept = default;
TlsContext &TlsContext::operator=(TlsContext &&) noexcept = default;
TlsContext::~TlsContext() = default;

TlsContext::Role TlsContext::role() const noexcept
{
    return mImpl->mRole;
}
void *TlsContext::native_handle() const noexcept
{
    return mImpl->mCtx;
}
const AlpnList &TlsContext::alpns() const noexcept
{
    return mImpl->mAlpns;
}

TlsContext TlsContext::MakeServer(const std::filesystem::path &cert_chain_pem,
                                  const std::filesystem::path &private_key_pem, AlpnList alpns)
{
    EnsureCryptoInit();

    auto impl = std::make_unique<Impl>();
    impl->mRole = Role::Server;
    impl->mAlpns = std::move(alpns);
    impl->mAlpnEncoded = EncodeAlpn(impl->mAlpns);

    impl->mCtx = SSL_CTX_new(TLS_server_method());
    if (impl->mCtx == nullptr)
    {
        throw std::runtime_error(DrainOpenSslError("SSL_CTX_new(TLS_server_method)"));
    }

    if (ngtcp2_crypto_quictls_configure_server_context(impl->mCtx) != 0)
    {
        throw std::runtime_error("ngtcp2_crypto_quictls_configure_server_context failed");
    }

    if (SSL_CTX_use_certificate_chain_file(impl->mCtx, cert_chain_pem.string().c_str()) != 1)
    {
        throw std::runtime_error(DrainOpenSslError("SSL_CTX_use_certificate_chain_file"));
    }
    if (SSL_CTX_use_PrivateKey_file(impl->mCtx, private_key_pem.string().c_str(), SSL_FILETYPE_PEM) != 1)
    {
        throw std::runtime_error(DrainOpenSslError("SSL_CTX_use_PrivateKey_file"));
    }
    if (SSL_CTX_check_private_key(impl->mCtx) != 1)
    {
        throw std::runtime_error(DrainOpenSslError("SSL_CTX_check_private_key"));
    }

    SSL_CTX_set_alpn_select_cb(impl->mCtx, &AlpnSelectCb, &impl->mAlpnEncoded);

    return TlsContext(std::move(impl));
}

TlsContext TlsContext::MakeServerFromPem(std::string_view cert_chain_pem,
                                         std::string_view private_key_pem, AlpnList alpns)
{
    EnsureCryptoInit();

    auto impl = std::make_unique<Impl>();
    impl->mRole = Role::Server;
    impl->mAlpns = std::move(alpns);
    impl->mAlpnEncoded = EncodeAlpn(impl->mAlpns);

    impl->mCtx = SSL_CTX_new(TLS_server_method());
    if (impl->mCtx == nullptr)
    {
        throw std::runtime_error(DrainOpenSslError("SSL_CTX_new(TLS_server_method)"));
    }
    if (ngtcp2_crypto_quictls_configure_server_context(impl->mCtx) != 0)
    {
        throw std::runtime_error("ngtcp2_crypto_quictls_configure_server_context failed");
    }

    LoadCertChainAndKeyFromPem(impl->mCtx, cert_chain_pem, private_key_pem);

    SSL_CTX_set_alpn_select_cb(impl->mCtx, &AlpnSelectCb, &impl->mAlpnEncoded);

    return TlsContext(std::move(impl));
}

TlsContext TlsContext::MakeClient(AlpnList alpns)
{
    EnsureCryptoInit();

    auto impl = std::make_unique<Impl>();
    impl->mRole = Role::Client;
    impl->mAlpns = std::move(alpns);
    impl->mAlpnEncoded = EncodeAlpn(impl->mAlpns);

    impl->mCtx = SSL_CTX_new(TLS_client_method());
    if (impl->mCtx == nullptr)
    {
        throw std::runtime_error(DrainOpenSslError("SSL_CTX_new(TLS_client_method)"));
    }

    if (ngtcp2_crypto_quictls_configure_client_context(impl->mCtx) != 0)
    {
        throw std::runtime_error("ngtcp2_crypto_quictls_configure_client_context failed");
    }

    // Phase 1 unit-test mode: peer verification disabled. Production
    // builds must layer verification on top (CA bundle, hostname check)
    // before the transport is wired into MeshTransport.
    SSL_CTX_set_verify(impl->mCtx, SSL_VERIFY_NONE, nullptr);
    SSL_CTX_set_session_cache_mode(impl->mCtx, SSL_SESS_CACHE_OFF);

    if (!impl->mAlpnEncoded.empty())
    {
        if (SSL_CTX_set_alpn_protos(impl->mCtx, impl->mAlpnEncoded.data(), static_cast<unsigned int>(impl->mAlpnEncoded.size())) != 0)
        {
            throw std::runtime_error(DrainOpenSslError("SSL_CTX_set_alpn_protos"));
        }
    }

    return TlsContext(std::move(impl));
}

TlsContext TlsContext::MakeClientFromPem(std::string_view cert_chain_pem,
                                         std::string_view private_key_pem, AlpnList alpns)
{
    EnsureCryptoInit();

    auto impl = std::make_unique<Impl>();
    impl->mRole = Role::Client;
    impl->mAlpns = std::move(alpns);
    impl->mAlpnEncoded = EncodeAlpn(impl->mAlpns);

    impl->mCtx = SSL_CTX_new(TLS_client_method());
    if (impl->mCtx == nullptr)
    {
        throw std::runtime_error(DrainOpenSslError("SSL_CTX_new(TLS_client_method)"));
    }
    if (ngtcp2_crypto_quictls_configure_client_context(impl->mCtx) != 0)
    {
        throw std::runtime_error("ngtcp2_crypto_quictls_configure_client_context failed");
    }

    SSL_CTX_set_verify(impl->mCtx, SSL_VERIFY_NONE, nullptr);
    SSL_CTX_set_session_cache_mode(impl->mCtx, SSL_SESS_CACHE_OFF);

    LoadCertChainAndKeyFromPem(impl->mCtx, cert_chain_pem, private_key_pem);

    if (!impl->mAlpnEncoded.empty())
    {
        if (SSL_CTX_set_alpn_protos(impl->mCtx, impl->mAlpnEncoded.data(), static_cast<unsigned int>(impl->mAlpnEncoded.size())) != 0)
        {
            throw std::runtime_error(DrainOpenSslError("SSL_CTX_set_alpn_protos"));
        }
    }

    return TlsContext(std::move(impl));
}

void TlsContext::SetTrustedCaPem(std::string_view ca_pem)
{
    if (ca_pem.empty())
    {
        throw std::runtime_error("TlsContext::SetTrustedCaPem: PEM is empty");
    }
    BIO *bio = BIO_new_mem_buf(ca_pem.data(), static_cast<int>(ca_pem.size()));
    if (bio == nullptr)
    {
        throw std::runtime_error(DrainOpenSslError("BIO_new_mem_buf"));
    }

    X509_STORE *store = SSL_CTX_get_cert_store(mImpl->mCtx);
    if (store == nullptr)
    {
        BIO_free(bio);
        throw std::runtime_error("TlsContext::SetTrustedCaPem: SSL_CTX has no cert store");
    }

    int loaded = 0;
    while (true)
    {
        X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        if (cert == nullptr)
        {
            // EOF is the normal terminator; clear OpenSSL's "no start
            // line" error so it doesn't leak into the next call.
            ERR_clear_error();
            break;
        }
        const int rv = X509_STORE_add_cert(store, cert);
        if (rv != 1)
        {
            const unsigned long err = ERR_peek_last_error();
            if (ERR_GET_REASON(err) != X509_R_CERT_ALREADY_IN_HASH_TABLE)
            {
                X509_free(cert);
                BIO_free(bio);
                throw std::runtime_error(DrainOpenSslError("X509_STORE_add_cert"));
            }
            ERR_clear_error();
        }
        X509_free(cert);
        ++loaded;
    }
    BIO_free(bio);

    if (loaded == 0)
    {
        throw std::runtime_error("TlsContext::SetTrustedCaPem: no certificates parsed");
    }
}

void TlsContext::SetVerifyPeer(bool require_peer_cert)
{
    int mode = SSL_VERIFY_PEER;
    if (mImpl->mRole == Role::Server && require_peer_cert)
    {
        mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    }
    SSL_CTX_set_verify(mImpl->mCtx, mode, [](int preverify_ok, X509_STORE_CTX *) -> int
    { return preverify_ok; });
}

void TlsContext::SetVerifyPeerAcceptAny(bool require_peer_cert)
{
    int mode = SSL_VERIFY_PEER;
    if (mImpl->mRole == Role::Server && require_peer_cert)
    {
        mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    }
    SSL_CTX_set_verify(mImpl->mCtx, mode, [](int, X509_STORE_CTX *) -> int
    { return 1; });
}

} // namespace clv::quic
