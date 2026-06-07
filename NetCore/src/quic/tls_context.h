// Copyright (c) 2026- Charlie Vigue. All rights reserved.
//
// clv::quic TlsContext — Phase 1 Step 3.
//
// RAII wrapper around an SSL_CTX configured for ngtcp2_crypto_quictls.
// One TlsContext is shared across all connections of the same role
// (server or client) on a given Endpoint; per-connection SSL state is
// instantiated lazily by clv::quic::Connection in Step 4.
//
// The header keeps OpenSSL types behind a void* native_handle() so
// consumers can include this without pulling in <openssl/ssl.h>.
//
// See _planning/todo.md → "QUIC Transport: Migrate to ngtcp2".

#ifndef CLV_NETCORE_QUIC2_TLS_CONTEXT_H
#define CLV_NETCORE_QUIC2_TLS_CONTEXT_H

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace clv::quic {

/**
 * Application-Layer Protocol Negotiation (ALPN) protocol id, e.g. "h3"
 * or a custom value like "clv-mesh/1". The list is order-preserving;
 * the client offers in order and the server picks the first match.
 *
 * Each id must be 1..255 bytes — RFC 7301 wire-format limit.
 */
using AlpnList = std::vector<std::string>;

/**
 * TLS context for clv::quic endpoints. Wraps an SSL_CTX configured by
 * ngtcp2_crypto_quictls_configure_{server,client}_context.
 *
 * Constructors throw std::runtime_error on configuration failure
 * (missing cert file, unparseable key, OpenSSL/ngtcp2 init error, …).
 *
 * Movable, non-copyable. Reference-counted underneath (SSL_CTX is
 * shared by `SSL_CTX_up_ref` if needed in future).
 */
class TlsContext
{
  public:
    enum class Role
    {
        Server,
        Client,
    };

    /**
     * Construct a server-side context. Loads the certificate chain and
     * private key from PEM files, sets ALPN, and applies the
     * ngtcp2_crypto_quictls server configuration.
     */
    static TlsContext MakeServer(const std::filesystem::path &cert_chain_pem,
                                 const std::filesystem::path &private_key_pem,
                                 AlpnList alpns);

    /**
     * Same as MakeServer above but takes the certificate chain and
     * private key as in-memory PEM strings. The mesh transport keeps
     * these as configuration strings rather than on-disk files.
     */
    static TlsContext MakeServerFromPem(std::string_view cert_chain_pem,
                                        std::string_view private_key_pem,
                                        AlpnList alpns);

    /**
     * Construct a client-side context. Peer verification defaults to
     * SSL_VERIFY_NONE — call SetTrustedCaPem() / SetVerifyPeer() to
     * enable strict server-cert validation before opening real
     * connections.
     */
    static TlsContext MakeClient(AlpnList alpns);

    /**
     * Build a client context that presents a client certificate (for
     * mutual TLS, as the mesh peers do). Other behavior matches
     * MakeClient(alpns).
     */
    static TlsContext MakeClientFromPem(std::string_view cert_chain_pem,
                                        std::string_view private_key_pem,
                                        AlpnList alpns);

    /**
     * Install one or more PEM-encoded trust anchors into the context's
     * X509_STORE. The PEM bundle may contain multiple BEGIN/END
     * CERTIFICATE blocks; every parsed certificate becomes a trust
     * anchor for peer-cert chain validation.
     *
     * For tests pinning a self-signed leaf, pass the leaf PEM itself —
     * OpenSSL accepts self-signed certs added directly to the store as
     * trusted roots.
     *
     * Throws std::runtime_error if the PEM cannot be parsed or no
     * certificates were loaded.
     */
    void SetTrustedCaPem(std::string_view ca_pem);

    /**
     * Enable peer-certificate verification. On a client context this
     * makes the handshake fail when the server's certificate chain
     * cannot be validated against the installed trust anchors. On a
     * server context, set `require_peer_cert=true` to also require the
     * client to present a certificate (mutual TLS).
     *
     * The verify callback honors OpenSSL's preverify result; no custom
     * fingerprint pinning is layered in at this stage — pinning lives
     * one layer up (peer-id derivation on the validated peer cert).
     */
    void SetVerifyPeer(bool require_peer_cert);

    /**
     * Request the peer's certificate during the handshake but accept
     * any cert presented (the verify callback always returns 1). This
     * is the "trust on first use" / pin-by-identity mode used by the
     * mesh layer when no CA bundle is configured: the peer cert is
     * still required so a stable peer-id can be derived from its
     * SubjectPublicKeyInfo, but no chain validation is performed.
     *
     * On a server context this implies SSL_VERIFY_FAIL_IF_NO_PEER_CERT
     * so the client MUST present a cert.
     */
    void SetVerifyPeerAcceptAny(bool require_peer_cert);

    TlsContext(const TlsContext &) = delete;
    TlsContext &operator=(const TlsContext &) = delete;
    TlsContext(TlsContext &&) noexcept;
    TlsContext &operator=(TlsContext &&) noexcept;
    ~TlsContext();

    /** Role this context was built for. */
    [[nodiscard]] Role role() const noexcept;

    /**
     * Raw SSL_CTX* for use by Connection when instantiating per-conn
     * SSL state. The returned pointer remains valid for the lifetime
     * of this TlsContext.
     */
    [[nodiscard]] void *native_handle() const noexcept;

    /** ALPN list, in wire order. Read-only after construction. */
    [[nodiscard]] const AlpnList &alpns() const noexcept;

  private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;

    explicit TlsContext(std::unique_ptr<Impl> impl) noexcept;
};

} // namespace clv::quic

#endif // CLV_NETCORE_QUIC2_TLS_CONTEXT_H
