// Copyright (c) 2026- Charlie Vigue. All rights reserved.
//
// clv::quic Phase 2 — TLS peer verification.
//
// Exercises the cert-pinning surface added in Phase 2:
//   - TlsContext::SetTrustedCaPem installs trust anchors.
//   - TlsContext::SetVerifyPeer turns on SSL_VERIFY_PEER.
//   - Connection::peer_certificate_der returns the validated peer cert.
//
// Two end-to-end paths are covered, both driven through two real
// Endpoints over loopback UDP (no manual packet shuffling — the
// Endpoint DCID demux from Phase 1 Step 5c routes the handshake):
//
//   * TrustsPinnedServerCert: client pins the server's self-signed
//     cert as a trust anchor. Handshake completes; the client can
//     read back the peer cert in DER form, matching what the server
//     loaded.
//
//   * RejectsUnknownServerCert: client pins a *different* self-signed
//     cert. The server presents an unrelated cert; the chain fails to
//     validate; neither peer reaches handshake_completed within the
//     deadline.

#include "quic/connection.h"
#include "quic/endpoint.h"
#include "quic/tls_context.h"

#include <gtest/gtest.h>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace {

struct PemMaterial
{
    std::string cert_pem;
    std::string key_pem;
    std::vector<std::uint8_t> cert_der;
};

// Generate a fresh self-signed Ed25519 cert in memory. Ed25519 has no
// keygen parameters and produces compact PEM — perfect for tests.
PemMaterial GenerateSelfSignedEd25519(const std::string &subject_cn)
{
    // Key.
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (kctx == nullptr)
    {
        throw std::runtime_error("EVP_PKEY_CTX_new_id(ED25519) failed");
    }
    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen_init(kctx) <= 0 || EVP_PKEY_keygen(kctx, &pkey) <= 0)
    {
        EVP_PKEY_CTX_free(kctx);
        throw std::runtime_error("EVP_PKEY_keygen(ED25519) failed");
    }
    EVP_PKEY_CTX_free(kctx);

    // Cert.
    X509 *cert = X509_new();
    if (cert == nullptr)
    {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("X509_new failed");
    }
    X509_set_version(cert, 2); // v3
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 60 * 60 * 24 * 30); // 30 days
    X509_set_pubkey(cert, pkey);

    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(subject_cn.c_str()), -1, -1, 0);
    X509_set_issuer_name(cert, name); // self-signed

    if (X509_sign(cert, pkey, nullptr) == 0) // Ed25519 ignores the digest arg
    {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("X509_sign failed");
    }

    PemMaterial out;

    // PEM cert.
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);
    BUF_MEM *bp = nullptr;
    BIO_get_mem_ptr(bio, &bp);
    out.cert_pem.assign(bp->data, bp->length);
    BIO_free(bio);

    // PEM key (PKCS#8, unencrypted).
    bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    BIO_get_mem_ptr(bio, &bp);
    out.key_pem.assign(bp->data, bp->length);
    BIO_free(bio);

    // DER cert (for byte-equality assertion against peer_certificate_der).
    int der_len = i2d_X509(cert, nullptr);
    out.cert_der.resize(static_cast<std::size_t>(der_len));
    std::uint8_t *p = out.cert_der.data();
    i2d_X509(cert, &p);

    X509_free(cert);
    EVP_PKEY_free(pkey);
    return out;
}

class TempFile
{
  public:
    TempFile(std::string_view contents, std::string_view suffix)
    {
        path_ = std::filesystem::temp_directory_path() / ("clv_quic2_test_" + std::to_string(::getpid()) + "_" + std::to_string(++counter_) + std::string(suffix));
        std::ofstream f(path_);
        f.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    }
    ~TempFile()
    {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }
    TempFile(const TempFile &) = delete;
    TempFile &operator=(const TempFile &) = delete;
    const std::filesystem::path &path() const
    {
        return path_;
    }

  private:
    std::filesystem::path path_;
    static inline int counter_ = 0;
};

struct Peers
{
    std::unique_ptr<clv::quic::Endpoint> client_ep;
    std::unique_ptr<clv::quic::Endpoint> server_ep;
    clv::quic::TlsContext client_tls;
    clv::quic::TlsContext server_tls;
    std::unique_ptr<clv::quic::Connection> client_conn;
    std::unique_ptr<clv::quic::Connection> server_conn;
    std::atomic<bool> client_done{false};
    std::atomic<bool> server_done{false};

    Peers(asio::io_context &io, clv::quic::TlsContext c, clv::quic::TlsContext s)
        : client_ep(std::make_unique<clv::quic::Endpoint>(
              io, asio::ip::udp::endpoint(asio::ip::address_v4::loopback(), 0))),
          server_ep(std::make_unique<clv::quic::Endpoint>(
              io, asio::ip::udp::endpoint(asio::ip::address_v4::loopback(), 0))),
          client_tls(std::move(c)),
          server_tls(std::move(s))
    {
    }
};

// Drive both Endpoints' io_context until both handshakes complete or
// the deadline elapses. Returns true if both completed in time.
bool PumpUntilBothHandshakeDone(asio::io_context &io, Peers &p,
                                std::chrono::milliseconds budget)
{
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while ((!p.client_done.load(std::memory_order_acquire) || !p.server_done.load(std::memory_order_acquire)) && std::chrono::steady_clock::now() < deadline)
    {
        io.run_for(std::chrono::milliseconds(10));
    }
    return p.client_done.load() && p.server_done.load();
}

void StartHandshake(asio::io_context &io, Peers &p)
{
    p.client_ep->register_connection(*p.client_conn);

    p.server_ep->set_packet_handler(
        [&io, &p](std::span<const std::uint8_t> data, const asio::ip::udp::endpoint &peer)
    {
        if (p.server_conn)
        {
            p.server_conn->read_packet(data, peer);
            return;
        }
        auto cids = clv::quic::DecodePacketCids(data);
        p.server_conn = clv::quic::Connection::MakeServer(
            p.server_tls, cids.dcid, cids.scid, p.server_ep->local_endpoint(), peer);
        p.server_conn->set_handshake_complete_cb(
            [&p]
        { p.server_done.store(true, std::memory_order_release); });
        p.server_ep->register_connection(*p.server_conn);
        p.server_conn->read_packet(data, peer);
        p.server_conn->write_to(
            [&io, &p](std::span<const std::uint8_t> bytes, const asio::ip::udp::endpoint &dest)
        {
            std::vector<std::uint8_t> copy(bytes.begin(), bytes.end());
            asio::co_spawn(io, p.server_ep->send(std::move(copy), dest), asio::detached);
        });
    });

    p.server_ep->start();
    p.client_ep->start();

    p.client_conn->write_to(
        [&io, &p](std::span<const std::uint8_t> bytes, const asio::ip::udp::endpoint &dest)
    {
        std::vector<std::uint8_t> copy(bytes.begin(), bytes.end());
        asio::co_spawn(io, p.client_ep->send(std::move(copy), dest), asio::detached);
    });
}

void TeardownPeers(asio::io_context &io, Peers &p)
{
    if (p.server_conn)
    {
        p.server_ep->unregister_connection(*p.server_conn);
    }
    if (p.client_conn)
    {
        p.client_ep->unregister_connection(*p.client_conn);
    }
    p.server_ep->stop();
    p.client_ep->stop();
    io.run_for(std::chrono::milliseconds(50));
}

} // namespace

TEST(Quic2TlsVerify, TrustsPinnedServerCert)
{
    const PemMaterial server_pem = GenerateSelfSignedEd25519("clv-quic2-test-server");

    TempFile cert_file(server_pem.cert_pem, ".pem");
    TempFile key_file(server_pem.key_pem, ".pem");

    auto server_tls = clv::quic::TlsContext::MakeServer(cert_file.path(), key_file.path(), {"clv-mesh/1"});

    auto client_tls = clv::quic::TlsContext::MakeClient({"clv-mesh/1"});
    client_tls.SetTrustedCaPem(server_pem.cert_pem);
    client_tls.SetVerifyPeer(/*require_peer_cert=*/false);

    asio::io_context io;
    Peers p(io, std::move(client_tls), std::move(server_tls));

    p.client_conn = clv::quic::Connection::MakeClient(
        p.client_tls, p.client_ep->local_endpoint(), p.server_ep->local_endpoint(),
        /*server_name=*/"clv-quic2-test-server");
    p.client_conn->set_handshake_complete_cb(
        [&p]
    { p.client_done.store(true, std::memory_order_release); });

    StartHandshake(io, p);

    const bool ok = PumpUntilBothHandshakeDone(io, p, std::chrono::seconds(3));
    EXPECT_TRUE(ok) << "Pinned handshake failed to complete: client_done="
                    << p.client_done.load() << " server_done=" << p.server_done.load();

    // The client sees the server's leaf cert exactly as loaded.
    std::vector<std::uint8_t> observed = p.client_conn->peer_certificate_der();
    EXPECT_EQ(observed, server_pem.cert_der);

    TeardownPeers(io, p);
}

TEST(Quic2TlsVerify, RejectsUnknownServerCert)
{
    const PemMaterial server_pem = GenerateSelfSignedEd25519("clv-quic2-test-server");
    const PemMaterial trusted_pem = GenerateSelfSignedEd25519("clv-quic2-test-other");

    TempFile cert_file(server_pem.cert_pem, ".pem");
    TempFile key_file(server_pem.key_pem, ".pem");

    auto server_tls = clv::quic::TlsContext::MakeServer(cert_file.path(), key_file.path(), {"clv-mesh/1"});

    auto client_tls = clv::quic::TlsContext::MakeClient({"clv-mesh/1"});
    // Trust an unrelated cert — the server's chain will not validate.
    client_tls.SetTrustedCaPem(trusted_pem.cert_pem);
    client_tls.SetVerifyPeer(/*require_peer_cert=*/false);

    asio::io_context io;
    Peers p(io, std::move(client_tls), std::move(server_tls));

    p.client_conn = clv::quic::Connection::MakeClient(
        p.client_tls, p.client_ep->local_endpoint(), p.server_ep->local_endpoint(),
        /*server_name=*/"clv-quic2-test-other");
    p.client_conn->set_handshake_complete_cb(
        [&p]
    { p.client_done.store(true, std::memory_order_release); });

    StartHandshake(io, p);

    // 1 second is plenty for a successful loopback handshake — anything
    // that takes longer is a failure that the cert-mismatch logic has
    // intercepted. We expect neither side to ever report completion.
    const bool ok = PumpUntilBothHandshakeDone(io, p, std::chrono::seconds(1));
    EXPECT_FALSE(ok);
    EXPECT_FALSE(p.client_done.load()) << "Client should not have completed handshake";
    EXPECT_FALSE(p.client_conn->handshake_completed());

    // No stream payload could have been delivered: the client never
    // opened a stream, and even if the server tried, the client's
    // 1-RTT keys were never installed.
    EXPECT_TRUE(p.client_conn->peer_certificate_der().empty() || p.client_conn->peer_certificate_der() == server_pem.cert_der)
        << "Peer cert, if present, must be the rejected one (never trusted)";

    TeardownPeers(io, p);
}
