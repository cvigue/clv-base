// Copyright (c) 2026- Charlie Vigue. All rights reserved.
//
// clv::quic Connection implementation — Phase 1 Step 4.
//
// Construction + callback wiring only. Read/write drive and the expiry
// timer land in Step 5.

#include "quic/connection.h"
#include "quic/tls_context.h"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_quictls.h>

#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdarg>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <utility>

namespace clv::quic {

namespace {

// Monotonic timestamp in nanoseconds — ngtcp2's chosen time unit.
ngtcp2_tstamp NowNs()
{
    const auto t = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<ngtcp2_tstamp>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(t).count());
}

void RandFill(std::uint8_t *dst, std::size_t len)
{
    if (RAND_bytes(dst, static_cast<int>(len)) != 1)
    {
        throw std::runtime_error("RAND_bytes failed");
    }
}

// ---- ngtcp2 callback bridges ----

void RandCb(std::uint8_t *dest, std::size_t destlen, const ngtcp2_rand_ctx * /*rand_ctx*/)
{
    // ngtcp2_rand can't propagate failure; abort matches the simpleclient
    // pattern and surfaces the (vanishingly unlikely) failure loudly.
    if (RAND_bytes(dest, static_cast<int>(destlen)) != 1)
    {
        std::abort();
    }
}

int GetNewConnectionIdCb(ngtcp2_conn * /*conn*/, ngtcp2_cid *cid,
                         ngtcp2_stateless_reset_token *token, std::size_t cidlen,
                         void * /*user_data*/)
{
    if (RAND_bytes(cid->data, static_cast<int>(cidlen)) != 1)
    {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    cid->datalen = cidlen;
    if (RAND_bytes(token->data, sizeof(token->data)) != 1)
    {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
}
} // namespace

ConnectionId MakeRandomConnectionId(std::size_t len)
{
    if (len == 0 || len > ConnectionId::kMaxLen)
    {
        throw std::invalid_argument("ConnectionId length must be 1..20");
    }
    ConnectionId cid;
    cid.len = len;
    RandFill(cid.data.data(), len);
    return cid;
}

PacketCids DecodePacketCids(std::span<const std::uint8_t> data)
{
    ngtcp2_version_cid vc{};
    // short_dcidlen=0: we only care about long-header (Initial/Handshake)
    // packets here; short-header demux happens via the established
    // Endpoint connection table once handshake completes.
    int rv = ngtcp2_pkt_decode_version_cid(&vc, data.data(), data.size(), /*short_dcidlen=*/0);
    if (rv != 0 && rv != NGTCP2_ERR_VERSION_NEGOTIATION)
    {
        throw std::invalid_argument(
            std::string("ngtcp2_pkt_decode_version_cid: ") + ngtcp2_strerror(rv));
    }
    if (vc.dcidlen > ConnectionId::kMaxLen || vc.scidlen > ConnectionId::kMaxLen)
    {
        throw std::invalid_argument("Connection ID exceeds 20 bytes");
    }
    PacketCids out{};
    out.dcid.len = vc.dcidlen;
    if (vc.dcidlen > 0)
    {
        std::memcpy(out.dcid.data.data(), vc.dcid, vc.dcidlen);
    }
    out.scid.len = vc.scidlen;
    if (vc.scidlen > 0)
    {
        std::memcpy(out.scid.data.data(), vc.scid, vc.scidlen);
    }
    return out;
}

// Per-connection state. Lives behind a unique_ptr so callbacks can
// capture a stable `this` via ngtcp2's `user_data`. The Connection
// public type holds a unique_ptr<Impl>; we forward to Impl methods
// where useful and use bridge static functions where ngtcp2's C ABI
// is involved.
struct Connection::Impl
{
    // First member: ngtcp2_crypto_conn_ref must be reachable from the
    // SSL* via SSL_set_app_data. Its get_conn() callback returns our
    // ngtcp2_conn*.
    ngtcp2_crypto_conn_ref mConnRef{};

    ngtcp2_conn *mConn{nullptr};
    SSL *mSsl{nullptr};

    asio::ip::udp::endpoint mLocal;
    asio::ip::udp::endpoint mRemote;

    // Sockaddr storage backing the ngtcp2_path. ngtcp2_path holds raw
    // pointers, so the buffers must outlive every ngtcp2 call.
    std::array<std::uint8_t, sizeof(sockaddr_storage)> mLocalAddrBuf{};
    std::array<std::uint8_t, sizeof(sockaddr_storage)> mRemoteAddrBuf{};
    ngtcp2_socklen mLocalAddrLen{0};
    ngtcp2_socklen mRemoteAddrLen{0};

    HandshakeCompleteCb mHandshakeCb;
    StreamDataCb mStreamDataCb;
    StreamCloseCb mStreamCloseCb;
    AckedStreamDataOffsetCb mAckedStreamDataCb;
    PreWriteCb mPreWriteCb;

    bool mHandshakeDone{false};

    ~Impl()
    {
        if (mConn != nullptr)
        {
            ngtcp2_conn_del(mConn);
            mConn = nullptr;
        }
        if (mSsl != nullptr)
        {
            SSL_free(mSsl);
            mSsl = nullptr;
        }
    }

    // ngtcp2_crypto_conn_ref::get_conn — returns the ngtcp2_conn* given
    // the conn_ref pointer that OpenSSL holds via SSL_get_app_data.
    // We stash the owning Impl in conn_ref.user_data during setup so
    // this stays a plain pointer chase — no offsetof gymnastics.
    static ngtcp2_conn *GetConn(ngtcp2_crypto_conn_ref *ref)
    {
        return static_cast<Impl *>(ref->user_data)->mConn;
    }

    void StoreEndpointSockaddr()
    {
        // asio::ip::basic_endpoint exposes its sockaddr layout via
        // data() + size(). Copy into the heap-resident buffers so the
        // ngtcp2_path stays valid for the lifetime of this Impl.
        auto local_data = mLocal.data();
        mLocalAddrLen = static_cast<ngtcp2_socklen>(mLocal.size());
        std::memcpy(mLocalAddrBuf.data(), local_data, mLocalAddrLen);
        auto remote_data = mRemote.data();
        mRemoteAddrLen = static_cast<ngtcp2_socklen>(mRemote.size());
        std::memcpy(mRemoteAddrBuf.data(), remote_data, mRemoteAddrLen);
    }

    ngtcp2_path MakePath() const
    {
        ngtcp2_path p{};
        p.local.addr = reinterpret_cast<ngtcp2_sockaddr *>(const_cast<std::uint8_t *>(mLocalAddrBuf.data()));
        p.local.addrlen = mLocalAddrLen;
        p.remote.addr = reinterpret_cast<ngtcp2_sockaddr *>(const_cast<std::uint8_t *>(mRemoteAddrBuf.data()));
        p.remote.addrlen = mRemoteAddrLen;
        return p;
    }
};

namespace {

// ---- Instance-method bridges ----

int HandshakeCompletedCb(ngtcp2_conn * /*conn*/, void *user_data)
{
    auto *self = static_cast<Connection::Impl *>(user_data);
    self->mHandshakeDone = true;
    if (self->mHandshakeCb)
    {
        self->mHandshakeCb();
    }
    return 0;
}

int RecvStreamDataCb(ngtcp2_conn * /*conn*/, std::uint32_t flags, std::int64_t stream_id,
                     std::uint64_t /*offset*/, const std::uint8_t *data, std::size_t datalen,
                     void *user_data, void * /*stream_user_data*/)
{
    auto *self = static_cast<Connection::Impl *>(user_data);
    if (self->mStreamDataCb)
    {
        const bool fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0;
        self->mStreamDataCb(stream_id, std::span<const std::uint8_t>(data, datalen), fin);
    }
    return 0;
}

int StreamCloseCb(ngtcp2_conn * /*conn*/, std::uint32_t /*flags*/, std::int64_t stream_id,
                  std::uint64_t app_error_code, void *user_data, void * /*stream_user_data*/)
{
    auto *self = static_cast<Connection::Impl *>(user_data);
    if (self->mStreamCloseCb)
    {
        self->mStreamCloseCb(stream_id, app_error_code);
    }
    return 0;
}

int AckedStreamDataOffsetCb(ngtcp2_conn * /*conn*/, std::int64_t stream_id,
                            std::uint64_t offset, std::uint64_t datalen,
                            void *user_data, void * /*stream_user_data*/)
{
    auto *self = static_cast<Connection::Impl *>(user_data);
    if (self->mAckedStreamDataCb)
    {
        self->mAckedStreamDataCb(stream_id, offset, datalen);
    }
    return 0;
}

// ---- Settings & transport params ----

void Ngtcp2LogPrintf(void * /*user*/, const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    spdlog::debug("[ngtcp2] {}", buf);
}

void InitSettings(ngtcp2_settings &settings)
{
    ngtcp2_settings_default(&settings);
    settings.initial_ts = NowNs();
    // Opt-in ngtcp2 packet/frame trace: set CLV_NGTCP2_LOG=1 in the env.
    // Off by default to avoid log spam at info level.
    static const bool kNgtcp2LogEnabled = []()
    {
        const char *e = std::getenv("CLV_NGTCP2_LOG");
        return e != nullptr && e[0] != '\0' && e[0] != '0';
    }();
    if (kNgtcp2LogEnabled)
    {
        settings.log_printf = &Ngtcp2LogPrintf;
    }
}

void InitTransportParams(ngtcp2_transport_params &params)
{
    ngtcp2_transport_params_default(&params);
    // Mesh traffic uses bidi streams primarily; allow a generous
    // initial budget. Concrete tuning ships with the production wiring.
    params.initial_max_streams_bidi = 100;
    params.initial_max_streams_uni = 3;
    params.initial_max_stream_data_bidi_local = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.initial_max_stream_data_uni = 256 * 1024;
    params.initial_max_data = 1024 * 1024;
    params.max_idle_timeout = 30ULL * NGTCP2_SECONDS;
}

// Server-side callback table. Uses ngtcp2_crypto defaults for all
// crypto-related callbacks; instance bridges for stream + handshake.
ngtcp2_callbacks MakeServerCallbacks()
{
    ngtcp2_callbacks cb{};
    cb.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
    cb.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    cb.encrypt = ngtcp2_crypto_encrypt_cb;
    cb.decrypt = ngtcp2_crypto_decrypt_cb;
    cb.hp_mask = ngtcp2_crypto_hp_mask_cb;
    cb.update_key = ngtcp2_crypto_update_key_cb;
    cb.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    cb.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    cb.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
    cb.rand = RandCb;
    cb.get_new_connection_id2 = GetNewConnectionIdCb;
    cb.handshake_completed = HandshakeCompletedCb;
    cb.recv_stream_data = RecvStreamDataCb;
    cb.stream_close = StreamCloseCb;
    cb.acked_stream_data_offset = AckedStreamDataOffsetCb;
    return cb;
}

// Client-side callback table.
ngtcp2_callbacks MakeClientCallbacks()
{
    ngtcp2_callbacks cb{};
    cb.client_initial = ngtcp2_crypto_client_initial_cb;
    cb.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    cb.encrypt = ngtcp2_crypto_encrypt_cb;
    cb.decrypt = ngtcp2_crypto_decrypt_cb;
    cb.hp_mask = ngtcp2_crypto_hp_mask_cb;
    cb.recv_retry = ngtcp2_crypto_recv_retry_cb;
    cb.update_key = ngtcp2_crypto_update_key_cb;
    cb.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    cb.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    cb.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    cb.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
    cb.rand = RandCb;
    cb.get_new_connection_id2 = GetNewConnectionIdCb;
    cb.handshake_completed = HandshakeCompletedCb;
    cb.recv_stream_data = RecvStreamDataCb;
    cb.stream_close = StreamCloseCb;
    cb.acked_stream_data_offset = AckedStreamDataOffsetCb;
    return cb;
}

void ToNgtcp2Cid(const ConnectionId &src, ngtcp2_cid &dst)
{
    dst.datalen = src.len;
    std::memcpy(dst.data, src.data.data(), src.len);
}

// Configure SSL* after creation. role: 0 = server (accept), 1 = client (connect).
void ConfigureSsl(Connection::Impl &impl, TlsContext &tls, std::string_view server_name)
{
    auto *ssl_ctx = static_cast<SSL_CTX *>(tls.native_handle());
    impl.mSsl = SSL_new(ssl_ctx);
    if (impl.mSsl == nullptr)
    {
        throw std::runtime_error("SSL_new failed");
    }

    impl.mConnRef.get_conn = &Connection::Impl::GetConn;
    impl.mConnRef.user_data = &impl;
    SSL_set_app_data(impl.mSsl, &impl.mConnRef);

    if (tls.role() == TlsContext::Role::Client)
    {
        SSL_set_connect_state(impl.mSsl);
        if (!tls.alpns().empty())
        {
            // Reconstruct wire-format ALPN from the high-level list,
            // matching what TlsContext stores for the SSL_CTX-wide
            // setting. Per-SSL override is what the ngtcp2 examples do.
            std::vector<std::uint8_t> wire;
            for (const auto &a : tls.alpns())
            {
                wire.push_back(static_cast<std::uint8_t>(a.size()));
                wire.insert(wire.end(), a.begin(), a.end());
            }
            SSL_set_alpn_protos(impl.mSsl, wire.data(), static_cast<unsigned>(wire.size()));
        }
        if (!server_name.empty())
        {
            // SSL_set_tlsext_host_name expects a NUL-terminated string.
            std::string sni(server_name);
            SSL_set_tlsext_host_name(impl.mSsl, sni.c_str());
        }
    }
    else
    {
        SSL_set_accept_state(impl.mSsl);
    }
}

std::unique_ptr<Connection::Impl> NewImpl(TlsContext &tls, const asio::ip::udp::endpoint &local,
                                          const asio::ip::udp::endpoint &remote,
                                          std::string_view server_name)
{
    auto impl = std::make_unique<Connection::Impl>();
    impl->mLocal = local;
    impl->mRemote = remote;
    impl->StoreEndpointSockaddr();
    ConfigureSsl(*impl, tls, server_name);
    return impl;
}

} // namespace

Connection::Connection(std::unique_ptr<Impl> impl) noexcept : mImpl(std::move(impl))
{
}
Connection::~Connection() = default;

std::unique_ptr<Connection> Connection::MakeServer(TlsContext &tls, ConnectionId client_dcid,
                                                   ConnectionId client_scid,
                                                   const asio::ip::udp::endpoint &local,
                                                   const asio::ip::udp::endpoint &remote)
{
    if (tls.role() != TlsContext::Role::Server)
    {
        throw std::invalid_argument("MakeServer requires a server-role TlsContext");
    }

    auto impl = NewImpl(tls, local, remote, /*server_name=*/{});

    // Per RFC 9000 §7.2: the server's outbound DCID is the client's
    // SCID. params.original_dcid is the value the client put as DCID
    // in its first Initial (= client_dcid). The server's own SCID is
    // freshly generated below and never matches anything client-side.
    ngtcp2_cid ng_client_dcid{}; // = original_dcid
    ngtcp2_cid ng_client_scid{}; // = server's outbound DCID
    ToNgtcp2Cid(client_dcid, ng_client_dcid);
    ToNgtcp2Cid(client_scid, ng_client_scid);

    ConnectionId server_scid_app = MakeRandomConnectionId(8);
    ngtcp2_cid ng_server_scid{};
    ToNgtcp2Cid(server_scid_app, ng_server_scid);

    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    InitSettings(settings);
    InitTransportParams(params);
    params.original_dcid = ng_client_dcid;
    params.original_dcid_present = 1;

    ngtcp2_path path = impl->MakePath();
    ngtcp2_callbacks cb = MakeServerCallbacks();

    int rv = ngtcp2_conn_server_new(&impl->mConn, &ng_client_scid, &ng_server_scid, &path, NGTCP2_PROTO_VER_V1, &cb, &settings, &params, /*mem=*/nullptr,
                                    /*user_data=*/impl.get());
    if (rv != 0)
    {
        throw std::runtime_error(std::string("ngtcp2_conn_server_new: ") + ngtcp2_strerror(rv));
    }
    ngtcp2_conn_set_tls_native_handle(impl->mConn, impl->mSsl);

    return std::unique_ptr<Connection>(new Connection(std::move(impl)));
}

std::unique_ptr<Connection> Connection::MakeClient(TlsContext &tls,
                                                   const asio::ip::udp::endpoint &local,
                                                   const asio::ip::udp::endpoint &remote,
                                                   std::string_view server_name)
{
    if (tls.role() != TlsContext::Role::Client)
    {
        throw std::invalid_argument("MakeClient requires a client-role TlsContext");
    }

    auto impl = NewImpl(tls, local, remote, server_name);

    // Client picks both CIDs locally. DCID is what the server will see
    // as its initial destination CID; SCID identifies this side.
    ConnectionId dcid_app = MakeRandomConnectionId(NGTCP2_MIN_INITIAL_DCIDLEN);
    ConnectionId scid_app = MakeRandomConnectionId(8);
    ngtcp2_cid ng_dcid{};
    ngtcp2_cid ng_scid{};
    ToNgtcp2Cid(dcid_app, ng_dcid);
    ToNgtcp2Cid(scid_app, ng_scid);

    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    InitSettings(settings);
    InitTransportParams(params);

    ngtcp2_path path = impl->MakePath();
    ngtcp2_callbacks cb = MakeClientCallbacks();

    int rv = ngtcp2_conn_client_new(&impl->mConn, &ng_dcid, &ng_scid, &path, NGTCP2_PROTO_VER_V1, &cb, &settings, &params, /*mem=*/nullptr,
                                    /*user_data=*/impl.get());
    if (rv != 0)
    {
        throw std::runtime_error(std::string("ngtcp2_conn_client_new: ") + ngtcp2_strerror(rv));
    }
    ngtcp2_conn_set_tls_native_handle(impl->mConn, impl->mSsl);

    return std::unique_ptr<Connection>(new Connection(std::move(impl)));
}

void Connection::set_handshake_complete_cb(HandshakeCompleteCb cb)
{
    mImpl->mHandshakeCb = std::move(cb);
}
void Connection::set_stream_data_cb(StreamDataCb cb)
{
    mImpl->mStreamDataCb = std::move(cb);
}
void Connection::set_stream_close_cb(StreamCloseCb cb)
{
    mImpl->mStreamCloseCb = std::move(cb);
}

void Connection::set_acked_stream_data_offset_cb(AckedStreamDataOffsetCb cb)
{
    mImpl->mAckedStreamDataCb = std::move(cb);
}

void Connection::set_pre_write_cb(PreWriteCb cb)
{
    mImpl->mPreWriteCb = std::move(cb);
}

void *Connection::native_conn() const noexcept
{
    return mImpl->mConn;
}
const asio::ip::udp::endpoint &Connection::local_endpoint() const noexcept
{
    return mImpl->mLocal;
}
const asio::ip::udp::endpoint &Connection::remote_endpoint() const noexcept
{
    return mImpl->mRemote;
}
bool Connection::handshake_completed() const noexcept
{
    return mImpl->mHandshakeDone;
}

int Connection::read_packet(std::span<const std::uint8_t> data,
                            const asio::ip::udp::endpoint &remote)
{
    // Refresh the remote sockaddr in case the source endpoint differs
    // from the cached one (e.g., NAT rebinding). Per QUIC the local
    // endpoint stays put for these tests, so we leave it alone.
    if (remote != mImpl->mRemote)
    {
        mImpl->mRemote = remote;
        mImpl->StoreEndpointSockaddr();
    }
    ngtcp2_path path = mImpl->MakePath();
    ngtcp2_pkt_info pi{}; // ECN bits zero — Phase 1 doesn't read them.
    int rv = ngtcp2_conn_read_pkt(mImpl->mConn, &path, &pi, data.data(), data.size(), NowNs());
    if (rv != 0)
    {
        spdlog::warn("ngtcp2_conn_read_pkt -> {} ({})", rv, ngtcp2_strerror(rv));
    }
    return rv;
}

int Connection::write_to(const SendFn &send_fn)
{
    // Let higher layers (HTTP/3) push application stream data into
    // ngtcp2 before the QUIC-only flush runs. Without this, packets
    // arriving via the Endpoint demux only trigger ACKs / control
    // frames and HTTP/3 streams stall.
    if (mImpl->mPreWriteCb)
    {
        mImpl->mPreWriteCb(send_fn);
    }

    // Drive ngtcp2 until it has nothing more to emit. Per RFC 9000 the
    // sender MAY coalesce, but each writev_stream call produces at most
    // one UDP datagram; loop until the function returns 0.
    constexpr std::size_t kBufLen = 1452; // safe IPv4 path MTU minus headers
    std::array<std::uint8_t, kBufLen> buf{};

    while (true)
    {
        ngtcp2_path path = mImpl->MakePath();
        ngtcp2_pkt_info pi{};
        ngtcp2_ssize ndatalen = 0;
        ngtcp2_ssize n = ngtcp2_conn_writev_stream(
            mImpl->mConn, &path, &pi, buf.data(), buf.size(), &ndatalen, NGTCP2_WRITE_STREAM_FLAG_NONE, -1, nullptr, 0, NowNs());

        if (n == 0)
        {
            // Nothing more to send right now.
            return 0;
        }
        if (n < 0)
        {
            if (n == NGTCP2_ERR_WRITE_MORE)
            {
                // Shouldn't occur without MORE flag, but tolerate it.
                continue;
            }
            return static_cast<int>(n);
        }

        // Echo the path back into our cached endpoints in case ngtcp2
        // selected an alternate path (path migration / preferred addr).
        // For Phase 1 the path doesn't change; this is defensive.
        send_fn({buf.data(), static_cast<std::size_t>(n)}, mImpl->mRemote);
    }
}

int Connection::open_bidi_stream(std::int64_t &stream_id)
{
    return ngtcp2_conn_open_bidi_stream(mImpl->mConn, &stream_id, /*user_data=*/nullptr);
}

int Connection::write_stream(std::int64_t stream_id, std::span<const std::uint8_t> data, bool fin,
                             const SendFn &send_fn, std::size_t *bytes_written)
{
    constexpr std::size_t kBufLen = 1452;
    std::array<std::uint8_t, kBufLen> buf{};

    std::size_t offset = 0;
    bool fin_pending = fin;
    bool stream_done = false;

    while (true)
    {
        ngtcp2_path path = mImpl->MakePath();
        ngtcp2_pkt_info pi{};
        ngtcp2_ssize ndatalen = 0;

        // Once the stream payload + FIN have been consumed by ngtcp2 we
        // must stop passing the stream_id (ngtcp2 returns
        // NGTCP2_ERR_STREAM_SHUT_WR if we keep referencing a half-closed
        // write side). Pass stream_id=-1 to flush coalesced packets.
        std::int64_t sid = stream_done ? -1 : stream_id;
        ngtcp2_vec vec{};
        ngtcp2_vec *vecp = nullptr;
        std::size_t vec_cnt = 0;
        std::uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
        if (!stream_done)
        {
            vec.base = const_cast<std::uint8_t *>(data.data() + offset);
            vec.len = data.size() - offset;
            vecp = &vec;
            vec_cnt = 1;
            if (fin_pending)
            {
                flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
            }
        }

        ngtcp2_ssize n = ngtcp2_conn_writev_stream(
            mImpl->mConn, &path, &pi, buf.data(), buf.size(), &ndatalen, flags, sid, vecp, vec_cnt, NowNs());

        if (n < 0)
        {
            return static_cast<int>(n);
        }

        if (ndatalen > 0)
        {
            offset += static_cast<std::size_t>(ndatalen);
            if (offset == data.size())
            {
                fin_pending = false;
            }
        }

        // Once everything we wanted to write is in ngtcp2's queue, stop
        // referencing the stream_id on subsequent iterations.
        if (!stream_done && offset == data.size() && !fin_pending)
        {
            stream_done = true;
        }

        if (n == 0)
        {
            break;
        }
        send_fn({buf.data(), static_cast<std::size_t>(n)}, mImpl->mRemote);
    }
    if (bytes_written != nullptr)
    {
        *bytes_written = offset;
    }
    return 0;
}

std::chrono::steady_clock::time_point Connection::expiry() const noexcept
{
    // ngtcp2 returns UINT64_MAX when no deadline is armed. Convert the
    // ngtcp2 nanosecond timestamp (anchored on steady_clock via NowNs)
    // into a steady_clock::time_point so callers can compare against
    // their existing asio::steady_timer state directly.
    ngtcp2_tstamp t = ngtcp2_conn_get_expiry(mImpl->mConn);
    if (t == UINT64_MAX)
    {
        return std::chrono::steady_clock::time_point::max();
    }
    return std::chrono::steady_clock::time_point{std::chrono::nanoseconds{t}};
}

int Connection::handle_expiry()
{
    int rv = ngtcp2_conn_handle_expiry(mImpl->mConn, NowNs());
    if (rv != 0)
    {
        return rv;
    }
    return 0;
}

std::vector<ConnectionId> Connection::local_scids() const
{
    std::size_t n = ngtcp2_conn_get_scid(mImpl->mConn, nullptr);
    std::vector<ngtcp2_cid> tmp(n);
    if (n > 0)
    {
        ngtcp2_conn_get_scid(mImpl->mConn, tmp.data());
    }
    std::vector<ConnectionId> out;
    out.reserve(n);
    for (auto const &cid : tmp)
    {
        ConnectionId id{};
        // ngtcp2_cid::datalen is capped at NGTCP2_MAX_CIDLEN == 20.
        id.len = cid.datalen;
        std::memcpy(id.data.data(), cid.data, cid.datalen);
        out.push_back(id);
    }
    return out;
}

std::vector<std::uint8_t> Connection::peer_certificate_der() const
{
    if (mImpl->mSsl == nullptr)
    {
        return {};
    }
    // SSL_get1_peer_certificate (OpenSSL 3.x) bumps the refcount; we
    // own the X509* and must X509_free it. Older builds may still ship
    // SSL_get_peer_certificate as the spelling — quictls aliases both.
    X509 *cert = SSL_get1_peer_certificate(mImpl->mSsl);
    if (cert == nullptr)
    {
        return {};
    }
    const int der_len = i2d_X509(cert, nullptr);
    if (der_len <= 0)
    {
        X509_free(cert);
        return {};
    }
    std::vector<std::uint8_t> out(static_cast<std::size_t>(der_len));
    std::uint8_t *p = out.data();
    if (i2d_X509(cert, &p) <= 0)
    {
        X509_free(cert);
        return {};
    }
    X509_free(cert);
    return out;
}

} // namespace clv::quic
