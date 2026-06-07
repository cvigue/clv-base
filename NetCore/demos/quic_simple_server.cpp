// Copyright (c) 2025- Charlie Vigue. All rights reserved.
//
// quic_simple_server — HTTP/3 file server used by the test-infra interop
// adapter. Built on:
//   - clv::quic::TlsContext  (quictls + ngtcp2_crypto)
//   - clv::quic::Endpoint    (asio UDP socket + DCID demux)
//   - clv::quic::Connection  (per-connection ngtcp2 state)
//   - nghttp3                (HTTP/3 server-side framing + QPACK)
//
// Scope: handshake + transfer interop test cases. Static files only.
// GET requests resolve against config.static.root_dir; everything else
// answers 405/404. No mTLS, no 0-RTT, no qlog.

#include "quic/connection.h"
#include "quic/endpoint.h"
#include "quic/tls_context.h"
#include "util/MimeType.h"

#include "asan_notify.h"
#include "config_json_parser.h"

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>

#include <openssl/ssl.h>

#include <asio.hpp>
#include <asio/signal_set.hpp>
#include <asio/steady_timer.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <exception>
#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

namespace {

// ----------------------------------------------------------------------------
// Per-connection HTTP/3 state.
//
// Owns the nghttp3_conn for one QUIC connection. Receives stream data from
// the Connection's StreamDataCb, drives request parsing, and provides the
// outbound queue that pump() drains.
// ----------------------------------------------------------------------------
class H3Connection : public std::enable_shared_from_this<H3Connection>
{
  public:
    // Per-stream state for the request being served.
    struct StreamState
    {
        std::int64_t stream_id{-1};
        std::string method;
        std::string path;
        // Response body (entire file loaded eagerly; interop runner uploads
        // small files, ~MBs max). Holding it as a shared buffer simplifies
        // the nghttp3_data_reader lifetime.
        std::shared_ptr<std::vector<std::uint8_t>> body;
        std::size_t body_offset{0};
    };

    H3Connection(std::weak_ptr<clv::quic::Connection> conn,
                 const asio::ip::udp::endpoint &remote, fs::path root_dir,
                 std::string default_file)
        : mConnWeak(std::move(conn)), mRemote(remote), mRootDir(std::move(root_dir)),
          mDefaultFile(std::move(default_file))
    {
    }

    ~H3Connection()
    {
        if (mHttp3 != nullptr)
        {
            nghttp3_conn_del(mHttp3);
            mHttp3 = nullptr;
        }
    }

    H3Connection(const H3Connection &) = delete;
    H3Connection &operator=(const H3Connection &) = delete;
    H3Connection(H3Connection &&) = delete;
    H3Connection &operator=(H3Connection &&) = delete;

    void setup_http3();

    // Called from Connection::StreamDataCb. Feeds bytes into nghttp3.
    void on_stream_data(std::int64_t stream_id,
                        std::span<const std::uint8_t> data, bool fin);

    // Called from Connection::StreamCloseCb.
    void on_stream_close(std::int64_t stream_id, std::uint64_t err);

    // Called from Connection's acked_stream_data_offset hook.
    void on_acked_stream_data_offset(std::int64_t stream_id, std::uint64_t datalen);

    // Drain HTTP/3 outbound stream data into the QUIC connection. Each chunk
    // is queued via Connection::write_stream which flushes packets through
    // send_fn. Returns false on a fatal error.
    bool pump_outbound(const clv::quic::Connection::SendFn &send_fn);

    [[nodiscard]] const asio::ip::udp::endpoint &remote() const noexcept
    {
        return mRemote;
    }

  private:
    // nghttp3 callback bridges.
    static int CbRecvHeader(nghttp3_conn *, std::int64_t stream_id, std::int32_t token,
                            nghttp3_rcbuf *name, nghttp3_rcbuf *value, std::uint8_t flags,
                            void *user_data, void *stream_user_data);
    static int CbEndHeaders(nghttp3_conn *, std::int64_t stream_id, int fin,
                            void *user_data, void *stream_user_data);
    static int CbStreamClose(nghttp3_conn *, std::int64_t stream_id,
                             std::uint64_t app_error_code, void *user_data,
                             void *stream_user_data);
    static int CbDeferredConsume(nghttp3_conn *, std::int64_t stream_id,
                                 std::size_t nconsumed, void *user_data,
                                 void *stream_user_data);
    static int CbStopSending(nghttp3_conn *, std::int64_t stream_id,
                             std::uint64_t app_error_code, void *user_data,
                             void *stream_user_data);
    static int CbResetStream(nghttp3_conn *, std::int64_t stream_id,
                             std::uint64_t app_error_code, void *user_data,
                             void *stream_user_data);

    // nghttp3 data reader for response bodies.
    static nghttp3_ssize CbReadData(nghttp3_conn *, std::int64_t stream_id,
                                    nghttp3_vec *vec, std::size_t veccnt,
                                    std::uint32_t *pflags, void *user_data,
                                    void *stream_user_data);

    StreamState *get_or_create_stream(std::int64_t stream_id);
    StreamState *find_stream(std::int64_t stream_id);

    // Build + queue a fixed-status, no-body response (4xx/5xx).
    void send_status_response(std::int64_t stream_id, std::string_view status);

    // Resolve `path` under mRootDir, load file into body if possible, and
    // submit a 200 response with content-type / content-length headers.
    void send_file_response(StreamState &st);

    std::weak_ptr<clv::quic::Connection> mConnWeak;
    asio::ip::udp::endpoint mRemote;
    fs::path mRootDir;
    std::string mDefaultFile;
    nghttp3_conn *mHttp3{nullptr};
    std::unordered_map<std::int64_t, std::unique_ptr<StreamState>> mStreams;
};

// ----------------------------------------------------------------------------
// Per-connection HTTP/0.9-over-QUIC ("hq-interop") state. This ALPN is
// used by the quic-interop-runner "handshake" / "transfer" / etc. test
// cases — the request is a single line `GET /path\r\n`, the response is
// the raw file body followed by FIN. No framing, no headers.
// ----------------------------------------------------------------------------
class HqConnection : public std::enable_shared_from_this<HqConnection>
{
  public:
    HqConnection(std::weak_ptr<clv::quic::Connection> conn,
                 const asio::ip::udp::endpoint &remote, fs::path root_dir,
                 std::string default_file)
        : mConnWeak(std::move(conn)), mRemote(remote), mRootDir(std::move(root_dir)),
          mDefaultFile(std::move(default_file))
    {
    }

    void on_stream_data(std::int64_t stream_id,
                        std::span<const std::uint8_t> data, bool /*fin*/);

    // Flushes any pending response bodies via Connection::write_stream.
    bool pump_outbound(const clv::quic::Connection::SendFn &send_fn);

  private:
    struct Pending
    {
        std::int64_t stream_id;
        std::shared_ptr<std::vector<std::uint8_t>> body;
        std::size_t offset{0};
    };

    std::weak_ptr<clv::quic::Connection> mConnWeak;
    asio::ip::udp::endpoint mRemote;
    fs::path mRootDir;
    std::string mDefaultFile;
    std::unordered_map<std::int64_t, std::vector<std::uint8_t>> mRecvBuf;
    std::deque<Pending> mPending;
};

// ----------------------------------------------------------------------------
// Per-connection holder: owns Connection + H3Connection + expiry timer.
// ----------------------------------------------------------------------------
struct ConnSlot : std::enable_shared_from_this<ConnSlot>
{
    enum class Mode
    {
        Unknown,
        Http3,
        Hq
    };

    std::shared_ptr<clv::quic::Connection> conn;
    std::shared_ptr<H3Connection> h3;
    std::shared_ptr<HqConnection> hq;
    asio::steady_timer expiry_timer;
    Mode mode{Mode::Unknown};

    ConnSlot(asio::io_context &io_ctx,
             std::shared_ptr<clv::quic::Connection> c,
             std::shared_ptr<H3Connection> h,
             std::shared_ptr<HqConnection> hqc)
        : conn(std::move(c)), h3(std::move(h)), hq(std::move(hqc)), expiry_timer(io_ctx)
    {
    }
};

// ----------------------------------------------------------------------------
// H3Connection implementation.
// ----------------------------------------------------------------------------

H3Connection::StreamState *H3Connection::get_or_create_stream(std::int64_t stream_id)
{
    auto it = mStreams.find(stream_id);
    if (it != mStreams.end())
    {
        return it->second.get();
    }
    auto st = std::make_unique<StreamState>();
    st->stream_id = stream_id;
    auto *raw = st.get();
    mStreams.emplace(stream_id, std::move(st));
    return raw;
}

H3Connection::StreamState *H3Connection::find_stream(std::int64_t stream_id)
{
    auto it = mStreams.find(stream_id);
    return it == mStreams.end() ? nullptr : it->second.get();
}

void H3Connection::setup_http3()
{
    if (mHttp3 != nullptr)
    {
        return;
    }
    auto conn = mConnWeak.lock();
    if (!conn)
    {
        return;
    }
    auto *ngc = static_cast<ngtcp2_conn *>(conn->native_conn());

    nghttp3_callbacks callbacks{};
    callbacks.recv_header = &H3Connection::CbRecvHeader;
    callbacks.end_headers = &H3Connection::CbEndHeaders;
    callbacks.stream_close = &H3Connection::CbStreamClose;
    callbacks.deferred_consume = &H3Connection::CbDeferredConsume;
    callbacks.stop_sending = &H3Connection::CbStopSending;
    callbacks.reset_stream = &H3Connection::CbResetStream;

    nghttp3_settings settings{};
    nghttp3_settings_default(&settings);
    settings.qpack_max_dtable_capacity = 4096;
    settings.qpack_blocked_streams = 100;

    if (auto rv = nghttp3_conn_server_new(&mHttp3, &callbacks, &settings, nghttp3_mem_default(), this);
        rv != 0)
    {
        spdlog::error("nghttp3_conn_server_new failed: {}", nghttp3_strerror(rv));
        mHttp3 = nullptr;
        return;
    }

    const auto *tp = ngtcp2_conn_get_local_transport_params(ngc);
    nghttp3_conn_set_max_client_streams_bidi(mHttp3, tp->initial_max_streams_bidi);

    // Open three server-initiated unidirectional control/QPACK streams.
    std::int64_t ctrl_id = -1;
    std::int64_t qpack_enc_id = -1;
    std::int64_t qpack_dec_id = -1;
    if (auto rv = ngtcp2_conn_open_uni_stream(ngc, &ctrl_id, nullptr); rv != 0)
    {
        spdlog::error("open_uni_stream(ctrl) failed: {}", ngtcp2_strerror(rv));
        nghttp3_conn_del(mHttp3);
        mHttp3 = nullptr;
        return;
    }
    if (auto rv = ngtcp2_conn_open_uni_stream(ngc, &qpack_enc_id, nullptr); rv != 0)
    {
        spdlog::error("open_uni_stream(qpack_enc) failed: {}", ngtcp2_strerror(rv));
        nghttp3_conn_del(mHttp3);
        mHttp3 = nullptr;
        return;
    }
    if (auto rv = ngtcp2_conn_open_uni_stream(ngc, &qpack_dec_id, nullptr); rv != 0)
    {
        spdlog::error("open_uni_stream(qpack_dec) failed: {}", ngtcp2_strerror(rv));
        nghttp3_conn_del(mHttp3);
        mHttp3 = nullptr;
        return;
    }
    if (auto rv = nghttp3_conn_bind_control_stream(mHttp3, ctrl_id); rv != 0)
    {
        spdlog::error("bind_control_stream failed: {}", nghttp3_strerror(rv));
        nghttp3_conn_del(mHttp3);
        mHttp3 = nullptr;
        return;
    }
    if (auto rv = nghttp3_conn_bind_qpack_streams(mHttp3, qpack_enc_id, qpack_dec_id);
        rv != 0)
    {
        spdlog::error("bind_qpack_streams failed: {}", nghttp3_strerror(rv));
        nghttp3_conn_del(mHttp3);
        mHttp3 = nullptr;
        return;
    }

    spdlog::debug("HTTP/3 setup complete (ctrl={}, qpack_enc={}, qpack_dec={})", ctrl_id, qpack_enc_id, qpack_dec_id);
}

void H3Connection::on_stream_data(std::int64_t stream_id,
                                  std::span<const std::uint8_t> data, bool fin)
{
    if (mHttp3 == nullptr)
    {
        return;
    }
    get_or_create_stream(stream_id);

    auto n = nghttp3_conn_read_stream(mHttp3, stream_id, data.data(), data.size(), fin ? 1 : 0);
    if (n < 0)
    {
        spdlog::warn("nghttp3_conn_read_stream({}) failed: {}", stream_id, nghttp3_strerror(static_cast<int>(n)));
        return;
    }
    if (auto conn = mConnWeak.lock())
    {
        auto *ngc = static_cast<ngtcp2_conn *>(conn->native_conn());
        ngtcp2_conn_extend_max_stream_offset(ngc, stream_id, static_cast<std::uint64_t>(n));
        ngtcp2_conn_extend_max_offset(ngc, static_cast<std::uint64_t>(n));
    }
}

void H3Connection::on_stream_close(std::int64_t stream_id, std::uint64_t err)
{
    if (mHttp3 != nullptr)
    {
        // nghttp3_conn_close_stream signals app-level FIN/abort to nghttp3
        // so it can release per-stream state. Ignore errors here — they
        // typically indicate the stream was already closed.
        nghttp3_conn_close_stream(mHttp3, stream_id, err);
    }
    mStreams.erase(stream_id);
}

void H3Connection::on_acked_stream_data_offset(std::int64_t stream_id,
                                               std::uint64_t datalen)
{
    if (mHttp3 == nullptr)
    {
        return;
    }
    if (auto rv = nghttp3_conn_add_ack_offset(mHttp3, stream_id, datalen); rv != 0)
    {
        spdlog::debug("nghttp3_conn_add_ack_offset({}, {}) returned {}", stream_id, datalen, nghttp3_strerror(rv));
    }
}

bool H3Connection::pump_outbound(const clv::quic::Connection::SendFn &send_fn)
{
    auto conn = mConnWeak.lock();
    if (!conn || mHttp3 == nullptr)
    {
        return true;
    }

    // Drain everything nghttp3 wants to send right now. Each iteration we
    // gather one or more nghttp3_vec chunks for a single stream, copy them
    // into a contiguous buffer (interop traffic is small; zero-copy isn't
    // worth the complexity here), hand to Connection::write_stream which
    // packetizes + emits via send_fn, then tell nghttp3 it's "on the wire".
    //
    // The loop terminates when nghttp3 has no more stream data to emit. The
    // caller is responsible for calling Connection::write_to afterwards to
    // flush any remaining QUIC control frames (ACKs, etc.).
    constexpr std::size_t kMaxIter = 64;
    constexpr std::size_t kMaxVec = 16;
    std::array<nghttp3_vec, kMaxVec> vec{};

    for (std::size_t iter = 0; iter < kMaxIter; ++iter)
    {
        std::int64_t stream_id = -1;
        int fin = 0;
        auto nvec = nghttp3_conn_writev_stream(mHttp3, &stream_id, &fin, vec.data(), vec.size());
        if (nvec < 0)
        {
            spdlog::warn("nghttp3_conn_writev_stream failed: {}",
                         nghttp3_strerror(static_cast<int>(nvec)));
            return false;
        }
        if (nvec == 0 && fin == 0)
        {
            break;
        }

        // Concatenate vec data.
        std::size_t total = 0;
        for (nghttp3_ssize i = 0; i < nvec; ++i)
        {
            total += vec[i].len;
        }
        std::vector<std::uint8_t> buf;
        buf.reserve(total);
        for (nghttp3_ssize i = 0; i < nvec; ++i)
        {
            buf.insert(buf.end(), vec[i].base, vec[i].base + vec[i].len);
        }

        // Write the chunk to the QUIC stream with optional FIN.
        const int rv = conn->write_stream(stream_id, std::span<const std::uint8_t>(buf), fin != 0, send_fn);
        if (rv != 0)
        {
            spdlog::warn("Connection::write_stream({}) failed: {}", stream_id, rv);
            return false;
        }

        // Tell nghttp3 the data has been handed to the transport. After this
        // call nghttp3 may release internal buffers (the actual ack arrives
        // via on_acked_stream_data_offset).
        if (total > 0 || fin != 0)
        {
            if (auto rv2 = nghttp3_conn_add_write_offset(mHttp3, stream_id, total);
                rv2 != 0)
            {
                spdlog::warn("nghttp3_conn_add_write_offset({}, {}) failed: {}",
                             stream_id,
                             total,
                             nghttp3_strerror(rv2));
                return false;
            }
        }

        if (total == 0 && fin == 0)
        {
            // Defensive: avoid spinning if nghttp3 keeps signaling nothing.
            break;
        }
    }
    return true;
}

int H3Connection::CbRecvHeader(nghttp3_conn * /*conn*/, std::int64_t stream_id,
                               std::int32_t /*token*/, nghttp3_rcbuf *name,
                               nghttp3_rcbuf *value, std::uint8_t /*flags*/,
                               void *user_data, void * /*stream_user_data*/)
{
    auto *self = static_cast<H3Connection *>(user_data);
    auto *st = self->get_or_create_stream(stream_id);
    auto nv = nghttp3_rcbuf_get_buf(name);
    auto vv = nghttp3_rcbuf_get_buf(value);
    std::string_view ns(reinterpret_cast<const char *>(nv.base), nv.len);
    std::string_view vs(reinterpret_cast<const char *>(vv.base), vv.len);
    if (ns == ":method")
    {
        st->method.assign(vs);
    }
    else if (ns == ":path")
    {
        st->path.assign(vs);
    }
    return 0;
}

int H3Connection::CbEndHeaders(nghttp3_conn * /*conn*/, std::int64_t stream_id,
                               int /*fin*/, void *user_data, void * /*stream_user_data*/)
{
    auto *self = static_cast<H3Connection *>(user_data);
    auto *st = self->find_stream(stream_id);
    if (st == nullptr)
    {
        return 0;
    }
    spdlog::debug("HTTP/3 request stream={} method={} path={}", stream_id, st->method, st->path);

    if (st->method != "GET" && st->method != "HEAD")
    {
        self->send_status_response(stream_id, "405");
        return 0;
    }
    self->send_file_response(*st);
    return 0;
}

int H3Connection::CbStreamClose(nghttp3_conn * /*conn*/, std::int64_t stream_id,
                                std::uint64_t /*app_error_code*/, void *user_data,
                                void * /*stream_user_data*/)
{
    auto *self = static_cast<H3Connection *>(user_data);
    self->mStreams.erase(stream_id);
    return 0;
}

int H3Connection::CbDeferredConsume(nghttp3_conn * /*conn*/, std::int64_t stream_id,
                                    std::size_t nconsumed, void *user_data,
                                    void * /*stream_user_data*/)
{
    auto *self = static_cast<H3Connection *>(user_data);
    if (auto c = self->mConnWeak.lock())
    {
        auto *ngc = static_cast<ngtcp2_conn *>(c->native_conn());
        ngtcp2_conn_extend_max_stream_offset(ngc, stream_id, static_cast<std::uint64_t>(nconsumed));
        ngtcp2_conn_extend_max_offset(ngc, static_cast<std::uint64_t>(nconsumed));
    }
    return 0;
}

int H3Connection::CbStopSending(nghttp3_conn *conn, std::int64_t stream_id,
                                std::uint64_t /*app_error_code*/, void * /*user_data*/,
                                void * /*stream_user_data*/)
{
    nghttp3_conn_shutdown_stream_read(conn, stream_id);
    return 0;
}

int H3Connection::CbResetStream(nghttp3_conn *conn, std::int64_t stream_id,
                                std::uint64_t /*app_error_code*/, void * /*user_data*/,
                                void * /*stream_user_data*/)
{
    nghttp3_conn_shutdown_stream_read(conn, stream_id);
    return 0;
}

nghttp3_ssize H3Connection::CbReadData(nghttp3_conn * /*conn*/, std::int64_t stream_id,
                                       nghttp3_vec *vec, std::size_t veccnt,
                                       std::uint32_t *pflags, void *user_data,
                                       void * /*stream_user_data*/)
{
    auto *self = static_cast<H3Connection *>(user_data);
    auto *st = self->find_stream(stream_id);
    if (st == nullptr || !st->body)
    {
        *pflags |= NGHTTP3_DATA_FLAG_EOF;
        return 0;
    }
    if (veccnt == 0)
    {
        return 0;
    }
    const std::size_t remaining = st->body->size() - st->body_offset;
    if (remaining == 0)
    {
        *pflags |= NGHTTP3_DATA_FLAG_EOF;
        return 0;
    }
    vec[0].base = st->body->data() + st->body_offset;
    vec[0].len = remaining;
    st->body_offset = st->body->size();
    *pflags |= NGHTTP3_DATA_FLAG_EOF;
    return 1;
}

void H3Connection::send_status_response(std::int64_t stream_id, std::string_view status)
{
    std::string status_str(status);
    std::array<nghttp3_nv, 2> nva{
        nghttp3_nv{(std::uint8_t *)":status", (std::uint8_t *)status_str.data(), 7, status_str.size(), NGHTTP3_NV_FLAG_NO_COPY_NAME},
        nghttp3_nv{(std::uint8_t *)"content-length", (std::uint8_t *)"0", 14, 1, NGHTTP3_NV_FLAG_NO_COPY_NAME | NGHTTP3_NV_FLAG_NO_COPY_VALUE},
    };
    // Note: status_str must outlive submit_response; nghttp3 copies the value
    // by default (no NO_COPY_VALUE flag), so the temporary is safe.
    if (auto rv = nghttp3_conn_submit_response(mHttp3, stream_id, nva.data(), nva.size(), nullptr);
        rv != 0)
    {
        spdlog::warn("submit_response({}) failed: {}", stream_id, nghttp3_strerror(rv));
    }
}

void H3Connection::send_file_response(StreamState &st)
{
    // Resolve path. Disallow ".." anywhere to thwart traversal.
    std::string rel = st.path;
    if (rel.empty() || rel[0] != '/')
    {
        rel.insert(rel.begin(), '/');
    }
    // Strip query string.
    if (auto qpos = rel.find('?'); qpos != std::string::npos)
    {
        rel.resize(qpos);
    }
    if (rel.find("..") != std::string::npos)
    {
        send_status_response(st.stream_id, "404");
        return;
    }

    fs::path full = mRootDir;
    // Avoid leading "/" causing operator/= to reset to root.
    full /= rel.substr(1);
    std::error_code ec;
    if (fs::is_directory(full, ec))
    {
        full /= mDefaultFile;
    }
    if (!fs::is_regular_file(full, ec))
    {
        spdlog::debug("404 not found: {}", full.string());
        send_status_response(st.stream_id, "404");
        return;
    }

    // Load file into memory.
    std::ifstream in(full, std::ios::binary | std::ios::ate);
    if (!in)
    {
        send_status_response(st.stream_id, "404");
        return;
    }
    const auto sz = static_cast<std::streamsize>(in.tellg());
    in.seekg(0);
    auto body = std::make_shared<std::vector<std::uint8_t>>(static_cast<std::size_t>(sz));
    if (sz > 0 && !in.read(reinterpret_cast<char *>(body->data()), sz))
    {
        send_status_response(st.stream_id, "500");
        return;
    }
    st.body = std::move(body);
    st.body_offset = 0;

    // Build headers. nghttp3 copies header values by default, so locals are
    // safe to drop after the submit call.
    std::string content_type = clv::http::MimeType::GetMimeType(full);
    if (content_type.empty())
    {
        content_type = "application/octet-stream";
    }
    std::string content_length = std::to_string(st.body->size());

    std::array<nghttp3_nv, 3> nva{
        nghttp3_nv{(std::uint8_t *)":status", (std::uint8_t *)"200", 7, 3, NGHTTP3_NV_FLAG_NO_COPY_NAME | NGHTTP3_NV_FLAG_NO_COPY_VALUE},
        nghttp3_nv{(std::uint8_t *)"content-type",
                   reinterpret_cast<std::uint8_t *>(content_type.data()),
                   12,
                   content_type.size(),
                   NGHTTP3_NV_FLAG_NO_COPY_NAME},
        nghttp3_nv{(std::uint8_t *)"content-length",
                   reinterpret_cast<std::uint8_t *>(content_length.data()),
                   14,
                   content_length.size(),
                   NGHTTP3_NV_FLAG_NO_COPY_NAME},
    };

    nghttp3_data_reader dr{};
    dr.read_data = &H3Connection::CbReadData;

    if (auto rv = nghttp3_conn_submit_response(mHttp3, st.stream_id, nva.data(), nva.size(), &dr);
        rv != 0)
    {
        spdlog::warn("submit_response({}) failed: {}", st.stream_id, nghttp3_strerror(rv));
    }
}

// ----------------------------------------------------------------------------
// HqConnection implementation.
// ----------------------------------------------------------------------------
void HqConnection::on_stream_data(std::int64_t stream_id,
                                  std::span<const std::uint8_t> data, bool /*fin*/)
{
    auto &buf = mRecvBuf[stream_id];
    buf.insert(buf.end(), data.begin(), data.end());

    // Always extend flow-control credits for the consumed bytes.
    if (auto conn = mConnWeak.lock())
    {
        auto *ngc = static_cast<ngtcp2_conn *>(conn->native_conn());
        ngtcp2_conn_extend_max_stream_offset(ngc, stream_id, data.size());
        ngtcp2_conn_extend_max_offset(ngc, data.size());
    }

    auto nl_it = std::find(buf.begin(), buf.end(), '\n');
    if (nl_it == buf.end())
    {
        return; // still waiting for end-of-request-line
    }

    std::string line(buf.begin(), nl_it);
    if (!line.empty() && line.back() == '\r')
    {
        line.pop_back();
    }
    mRecvBuf.erase(stream_id);

    // Parse "GET /<path>".
    std::string path;
    constexpr std::string_view kPrefix = "GET ";
    if (line.size() >= kPrefix.size() && line.compare(0, kPrefix.size(), kPrefix) == 0)
    {
        path = line.substr(kPrefix.size());
        // Drop any trailing HTTP-version token (HTTP/0.9 has none, but be lenient).
        auto sp = path.find(' ');
        if (sp != std::string::npos)
        {
            path.resize(sp);
        }
    }
    if (!path.empty() && path.front() == '/')
    {
        path.erase(0, 1);
    }
    if (path.empty())
    {
        path = mDefaultFile;
    }

    auto body = std::make_shared<std::vector<std::uint8_t>>();
    fs::path full = mRootDir / path;
    std::error_code ec;
    auto canon = fs::weakly_canonical(full, ec);
    auto root_canon = fs::weakly_canonical(mRootDir, ec);
    bool inside_root = !ec && canon.string().rfind(root_canon.string(), 0) == 0;

    if (inside_root)
    {
        std::ifstream f(full, std::ios::binary);
        if (f)
        {
            f.seekg(0, std::ios::end);
            auto sz = static_cast<std::streamoff>(f.tellg());
            f.seekg(0);
            if (sz > 0)
            {
                body->resize(static_cast<std::size_t>(sz));
                f.read(reinterpret_cast<char *>(body->data()), sz);
            }
        }
        else
        {
            spdlog::warn("hq: file not found: {}", full.string());
        }
    }
    else
    {
        spdlog::warn("hq: path escapes root: {}", path);
    }

    mPending.push_back({stream_id, std::move(body)});
}

bool HqConnection::pump_outbound(const clv::quic::Connection::SendFn &send_fn)
{
    auto conn = mConnWeak.lock();
    if (!conn)
    {
        return false;
    }
    while (!mPending.empty())
    {
        auto &p = mPending.front();
        std::span<const std::uint8_t> remaining(p.body->data() + p.offset,
                                                p.body->size() - p.offset);
        std::size_t written = 0;
        const int rv = conn->write_stream(p.stream_id, remaining, /*fin=*/true, send_fn, &written);
        if (rv != 0)
        {
            spdlog::warn("hq: write_stream({}) failed: {}", p.stream_id, rv);
            return false;
        }
        p.offset += written;
        if (p.offset < p.body->size())
        {
            // Flow / congestion control blocked us; ngtcp2 will re-arm
            // and pre_write_cb will run again once credits open up.
            break;
        }
        mPending.pop_front();
    }
    return true;
}

// ----------------------------------------------------------------------------
// Server: owns Endpoint + TLS + connection slot table.
// ----------------------------------------------------------------------------

struct ServerConfig
{
    std::string host;
    int port{0};
    fs::path cert_path;
    fs::path key_path;
    fs::path root_dir;
    std::string default_file;
};

class Server
{
  public:
    Server(asio::io_context &io_ctx, const ServerConfig &cfg)
        : mIoCtx(io_ctx),
          mTls(clv::quic::TlsContext::MakeServer(cfg.cert_path, cfg.key_path,
                                                 clv::quic::AlpnList{"h3", "hq-interop"})),
          mEndpoint(io_ctx, asio::ip::udp::endpoint(asio::ip::make_address(cfg.host),
                                                    static_cast<unsigned short>(cfg.port))),
          mRootDir(cfg.root_dir), mDefaultFile(cfg.default_file)
    {
        mSendFn = [this](std::span<const std::uint8_t> bytes,
                         const asio::ip::udp::endpoint &dst)
        {
            mEndpoint.send_sync(bytes, dst);
        };

        mEndpoint.set_packet_handler(
            [this](std::span<const std::uint8_t> pkt,
                   const asio::ip::udp::endpoint &remote)
        { on_packet(pkt, remote); });
        mEndpoint.start();

        spdlog::info("HTTP/3 server listening on {}:{}", cfg.host, mEndpoint.local_endpoint().port());
    }

    ~Server()
    {
        mEndpoint.stop();
    }

  private:
    void on_packet(std::span<const std::uint8_t> pkt,
                   const asio::ip::udp::endpoint &remote);

    void create_server_connection(const clv::quic::PacketCids &cids,
                                  std::span<const std::uint8_t> first_pkt,
                                  const asio::ip::udp::endpoint &remote);

    void schedule_expiry(const std::shared_ptr<ConnSlot> &slot);

    void drain(const std::shared_ptr<ConnSlot> &slot);

    asio::io_context &mIoCtx;
    clv::quic::TlsContext mTls;
    clv::quic::Endpoint mEndpoint;
    fs::path mRootDir;
    std::string mDefaultFile;
    clv::quic::Connection::SendFn mSendFn;

    // Active connections keyed by SCID (the value we hand out to the peer;
    // they put it in DCID of subsequent packets). Initial packets that
    // don't match a known SCID fall here via the Endpoint packet handler
    // and get a fresh Connection.
    std::unordered_map<std::string, std::shared_ptr<ConnSlot>> mSlots;
};

void Server::on_packet(std::span<const std::uint8_t> pkt,
                       const asio::ip::udp::endpoint &remote)
{
    // The Endpoint demux already routes to registered Connection::read_packet
    // for packets whose DCID matches a known SCID. We get here only for
    // unmatched packets — typically the first Initial from a new client,
    // or a probe packet using an unsupported QUIC version (e.g., the
    // quic-network-simulator wait-for-it-quic probe using version
    // 0x57414954 "WAIT").
    ngtcp2_version_cid vc{};
    int dv = ngtcp2_pkt_decode_version_cid(&vc, pkt.data(), pkt.size(),
                                           /*short_dcidlen=*/0);
    if (dv == NGTCP2_ERR_VERSION_NEGOTIATION)
    {
        // Reply with a Version Negotiation packet announcing v1 support.
        // The peer-supplied DCID/SCID get swapped (RFC 9000 §17.2.1).
        std::array<std::uint8_t, 1280> buf{};
        std::array<std::uint32_t, 1> supported{NGTCP2_PROTO_VER_V1};
        std::random_device rd;
        std::uint8_t unused = static_cast<std::uint8_t>(rd() & 0xff);
        ngtcp2_ssize n = ngtcp2_pkt_write_version_negotiation(
            buf.data(), buf.size(), unused, vc.scid, vc.scidlen, // peer's SCID becomes our DCID
            vc.dcid,
            vc.dcidlen, // peer's DCID becomes our SCID
            supported.data(),
            supported.size());
        if (n > 0)
        {
            mSendFn({buf.data(), static_cast<std::size_t>(n)}, remote);
        }
        return;
    }
    if (dv != 0)
    {
        spdlog::debug("Drop unparsable packet from {}: decode_version_cid rv={}",
                      remote.address().to_string(),
                      dv);
        return;
    }

    // Guard with ngtcp2_accept: only create a fresh server connection for
    // packets that are valid client Initials. Otherwise we'd spin up a
    // Connection with no keys and trip a ngtcp2 assertion on first
    // writev_stream.
    ngtcp2_pkt_hd hd{};
    if (auto rv = ngtcp2_accept(&hd, pkt.data(), pkt.size()); rv != 0)
    {
        spdlog::debug("Drop non-Initial packet from {}: ngtcp2_accept rv={}",
                      remote.address().to_string(),
                      rv);
        return;
    }
    spdlog::debug("on_packet: accepting Initial from {} (size={})",
                  remote.address().to_string(),
                  pkt.size());
    try
    {
        auto cids = clv::quic::DecodePacketCids(pkt);
        create_server_connection(cids, pkt, remote);
    }
    catch (const std::exception &e)
    {
        spdlog::warn("Drop unparsable packet from {}: {}", remote.address().to_string(), e.what());
    }
}

void Server::create_server_connection(const clv::quic::PacketCids &cids,
                                      std::span<const std::uint8_t> first_pkt,
                                      const asio::ip::udp::endpoint &remote)
{
    auto local = mEndpoint.local_endpoint();
    std::shared_ptr<clv::quic::Connection> conn = clv::quic::Connection::MakeServer(mTls, cids.dcid, cids.scid, local, remote);
    if (!conn)
    {
        spdlog::warn("create_server_connection: MakeServer returned null");
        return;
    }
    spdlog::debug("create_server_connection: created Connection for {}",
                  remote.address().to_string());

    auto h3 = std::make_shared<H3Connection>(std::weak_ptr<clv::quic::Connection>(conn),
                                             remote,
                                             mRootDir,
                                             mDefaultFile);
    auto hq = std::make_shared<HqConnection>(std::weak_ptr<clv::quic::Connection>(conn),
                                             remote,
                                             mRootDir,
                                             mDefaultFile);

    auto slot = std::make_shared<ConnSlot>(mIoCtx, conn, h3, hq);
    std::weak_ptr<ConnSlot> slot_weak = slot;

    // Wire callbacks. We don't yet know which ALPN ngtcp2/quictls will
    // negotiate; the routing decision happens in handshake_complete_cb.
    conn->set_handshake_complete_cb([slot_weak]()
    {
        auto s = slot_weak.lock();
        if (!s)
        {
            return;
        }
        auto *ngc = static_cast<ngtcp2_conn *>(s->conn->native_conn());
        auto *ssl = static_cast<SSL *>(ngtcp2_conn_get_tls_native_handle(ngc));
        const unsigned char *alpn = nullptr;
        unsigned int alpn_len = 0;
        SSL_get0_alpn_selected(ssl, &alpn, &alpn_len);
        std::string_view negotiated(reinterpret_cast<const char *>(alpn), alpn_len);
        if (negotiated == "h3")
        {
            s->mode = ConnSlot::Mode::Http3;
            s->h3->setup_http3();
            spdlog::debug("QUIC handshake complete (alpn=h3)");
        }
        else if (negotiated == "hq-interop")
        {
            s->mode = ConnSlot::Mode::Hq;
            spdlog::debug("QUIC handshake complete (alpn=hq-interop)");
        }
        else
        {
            spdlog::warn("QUIC handshake complete with unknown ALPN: '{}'", negotiated);
        }
    });
    conn->set_stream_data_cb(
        [slot_weak](std::int64_t sid, std::span<const std::uint8_t> data, bool fin)
    {
        auto s = slot_weak.lock();
        if (!s)
        {
            return;
        }
        if (s->mode == ConnSlot::Mode::Hq)
        {
            s->hq->on_stream_data(sid, data, fin);
        }
        else
        {
            s->h3->on_stream_data(sid, data, fin);
        }
    });
    conn->set_stream_close_cb([slot_weak](std::int64_t sid, std::uint64_t err)
    {
        auto s = slot_weak.lock();
        if (!s)
        {
            return;
        }
        if (s->mode == ConnSlot::Mode::Http3)
        {
            s->h3->on_stream_close(sid, err);
        }
    });
    conn->set_acked_stream_data_offset_cb(
        [slot_weak](std::int64_t sid, std::uint64_t /*offset*/, std::uint64_t datalen)
    {
        auto s = slot_weak.lock();
        if (!s)
        {
            return;
        }
        if (s->mode == ConnSlot::Mode::Http3)
        {
            s->h3->on_acked_stream_data_offset(sid, datalen);
        }
    });
    // Driven from Endpoint::start whenever it flushes a connection. Lets the
    // application layer (H3 or HQ) inject any pending stream data into ngtcp2
    // before the QUIC-only flush runs.
    conn->set_pre_write_cb([slot_weak](const clv::quic::Connection::SendFn &send_fn)
    {
        auto s = slot_weak.lock();
        if (!s)
        {
            return;
        }
        if (s->mode == ConnSlot::Mode::Hq)
        {
            s->hq->pump_outbound(send_fn);
        }
        else if (s->mode == ConnSlot::Mode::Http3)
        {
            s->h3->pump_outbound(send_fn);
        }
    });

    // Register for inbound demux. The Endpoint reads conn->local_scids() and
    // routes by DCID match.
    mEndpoint.register_connection(*conn);
    // Also alias the client-chosen original DCID so retransmitted Initials
    // arriving before the client has learned a server-issued SCID still
    // route to this connection instead of falling through to on_packet.
    mEndpoint.register_cid_alias(
        *conn, std::span<const std::uint8_t>(cids.dcid.data.data(), cids.dcid.len));

    // Track by every local SCID so the slot survives across CID rotation.
    for (const auto &scid : conn->local_scids())
    {
        std::string key(reinterpret_cast<const char *>(scid.data.data()), scid.len);
        mSlots[key] = slot;
    }

    // Feed the first packet through the connection itself (the Endpoint
    // demux didn't see it because the SCID was not yet registered).
    if (auto rv = conn->read_packet(first_pkt, remote); rv != 0)
    {
        // The Initial was malformed (e.g., token check failed). Discard
        // the connection to avoid spinning ngtcp2 without keys.
        spdlog::warn("initial read_packet returned {}; dropping connection", rv);
        for (const auto &scid : conn->local_scids())
        {
            std::string key(reinterpret_cast<const char *>(scid.data.data()), scid.len);
            mSlots.erase(key);
        }
        mEndpoint.unregister_connection(*conn);
        return;
    }

    drain(slot);
}

void Server::drain(const std::shared_ptr<ConnSlot> &slot)
{
    // Pump application-layer outbound first so any queued response data flows
    // out; then flush any QUIC control frames.
    if (slot->mode == ConnSlot::Mode::Hq)
    {
        slot->hq->pump_outbound(mSendFn);
    }
    else if (slot->mode == ConnSlot::Mode::Http3)
    {
        slot->h3->pump_outbound(mSendFn);
    }
    if (auto rv = slot->conn->write_to(mSendFn); rv != 0)
    {
        spdlog::warn("write_to returned {}", rv);
    }
    schedule_expiry(slot);
}

void Server::schedule_expiry(const std::shared_ptr<ConnSlot> &slot)
{
    auto exp = slot->conn->expiry();
    if (exp == std::chrono::steady_clock::time_point::max())
    {
        slot->expiry_timer.cancel();
        return;
    }
    slot->expiry_timer.expires_at(exp);
    std::weak_ptr<ConnSlot> weak = slot;
    slot->expiry_timer.async_wait([this, weak](const asio::error_code &ec)
    {
        if (ec)
        {
            return;
        }
        auto s = weak.lock();
        if (!s)
        {
            return;
        }
        if (auto rv = s->conn->handle_expiry(); rv != 0)
        {
            spdlog::debug("handle_expiry returned {}", rv);
            return;
        }
        drain(s);
    });
}

} // namespace

int main(int argc, char *argv[])
{
    clv_announce_asan();

    // Logging.
    if (const char *env = std::getenv("SPDLOG_LEVEL"))
    {
        std::string_view v = env;
        if (v == "trace")
            spdlog::set_level(spdlog::level::trace);
        else if (v == "debug")
            spdlog::set_level(spdlog::level::debug);
        else if (v == "info")
            spdlog::set_level(spdlog::level::info);
        else if (v == "warn")
            spdlog::set_level(spdlog::level::warn);
        else if (v == "err" || v == "error")
            spdlog::set_level(spdlog::level::err);
    }
    else
    {
        spdlog::set_level(spdlog::level::info);
    }
    spdlog::set_pattern("[%H:%M:%S.%e] [%^%l%$] %v");

    if (argc < 2)
    {
        spdlog::error("usage: {} <server_config.json>", argv[0]);
        return 1;
    }

    try
    {
        const std::string config_file = argv[1];
        spdlog::info("Loading configuration from: {}", config_file);
        auto cfg = clv::config::ConfigJsonParser<std::string, int, double, bool>::ParseFile(
            config_file);

        ServerConfig sc;
        sc.host = cfg["server"]["host"].get<std::string>();
        sc.port = cfg["server"]["port"].get<int>();
        sc.cert_path = cfg["ssl"]["cert_path"].get<std::string>();
        sc.key_path = cfg["ssl"]["key_path"].get<std::string>();
        sc.root_dir = cfg["static"]["root_dir"].get<std::string>();
        sc.default_file = cfg["static"]["default_file"].get<std::string>("index.html");

        if (!fs::exists(sc.cert_path))
        {
            spdlog::error("certificate not found: {}", sc.cert_path.string());
            return 1;
        }
        if (!fs::exists(sc.key_path))
        {
            spdlog::error("private key not found: {}", sc.key_path.string());
            return 1;
        }
        if (!fs::exists(sc.root_dir))
        {
            spdlog::warn("static root missing, creating: {}", sc.root_dir.string());
            fs::create_directories(sc.root_dir);
        }

        spdlog::info("  host: {}", sc.host);
        spdlog::info("  port: {}", sc.port);
        spdlog::info("  cert: {}", sc.cert_path.string());
        spdlog::info("  key:  {}", sc.key_path.string());
        spdlog::info("  root: {}", sc.root_dir.string());
        spdlog::info("  default: {}", sc.default_file);

        asio::io_context io_ctx{1};
        auto work_guard = asio::make_work_guard(io_ctx);

        Server server(io_ctx, sc);

        asio::signal_set signals(io_ctx, SIGINT, SIGTERM);
        signals.async_wait([&](const asio::error_code & /*ec*/, int sig)
        {
            spdlog::info("Received signal {}, shutting down", sig);
            work_guard.reset();
            io_ctx.stop();
        });

        spdlog::info("Server running (press Ctrl+C to stop)");
        io_ctx.run();
        spdlog::info("Server stopped");
        return 0;
    }
    catch (const std::exception &e)
    {
        spdlog::error("Fatal: {}", e.what());
        return 1;
    }
}
