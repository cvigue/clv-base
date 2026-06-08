# QUIC implementation (`clv::quic`)

## Status

**Current stack:** ngtcp2 + quictls (`ngtcp2_crypto_quictls`), namespace `clv::quic`.

The previous in-tree custom QUIC stack (`quic_legacy`, MicroUdpServer / frame parser) was removed after ngtcp2 interop validation. Some older docs and demos may still mention the legacy layout — this file describes the **current** code under `NetCore/src/quic/`.

## Architecture

```
┌─────────────────────────────────────────┐
│  Application (e.g. mesh transport)      │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│  clv::quic::Endpoint                    │  UDP bind, recv loop, DCID demux
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│  clv::quic::Connection                  │  ngtcp2_conn + per-conn SSL
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│  clv::quic::TlsContext                  │  Shared SSL_CTX (server or client role)
└─────────────────────────────────────────┘
```

One `TlsContext` is typically shared across all connections of the same role on an endpoint. Per-connection `SSL` objects are created inside `Connection`.

## Components

| File | Description |
|------|-------------|
| `quic/tls_context.h` | `TlsContext` — cert/key PEM, ALPN, `SetTrustedCaPem`, `UseSharedCertStore` |
| `quic/endpoint.h` | UDP I/O, packet handler callback |
| `quic/connection.h` | Connection lifecycle, stream callbacks, handshake drive |

Public headers avoid including `<openssl/ssl.h>` and `<ngtcp2/...>` where possible; implementation details live in `.cpp` translation units.

## TLS and trust

`TlsContext` factory methods:

- `MakeServer` / `MakeServerFromPem` — server cert chain + key + ALPN
- `MakeClient` / `MakeClientFromPem` — client context; optional client cert for mTLS

Trust configuration:

| Method | Tier | Description |
|--------|------|-------------|
| `SetTrustedCaPem` | 1 | Add CA(s) to context's internal store |
| `SetTrustedCrlPem` | 1 | Add CRL(s), enable leaf CRL check |
| `UseSharedCertStore` | 2 | `SSL_CTX_set1_cert_store` — share external store |
| `SetVerifyPeer` | — | `SSL_VERIFY_PEER`; optional `FAIL_IF_NO_PEER_CERT` on server |
| `SetVerifyPeerAcceptAny` | — | Require peer cert but skip chain validation (pin-by-identity mode) |

PEM parsing uses `clv::OpenSSL::SslX509Store` from SslHelp. See [../../SslHelp/docs/CERTIFICATE_VALIDATION.md](../../SslHelp/docs/CERTIFICATE_VALIDATION.md).

## HTTP/3

`demos/quic_simple_server.cpp` is an HTTP/3 server on top of `Endpoint` + `Connection` + nghttp3, used by interop test infrastructure. See [../demos/QUIC_SIMPLE_SERVER.md](../demos/QUIC_SIMPLE_SERVER.md).

## Testing

```bash
cd build
ctest -R Quic2 --output-on-failure
```

Covers `TlsContext` construction, TLS verify paths, connection scaffolding, endpoint smoke tests.

## References

- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html) — QUIC transport
- [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html) — QUIC-TLS
- [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114.html) — HTTP/3
- [ngtcp2](https://github.com/ngtcp2/ngtcp2)
