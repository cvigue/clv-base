# NetCore

C++ networking components for CLV projects: STUN/NAT helpers, TUN devices, and the `clv::quic` transport built on ngtcp2 + quictls.

## Layout

| Path | Contents |
|------|----------|
| `src/quic/` | `clv::quic::Endpoint`, `Connection`, `TlsContext` |
| `src/` | STUN client, TUN, netlink/nftables helpers |
| `tests/` | Unit tests (QUIC handshake, TLS verify, STUN, …) |
| `demos/` | Sample programs — see [demos/README.md](demos/README.md) |
| `docs/` | QUIC and testing notes |

## Key components

### `clv::quic` transport

ngtcp2-based QUIC stack (replaced the earlier custom `quic_legacy` implementation).

| Type | Header | Role |
|------|--------|------|
| `TlsContext` | `quic/tls_context.h` | Shared `SSL_CTX` per role (server/client); ALPN, mTLS, trust anchors |
| `Endpoint` | `quic/endpoint.h` | UDP socket + inbound demux |
| `Connection` | `quic/connection.h` | Per-connection ngtcp2 + TLS state |

`TlsContext` keeps OpenSSL out of its public header (`native_handle()` returns `void*`; trust store attach uses forward-declared `x509_store_st*`).

**Trust anchors (two tiers):**

```cpp
// Tier 1 — static CA bundle on this context's built-in store
client.SetTrustedCaPem(ca_pem);
client.SetTrustedCrlPem(crl_pem);
client.SetVerifyPeer(false);

// Tier 2 — alias a shared canonical X509_STORE (must outlive TlsContext)
tls.UseSharedCertStore(trust.store());  // clv::OpenSSL::SslX509Store converts to X509_STORE*
```

Tier-1 PEM loading delegates to `clv::sslhelp` (`SslX509Store`). See [../SslHelp/docs/CERTIFICATE_VALIDATION.md](../SslHelp/docs/CERTIFICATE_VALIDATION.md).

Further detail: [docs/QUIC_IMPLEMENTATION.md](docs/QUIC_IMPLEMENTATION.md).

### STUN client (`stun_client.hpp`)

RFC 5389 STUN client on standalone Asio + C++20 coroutines: public address discovery, NAT classification, multi-server fallback.

### STUN utilities (`stun_utils.hpp`)

Packet build/parse helpers, typed enums for message and NAT types.

### Linux utilities

- `util/netlink_helper.h`, `util/nla_helpers.h` — generic netlink (`clv::netlink`)
- IP helpers live in Core: `Core/src/net/ipv4_utils.h`, `ipv6_utils.h` (`clv::net::ipv4/ipv6`)

## Building and testing

From a parent project build tree:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --target clv_netcore test_netcore
ctest --test-dir build -R Quic2 --output-on-failure
```

## Demos

| Demo | Description |
|------|-------------|
| `quic_simple_server` | HTTP/3 over QUIC (interop test infra) |
| `simple_server` | Config-driven HTTPS server |
| `stun_test_client` | STUN connectivity / NAT type |
| `hole_punch_demo` | UDP hole punching |

See [demos/README.md](demos/README.md).

## Appendix: GCC 15.2 coroutine leak

In `query_server_impl`, structured bindings that span `co_await` in coroutine frames may not be destroyed on GCC 15.2 (STUN client). GCC 14 and Clang are fine. ASAN reports this correctly when probing multiple STUN servers.
