# CLV Base

Foundation libraries for CLV projects: Core utilities, SSL helpers, and networking infrastructure.

| Component | CMake target | Role |
|-----------|--------------|------|
| **Core** | `clv::core` | C++23 utilities (containers, sync, config helpers) |
| **SslHelp** | `clv::sslhelp` | Header-only OpenSSL RAII wrappers ([docs](SslHelp/README.md)) |
| **NetTransport** | `clv::nettransport` | QUIC, STUN, HTTP helpers (portable) |
| **NetLinux** | `clv::netlinux` | Generic netlink helpers (Linux only) |
| **Compat** | `clv::netcore` | INTERFACE alias: transport + linux slices |

Mesh consumers should link `clv::nettransport` only. VpnCore links `clv::netcore` (alias) or
the Linux slices explicitly.

Not all components are fully tested or implemented. QUIC-adjacent code is newer and evolving.

## SslHelp

Header-only C++ RAII wrappers around OpenSSL:

- Trust stores (`SslX509Store`, `SslTrustStore`) with tier-1 populate vs tier-2 attach patterns
- Certificate validation (`SslCertValidator`, `SslVerifyHelper`)
- PKEY crypto (`HelpSslPkeyCrypto.h`: RSA-OAEP, EC ECDH/HKDF, PSS) for downstream envelope security

See [SslHelp/docs/CERTIFICATE_VALIDATION.md](SslHelp/docs/CERTIFICATE_VALIDATION.md) for trust-store design.

## NetCore / NetTransport

Networking infrastructure (`clv::nettransport`):

- **`clv::quic`** — ngtcp2-based QUIC transport (`Endpoint`, `Connection`, `TlsContext`)
- STUN client for NAT traversal
- HTTP helpers and demos (including `quic_simple_server` HTTP/3 interop)

## Usage

Designed as a git submodule in larger projects:

```bash
git submodule add <repo-url> extern/clv-base
```

## Submodules

Third-party sources under `extern/` are git submodules: `asio`, `cpptrace`, `googletest`, `json`, `libqsbr`, `nghttp3`, `ngtcp2`, `quictls`, `spdlog`. Initialize recursively (`nghttp3` nests `lib/sfparse`).

```bash
git clone --recurse-submodules <repo-url> clv-base
# or
git submodule update --init --recursive
```

## Building

Requires C++23 (GCC 11+, Clang 14+), CMake 3.15+, OpenSSL or quictls.

```bash
mkdir build && cd build
cmake ..
make
ctest
```

## License

See license doc.
