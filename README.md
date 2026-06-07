# CLV Base

Foundation libraries for CLV projects: Core utilities, SSL helpers, and networking infrastructure. Not all components are fully tested or implemented. The quic protocol and things adjacent are particularly suspect at this time.

## Components

### Core
Essential C++23 utilities used across CLV projects:

### SslHelp
Header-only C++ RAII wrappers around OpenSSL for safe SSL/TLS operations,
including AEAD ciphers, certificate validation, and higher-level PKEY helpers
(`HelpSslPkeyCrypto.h`: RSA-OAEP, EC ECDH/HKDF, digest sign/verify) used by
downstream projects such as clv-meshcore envelope security.

### NetCore
Networking infrastructure including:
- QUIC protocol implementation
- HTTP/3 support
- STUN client for NAT traversal
- Async I/O primitives

## Usage

This repository is designed to be used as a git submodule in larger projects.

```bash
git submodule add <repo-url> extern/clv-base
```

## Submodules

Third-party sources under `extern/` are git submodules, not vendored copies:
`asio`, `cpptrace`, `googletest`, `json`, `libqsbr`, `nghttp3`, `ngtcp2`,
`quictls`, `spdlog`. `nghttp3` has its own nested submodule (`lib/sfparse`)
that must also be initialized.

Clone fresh:

```bash
git clone --recurse-submodules <repo-url> clv-base
```

Update an existing checkout:

```bash
git submodule update --init --recursive
```

## Building

Requires:
- C++23 compiler (GCC 11+, Clang 14+)
- CMake 3.15+
- OpenSSL/quictls

```bash
mkdir build && cd build
cmake ..
make
ctest
```

## License

See license doc
