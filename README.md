# CLV Base

Foundation libraries for CLV projects: Core utilities, SSL helpers, and networking infrastructure. Not all components are fully tested or implemented. The quic protocol and things adjacent are particularly suspect at this time.

## Components

### Core
Essential C++23 utilities used across CLV projects:

### SslHelp
C++ RAII wrappers around OpenSSL for safe SSL/TLS operations.

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
