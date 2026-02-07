# SslHelp

RAII C++ wrappers for OpenSSL types.

## Overview

SslHelp provides safe, modern C++ wrappers around OpenSSL's C API:
- Automatic memory management (no leaks)
- Reference counting where appropriate
- Exception-based error handling
- Move semantics support

## Documentation

See [docs/README.md](docs/README.md) for API overview.

See [docs/CERTIFICATE_VALIDATION.md](docs/CERTIFICATE_VALIDATION.md) for certificate validation reference.

## Key Components

### Core Wrappers

| Header | OpenSSL Type | Description |
|--------|--------------|-------------|
| `HelpSslContext.h` | `SSL_CTX` | TLS context |
| `HelpSslSsl.h` | `SSL` | TLS connection |
| `HelpSslX509.h` | `X509` | Certificate |
| `HelpSslEvpPkey.h` | `EVP_PKEY` | Public/private key |
| `HelpSslBio.h` | `BIO` | I/O abstraction |

### RAII Templates

| Header | Description |
|--------|-------------|
| `HelpSslNoRc.h` | Non-refcounted types (`std::unique_ptr` style) |
| `HelpSslWithRc.h` | Refcounted types (handles `up_ref`/`free`) |

### Certificate Validation

| Header | Description |
|--------|-------------|
| `HelpSslTrustStore.h` | CA store and CRL management |
| `HelpSslCertValidator.h` | Chain validation with results |
| `HelpSslVerifyHelper.h` | TLS handshake integration |

### Utilities

| Header | Description |
|--------|-------------|
| `HelpSslHandshakeContext.h` | Memory BIO-based TLS handshake |
| `HelpSslHmac.h` | HMAC operations |
| `HelpSslCipher.h` | Symmetric encryption |
| `HelpSslAsn1.h` | ASN.1 utilities |
| `HelpSslBigNum.h` | Big number operations |

## Usage

```cpp
#include "SslHelp/src/HelpSslContext.h"
#include "SslHelp/src/HelpSslX509.h"

// Load certificate - automatic cleanup on scope exit
SslX509 cert = SslX509::LoadFromFile("cert.pem");
std::string cn = cert.GetCommonName();

// Create TLS context
SslContext ctx = SslContext::CreateServer();
ctx.UseCertificate(cert);
```

## Tests

250+ tests covering all wrappers:

```bash
cd build
ctest -R SslHelp --output-on-failure
```
