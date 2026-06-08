# SslHelp

RAII C++ wrappers for OpenSSL types. Header-only — include from `SslHelp/src/`.

## Overview

- Automatic memory management (RAII + refcount where OpenSSL refcountes)
- Exception-based error handling (`SslException`)
- Move semantics; explicit `nullptr` assignment where needed
- Implicit `T*` conversion on refcounted wrappers for C API interop

## Documentation

| Doc | Contents |
|-----|----------|
| [docs/README.md](docs/README.md) | API map, quick examples |
| [docs/CERTIFICATE_VALIDATION.md](docs/CERTIFICATE_VALIDATION.md) | Trust stores, tier-1 vs tier-2, NetCore integration |

## Key components

### Core wrappers

| Header | OpenSSL type | Description |
|--------|--------------|-------------|
| `HelpSslContext.h` | `SSL_CTX` | TLS context, `UseCertStore`, `LoadVerifyPem` |
| `HelpSslSsl.h` | `SSL` | TLS connection |
| `HelpSslX509.h` | `X509` | Certificate parse and inspect |
| `HelpSslEvpPkey.h` | `EVP_PKEY` | Public/private key |
| `HelpSslBio.h` | `BIO` | I/O abstraction |

### RAII templates

| Header | Description |
|--------|-------------|
| `HelpSslNoRc.h` | Single-owner types (`unique_ptr` style) |
| `HelpSslWithRc.h` | Refcounted types (`up_ref` / `free`) |

### Trust and validation

| Header | Description |
|--------|-------------|
| `HelpSslX509Store.h` | `X509_STORE` — PEM loaders, idempotent `AddCert` |
| `HelpSslX509StoreCtx.h` | `X509_STORE_CTX` — chain verification |
| `HelpSslTrustStore.h` | CA/CRL policy, fingerprint pinning |
| `HelpSslCertValidator.h` | Chain validation with structured results |
| `HelpSslVerifyHelper.h` | TLS handshake verify integration |

### Crypto utilities

| Header | Description |
|--------|-------------|
| `HelpSslHandshakeContext.h` | Memory BIO TLS handshake |
| `HelpSslCipher.h` | AEAD (AES-GCM, ChaCha20-Poly1305) |
| `HelpSslPkeyCrypto.h` | RSA-OAEP, EC ECDH/HKDF, PSS sign/verify |
| `HelpSslHmac.h` | HMAC |
| `HelpSslAsn1.h` | ASN.1 helpers |
| `HelpSslBigNum.h` | BIGNUM operations |

## Usage

```cpp
#include "HelpSslContext.h"
#include "HelpSslX509.h"
#include "HelpSslTrustStore.h"

using namespace clv::OpenSSL;

// Parse certificate — cleanup on scope exit
SslX509 cert("-----BEGIN CERTIFICATE-----\n...");
std::string cn = cert.GetCommonName();

// Tier 1: load trust anchors into a context's built-in store
SslContext ctx(TLS_client_method());
ctx.LoadVerifyPem(ca_bundle_pem);
ctx.SetVerifyMode(SSL_VERIFY_PEER);

// Tier 2: share one canonical store across contexts
SslTrustStore trust;
trust.AddTrustedCA(ca_cert);
ctx.UseCertStore(trust.store());
```

Downstream projects (e.g. clv-meshcore) use `HelpSslPkeyCrypto.h` for envelope signing and E2E crypto.

## Tests

```bash
cd build
ctest -R test_sslhelp --output-on-failure
```
