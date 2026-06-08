# SslHelp API Overview

SslHelp is a **header-only** C++ library of RAII wrappers around OpenSSL. Headers live under `SslHelp/src/`.

## Design principles

- **RAII everywhere** — refcounted types use `SslWithRc`; single-owner types use `SslNoRc`.
- **Exceptions on failure** — OpenSSL `0` / `NULL` returns become `SslException` at wrapper boundaries.
- **Implicit conversion to raw pointers** — refcounted wrappers (`SslX509Store`, `SslX509`, …) convert to `T*` for interop with C APIs and with attach-style helpers that take `X509_STORE*`.
- **Two trust tiers** — *populate* a store (add CAs/CRLs) vs *attach* a store to a TLS context (`SSL_CTX_set1_cert_store`). See [CERTIFICATE_VALIDATION.md](CERTIFICATE_VALIDATION.md).

## Layer map

```
SslWithRc / SslNoRc          ← lifetime primitives
    ↓
SslX509, SslX509Crl, SslX509Store, SslX509StoreCtx, SslContext, SslSsl
    ↓
SslTrustStore                ← policy: fingerprints, CRL enablement, convenience loaders
    ↓
SslCertValidator, SslVerifyHelper
```

## Core wrappers

| Header | Type | OpenSSL | Notes |
|--------|------|---------|-------|
| `HelpSslContext.h` | `SslContext` | `SSL_CTX` | Certs, verify mode, `UseCertStore`, `LoadVerifyPem` |
| `HelpSslSsl.h` | `SslSsl` | `SSL` | Per-connection TLS state |
| `HelpSslX509.h` | `SslX509` | `X509` | Parse PEM/DER, extensions, identity matching |
| `HelpSslX509Crl.h` | `SslX509Crl` | `X509_CRL` | CRL parse and inspect |
| `HelpSslEvpPkey.h` | `SslEvpKey` | `EVP_PKEY` | Keys from PEM |
| `HelpSslBio.h` | `SslBio` | `BIO` | Memory/file I/O |

## Trust and validation

| Header | Type | Role |
|--------|------|------|
| `HelpSslX509Store.h` | `SslX509Store` | Owned `X509_STORE`; PEM loaders, idempotent `AddCert` |
| `HelpSslX509StoreCtx.h` | `SslX509StoreCtx` | Chain verification (`X509_verify_cert`) |
| `HelpSslTrustStore.h` | `SslTrustStore` | Application trust policy over `SslX509Store` |
| `HelpSslCertValidator.h` | `SslCertValidator` | High-level chain validation + optional pinning |
| `HelpSslVerifyHelper.h` | `SslVerifyHelper` | Wire `SslTrustStore` into `SslContext` verify callback |

## Crypto utilities

| Header | Purpose |
|--------|---------|
| `HelpSslCipher.h` | AEAD (AES-GCM, ChaCha20-Poly1305) |
| `HelpSslPkeyCrypto.h` | RSA-OAEP, EC ECDH/HKDF, PSS sign/verify |
| `HelpSslHmac.h` | HMAC |
| `HelpSslHandshakeContext.h` | Memory-BIO TLS handshake (no sockets) |

## Quick examples

### Load a certificate

```cpp
#include "HelpSslX509.h"

clv::OpenSSL::SslX509 cert("-----BEGIN CERTIFICATE-----\n...");
std::string cn = cert.GetCommonName();
```

### Tier 1 — trust anchors on a TLS context

```cpp
#include "HelpSslContext.h"

clv::OpenSSL::SslContext ctx(TLS_client_method());
ctx.LoadVerifyPem(ca_bundle_pem);   // multi-cert PEM OK
ctx.SetVerifyMode(SSL_VERIFY_PEER);
```

### Tier 2 — share a canonical store across contexts

```cpp
#include "HelpSslTrustStore.h"
#include "HelpSslContext.h"

clv::OpenSSL::SslTrustStore trust;
trust.AddTrustedCA(ca_cert);
trust.EnableCRLCheck(true);

clv::OpenSSL::SslContext server(TLS_server_method());
clv::OpenSSL::SslContext client(TLS_client_method());
server.UseCertStore(trust.store());  // SslX509Store → X509_STORE*
client.UseCertStore(trust.store());
```

### Offline chain validation

```cpp
#include "HelpSslCertValidator.h"

clv::OpenSSL::SslCertValidator validator(trust);
auto result = validator.ValidateChain(peer_cert);
```

## Tests

```bash
cd build
ctest -R test_sslhelp --output-on-failure
# or
./clv-base/SslHelp/test_sslhelp
```

## See also

- [CERTIFICATE_VALIDATION.md](CERTIFICATE_VALIDATION.md) — trust store tiers, NetCore integration
- [../README.md](../README.md) — component summary
