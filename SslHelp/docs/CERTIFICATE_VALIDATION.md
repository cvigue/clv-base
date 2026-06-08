# Certificate validation and trust stores

SslHelp separates **store mechanics** (`SslX509Store`) from **application policy** (`SslTrustStore`) and **TLS wiring** (`SslContext`, `SslVerifyHelper`, NetCore `TlsContext`).

## Types

### `SslX509Store` — primitive

RAII wrapper for `X509_STORE`. Owns (or borrows via refcount) the OpenSSL store object.

| Method | Purpose |
|--------|---------|
| `AddCert` | Add a trusted CA; duplicate certs are ignored |
| `AddCertsFromPem` | Parse a PEM bundle (multiple `BEGIN CERTIFICATE` blocks) |
| `LoadCertsFromFile` | Load CA certs from a PEM file |
| `AddCrl` / `AddCrlsFromPem` | Add CRL(s); PEM variant enables `X509_V_FLAG_CRL_CHECK` |
| `SetFlags` | e.g. `X509_V_FLAG_CRL_CHECK`, `X509_V_FLAG_CRL_CHECK_ALL` |
| `LoadDirectory` / `SetDefaultPaths` | System CA dir / default paths |
| `Borrow(X509_STORE*)` | Temporary view of an external store (e.g. `SSL_CTX`'s internal store) |

`SslX509Store` implicitly converts to `X509_STORE*` via `SslWithRc`.

### `SslTrustStore` — policy layer

Owns an `SslX509Store` plus:

- Fingerprint pinning (`AddTrustedFingerprint`, `IsFingerprintTrusted`)
- Convenience wrappers (`LoadCAFile`, `EnableCRLCheck`, `IsRevoked`)
- Accessors: `store()` (preferred in SslHelp code), `GetStore()` (explicit `X509_STORE*` for NetCore interop)

Use `SslTrustStore` when the application has **trust policy** beyond “these CAs are trusted.”

### `SslX509StoreCtx` + `SslCertValidator`

`SslX509StoreCtx` runs `X509_verify_cert` against a store and leaf cert.

`SslCertValidator` adds:

- Validity window check
- Fingerprint pinning short-circuit
- Optional EKU / identity helpers

### `SslVerifyHelper`

Connects a `SslTrustStore` to an `SslContext` verify callback (hostname/EKU/custom checks during TLS handshake). Uses `SslContext::UseCertStore` internally.

## Two trust tiers

### Tier 1 — populate the context's built-in store

Each `SSL_CTX` has a default `X509_STORE`. Tier-1 APIs **mutate that store in place** without replacing the pointer.

| API | Module |
|-----|--------|
| `SslContext::LoadVerifyPem` | SslHelp |
| `SslContext::LoadVerifyFile` | SslHelp |
| `TlsContext::SetTrustedCaPem` | NetCore (`clv::quic`) |
| `TlsContext::SetTrustedCrlPem` | NetCore |

Implementation delegates to `SslX509Store::Borrow(SSL_CTX_get_cert_store(...))` and the PEM loaders.

**Typical consumers:** demos, tests, simple clients that load a static CA bundle once.

### Tier 2 — attach a shared canonical store

When one process owns a **single trust anchor** that must be shared across multiple `SSL_CTX` objects (e.g. server + client contexts) and may be **updated at runtime** (CRL gossip), use attach:

| API | Module |
|-----|--------|
| `SslContext::UseCertStore(X509_STORE*)` | SslHelp |
| `TlsContext::UseSharedCertStore(x509_store_st*)` | NetCore |

Both call `SSL_CTX_set1_cert_store` (refcount share). OpenSSL keeps the store alive while any context holds a ref; the attach API is still **single-owner** from the application's perspective — one canonical object receives CRL updates, and every aliased context must see those mutations without concurrent writers.

`SslContext::UseCertStore` and `TlsContext::UseSharedCertStore` are the same one-liner (`SSL_CTX_set1_cert_store`) in two libraries. NetCore does not expose SslHelp's `SslContext` type in its public API, so the duplication is intentional.

**Typical consumers:** mesh nodes with live CRL updates, any multi-context app sharing one trust anchor.

```cpp
// SslHelp — implicit conversion
ctx.UseCertStore(trust.store());

// NetCore — same pattern; header forward-declares x509_store_st
tls.UseSharedCertStore(trust.store());
```

OpenSSL-native integrators can pass a raw `X509_STORE*` they manage themselves; no SslHelp types required at the call site beyond the pointer.

## NetCore `TlsContext` notes

`clv::quic::TlsContext` keeps OpenSSL out of its public header:

- `native_handle()` → `SSL_CTX*` as `void*`
- `UseSharedCertStore(x509_store_st*)` — forward-declared opaque store pointer
- `SetVerifyPeer` / `SetVerifyPeerAcceptAny` — verify mode only; no fingerprint pinning (that lives upstream)

NetCore links `clv::sslhelp` and uses `SslX509Store` internally for PEM parsing in `SetTrusted*Pem`.

## Ownership and concurrency

| API | Semantics |
|-----|-----------|
| `SSL_CTX_set1_cert_store` | Context holds a ref; refcount prevents UAF if the owner is destroyed first |
| `SslX509Store::Borrow` | Wrapper bumps refcount for the borrow scope only |
| `AddCert` / `AddCertsFromPem` | Store holds refs to added objects |
| Live CRL updates on a shared store | **Single writer** on the reactor thread (mesh: `MeshTrustAnchor::ApplyCrlUpdate` after `BindReactor`) |

Member ordering in `MeshAgent` (`trust_` before `transport_`) is about **update visibility** — CRL mutations must not race TLS handshakes reading the same store — not about refcount lifetime.

**Do not** use `SSL_CTX_set_cert_store` + manual `X509_STORE_up_ref`; use `set1_cert_store` via `UseCertStore` / `UseSharedCertStore`.

## Choosing an API

| Need | Use |
|------|-----|
| Static CA PEM on one context | Tier 1 (`LoadVerifyPem` / `SetTrustedCaPem`) |
| Shared store, live CRL updates | Tier 2 + `SslTrustStore` |
| Offline cert check before cache | `SslCertValidator` |
| TLS handshake identity checks | `SslVerifyHelper` or NetCore `SetVerifyPeer` |
| Raw OpenSSL interop | `GetStore()` or `X509_STORE*` attach |
