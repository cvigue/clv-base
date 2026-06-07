// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_SSLHELP_SSL_NO_RC_COPY_H
#define CLV_SSLHELP_SSL_NO_RC_COPY_H

#include "HelpSslException.h"
#include "HelpSslNoRc.h"

namespace clv::OpenSSL {

// ================================================================================================
//  Clone-strategy adapters
// ================================================================================================
//
//  OpenSSL exposes two conventions for duplicating opaque objects:
//
//    _dup pattern :  T* X509_NAME_dup(const T*)          — alloc + copy in one call
//    _copy pattern:  int EVP_CIPHER_CTX_copy(T*, const T*) — copy into pre-allocated dst
//
//  The adapters below normalise both into a single static interface:
//
//      static OpenSslT* Clone(const OpenSslT* src);   // returns owning ptr or nullptr
//
//  Pass the chosen adapter as the ClonerT parameter of SslNoRcCopy.
// ================================================================================================

/**
 * @brief Adapter for the OpenSSL _dup pattern: `T* fn(const T*)`
 * @tparam OpenSslT The OpenSSL opaque type
 * @tparam DupFn    The duplication function (e.g. X509_NAME_dup)
 */
template <typename OpenSslT, OpenSslT *(*DupFn)(const OpenSslT *)>
struct SslDupCloner
{
    static OpenSslT *Clone(const OpenSslT *src)
    {
        return DupFn(src);
    }
};

/**
 * @brief Adapter for the OpenSSL alloc + _copy pattern:
 *        `T* alloc()` then `int copy(T* dst, const T* src)`
 * @tparam OpenSslT The OpenSSL opaque type
 * @tparam AllocFn  Allocation function (e.g. EVP_CIPHER_CTX_new)
 * @tparam FreeFn   Deallocation function (e.g. EVP_CIPHER_CTX_free)
 * @tparam CopyFn   Copy function returning 1 on success (e.g. EVP_CIPHER_CTX_copy)
 */
template <typename OpenSslT, auto AllocFn, void (*FreeFn)(OpenSslT *),
          int (*CopyFn)(OpenSslT *, const OpenSslT *)>
struct SslCopyCloner
{
    static OpenSslT *Clone(const OpenSslT *src)
    {
        OpenSslT *dup = AllocFn();
        if (!dup)
            return nullptr;
        if (CopyFn(dup, src) != 1)
        {
            FreeFn(dup);
            return nullptr;
        }
        return dup;
    }
};

// ================================================================================================
//  SslNoRcCopy — CRTP base providing Clone()
// ================================================================================================

/**
 * @brief Copyable extension of SslNoRc using CRTP
 * @details Provides a generic Clone() method for any OpenSSL type that can be
 *          duplicated.  The copy strategy is selected at compile-time via
 *          ClonerT, which must expose `static OpenSslT* Clone(const OpenSslT*)`.
 *          Use SslDupCloner for _dup-style functions and SslCopyCloner for
 *          alloc + _copy-style functions.
 *
 * @tparam DerivedT  The concrete derived type (CRTP — for correct Clone() return type)
 * @tparam OpenSslT  The OpenSSL opaque type (e.g. EVP_CIPHER_CTX)
 * @tparam SslAlloc  Allocation function (e.g. EVP_CIPHER_CTX_new)
 * @tparam SslFree   Deallocation function (e.g. EVP_CIPHER_CTX_free)
 * @tparam ClonerT   Clone strategy adapter (SslDupCloner or SslCopyCloner)
 *
 * @see SslNoRc, SslDupCloner, SslCopyCloner
 */
template <typename DerivedT, typename OpenSslT, auto SslAlloc,
          void (*SslFree)(OpenSslT *), typename ClonerT>
class SslNoRcCopy : public SslNoRc<OpenSslT, SslAlloc, SslFree>
{
    using Base = SslNoRc<OpenSslT, SslAlloc, SslFree>;

  public:
    using Base::Base; // inherit all SslNoRc constructors

    /**
     * @brief Deep-copy the managed OpenSSL object, returning the derived type
     * @details Delegates to ClonerT::Clone() to produce an independent copy.
     *          The returned object is fully independent — safe for concurrent
     *          use on a different thread.
     * @return A new DerivedT owning an independent copy
     * @throws SslException if duplication fails
     */
    [[nodiscard]] DerivedT Clone() const
    {
        OpenSslT *dup = ClonerT::Clone(this->Get());
        if (!dup)
            throw SslException("Clone failed");
        return DerivedT(dup);
    }
};

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_SSL_NO_RC_COPY_H
