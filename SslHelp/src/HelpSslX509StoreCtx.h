// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_SSLHELP_SSLX509STORECTX_H
#define CLV_SSLHELP_SSLX509STORECTX_H

#include "HelpSslException.h"
#include "HelpSslNoRc.h"

#include <openssl/safestack.h>
#include <openssl/stack.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

namespace clv::OpenSSL {

inline STACK_OF(X509) * CreateX509Stack()
{
    return sk_X509_new_null();
}

inline void FreeX509Stack(STACK_OF(X509) * stack)
{
    sk_X509_free(stack);
}

/**
    @brief RAII wrapper for X509_STORE_CTX
    @details Simplifies initializing and verifying chains while ensuring cleanup.
*/
struct SslX509StoreCtx : SslNoRc<X509_STORE_CTX, &X509_STORE_CTX_new, &X509_STORE_CTX_free>
{
    using SslNoRc<X509_STORE_CTX, &X509_STORE_CTX_new, &X509_STORE_CTX_free>::SslNoRc;

    bool Init(X509_STORE *store, X509 *leaf, STACK_OF(X509) *chain = nullptr)
    {
        return X509_STORE_CTX_init(Get(), store, leaf, chain) == 1;
    }

    int Verify()
    {
        return X509_verify_cert(Get());
    }

    int Error() const
    {
        return X509_STORE_CTX_get_error(Get());
    }

    void SetError(int error)
    {
        X509_STORE_CTX_set_error(Get(), error);
    }

    X509 *GetCurrentCert()
    {
        return X509_STORE_CTX_get_current_cert(Get());
    }

    int GetErrorDepth() const
    {
        return X509_STORE_CTX_get_error_depth(Get());
    }
};

/**
    @brief RAII wrapper for STACK_OF(X509)
    @details Owns only the stack container; pushed certificates remain external.
*/
struct SslX509Stack : SslNoRc<STACK_OF(X509), &CreateX509Stack, &FreeX509Stack>
{
    using SslNoRc<STACK_OF(X509), &CreateX509Stack, &FreeX509Stack>::SslNoRc;

    STACK_OF(X509) * Raw() noexcept
    {
        return SslNoRc<STACK_OF(X509), &CreateX509Stack, &FreeX509Stack>::Get();
    }

    void Push(X509 *cert)
    {
        if (!sk_X509_push(Raw(), cert))
            throw SslException("sk_X509_push failed");
    }
};

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_SSLX509STORECTX_H
