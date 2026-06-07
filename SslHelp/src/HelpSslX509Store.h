// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_SSLHELP_X509STORE_H
#define CLV_SSLHELP_X509STORE_H

#include "HelpSslException.h"
#include "HelpSslWithRc.h"
#include "HelpSslX509.h"
#include "HelpSslX509Crl.h"

#include <filesystem>

#include <openssl/types.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509.h>

namespace clv::OpenSSL {

/**
    @brief RAII wrapper for OpenSSL X509_STORE
    @details Manages lifetime and refcount of X509_STORE.
*/
struct SslX509Store : SslWithRc<X509_STORE, &X509_STORE_new, &X509_STORE_free, &X509_STORE_up_ref>
{
    using Base = SslWithRc<X509_STORE, &X509_STORE_new, &X509_STORE_free, &X509_STORE_up_ref>;
    using Base::Base;

    /**
        @brief Add a trusted certificate to the store
        @param cert Certificate to add (store takes ownership of a reference)
        @note X509_STORE_add_cert increments refcount, so cert remains valid
              after the SslX509 wrapper is destroyed.
    */
    void AddCert(const SslX509 &cert)
    {
        AddCert(const_cast<X509 *>(cert.Get()));
    }

    /**
        @brief Add a trusted certificate to the store (raw pointer version)
        @param cert Raw X509 pointer (store takes ownership of a reference)
        @warning Prefer the SslX509 version. This is for low-level integration only.
    */
    void AddCert(X509 *cert)
    {
        if (X509_STORE_add_cert(Get(), cert) != 1)
            throw SslException("X509_STORE_add_cert failed");
    }

    void LoadDirectory(const std::filesystem::path &ca_dir)
    {
        if (X509_STORE_load_locations(Get(), nullptr, ca_dir.string().c_str()) != 1)
            throw SslException("X509_STORE_load_locations failed for directory");
    }

    void SetDefaultPaths()
    {
        if (X509_STORE_set_default_paths(Get()) != 1)
            throw SslException("X509_STORE_set_default_paths failed");
    }

    void AddCrl(const SslX509Crl &crl)
    {
        if (X509_STORE_add_crl(Get(), const_cast<X509_CRL *>(crl.Get())) != 1)
            throw SslException("X509_STORE_add_crl failed");
    }

    void SetFlags(unsigned long flags)
    {
        X509_STORE_set_flags(Get(), flags);
    }
};

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_X509STORE_H
