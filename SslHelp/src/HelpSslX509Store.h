// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_SSLHELP_X509STORE_H
#define CLV_SSLHELP_X509STORE_H

#include "HelpSslException.h"
#include "HelpSslFileUtils.h"
#include "HelpSslWithRc.h"
#include "HelpSslX509.h"
#include "HelpSslX509Crl.h"

#include <cstdio>
#include <filesystem>
#include <memory>
#include <openssl/x509err.h>
#include <string_view>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
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

    /** @brief Non-owning refcount bump for an external X509_STORE (e.g. SSL_CTX's internal store) */
    static SslX509Store Borrow(X509_STORE *store)
    {
        return BorrowRef<SslX509Store>(store);
    }

    /**
        @brief Add a trusted certificate to the store
        @param cert Certificate to add (store takes ownership of a reference)
        @note X509_STORE_add_cert increments refcount, so cert remains valid
              after the SslX509 wrapper is destroyed. Duplicate certs are ignored.
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
        {
            const unsigned long err = ERR_peek_last_error();
            if (ERR_GET_REASON(err) != X509_R_CERT_ALREADY_IN_HASH_TABLE)
                throw SslException("X509_STORE_add_cert failed");
            ERR_clear_error();
        }
    }

    /**
        @brief Load one or more trusted CA certificates from a PEM bundle
        @throws SslException if PEM is empty or no certificates were parsed
    */
    void AddCertsFromPem(std::string_view pem)
    {
        if (pem.empty())
            throw SslException("AddCertsFromPem: PEM is empty");

        BIO *bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
        if (bio == nullptr)
            throw SslException("BIO_new_mem_buf failed");

        int loaded = 0;
        while (true)
        {
            X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
            if (cert == nullptr)
            {
                ERR_clear_error();
                break;
            }
            AddCert(cert);
            X509_free(cert);
            ++loaded;
        }
        BIO_free(bio);

        if (loaded == 0)
            throw SslException("AddCertsFromPem: no certificates parsed");
    }

    /**
        @brief Load one or more trusted CA certificates from a PEM file
    */
    void LoadCertsFromFile(const std::filesystem::path &ca_file)
    {
        if (!std::filesystem::exists(ca_file))
            throw SslException("CA file not found: " + ca_file.string());

        std::unique_ptr<FILE, decltype(&FileDeleter)> fp(fopen(ca_file.string().c_str(), "r"), &FileDeleter);
        if (!fp)
            throw SslException("Failed to open CA file: " + ca_file.string());

        int loaded = 0;
        while (true)
        {
            X509 *cert = PEM_read_X509(fp.get(), nullptr, nullptr, nullptr);
            if (cert == nullptr)
            {
                ERR_clear_error();
                break;
            }
            AddCert(cert);
            X509_free(cert);
            ++loaded;
        }

        if (loaded == 0)
            throw SslException("No valid CA certificates found in file");
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

    /**
        @brief Load one or more CRLs from a PEM bundle and enable leaf CRL checking
    */
    void AddCrlsFromPem(std::string_view pem)
    {
        if (pem.empty())
            throw SslException("AddCrlsFromPem: PEM is empty");

        BIO *bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
        if (bio == nullptr)
            throw SslException("BIO_new_mem_buf failed");

        int loaded = 0;
        while (true)
        {
            X509_CRL *crl = PEM_read_bio_X509_CRL(bio, nullptr, nullptr, nullptr);
            if (crl == nullptr)
            {
                ERR_clear_error();
                break;
            }
            if (X509_STORE_add_crl(Get(), crl) != 1)
            {
                X509_CRL_free(crl);
                BIO_free(bio);
                throw SslException("X509_STORE_add_crl failed");
            }
            X509_CRL_free(crl);
            ++loaded;
        }
        BIO_free(bio);

        if (loaded == 0)
            throw SslException("AddCrlsFromPem: no CRLs parsed");

        SetFlags(X509_V_FLAG_CRL_CHECK);
    }

    void SetFlags(unsigned long flags)
    {
        X509_STORE_set_flags(Get(), flags);
    }
};

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_X509STORE_H
