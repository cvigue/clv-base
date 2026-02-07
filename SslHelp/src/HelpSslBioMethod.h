// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLV_SSLHELP_SSL_BIO_METHOD_H
#define CLV_SSLHELP_SSL_BIO_METHOD_H

#include "HelpSslNoRc.h"

#include <openssl/bio.h>

namespace clv::OpenSSL {

/**
  @brief wrapper for OpenSSL BIO_METHOD
*/
using SslBioMethod = SslNoRc<BIO_METHOD, BIO_meth_new, BIO_meth_free>;

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_SSL_BIO_METHOD_H
