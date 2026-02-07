// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLV_SSLHELP_SSL_BIO_H
#define CLV_SSLHELP_SSL_BIO_H

#include "HelpSslWithRc.h"

#include <openssl/bio.h>
#include <openssl/types.h>

namespace clv::OpenSSL {

/**
  @brief wrapper for OpenSSL BIO
*/
using SslBio = SslWithRc<BIO, BIO_new, BIO_vfree, BIO_up_ref>;

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_SSL_BIO_H
