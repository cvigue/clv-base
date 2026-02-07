// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_SSLHELP_SSL_EXCEPTION_H
#define CLV_SSLHELP_SSL_EXCEPTION_H

#include <string>
#include <openssl/err.h>
#include <stdexcept>

namespace clv::OpenSSL {

/**
 * @brief Exception for OpenSSL/quictls errors
 */
class SslException : public std::runtime_error
{
  public:
    using std::runtime_error::runtime_error;

    SslException(const char *what_arg)
        : std::runtime_error(make_message(what_arg))
    {
    }

  private:
    static std::string make_message(const char *what_arg)
    {
        if (!what_arg)
            what_arg = "SslException";

        auto err = ERR_get_error();
        if (err == 0)
            return std::string(what_arg); // No SSL error in queue

        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        return std::string(what_arg) + " SSL: " + std::string(buf);
    }
};

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_SSL_EXCEPTION_H