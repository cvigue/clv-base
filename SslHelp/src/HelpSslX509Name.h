// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLV_SSLHELP_SSLX509NAME_H
#define CLV_SSLHELP_SSLX509NAME_H

#include <unordered_map>
#include <string>
#include <string_view>

#include "HelpSslException.h"
#include "HelpSslNoRcCopy.h"

#include <openssl/x509.h>


namespace clv::OpenSSL {
/**
  @brief Wraps an OpenSSL X509_NAME in an RAII wrapper
*/
struct SslX509Name : SslNoRcCopy<SslX509Name, X509_NAME,
                                 &X509_NAME_new, &X509_NAME_free,
                                 SslDupCloner<X509_NAME, &X509_NAME_dup>>
{
    using KeyValueStrListT = std::unordered_map<std::string_view, std::string_view>;

    SslX509Name() = default;
    explicit SslX509Name(std::nullptr_t) noexcept
        : SslNoRcCopy(nullptr) {};
    explicit SslX509Name(X509_NAME *ptr)
        : SslNoRcCopy(ptr) {};
    SslX509Name(std::string_view key, std::string_view value)
        : SslX509Name()
    {
        AddEntry(key, value);
    }
    SslX509Name(const KeyValueStrListT &strList)
        : SslX509Name()
    {
        AddEntries(strList);
    }
    // Clone() inherited from SslNoRcCopy — returns SslX509Name

    void AddEntry(std::string_view key, std::string_view value)
    {
        auto k = std::string(key);
        auto v = std::string(value);
        if (X509_NAME_add_entry_by_txt(Get(), k.c_str(), MBSTRING_UTF8, reinterpret_cast<const unsigned char *>(v.c_str()), -1, -1, 0) != 1)
            throw SslException("X509_NAME_add_entry_by_txt failed");
    }

  private: // Making private until I can sort out my 'exception guarantee' policy here
    void AddEntries(const KeyValueStrListT &strList)
    {
        for (const auto &item : strList)
            AddEntry(std::get<0>(item), std::get<1>(item));
    }
};

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_SSLX509NAME_H