// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLV_SSLHELP_SSL_ASN1_H
#define CLV_SSLHELP_SSL_ASN1_H

#include <cstddef>
#include <openssl/types.h>
#include <string>
#include <cstdint>

#include "HelpSslException.h"
#include "HelpSslNoRc.h"

#include <openssl/asn1.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <string_view>

namespace clv::OpenSSL {

//  ===============================================================================================
/**
    @brief wrapper for OpenSSL ASN1_INTEGER
    @class SslAsn1Integer

    Uses the SslNoRc<> template to provide instance management and then adds some useful
    member functions for common operations. This code defines the member functions for the
    SslAsn1Integer class, which is a wrapper around the OpenSSL ASN1_INTEGER data structure.
    The purpose of this code is to provide a convenient way to work with integer values in
    the context of OpenSSL's ASN.1 (Abstract Syntax Notation One) data encoding and decoding
    operations.

    The code takes two types of inputs: int64_t and uint64_t values. These inputs are used
    to initialize instances of the SslAsn1Integer class through the constructor functions
    SslAsn1Integer(int64_t i) and SslAsn1Integer(uint64_t i), respectively.

    The output of this code is an instance of the SslAsn1Integer class, which encapsulates
    an OpenSSL ASN1_INTEGER data structure. This instance can be used in various OpenSSL
    operations that involve ASN.1 data encoding and decoding.
*/
struct SslAsn1Integer : SslNoRc<ASN1_INTEGER, ASN1_INTEGER_new, ASN1_INTEGER_free>
{
    // Instance management boilerplate
    using SslNoRc<ASN1_INTEGER, ASN1_INTEGER_new, ASN1_INTEGER_free>::SslNoRc;

    // Custom construction
    explicit SslAsn1Integer(int64_t i);
    explicit SslAsn1Integer(uint64_t i);

    // Type API
    auto AsInt() const;
    auto AsUint() const;

    // Helper
    static SslAsn1Integer Random64();
};

//  ===============================================================================================
//  SslAsn1Integer Member function definitions
//  ===============================================================================================
/**
    @brief Initialize an OpenSSL ASN1 integer with the given value
    @param i Initial value
*/
inline SslAsn1Integer::SslAsn1Integer(int64_t i)
    : SslAsn1Integer()
{
    if (ASN1_INTEGER_set_int64(Get(), i) != 1)
        throw SslException("ASN1_INTEGER_set_int64() failed");
}
/**
    @brief Initialize an OpenSSL ASN1 integer with the given value
    @param i Initial value
*/
inline SslAsn1Integer::SslAsn1Integer(uint64_t i)
    : SslAsn1Integer()
{
    if (ASN1_INTEGER_set_uint64(Get(), i) != 1)
        throw SslException("ASN1_INTEGER_set_uint64() failed");
}
/**
    @brief Extract the value stored in the ASN1 and return it as an int64_t
    @return auto Stored value
*/
inline auto SslAsn1Integer::AsInt() const
{
    int64_t result = 0;
    if (ASN1_INTEGER_get_int64(&result, Get()) != 1)
        throw SslException("ASN1_INTEGER_get_int64() failed");
    return result;
}
/**
    @brief Extract the value stored in the ASN1 and return it as an uint64_t
    @return auto Stored value
*/
inline auto SslAsn1Integer::AsUint() const
{
    uint64_t result = 0;
    if (ASN1_INTEGER_get_uint64(&result, Get()) != 1)
        throw SslException("ASN1_INTEGER_get_uint64() failed");
    return result;
}
/**
    @brief Generate a 64 bit random number and return it in an ASN1
    @return SslAsn1Integer Random number
*/
inline SslAsn1Integer SslAsn1Integer::Random64()
{
    uint64_t rand64;
    if (RAND_bytes(reinterpret_cast<unsigned char *>(&rand64), sizeof(rand64)) != 1)
        throw SslException("RAND_bytes() failed");
    return SslAsn1Integer(rand64);
}

//  ===============================================================================================
//  SslAsn1String related - CRTP helper and derived classes for string manipulations
//  ===============================================================================================
/**
    @brief CRTP string ops helper for OpenSSL string types
    @tparam Ans1StrT The string type to add API for
    @class SslAsn1StringOps
    @note Provides shared operations for OpenSSL string-like derived class wrappers.
*/
template <typename Ans1StrT>
class SslAsn1StringOps
{
    // CRTP helpers
    auto &Base();
    const auto &Base() const;

  public:
    auto AsStringView() const;
    auto AsString() const;
};
/**
    @brief CRTP helper - returns derived reference
    @tparam Ans1StrT Derived type
    @return auto& Reference to the derived instance
*/
template <typename Ans1StrT>
auto &SslAsn1StringOps<Ans1StrT>::Base()
{
    return static_cast<Ans1StrT &>(*this);
}
/**
    @brief CRTP helper - returns derived reference
    @tparam Ans1StrT Derived type
    @return auto& Reference to the derived instance
*/
template <typename Ans1StrT>
const auto &SslAsn1StringOps<Ans1StrT>::Base() const
{
    return static_cast<const Ans1StrT &>(*this);
}
/**
    @brief Return a view of the string data
    @tparam Ans1StrT Derived type
    @return auto std::string_view of the data
*/
template <typename Ans1StrT>
auto SslAsn1StringOps<Ans1StrT>::AsStringView() const
{
    return std::string_view(reinterpret_cast<const char *>(ASN1_STRING_get0_data(Base())),
                            static_cast<std::size_t>(ASN1_STRING_length(Base())));
}
/**
    @brief Return a copy of the string data
    @tparam Ans1StrT Derived type
    @return auto std::string of the data
*/
template <typename Ans1StrT>
auto SslAsn1StringOps<Ans1StrT>::AsString() const
{
    return std::string(reinterpret_cast<const char *>(ASN1_STRING_get0_data(Base())),
                       static_cast<std::size_t>(ASN1_STRING_length(Base())));
}

//  ===============================================================================================
/**
    @brief wrapper for OpenSSL ASN1_OCTET_STRING
    @class SslAsn1OctetString
    @details This type provides type correct instance management for the wrapper and defers higher
             level operations to the inherited CRTP base class.
*/
struct SslAsn1OctetString
    : SslNoRc<ASN1_OCTET_STRING, &ASN1_OCTET_STRING_new, &ASN1_OCTET_STRING_free>,
      SslAsn1StringOps<SslAsn1OctetString>
{
    using SslNoRc<ASN1_OCTET_STRING, &ASN1_OCTET_STRING_new, &ASN1_OCTET_STRING_free>::SslNoRc;
    explicit SslAsn1OctetString(std::string_view str);
};
/**
    @brief Type specific construction - initialise with the given string
    @param str Initial value
*/
inline SslAsn1OctetString::SslAsn1OctetString(std::string_view str)
    : SslAsn1OctetString()
{
    if (ASN1_OCTET_STRING_set(Get(),
                              reinterpret_cast<const unsigned char *>(str.data()),
                              static_cast<int>(str.length()))
        != 1)
        throw SslException("ASN1_OCTET_STRING_set() failed");
}

//  ===============================================================================================
/**
    @brief wrapper for OpenSSL ASN1_STRING
    @class SslAsn1String
    @details This type provides type correct instance management for the wrapper and defers higher
             level operations to the inherited CRTP base class.
*/
struct SslAsn1String : SslNoRc<ASN1_STRING, &ASN1_STRING_new, &ASN1_STRING_free>,
                       SslAsn1StringOps<SslAsn1String>
{
    using SslNoRc<ASN1_STRING, &ASN1_STRING_new, &ASN1_STRING_free>::SslNoRc;
    explicit SslAsn1String(std::string_view str);
};
/**
    @brief Type specific construction - initialise with the given string
    @param str Initial value
*/
inline SslAsn1String::SslAsn1String(std::string_view str)
    : SslAsn1String()
{
    if (ASN1_STRING_set(Get(),
                        reinterpret_cast<const unsigned char *>(str.data()),
                        static_cast<int>(str.length()))
        != 1)
        throw SslException("ASN1_STRING_set() failed");
}

//  ===============================================================================================
/**
    @brief wrapper for X509v3 BASIC_CONSTRAINTS
    @class SslAsn1BasicConstraints
    @details Used for CA flag and path length constraint extraction
*/
struct SslAsn1BasicConstraints : SslNoRc<BASIC_CONSTRAINTS, &BASIC_CONSTRAINTS_new, &BASIC_CONSTRAINTS_free>
{
    using SslNoRc<BASIC_CONSTRAINTS, &BASIC_CONSTRAINTS_new, &BASIC_CONSTRAINTS_free>::SslNoRc;
};

//  ===============================================================================================
/**
    @brief wrapper for ASN1_BIT_STRING (key usage extension)
    @class SslAsn1BitString
    @details Used for key usage extension extraction
*/
struct SslAsn1BitString : SslNoRc<ASN1_BIT_STRING, &ASN1_BIT_STRING_new, &ASN1_BIT_STRING_free>
{
    using SslNoRc<ASN1_BIT_STRING, &ASN1_BIT_STRING_new, &ASN1_BIT_STRING_free>::SslNoRc;
};

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_SSL_ASN1_H