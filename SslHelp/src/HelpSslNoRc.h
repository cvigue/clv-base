// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_SSLHELP_SSL_NO_RC_H
#define CLV_SSLHELP_SSL_NO_RC_H

#include "HelpSslException.h"
#include <cstddef>
#include <memory>
#include <string>
#include <utility>
#include <string_view>

namespace clv::OpenSSL {

using std::string_literals::operator""s;
using std::string_view_literals::operator""sv;

/**
    @brief Base for OpenSSL types that do not maintain an internal reference count
    @tparam OpenSslT  The OpenSSL type that the class will manage.
    @tparam SslAlloc A function that creates a new instance of the OpenSslT type.
    @tparam (*SslFree)(OpenSslT *) A function that frees the resources associated
            with this instance of the OpenSslT type.
    @class SslNoRc

    The SslNoRc class is a template class that provides a wrapper around OpenSSL types
    that do not maintain an internal reference count. Its purpose is to ensure proper
    memory management and cleanup of these OpenSSL types.

    The class achieves its purpose by using a std::unique_ptr to manage the lifetime
    of the OpenSslT instance. The Free function is used as the deleter for the unique_ptr,
    ensuring that the SslFree function is called to free the resources associated
    with the OpenSslT instance when the SslNoRc object goes out of scope or is explicitly
    reset. The class does not need an explicit destructor since it leverages std::unique_ptr.

    The class also disables copy construction and copy assignment to prevent unintended
    sharing of the managed OpenSslT instance. Move construction and move assignment are
    allowed, ensuring efficient transfer of ownership.

    The code

         typename = decltype(SslAlloc(std::declval<ArgsT>()...))

    In the declaration informs the compiler that the forwarding constructor
    should be disabled if it would not generate code that would cause SslAlloc
    to be called correctly. The definition only has the odd looking 'typename'
    argument since it's not allowed name the argument after a variadic.
*/
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *)>
class SslNoRc
{
    static void Free(OpenSslT *ptr) noexcept;
    std::unique_ptr<OpenSslT, decltype(&Free)> mSslPtr;

  public:
    template <typename... ArgsT, typename = decltype(SslAlloc(std::declval<ArgsT>()...))>
    SslNoRc(ArgsT &&...args);
    explicit SslNoRc(std::nullptr_t) noexcept;
    explicit SslNoRc(OpenSslT *ptr);
    SslNoRc(const SslNoRc &) noexcept = delete;
    SslNoRc &operator=(const SslNoRc &) = delete;
    SslNoRc(SslNoRc &&) noexcept = default;
    SslNoRc &operator=(SslNoRc &&) = default;

    void ThrowIfNull(std::string_view msg = ""sv) const;

    operator const OpenSslT *() const noexcept;
    operator OpenSslT *() noexcept;

    OpenSslT *Get() noexcept;
    const OpenSslT *Get() const noexcept;
    void Reset(std::nullptr_t = nullptr) noexcept;
    void Reset(OpenSslT *ptr);
    OpenSslT *Release() noexcept;
};
/**
    @brief Uses the \p SslFree function to free the wrapped instance.
    @tparam OpenSslT  The OpenSSL type that the class will manage.
    @tparam SslAlloc A function that creates a new instance of the OpenSslT type.
    @tparam (*SslFree)(OpenSslT *) A function that frees the resources associated
            with this instance of the OpenSslT type.
    @param ptr Pointer that should be freed if not null.
*/
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *)>
void SslNoRc<OpenSslT, SslAlloc, SslFree>::Free(OpenSslT *ptr) noexcept
{
    if (ptr)
        SslFree(ptr);
}
/**
    @brief The perfect forwarding constructor
    @tparam OpenSslT  The OpenSSL type that the class will manage.
    @tparam SslAlloc A function that creates a new instance of the OpenSslT type.
    @tparam (*SslFree)(OpenSslT *) A function that frees the resources associated
            with this instance of the OpenSslT type.
    @tparam ArgsT variadic argument types
    @param args arguments

    The perfect forwarding constructor SslNoRc(ArgsT &&...args) takes any number of
    arguments and forwards them to the SslAlloc function to create a new instance of
    OpenSslT.

    The code

         typename = decltype(SslAlloc(std::declval<ArgsT>()...))

    In the declaration informs the compiler that the forwarding constructor
    should be disabled if it would not generate code that would cause SslAlloc
    to be called correctly. The definition only has the odd looking 'typename'
    argument since it's not allowed to repeat the defaulted argument.
*/
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *)>
template <typename... ArgsT, typename>
SslNoRc<OpenSslT, SslAlloc, SslFree>::SslNoRc(ArgsT &&...args)
    : SslNoRc(SslAlloc(std::forward<ArgsT>(args)...)){};
/**
    @brief Set the internal wrapped data to nullptr
    @tparam OpenSslT  The OpenSSL type that the class will manage.
    @tparam SslAlloc A function that creates a new instance of the OpenSslT type.
    @tparam (*SslFree)(OpenSslT *) A function that frees the resources associated
            with this instance of the OpenSslT type.

    The constructor that accepts an argument of OpenSslT * will test that pointer
    against nullptr and throw if equal. This constructor exists to allow intentional
    assignment of nullptr.
*/
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *)>
SslNoRc<OpenSslT, SslAlloc, SslFree>::SslNoRc(std::nullptr_t) noexcept
    : mSslPtr(nullptr, &Free){};
/**
    @brief Wrap an OpenSslT * and manage the instance lifespan
    @tparam OpenSslT  The OpenSSL type that the class will manage.
    @tparam SslAlloc A function that creates a new instance of the OpenSslT type.
    @tparam (*SslFree)(OpenSslT *) A function that frees the resources associated
            with this instance of the OpenSslT type.
    @param ptr Pointer to be wrapped and managed.
*/
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *)>
SslNoRc<OpenSslT, SslAlloc, SslFree>::SslNoRc(OpenSslT *ptr)
    : mSslPtr(ptr, &Free)
{
    ThrowIfNull();
}
/**
    @brief Conversion operator to const OpenSslT *
    @tparam OpenSslT  The OpenSSL type that the class will manage.
    @tparam SslAlloc A function that creates a new instance of the OpenSslT type.
    @tparam (*SslFree)(OpenSslT *) A function that frees the resources associated
            with this instance of the OpenSslT type.
    @return const OpenSslT * pointer to the enclosed SSL object.
    @note This is a conversion operator that allows the class to be used in
          contexts where a const OpenSslT * is expected.  It is possible but
          not likely that the pointer might be nullptr. The caller should
          check for this. The class should not contain a nullptr unless
          set to nullptr or Release is called.
*/
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *)>
inline SslNoRc<OpenSslT, SslAlloc, SslFree>::operator const OpenSslT *() const noexcept
{
    return Get();
}
/**
    @brief Conversion operator to OpenSslT *
    @tparam OpenSslT  The OpenSSL type that the class will manage.
    @tparam SslAlloc A function that creates a new instance of the OpenSslT type.
    @tparam (*SslFree)(OpenSslT *) A function that frees the resources associated
            with this instance of the OpenSslT type.
    @return OpenSslT * pointer to the enclosed SSL object.
    @note This is a conversion operator that allows the class to be used in
          contexts where an OpenSslT * is expected.  It is possible but
          not likely that the pointer might be nullptr. The caller should
          check for this. The class should not contain a nullptr unless
          set to nullptr or Release is called.
*/
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *)>
inline SslNoRc<OpenSslT, SslAlloc, SslFree>::operator OpenSslT *() noexcept
{
    return Get();
}
/**
    @brief Get the wrapped OpenSslT * with no validity check
    @tparam OpenSslT  The OpenSSL type that the class will manage.
    @tparam SslAlloc A function that creates a new instance of the OpenSslT type.
    @tparam (*SslFree)(OpenSslT *) A function that frees the resources associated
            with this instance of the OpenSslT type.
    @return OpenSslT * the wrapped instance pointer.
*/
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *)>
OpenSslT *SslNoRc<OpenSslT, SslAlloc, SslFree>::Get() noexcept
{
    return mSslPtr.get();
}
/**
    @brief Get the wrapped OpenSslT * with no validity check
    @tparam OpenSslT  The OpenSSL type that the class will manage.
    @tparam SslAlloc A function that creates a new instance of the OpenSslT type.
    @tparam (*SslFree)(OpenSslT *) A function that frees the resources associated
            with this instance of the OpenSslT type.
    @return const OpenSslT * the wrapped instance pointer.
*/
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *)>
const OpenSslT *SslNoRc<OpenSslT, SslAlloc, SslFree>::Get() const noexcept
{
    return mSslPtr.get();
}

template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *)>
void SslNoRc<OpenSslT, SslAlloc, SslFree>::ThrowIfNull(std::string_view msg) const
{
    if (!mSslPtr)
        throw SslException(std::string("SslNoRc::ThrowIfNull() mSslPtr == null")
                           + (msg.empty() ? "" : ": " + std::string(msg)));
}
/**
    @brief Reset the managed pointer to nullptr
    @tparam OpenSslT  The OpenSSL type that the class will manage.
    @tparam SslAlloc A function that creates a new instance of the OpenSslT type.
    @tparam (*SslFree)(OpenSslT *) A function that frees the resources associated
    @note This is not recommended generally, use with caution.
*/
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *)>
void SslNoRc<OpenSslT, SslAlloc, SslFree>::Reset(std::nullptr_t) noexcept
{
    mSslPtr.reset();
}
/**
    @brief Replace the current managed pointer with a new one.
    @tparam OpenSslT  The OpenSSL type that the class will manage.
    @tparam SslAlloc A function that creates a new instance of the OpenSslT type.
    @tparam (*SslFree)(OpenSslT *) A function that frees the resources associated
            with this instance of the OpenSslT type.
    @param ptr New pointer that is to be managed.
    @throws SslException if \p ptr is not valid.
*/
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *)>
void SslNoRc<OpenSslT, SslAlloc, SslFree>::Reset(OpenSslT *ptr)
{
    mSslPtr.reset(ptr);
    if (!mSslPtr)
        throw SslException("SslNoRc::Reset mSslPtr == null");
}
/**
    @brief Stop managing the current pointer and return it for unmanaged use.
    @tparam OpenSslT  The OpenSSL type that the class will manage.
    @tparam SslAlloc A function that creates a new instance of the OpenSslT type.
    @tparam (*SslFree)(OpenSslT *) A function that frees the resources associated
            with this instance of the OpenSslT type.
    @return auto OpenSslT * that is currently under management
*/
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *)>
OpenSslT *SslNoRc<OpenSslT, SslAlloc, SslFree>::Release() noexcept
{
    return mSslPtr.release();
}

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_SSL_NO_RC_H