// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_SSLHELP_SSLWITHRC_H
#define CLV_SSLHELP_SSLWITHRC_H

#include "HelpSslException.h"
#include <cstddef>
#include <type_traits>
#include <string>
#include <utility>
#include <string_view>

namespace clv::OpenSSL {

using std::string_literals::operator""s;
using std::string_view_literals::operator""sv;

/**
    @brief Base for OpenSSL types that do maintain an internal reference count
    @tparam OpenSslT  The OpenSSL type that the class will manage.
    @tparam SslAlloc A function that creates a new instance of the OpenSslT type.
    @tparam (*SslFree)(OpenSslT *) A function that decrements the reference
            count and potentially frees the resources associated with an instance
            of the OpenSslT type.
    @tparam (*SslIncCount)(OpenSslT *) A function that increments the internal
            reference count of an OpenSslT instance.
    @class SslWithRc

    SslWithRc is a C++ class template that manages the lifetime of OpenSSL objects that maintain
    an internal reference count. Its purpose is to provide a safe and convenient way to work with
    these types of OpenSSL objects, ensuring proper memory management and avoiding common pitfalls
    like memory leaks or dangling pointers.

    Explicit assignment of nullptr is supported whereas accidental use of null type ptr will
    throw an exception. If default construction is enabled for a type the perfect forwarding
    constructor will attempt to call the SslAlloc function with no arguments to initialize the
    object. Some OpenSSL types don't allow this and are not therefore default constructable
    without extra logic such as a default set of arguments being supplied for SslAlloc.

    The class achieves its purpose by maintaining a pointer to the managed OpenSslT instance
    (mSslPtr) and using the provided SslIncCount and SslFree functions to manage the reference
    count and memory allocation/deallocation of the instance. The destructor ~SslWithRc() ensures
    that the managed instance is properly freed when the SslWithRc object goes out of scope.

    The class handles various scenarios, such as copying and moving instances, to ensure that
    the reference count of the managed OpenSslT instance is correctly maintained. It also throws
    exceptions when attempting to create an instance with a null pointer, ensuring that the class
    always manages a valid instance unless set to nullptr intentionally.

    Overall, the SslWithRc class provides a convenient and safe way to work with OpenSSL types
    that maintain an internal reference count, abstracting away the complexities of manual
    reference counting and memory management.

    The code

         typename = decltype(SslAlloc(std::declval<ArgsT>()...))

    In the declaration informs the compiler that the forwarding constructor
    should be disabled if it would not generate code that would cause SslAlloc
    to be called correctly. The definition only has the odd looking 'typename'
    argument since it's not allowed to repeat the defaulted argument.
*/
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *), int (*SslIncCount)(OpenSslT *)>
class SslWithRc
{
    static OpenSslT *SslIncRef(OpenSslT *ptr);
    static void Free(OpenSslT *&ptr) noexcept;

    OpenSslT *mSslPtr = nullptr;

  public:
    ~SslWithRc();
    template <typename... ArgsT, typename = decltype(SslAlloc(std::declval<ArgsT>()...))>
    SslWithRc(ArgsT &&...args);
    explicit SslWithRc(std::nullptr_t) noexcept;
    explicit SslWithRc(OpenSslT *ptr);
    SslWithRc(const SslWithRc &k);
    SslWithRc(SslWithRc &&k) noexcept;
    SslWithRc &operator=(const SslWithRc &rh);
    SslWithRc &operator=(SslWithRc &&rh) noexcept;

    void ThrowIfNull(std::string_view msg = ""sv) const;

    operator const OpenSslT *() const noexcept;
    operator OpenSslT *() noexcept;

    OpenSslT *Get() noexcept;
    const OpenSslT *Get() const noexcept;
    OpenSslT *Copy() noexcept;

    /**
        @brief Create a wrapper from an external reference (bumps refcount)
        @tparam Derived The derived wrapper type to construct (must inherit from SslWithRc)
        @param ptr Raw pointer from external source (e.g., OpenSSL context)
        @return New instance of Derived that owns a reference
        @note Use when wrapping objects from OpenSSL contexts that retain ownership
    */
    template <typename Derived = SslWithRc>
        requires std::is_base_of_v<SslWithRc, Derived>
    static Derived BorrowRef(OpenSslT *ptr)
    {
        return Derived(SslIncRef(ptr));
    }
};
/**
    @brief Increment the managed object ref count using the supplied OpenSSL API \p SslIncCount
    @tparam OpenSslT  The OpenSSL type that the class will manage.
    @tparam SslAlloc A function that creates a new instance of the OpenSslT type.
    @tparam (*SslFree)(OpenSslT *) A function that decrements the reference
            count and potentially frees the resources associated with an instance
            of the OpenSslT type.
    @tparam (*SslIncCount)(OpenSslT *) A function that increments the internal
            reference count of an OpenSslT instance.
    @param ptr pointer to the currently managed instance.
    @return OpenSslT * currently managed instance with ref count incremented
    @throws If the reference adjustment fails this will throw SslException
*/
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *), int (*SslIncCount)(OpenSslT *)>
OpenSslT *SslWithRc<OpenSslT, SslAlloc, SslFree, SslIncCount>::SslIncRef(OpenSslT *ptr)
{
    if (!ptr)
        return nullptr;

    if (SslIncCount(ptr) != 1)
        throw SslException("SslIncCount(OpenSslT *) failed");

    return ptr;
}
/**
    @brief Frees the resources associated with this instance by calling \p SslFree
    @tparam OpenSslT  The OpenSSL type that the class will manage.
    @tparam SslAlloc A function that creates a new instance of the OpenSslT type.
    @tparam (*SslFree)(OpenSslT *) A function that decrements the reference
            count and potentially frees the resources associated with an instance
            of the OpenSslT type.
    @tparam (*SslIncCount)(OpenSslT *) A function that increments the internal
            reference count of an OpenSslT instance.
    @param ptr Instance pointer to be freed
*/
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *), int (*SslIncCount)(OpenSslT *)>
void SslWithRc<OpenSslT, SslAlloc, SslFree, SslIncCount>::Free(OpenSslT *&ptr) noexcept
{
    if (ptr)
    {
        SslFree(ptr);
        ptr = nullptr;
    }
}
/**
    @brief Frees the resources associated with this instance.
    @tparam OpenSslT  The OpenSSL type that the class will manage.
    @tparam SslAlloc A function that creates a new instance of the OpenSslT type.
    @tparam (*SslFree)(OpenSslT *) A function that decrements the reference
            count and potentially frees the resources associated with an instance
            of the OpenSslT type.
    @tparam (*SslIncCount)(OpenSslT *) A function that increments the internal
            reference count of an OpenSslT instance.
*/
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *), int (*SslIncCount)(OpenSslT *)>
SslWithRc<OpenSslT, SslAlloc, SslFree, SslIncCount>::~SslWithRc()
{
    Free(mSslPtr);
}
/**
    @brief Perfect forwarding constructor
    @tparam OpenSslT  The OpenSSL type that the class will manage.
    @tparam SslAlloc A function that creates a new instance of the OpenSslT type.
    @tparam (*SslFree)(OpenSslT *) A function that decrements the reference
            count and potentially frees the resources associated with an instance
            of the OpenSslT type.
    @tparam (*SslIncCount)(OpenSslT *) A function that increments the internal
            reference count of an OpenSslT instance.
    @tparam ArgsT The forwarded arg types
    @param args Forwarded args
    @details
    SslWithRc(ArgsT &&...args) takes any number of arguments and forwards them to the
    SslAlloc function to create a new instance of OpenSslT. If default construction is
    attempted for a type the perfect forwarding constructor will attempt to call the
    SslAlloc function with no arguments to initialize the object. Some OpenSSL types
    don't allow this and are not therefore default constructable without extra logic
    such as a default set of arguments being supplied for SslAlloc.

    The code

         typename = decltype(SslAlloc(std::declval<ArgsT>()...))

    In the declaration informs the compiler that the forwarding constructor
    should be disabled if it would not generate code that would cause SslAlloc
    to be called correctly. The definition only has the odd looking 'typename'
    argument since it's not allowed to repeat the defaulted argument.
*/
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *), int (*SslIncCount)(OpenSslT *)>
template <typename... ArgsT, typename>
SslWithRc<OpenSslT, SslAlloc, SslFree, SslIncCount>::SslWithRc(ArgsT &&...args)
    : SslWithRc(SslAlloc(std::forward<ArgsT>(args)...)){};
/**
    @brief Construct a wrapper with the internal pointer intentionally set to nullptr
    @tparam OpenSslT  The OpenSSL type that the class will manage.
    @tparam SslAlloc A function that creates a new instance of the OpenSslT type.
    @tparam (*SslFree)(OpenSslT *) A function that decrements the reference
            count and potentially frees the resources associated with an instance
            of the OpenSslT type.
    @tparam (*SslIncCount)(OpenSslT *) A function that increments the internal
            reference count of an OpenSslT instance.
*/
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *), int (*SslIncCount)(OpenSslT *)>
SslWithRc<OpenSslT, SslAlloc, SslFree, SslIncCount>::SslWithRc(std::nullptr_t) noexcept
    : mSslPtr(nullptr){};
/**
    @brief Takes a pointer to an existing OpenSslT instance and wraps it
    @tparam OpenSslT  The OpenSSL type that the class will manage.
    @tparam SslAlloc A function that creates a new instance of the OpenSslT type.
    @tparam (*SslFree)(OpenSslT *) A function that decrements the reference
            count and potentially frees the resources associated with an instance
            of the OpenSslT type.
    @tparam (*SslIncCount)(OpenSslT *) A function that increments the internal
            reference count of an OpenSslT instance.
    @param ptr Instance to be wrapped
    @throws SslException if \p ptr is not valid.
*/
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *), int (*SslIncCount)(OpenSslT *)>
SslWithRc<OpenSslT, SslAlloc, SslFree, SslIncCount>::SslWithRc(OpenSslT *ptr)
    : mSslPtr(ptr)
{
    ThrowIfNull();
}
/**
    @brief  Creates a new instance wrapper by incrementing the reference count of the
            OpenSslT instance managed by the source object.
    @tparam OpenSslT  The OpenSSL type that the class will manage.
    @tparam SslAlloc A function that creates a new instance of the OpenSslT type.
    @tparam (*SslFree)(OpenSslT *) A function that decrements the reference
            count and potentially frees the resources associated with an instance
            of the OpenSslT type.
    @tparam (*SslIncCount)(OpenSslT *) A function that increments the internal
            reference count of an OpenSslT instance.
    @param rh other wrapper to duplicate and ref increment
    @throws If the underlying ref count increment fails this will throw SslException
    @details
    The copy constructor SslWithRc(const SslWithRc &k) creates a new instance by
    incrementing the reference count of the OpenSslT instance managed by the source
    object.
*/
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *), int (*SslIncCount)(OpenSslT *)>
SslWithRc<OpenSslT, SslAlloc, SslFree, SslIncCount>::SslWithRc(const SslWithRc &rh)
    : mSslPtr(rh.mSslPtr ? SslIncRef(rh.mSslPtr) : nullptr){};
/**
    @brief Transfers ownership
    @tparam OpenSslT  The OpenSSL type that the class will manage.
    @tparam SslAlloc A function that creates a new instance of the OpenSslT type.
    @tparam (*SslFree)(OpenSslT *) A function that decrements the reference
            count and potentially frees the resources associated with an instance
            of the OpenSslT type.
    @tparam (*SslIncCount)(OpenSslT *) A function that increments the internal
            reference count of an OpenSslT instance.
    @param rh Other wrapper to take from
    @details
    The move constructor SslWithRc(SslWithRc &&k) transfers ownership of the managed
    OpenSslT instance from the source object to the new instance.
*/
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *), int (*SslIncCount)(OpenSslT *)>
SslWithRc<OpenSslT, SslAlloc, SslFree, SslIncCount>::SslWithRc(SslWithRc &&rh) noexcept
    : mSslPtr(rh.mSslPtr)
{
    rh.mSslPtr = nullptr;
}
/**
    @brief  Copy assignment operator
    @tparam OpenSslT  The OpenSSL type that the class will manage.
    @tparam SslAlloc A function that creates a new instance of the OpenSslT type.
    @tparam (*SslFree)(OpenSslT *) A function that decrements the reference
            count and potentially frees the resources associated with an instance
            of the OpenSslT type.
    @tparam (*SslIncCount)(OpenSslT *) A function that increments the internal
            reference count of an OpenSslT instance.
    @param rh
    @return SslWithRc<OpenSslT, SslAlloc, SslFree, SslIncCount>&
    @details
    The copy assignment operator operator=(const SslWithRc &rh) increments the
    reference count of the OpenSslT instance managed by the right-hand side object
    and assigns it to the left-hand side object, properly handling the case where
    the left-hand side object already manages an instance.
*/
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *), int (*SslIncCount)(OpenSslT *)>
SslWithRc<OpenSslT, SslAlloc, SslFree, SslIncCount> &
SslWithRc<OpenSslT, SslAlloc, SslFree, SslIncCount>::operator=(const SslWithRc &rh)
{
    if (this != &rh)
    {
        auto t = SslWithRc(SslIncRef(rh.mSslPtr));
        std::swap(*this, t);
    }
    return *this;
}
/**
    @brief  Move assignment operator
    @tparam OpenSslT  The OpenSSL type that the class will manage.
    @tparam SslAlloc A function that creates a new instance of the OpenSslT type.
    @tparam (*SslFree)(OpenSslT *) A function that decrements the reference
            count and potentially frees the resources associated with an instance
            of the OpenSslT type.
    @tparam (*SslIncCount)(OpenSslT *) A function that increments the internal
            reference count of an OpenSslT instance.
    @param rh
    @return SslWithRc<OpenSslT, SslAlloc, SslFree, SslIncCount>&
    @details
    The move assignment operator operator=(SslWithRc &&rh) transfers ownership of
    the managed OpenSslT instance from the right-hand side object to the left-hand
    side object.
*/
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *), int (*SslIncCount)(OpenSslT *)>
SslWithRc<OpenSslT, SslAlloc, SslFree, SslIncCount> &
SslWithRc<OpenSslT, SslAlloc, SslFree, SslIncCount>::operator=(SslWithRc &&rh) noexcept
{
    std::swap(mSslPtr, rh.mSslPtr);
    return *this;
}

template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *), int (*SslIncCount)(OpenSslT *)>
void SslWithRc<OpenSslT, SslAlloc, SslFree, SslIncCount>::ThrowIfNull(std::string_view msg) const
{
    if (!mSslPtr)
        throw SslException(std::string("SslWithRc::ThrowIfNull() mSslPtr == null")
                           + (msg.empty() ? "" : ": " + std::string(msg)));
}
/**
    @brief Gets a pointer to the managed instance with no validity checking
    @tparam OpenSslT  The OpenSSL type that the class will manage.
    @tparam SslAlloc A function that creates a new instance of the OpenSslT type.
    @tparam (*SslFree)(OpenSslT *) A function that decrements the reference
            count and potentially frees the resources associated with an instance
            of the OpenSslT type.
    @tparam (*SslIncCount)(OpenSslT *) A function that increments the internal
            reference count of an OpenSslT instance.
    @return OpenSslT * pointer to the wrapped instance
*/
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *), int (*SslIncCount)(OpenSslT *)>
OpenSslT *SslWithRc<OpenSslT, SslAlloc, SslFree, SslIncCount>::Get() noexcept
{
    return mSslPtr;
}
/**
    @brief Gets a pointer to the managed instance with no validity checking
    @tparam OpenSslT  The OpenSSL type that the class will manage
    @tparam SslAlloc A function that creates a new instance of the OpenSslT type
    @tparam (*SslFree)(OpenSslT *) A function that decrements the reference
            count and potentially frees the resources associated with an instance
            of the OpenSslT type
    @tparam (*SslIncCount)(OpenSslT *) A function that increments the internal
            reference count of an OpenSslT instance
    @return const OpenSslT * pointer to the wrapped instance
*/
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *), int (*SslIncCount)(OpenSslT *)>
const OpenSslT *SslWithRc<OpenSslT, SslAlloc, SslFree, SslIncCount>::Get() const noexcept
{
    return mSslPtr;
}
/**
    @brief Conversion operator to OpenSslT *
    @tparam OpenSslT  The OpenSSL type that the class will manage.
    @tparam SslAlloc A function that creates a new instance of the OpenSslT type.
    @tparam (*SslFree)(OpenSslT *) A function that decrements the reference
            count and potentially frees the resources associated with an instance
            of the OpenSslT type.
    @tparam (*SslIncCount)(OpenSslT *) A function that increments the internal
            reference count of an OpenSslT instance.
    @return OpenSslT * pointer to the enclosed SSL object.
    @note This is a conversion operator that allows the class to be used in
          contexts where an OpenSslT * is expected.  It is possible but
          not likely that the pointer might be nullptr. The caller should
          check for this. The class should not contain a nullptr unless
          set to nullptr.
*/
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *), int (*SslIncCount)(OpenSslT *)>
inline SslWithRc<OpenSslT, SslAlloc, SslFree, SslIncCount>::operator OpenSslT *() noexcept
{
    return Get();
}
/**
    @brief Conversion operator to const OpenSslT *
    @tparam OpenSslT  The OpenSSL type that the class will manage.
    @tparam SslAlloc A function that creates a new instance of the OpenSslT type.
    @tparam (*SslFree)(OpenSslT *) A function that decrements the reference
            count and potentially frees the resources associated with an instance
            of the OpenSslT type.
    @tparam (*SslIncCount)(OpenSslT *) A function that increments the internal
            reference count of an OpenSslT instance.
    @return const OpenSslT * pointer to the enclosed SSL object.
    @note This is a conversion operator that allows the class to be used in
          contexts where a const OpenSslT * is expected.  It is possible but
          not likely that the pointer might be nullptr. The caller should
          check for this. The class should not contain a nullptr unless
          set to nullptr.
*/
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *), int (*SslIncCount)(OpenSslT *)>
inline SslWithRc<OpenSslT, SslAlloc, SslFree, SslIncCount>::operator const OpenSslT *() const noexcept
{
    return Get();
}
/**
    @brief Duplicates the OpenSSL object and returns a new reference-counted copy.
    @tparam OpenSslT The OpenSSL object type.
    @tparam SslAlloc The allocator function for the OpenSSL object.
    @tparam SslFree The free function for the OpenSSL object.
    @tparam SslIncCount The increment reference count function for the OpenSSL object.
    @return A new reference-counted copy of the OpenSSL object.
    @throws None.
    @details This function increases the ref count on the OpenSSL object by calling the SslIncCount
             function on the internal mSslPtr member. This is useful in cases where an OpenSSL API
             requires a pointer to a ref counted object, will take ownership, and will not be bothered
             to increment the ref count itself.
 */
template <typename OpenSslT, auto SslAlloc, void (*SslFree)(OpenSslT *), int (*SslIncCount)(OpenSslT *)>
OpenSslT *SslWithRc<OpenSslT, SslAlloc, SslFree, SslIncCount>::Copy() noexcept
{
    return SslIncRef(mSslPtr);
}

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_SSLWITHRC_H