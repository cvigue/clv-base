// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_SSLHELP_SSLCUSTOMBIO_H
#define CLV_SSLHELP_SSLCUSTOMBIO_H


#include <openssl/bio.h>
#include <cstddef>
#include <new>
#include <openssl/types.h>

#include "HelpSslBio.h"

namespace clv::OpenSSL {

/**
    @brief a class template that serves as a wrapper for OpenSSL's BIO
    @tparam CustomBioType
    @tparam type_arg
    @tparam *name_arg
    @details Builds out a custom BIO type using the CRTP pattern. The derived class \p CustomBioType
             must implement the methods it intends to have called, typically including:
                - int read(char *out, int size)
                - int write(const char *in, int size)
                - long ctrl(int cmd, long larg, void *parg)
                - int puts(const char *str)
    @note The shared BIO_METHOD structure is created as a Meyers singleton the first time it is needed
          in each derived BioMethodStatics<Derived>::methods() call. It thereafter lives for the
          duration of the program, shared by all instances of the derived BIO type.
*/
// Forward declare the static method table
template <typename Derived>
struct BioMethodStatics;

// Custom BIO
template <typename Derived, int BioTypeV, const char *NameV>
class SslCustomBio : public SslBio
{
  protected:
    /**
     *  @brief This constructor replaces the CTORs that are typically used from base via
     *         a using statement. It is protected because the CRTP pattern expects it
     *         to only be called by the derived class.
     */
    explicit SslCustomBio()
        : SslBio(BioMethodStatics<Derived>::methods())
    {
        // Maintaining this pointer back to the derived instance helps us resolve the
        // callbacks in BioMethodStatics. Move operations must update this pointer.
        BIO_set_data(this->Get(), static_cast<Derived *>(this));
        BIO_set_init(this->Get(), 1);
    }

  public:
    // TODO: Consider enabling copy constructor/assignment if needed
    SslCustomBio(const SslCustomBio &) = delete;
    SslCustomBio &operator=(const SslCustomBio &) = delete;

    // Move constructor to update BIO data pointer after move
    SslCustomBio(SslCustomBio &&rh) noexcept
        : SslBio(std::move(rh))
    {
        if (this->Get())
        {
            BIO_set_data(this->Get(), static_cast<Derived *>(this));
        }
    }

    // Move assignment operator to update BIO data pointer after move
    SslCustomBio &operator=(SslCustomBio &&rh) noexcept
    {
        SslBio::operator=(std::move(rh));
        if (this->Get())
        {
            BIO_set_data(this->Get(), static_cast<Derived *>(this));
        }
        return *this;
    }

    // Static constexpr accessors for BIO type and name
    static constexpr int bio_type()
    {
        return BioTypeV;
    }
    static constexpr const char *name()
    {
        return NameV;
    }

    // Copy/move inherit from SslWithRc — perfect, uses BIO_up_ref
    using SslBio::operator=;

  protected:
    // CRTP access to self from callbacks
    static Derived &self(BIO *b) noexcept
    {
        return *std::launder(reinterpret_cast<Derived *>(BIO_get_data(b)));
    }

    static const Derived &self(const BIO *cb) noexcept
    {
        auto b = const_cast<BIO *>(cb);
        return *std::launder(reinterpret_cast<const Derived *>(BIO_get_data(b)));
    }
};

/**
    @brief Static method table generator for custom BIO types
    @tparam Derived The derived custom BIO class
    @details This struct provides static methods that adapt the member functions of the derived
             custom BIO class to the C-style function signatures required by OpenSSL's BIO_METHOD.
 */
template <typename Derived>
struct BioMethodStatics
{
    // Callback wrappers that adapt the derived class to the C function signature
    static int write_fn(BIO *b, const char *data, int len)
    {
        return Derived::self(b).write(data, len);
    }

    static int write_ex_fn(BIO *b, const char *data, size_t len, size_t *written)
    {
        int ret = Derived::self(b).write(static_cast<const char *>(data), static_cast<int>(len));
        if (ret >= 0)
        {
            if (written)
                *written = static_cast<size_t>(ret);
            return 1; // success
        }
        return 0; // failure or retry
    }

    static int read_fn(BIO *b, char *out, int len)
    {
        return Derived::self(b).read(out, len);
    }

    static int read_ex_fn(BIO *b, char *out, size_t len, size_t *readbytes)
    {
        int ret = Derived::self(b).read(static_cast<char *>(out), static_cast<int>(len));
        if (ret >= 0)
        {
            if (readbytes)
                *readbytes = static_cast<size_t>(ret);
            return 1; // success
        }
        return 0; // failure or retry
    }

    static int puts_fn(BIO *b, const char *str)
    {
        return Derived::self(b).puts(str);
    }

    static long ctrl_fn(BIO *b, int cmd, long larg, void *parg)
    {
        return Derived::self(b).ctrl(cmd, larg, parg);
    }

    static int destroy_fn(BIO *b)
    {
        if (b && BIO_get_init(b))
        {
            BIO_set_data(b, nullptr);
            BIO_set_init(b, 0);
        }
        return 1;
    }
    // Classic Meyer's singleton pattern for the BIO_METHOD structure
    static const BIO_METHOD *methods() noexcept
    {
        // OpenSSL 3.x: BIO_METHOD is opaque, allocate and configure it once
        static const BIO_METHOD *meth = []() -> const BIO_METHOD *
        {
            BIO_METHOD *m = BIO_meth_new(Derived::bio_type(), Derived::name());
            if (!m)
                return nullptr;

            BIO_meth_set_write(m, write_fn);
            BIO_meth_set_write_ex(m, write_ex_fn);
            BIO_meth_set_read(m, read_fn);
            BIO_meth_set_read_ex(m, read_ex_fn);
            BIO_meth_set_puts(m, puts_fn);
            BIO_meth_set_ctrl(m, ctrl_fn);
            BIO_meth_set_destroy(m, destroy_fn);
            return m;
        }();
        return meth;
    }
};

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_SSLCUSTOMBIO_H