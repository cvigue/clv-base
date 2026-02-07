// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_SSLHELP_SSL_MEMBIO_H
#define CLV_SSLHELP_SSL_MEMBIO_H

#include "HelpSslBio.h"
#include "HelpSslSsl.h"
#include <array>
#include <openssl/bio.h>
#include <cstddef>
#include <cstdint>
#include <openssl/ssl.h>
#include <openssl/types.h>
#include <span>
#include <vector>

namespace clv::OpenSSL {

/**
 * @brief Memory BIO pair for in-memory TLS data flow
 *
 * Wraps a pair of memory BIOs (input and output) for use with SSL objects.
 * Both this class and the SSL object can hold references since OpenSSL
 * BIOs use reference counting internally.
 *
 * Usage:
 *   SslMemBio bios;
 *   bios.AttachToSSL(ssl);  // Safely attaches both BIOs
 *   bios.WriteInput(incoming_data);
 *   auto response = bios.ReadOutput();
 */
class SslMemBio
{
  public:
    /**
     * @brief Create a memory BIO pair
     * @throws SslException on BIO creation failure
     */
    SslMemBio();

    ~SslMemBio() = default;

    // Non-copyable, movable
    SslMemBio(const SslMemBio &) = delete;
    SslMemBio &operator=(const SslMemBio &) = delete;
    SslMemBio(SslMemBio &&) = default;
    SslMemBio &operator=(SslMemBio &&) = default;

    /**
     * @brief Write data to input BIO (what peer sends us)
     * @param data Bytes to feed to the SSL handshake
     * @return Bytes written (should match data.size())
     * @return -1 on error
     */
    int WriteInput(std::span<const std::uint8_t> data);

    /**
     * @brief Read pending output data (what we send to peer)
     * @tparam bufferBytes Size of each incremental read into the output vector.
     * @return Buffer containing all pending output
     */
    template <std::size_t bufferBytes = (4 * 1024)>
    std::vector<std::uint8_t> ReadOutput();

    /**
     * @brief Get amount of pending input data
     */
    size_t GetInputPending() const;

    /**
     * @brief Get amount of pending output data
     */
    size_t GetOutputPending() const;

    /**
     * @brief Attach BIOs to an SSL object
     * @param ssl SSL object to attach to (via SSL_set0_rbio/wbio)
     *
     * Safely attaches both input and output BIOs to the SSL object.
     * Both this class and SSL will hold references via OpenSSL's refcount.
     */
    void AttachToSSL(SslSsl &ssl);

    /**
     * @brief Clear all pending data
     */
    void Clear();

  private:
    SslBio input_;  // Where SSL reads from (fed by WriteInput)
    SslBio output_; // Where SSL writes to (read by ReadOutput)

    // Internal accessors - use AttachToSSL() for public API
    BIO *GetInputBio()
    {
        return input_.Copy();
    }
    BIO *GetOutputBio()
    {
        return output_.Copy();
    }
};

// ================================ INLINE IMPLEMENTATIONS ================================

inline SslMemBio::SslMemBio() : input_(BIO_s_mem()), output_(BIO_s_mem())
{
}

inline int SslMemBio::WriteInput(std::span<const std::uint8_t> data)
{
    if (data.empty())
        return 0;

    int written = BIO_write(input_.Get(), data.data(), static_cast<int>(data.size()));
    if (written < 0)
        return -1;

    return written;
}

template <std::size_t bufferBytes>
inline std::vector<std::uint8_t> SslMemBio::ReadOutput()
{
    std::vector<std::uint8_t> result;
    std::array<std::uint8_t, bufferBytes> buffer;

    while (BIO_ctrl_pending(const_cast<BIO *>(output_.Get())) > 0)
    {
        int read = BIO_read(output_.Get(), buffer.data(), static_cast<int>(buffer.size()));
        if (read > 0)
        {
            result.insert(result.end(), buffer.data(), buffer.data() + read);
        }
        else
        {
            break;
        }
    }

    return result;
}

inline size_t SslMemBio::GetInputPending() const
{
    long pending = static_cast<long>(BIO_ctrl_pending(const_cast<BIO *>(input_.Get())));
    return pending > 0 ? static_cast<size_t>(pending) : 0;
}

inline size_t SslMemBio::GetOutputPending() const
{
    long pending = static_cast<long>(BIO_ctrl_pending(const_cast<BIO *>(output_.Get())));
    return pending > 0 ? static_cast<size_t>(pending) : 0;
}

inline void SslMemBio::AttachToSSL(SslSsl &ssl)
{
    // Copy() bumps refcount, allowing both SslMemBio and SSL to hold references
    SSL_set0_rbio(ssl.Get(), input_.Copy());
    SSL_set0_wbio(ssl.Get(), output_.Copy());
}

inline void SslMemBio::Clear()
{
    if (input_.Get())
    {
        BIO_reset(input_.Get());
    }
    if (output_.Get())
    {
        BIO_reset(output_.Get());
    }
}

} // namespace clv::OpenSSL

#endif // CLV_SSLHELP_SSL_MEMBIO_H
