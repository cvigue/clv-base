// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_CORE_UNIQUE_FD_H
#define CLV_CORE_UNIQUE_FD_H

#include <cerrno>
#include <cstddef>
#include <system_error>
#include <unistd.h>

namespace clv {

/**
 * @brief RAII wrapper for a POSIX file descriptor
 *
 * Owns a single file descriptor and closes it on destruction.
 * Non-copyable, movable — analogous to std::unique_ptr for FDs.
 *
 * The int constructor enforces validity: passing a negative FD throws
 * std::system_error (capturing errno). Use the default constructor or
 * nullptr_t constructor to create an empty/null instance.
 *
 * Typical usage for ephemeral ioctl sockets:
 * @code
 *   UniqueFd sock(::socket(AF_INET, SOCK_DGRAM, 0));
 *   // throws on failure — no manual error check needed
 *   ::ioctl(sock.get(), SIOCSIFFLAGS, &ifr);
 *   // closed automatically at scope exit
 * @endcode
 *
 * As a class member (replaces hand-rolled fd lifecycle):
 * @code
 *   class NetlinkHelper {
 *       UniqueFd fd_;
 *   public:
 *       void Open()  { fd_ = UniqueFd(::socket(AF_NETLINK, SOCK_RAW, ...)); }
 *       void Close() { fd_ = {}; }
 *       bool IsOpen() const { return static_cast<bool>(fd_); }
 *   };
 * @endcode
 */
class UniqueFd
{
  public:
    /// Default-construct in closed/null state
    UniqueFd() noexcept = default;

    /// Construct in closed/null state (mirrors unique_ptr's nullptr_t ctor)
    UniqueFd(std::nullptr_t) noexcept
    {
    }

    /// Take ownership of a valid file descriptor; throws if fd < 0
    /// @throws std::system_error (with captured errno) when fd is negative
    explicit UniqueFd(int fd) : fd_(fd)
    {
        if (fd_ < 0)
        {
            throw std::system_error(errno, std::system_category(), "UniqueFd: invalid file descriptor");
        }
    }

    /// Close the owned FD (if any)
    ~UniqueFd()
    {
        if (fd_ >= 0)
            ::close(fd_);
    }

    // Non-copyable
    UniqueFd(const UniqueFd &) = delete;
    UniqueFd &operator=(const UniqueFd &) = delete;

    // Movable
    UniqueFd(UniqueFd &&other) noexcept : fd_(other.fd_)
    {
        other.fd_ = -1;
    }

    UniqueFd &operator=(UniqueFd &&other) noexcept
    {
        if (this != &other)
        {
            reset();
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }

    /// @brief Get the raw file descriptor
    [[nodiscard]] int get() const noexcept
    {
        return fd_;
    }

    /// @brief Check if an FD is held (fd >= 0)
    explicit operator bool() const noexcept
    {
        return fd_ >= 0;
    }

    /// @brief Release ownership without closing; returns the FD
    int release() noexcept
    {
        int f = fd_;
        fd_ = -1;
        return f;
    }

    /// @brief Close the current FD (if any) and reset to null
    void reset() noexcept
    {
        if (fd_ >= 0)
            ::close(fd_);
        fd_ = -1;
    }

    /// @brief Close the current FD (if any) and take ownership of a new valid FD
    /// @throws std::system_error (with captured errno) when new_fd is negative
    void reset(int new_fd)
    {
        if (new_fd < 0)
        {
            throw std::system_error(errno, std::system_category(), "UniqueFd::reset: invalid file descriptor");
        }
        if (fd_ >= 0)
            ::close(fd_);
        fd_ = new_fd;
    }

  private:
    int fd_ = -1;
};

} // namespace clv

#endif // CLV_CORE_UNIQUE_FD_H
