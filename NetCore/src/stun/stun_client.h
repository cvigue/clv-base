// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_NETCORE_STUN_CLIENT_HPP
#define CLV_NETCORE_STUN_CLIENT_HPP

#include "stun/stun_io.h"
#include "stun/stun_types.h"
#include "stun/stun_utils.h"
#include "stun_discovery.h"

#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace clv::netcore {

/**
 * Modern C++20 STUN client using ASIO and coroutines.
 *
 * This class owns a UDP socket and delegates protocol/orchestration to
 * @c stun_discovery building blocks (@c stun_io, @c stun_utils).
 *
 * Thread Safety: NOT thread-safe — use from the @c io_context thread only.
 */
class stun_client
{
  public:
    using stun_server_endpoint = ::clv::netcore::stun_server_endpoint;
    using stun_result = ::clv::netcore::stun_result;
    using nat_detection_config = ::clv::netcore::nat_detection_config;
    using transaction_id = ::clv::netcore::transaction_id;
    using stun_packet = ::clv::netcore::stun_packet;
    using stun_log_fn = ::clv::netcore::stun_log_fn;

    static inline constexpr std::chrono::milliseconds default_address_timeout = stun_defaults::address_timeout;
    static inline constexpr std::chrono::milliseconds default_nat_detection_timeout = stun_defaults::nat_detection_timeout;
    static inline constexpr std::size_t max_stun_response_size = stun_defaults::max_stun_response_size;
    static inline constexpr std::size_t nat_test_count = stun_defaults::nat_test_count;

    static constexpr int info_level = stun_log_level::info;
    static constexpr int debug_level = stun_log_level::debug;
    static constexpr int warn_level = stun_log_level::warn;
    static constexpr int error_level = stun_log_level::error;

    explicit stun_client(asio::io_context &io_context);

    explicit stun_client(std::uint16_t local_port, asio::io_context &io_context);

    template <typename First, typename... Rest>
    explicit stun_client(asio::io_context &io_context, First &&first, Rest &&...rest);

    template <typename First, typename... Rest>
    explicit stun_client(std::uint16_t local_port,
                         asio::io_context &io_context,
                         First &&first,
                         Rest &&...rest);

    template <typename ServerContainer>
    explicit stun_client(asio::io_context &io_context, ServerContainer &&servers);

    template <typename ServerContainer>
    explicit stun_client(std::uint16_t local_port,
                         asio::io_context &io_context,
                         ServerContainer &&servers);

    stun_client(const stun_client &) = delete;
    stun_client &operator=(const stun_client &) = delete;
    stun_client(stun_client &&) = default;
    stun_client &operator=(stun_client &&) = delete;

    ~stun_client() = default;

    asio::awaitable<stun_result>
    discover_public_address(std::chrono::milliseconds timeout = default_address_timeout);

    asio::awaitable<stun_result>
    detect_nat_type(std::chrono::milliseconds timeout = default_nat_detection_timeout);

    asio::awaitable<stun_result>
    detect_nat_type(const nat_detection_config &config);

    [[nodiscard]] std::uint16_t local_port() const noexcept;

    [[nodiscard]] asio::ip::udp::socket &get_socket() noexcept;

    [[nodiscard]] std::size_t server_count() const noexcept;

    [[nodiscard]] const std::vector<stun_server_endpoint> &get_servers() const noexcept;

    void set_logger(stun_log_fn logger) noexcept;

    /** Expose the underlying I/O adapter (e.g. for shared-socket integrations). */
    [[nodiscard]] stun_io &io() noexcept
    {
        return io_;
    }

    [[nodiscard]] const stun_io &io() const noexcept
    {
        return io_;
    }

  private:
    stun_client(std::in_place_t, std::uint16_t local_port, asio::io_context &io_context);

    void check_state_validity();
    void ensure_default_servers();
    void refresh_io();

    asio::io_context &io_context_;
    asio::ip::udp::socket socket_;
    stun_io io_;
    std::vector<stun_server_endpoint> servers_;
    std::uint16_t local_port_;
    stun_log_fn logger_;
};

inline stun_client::stun_client(std::in_place_t, std::uint16_t local_port, asio::io_context &io_context)
    : io_context_{io_context},
      socket_{io_context_, asio::ip::udp::endpoint{asio::ip::udp::v4(), local_port}},
      io_{},
      local_port_{socket_.local_endpoint().port()}
{
    refresh_io();
}

inline stun_client::stun_client(asio::io_context &io_context)
    : stun_client(0, io_context)
{
}

inline stun_client::stun_client(std::uint16_t local_port, asio::io_context &io_context)
    : stun_client(std::in_place, local_port, io_context)
{
    ensure_default_servers();
    check_state_validity();
}

template <typename First, typename... Rest>
inline stun_client::stun_client(asio::io_context &io_context, First &&first, Rest &&...rest)
    : stun_client(0, io_context, std::forward<First>(first), std::forward<Rest>(rest)...)
{
}

template <typename First, typename... Rest>
inline stun_client::stun_client(std::uint16_t local_port,
                                asio::io_context &io_context,
                                First &&first,
                                Rest &&...rest)
    : stun_client(std::in_place, local_port, io_context)
{
    servers_.emplace_back(std::forward<First>(first));
    (servers_.emplace_back(std::forward<Rest>(rest)), ...);
    check_state_validity();
}

template <typename ServerContainer>
inline stun_client::stun_client(asio::io_context &io_context, ServerContainer &&servers)
    : stun_client(0, io_context, std::forward<ServerContainer>(servers))
{
}

template <typename ServerContainer>
inline stun_client::stun_client(std::uint16_t local_port,
                                asio::io_context &io_context,
                                ServerContainer &&servers)
    : stun_client(std::in_place, local_port, io_context)
{
    for (auto &&server : servers)
        servers_.emplace_back(std::move(server));
    ensure_default_servers();
    check_state_validity();
}

inline void stun_client::refresh_io()
{
    io_ = make_socket_stun_io(socket_, io_context_);
}

inline std::uint16_t stun_client::local_port() const noexcept
{
    return local_port_;
}

inline asio::ip::udp::socket &stun_client::get_socket() noexcept
{
    return socket_;
}

inline std::size_t stun_client::server_count() const noexcept
{
    return servers_.size();
}

inline const std::vector<stun_client::stun_server_endpoint> &stun_client::get_servers() const noexcept
{
    return servers_;
}

inline void stun_client::set_logger(stun_log_fn logger) noexcept
{
    logger_ = std::move(logger);
}

inline void stun_client::check_state_validity()
{
    if (!socket_.is_open())
    {
        throw stun_exception(stun_error_code::initialization_error,
                             "STUN client socket is not open (failed to bind UDP socket to port?) after construction");
    }
    if (servers_.empty())
    {
        throw stun_exception(stun_error_code::initialization_error,
                             "STUN client has no configured STUN servers");
    }
}

inline void stun_client::ensure_default_servers()
{
    ensure_default_stun_servers(servers_);
}

inline auto stun_client::discover_public_address(std::chrono::milliseconds timeout) -> asio::awaitable<stun_result>
{
    const stun_log_sink sink{logger_};
    co_return co_await stun_discovery::discover_public_address(
        io_, io_context_, servers_, timeout, &sink);
}

inline auto stun_client::detect_nat_type(std::chrono::milliseconds timeout) -> asio::awaitable<stun_result>
{
    nat_detection_config config{};
    config.individual_test_timeout = timeout;
    co_return co_await detect_nat_type(config);
}

inline auto stun_client::detect_nat_type(const nat_detection_config &config) -> asio::awaitable<stun_result>
{
    const stun_log_sink sink{logger_};
    co_return co_await stun_discovery::detect_nat_type(
        io_, io_context_, servers_, config, &sink);
}

} // namespace clv::netcore

#endif // CLV_NETCORE_STUN_CLIENT_HPP
