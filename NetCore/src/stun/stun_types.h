// Copyright (c) 2023- Charlie Vigue. All rights reserved.

/**
 * @file stun_types.h
 * @brief Shared STUN configuration types, results, and logging helpers.
 *
 * Extracted from @c stun_client so @ref stun_discovery and custom I/O adapters
 * can share the same types without pulling in socket ownership.
 */

#ifndef CLV_NETCORE_STUN_TYPES_HPP
#define CLV_NETCORE_STUN_TYPES_HPP

#include "stun_utils.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace clv::netcore {

/** @brief STUN server hostname (or IP) and UDP port. */
struct stun_server_endpoint
{
    std::string host;
    std::uint16_t port = stun_constants::default_port;

    explicit stun_server_endpoint(std::string host,
                                  std::uint16_t port = stun_constants::default_port)
        : host{std::move(host)},
          port{port}
    {
    }
};

/**
 * @brief Outcome of a STUN discovery or NAT-detection operation.
 *
 * @c public_addr is valid when @c success is @c true. @c detected_nat_type is
 * populated by @ref stun_discovery::detect_nat_type.
 */
struct stun_result
{
    bool success = false;
    public_address public_addr{};
    nat_type detected_nat_type = nat_type::unknown;
    std::chrono::milliseconds response_time{};
    std::string error_message{};
    bool hairpin_supported = false;
};

/** @brief Tunables for @ref stun_discovery::perform_nat_tests / @ref stun_discovery::detect_nat_type. */
struct nat_detection_config
{
    std::chrono::milliseconds individual_test_timeout{2000};
    bool use_rfc5780_attributes = true;
    bool fallback_to_rfc3489 = true;
    asio::ip::address_v4 local_lan_addr = asio::ip::address_v4::any();
};

/** @brief Raw STUN message bytes (request or response). */
using stun_packet = std::vector<std::uint8_t>;

/** @brief Optional log callback: @c (level, message). Levels in @ref stun_log_level. */
using stun_log_fn = std::function<void(int level, std::string_view message)>;

/** @brief Severity constants for @ref stun_log_fn. */
namespace stun_log_level {
inline constexpr int info = 0;
inline constexpr int debug = 1;
inline constexpr int warn = 2;
inline constexpr int error = 3;
} // namespace stun_log_level

/** @brief Default timeouts and buffer sizes for STUN helpers. */
namespace stun_defaults {
inline constexpr std::chrono::milliseconds address_timeout{5000};
inline constexpr std::chrono::milliseconds nat_detection_timeout{10000};
inline constexpr std::size_t max_stun_response_size = 1024;
inline constexpr std::size_t nat_test_count = 3;
} // namespace stun_defaults

/**
 * @brief Optional diagnostic logging wrapper for @ref stun_discovery helpers.
 *
 * Swallows exceptions from the user callback so logging cannot fail discovery.
 */
struct stun_log_sink
{
    stun_log_fn logger;

    void log(int level, std::string_view message) const noexcept
    {
        if (!logger)
            return;
        try
        {
            logger(level, message);
        }
        catch (...)
        {
        }
    }
};

/**
 * @brief Populate @p servers with public STUN defaults when the list is empty.
 *
 * Used by @c stun_client construction; callers may also invoke directly.
 */
inline void ensure_default_stun_servers(std::vector<stun_server_endpoint> &servers)
{
    if (servers.empty())
    {
        servers.emplace_back("stun.l.google.com", 19302);
        servers.emplace_back("stun1.l.google.com", 19302);
        servers.emplace_back("stun.stunprotocol.org", 3478);
    }
}

} // namespace clv::netcore

#endif // CLV_NETCORE_STUN_TYPES_HPP
