// Copyright (c) 2023- Charlie Vigue. All rights reserved.

/**
 * @file stun_discovery.h
 * @brief Transport-agnostic STUN binding discovery and NAT characterization.
 *
 * Orchestration layer built on @ref stun_utils (wire format) and @ref stun_io
 * (send/receive). Callers supply I/O — typically @ref make_socket_stun_io for
 * an owned UDP socket, or a custom adapter that demuxes replies on a shared
 * socket (e.g. QUIC + STUN on one port).
 *
 * @c stun_client is a thin façade over these helpers; meshcore uses them
 * directly via @c MeshTransport::discover_server_reflexive.
 */

#ifndef CLV_NETCORE_STUN_DISCOVERY_HPP
#define CLV_NETCORE_STUN_DISCOVERY_HPP

#include "stun/stun_types.h"
#include "stun/stun_utils.h"
#include "stun_io.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/use_awaitable.hpp>
#include <utility>
#include <vector>

namespace clv::netcore {

/**
 * @namespace stun_discovery
 * @brief Coroutine helpers for STUN queries, failover, and NAT-type tests.
 *
 * Thread safety: functions are **not** thread-safe; run on the @c io_context
 * thread that owns @p io and @p io_context.
 */
namespace stun_discovery {

namespace detail {

struct simple_response_parser
{
    using return_type = std::optional<public_address>;

    std::optional<public_address>
    operator()(std::span<const std::uint8_t> response) const
    {
        if (auto parse_result = stun_utils::parse_binding_response(response); parse_result)
            return parse_result.value();
        return std::nullopt;
    }
};

struct advanced_response_parser
{
    using return_type = std::optional<std::pair<public_address, std::optional<public_address>>>;

    std::optional<std::pair<public_address, std::optional<public_address>>>
    operator()(std::span<const std::uint8_t> response) const
    {
        if (auto parse_result = stun_utils::parse_binding_response_with_other_address(response); parse_result)
            return parse_result.value();
        return std::nullopt;
    }
};

} // namespace detail

/**
 * @brief Resolve @p server, send @p packet, await a response, and parse it.
 *
 * @tparam Parser Callable with signature @c std::optional<T>(std::span<const std::uint8_t>).
 * @param io Send/receive adapter (must provide @c send_to and @c receive_with_timeout).
 * @param io_context Used for DNS resolution and receive timeouts.
 * @param server STUN host/port to query.
 * @param packet Pre-built STUN request (binding or change-request).
 * @param timeout Per-server response wait.
 * @param parser Parses the raw response bytes (e.g. @c detail::simple_response_parser).
 * @param log Optional diagnostic sink; may be @c nullptr.
 * @return Parser result, or empty optional on resolve/send/timeout/parse failure.
 */
template <typename Parser>
inline asio::awaitable<typename Parser::return_type>
query_stun_server(stun_io &io,
                  asio::io_context &io_context,
                  const stun_server_endpoint &server,
                  const stun_packet &packet,
                  std::chrono::milliseconds timeout,
                  Parser &&parser,
                  const stun_log_sink *log = nullptr)
{
    asio::ip::udp::resolver resolver{io_context};

    auto [resolve_ec, endpoints] = co_await resolver.async_resolve(
        server.host, std::to_string(server.port), asio::as_tuple(asio::use_awaitable));

    if (resolve_ec || endpoints.empty())
    {
        if (log)
            log->log(stun_log_level::warn,
                     std::format("DNS resolution failed for {}:{}", server.host, server.port));
        co_return typename Parser::return_type{};
    }

    const auto server_endpoint = *endpoints.begin();

    if (!io.send_to)
    {
        if (log)
            log->log(stun_log_level::error, "STUN I/O send_to is not configured");
        co_return typename Parser::return_type{};
    }

    try
    {
        co_await io.send_to(std::span<const std::uint8_t>{packet}, server_endpoint);
    }
    catch (const std::system_error &e)
    {
        if (log)
            log->log(stun_log_level::error,
                     std::format("Failed to send STUN request to {}:{}: {}",
                                 server.host,
                                 server.port,
                                 e.what()));
        co_return typename Parser::return_type{};
    }

    if (!io.receive_with_timeout)
    {
        if (log)
            log->log(stun_log_level::error, "STUN I/O receive_with_timeout is not configured");
        co_return typename Parser::return_type{};
    }

    std::optional<std::vector<std::uint8_t>> response;
    try
    {
        response = co_await io.receive_with_timeout(timeout);
    }
    catch (const std::system_error &e)
    {
        if (log)
            log->log(stun_log_level::warn,
                     std::format("Receive error from {}:{}: {}", server.host, server.port, e.what()));
        co_return typename Parser::return_type{};
    }

    if (!response || response->empty())
    {
        if (log)
            log->log(stun_log_level::warn,
                     std::format("Timeout or empty response from STUN server {}:{}", server.host, server.port));
        co_return typename Parser::return_type{};
    }

    co_return parser(std::span<const std::uint8_t>{*response});
}

/**
 * @brief RFC 5389 binding request to discover server-reflexive address.
 *
 * Generates a transaction ID, sends a binding request, and parses XOR-MAPPED-ADDRESS
 * (or MAPPED-ADDRESS) from the first successful response.
 */
inline asio::awaitable<std::optional<public_address>>
query_binding(stun_io &io,
              asio::io_context &io_context,
              const stun_server_endpoint &server,
              std::chrono::milliseconds timeout,
              const stun_log_sink *log = nullptr)
{
    const auto trans_id = stun_utils::generate_transaction_id();
    const auto packet = stun_utils::create_binding_request(trans_id);
    co_return co_await query_stun_server(
        io, io_context, server, packet, timeout, detail::simple_response_parser{}, log);
}

/**
 * @brief Binding request with a caller-supplied packet (e.g. CHANGE-REQUEST).
 *
 * Parser also extracts OTHER-ADDRESS when present (RFC 5780), used for NAT-type tests.
 */
inline asio::awaitable<std::optional<std::pair<public_address, std::optional<public_address>>>>
query_binding_advanced(stun_io &io,
                       asio::io_context &io_context,
                       const stun_server_endpoint &server,
                       const stun_packet &packet,
                       std::chrono::milliseconds timeout,
                       const stun_log_sink *log = nullptr)
{
    co_return co_await query_stun_server(
        io, io_context, server, packet, timeout, detail::advanced_response_parser{}, log);
}

/**
 * @brief Try each STUN server in order until @p callback reports success.
 *
 * @tparam Callback @c asio::awaitable<bool>(const stun_server_endpoint&, stun_result&).
 *        Return @c true to stop; @c false tries the next server.
 * @param servers Ordered failover list.
 * @param callback Per-server operation; may populate @c result on success.
 * @param error_message Stored in @c stun_result::error_message if all servers fail.
 */
template <typename Callback>
inline asio::awaitable<stun_result>
try_servers_with_timing(const std::vector<stun_server_endpoint> &servers,
                        Callback &&callback,
                        std::string_view error_message = "")
{
    stun_result result{};
    const auto start_time = std::chrono::steady_clock::now();

    for (const auto &server : servers)
    {
        if (co_await callback(server, result))
        {
            result.response_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start_time);
            co_return result;
        }
    }

    if (!error_message.empty())
        result.error_message = std::string(error_message);
    co_return result;
}

/**
 * @brief Discover the client's server-reflexive (public) address.
 *
 * Tries @p servers in order via @ref query_binding. The reflexive **port** in
 * @c stun_result::public_addr reflects the UDP socket used by @p io — for hole
 * punching, that socket must be the same one used for application traffic.
 */
inline asio::awaitable<stun_result>
discover_public_address(stun_io &io,
                        asio::io_context &io_context,
                        const std::vector<stun_server_endpoint> &servers,
                        std::chrono::milliseconds timeout = stun_defaults::address_timeout,
                        const stun_log_sink *log = nullptr)
{
    auto callback = [&](const stun_server_endpoint &server, stun_result &result) -> asio::awaitable<bool>
    {
        if (auto addr = co_await query_binding(io, io_context, server, timeout, log))
        {
            result.success = true;
            result.public_addr = *addr;
            co_return true;
        }
        co_return false;
    };

    co_return co_await try_servers_with_timing(
        servers, callback, std::format("Failed to get response from {} servers", servers.size()));
}

/**
 * @brief Test whether the NAT supports hairpinning (loopback to public address).
 *
 * Uses a **separate** ephemeral UDP socket (not @p io) per RFC 5780 §3.4 methodology.
 */
inline asio::awaitable<bool>
detect_hairpin(asio::io_context &io_context,
               const stun_server_endpoint &server,
               const public_address &public_addr,
               std::chrono::milliseconds timeout,
               const stun_log_sink *log = nullptr,
               const asio::ip::address_v4 &local_lan_addr = asio::ip::address_v4::any())
{
    (void)local_lan_addr;

    if (!public_addr.is_valid())
    {
        if (log)
            log->log(stun_log_level::debug, "Cannot perform hairpin detection: invalid public address");
        co_return false;
    }

    try
    {
        asio::ip::udp::socket hairpin_sock{
            io_context,
            asio::ip::udp::endpoint{asio::ip::udp::v4(), 0}};

        const auto local_port = hairpin_sock.local_endpoint().port();

        if (log)
            log->log(stun_log_level::debug, std::format("Hairpin: created test socket on port {}", local_port));

        asio::ip::udp::resolver resolver{io_context};
        auto [resolve_ec, resolve_results] = co_await resolver.async_resolve(
            asio::ip::udp::v4(),
            server.host,
            std::to_string(server.port),
            asio::as_tuple(asio::use_awaitable));

        if (resolve_ec || resolve_results.empty())
        {
            if (log)
                log->log(stun_log_level::debug,
                         std::format("Hairpin: failed to resolve STUN server {}: {}",
                                     server.host,
                                     resolve_ec.message()));
            hairpin_sock.close();
            co_return false;
        }

        const auto stun_server_ep = *resolve_results.begin();

        const auto trans_id_query = stun_utils::generate_transaction_id();
        const auto query_packet = stun_utils::create_binding_request(trans_id_query);

        auto [send_ec1, sent1] = co_await hairpin_sock.async_send_to(
            asio::buffer(query_packet), stun_server_ep, asio::as_tuple(asio::use_awaitable));

        if (send_ec1 || sent1 == 0)
        {
            if (log)
                log->log(stun_log_level::debug,
                         std::format("Hairpin: failed to query STUN server: {}", send_ec1.message()));
            hairpin_sock.close();
            co_return false;
        }

        std::array<std::uint8_t, 1500> stun_resp_buf{};
        asio::ip::udp::endpoint stun_sender;

        asio::steady_timer query_timer{io_context};
        query_timer.expires_after(timeout);
        std::atomic<bool> query_timeout{false};
        query_timer.async_wait([&](std::error_code ec)
        {
            if (!ec)
            {
                query_timeout = true;
                hairpin_sock.cancel();
            }
        });

        auto [recv_ec1, recv1] = co_await hairpin_sock.async_receive_from(
            asio::buffer(stun_resp_buf), stun_sender, asio::as_tuple(asio::use_awaitable));

        query_timer.cancel();

        if (recv_ec1 || recv1 == 0)
        {
            if (log)
                log->log(stun_log_level::debug,
                         std::format("Hairpin: failed to get STUN response: {}", recv_ec1.message()));
            hairpin_sock.close();
            co_return false;
        }

        auto parse_result = stun_utils::parse_binding_response(std::span{stun_resp_buf.data(), recv1});
        if (!parse_result)
        {
            if (log)
                log->log(stun_log_level::debug, "Hairpin: failed to parse STUN response");
            hairpin_sock.close();
            co_return false;
        }

        const auto our_public_addr = parse_result.value();
        if (log)
            log->log(stun_log_level::debug,
                     std::format("Hairpin: our test socket's public address is {}:{}",
                                 our_public_addr.address.to_string(),
                                 our_public_addr.port));

        const auto target_endpoint = asio::ip::udp::endpoint{
            asio::ip::make_address_v4(our_public_addr.address.to_string()),
            our_public_addr.port};

        const auto trans_id_hairpin = stun_utils::generate_transaction_id();
        const auto hairpin_packet = stun_utils::create_binding_request(trans_id_hairpin);

        auto [send_ec2, sent2] = co_await hairpin_sock.async_send_to(
            asio::buffer(hairpin_packet), target_endpoint, asio::as_tuple(asio::use_awaitable));

        if (send_ec2 || sent2 == 0)
        {
            if (log)
                log->log(stun_log_level::debug,
                         std::format("Hairpin: send to own address failed: {}", send_ec2.message()));
            hairpin_sock.close();
            co_return false;
        }

        if (log)
            log->log(stun_log_level::debug, "Hairpin: sent packet to our own public address, awaiting loopback...");

        asio::steady_timer hairpin_timer{io_context};
        hairpin_timer.expires_after(timeout);
        std::atomic<bool> timed_out{false};
        hairpin_timer.async_wait([&](std::error_code ec)
        {
            if (!ec)
            {
                timed_out = true;
                hairpin_sock.cancel();
            }
        });

        std::array<std::uint8_t, 1500> recv_buf{};
        asio::ip::udp::endpoint sender;

        auto [recv_ec2, received] = co_await hairpin_sock.async_receive_from(
            asio::buffer(recv_buf), sender, asio::as_tuple(asio::use_awaitable));

        hairpin_timer.cancel();
        hairpin_sock.close();

        if (recv_ec2)
        {
            if (log)
            {
                if (timed_out)
                    log->log(stun_log_level::debug, "Hairpin: timeout - NAT does not support hairpinning");
                else
                    log->log(stun_log_level::debug,
                             std::format("Hairpin: receive error: {}", recv_ec2.message()));
            }
            co_return false;
        }

        if (received == 0)
        {
            if (log)
                log->log(stun_log_level::debug, "Hairpin: received 0 bytes");
            co_return false;
        }

        if (stun_utils::matches_transaction_id(std::span{recv_buf.data(), received}, trans_id_hairpin))
        {
            if (log)
                log->log(stun_log_level::debug,
                         std::format("Hairpin: SUCCESS! Received our own STUN request from {}:{}",
                                     sender.address().to_string(),
                                     sender.port()));
            co_return true;
        }

        if (log)
            log->log(stun_log_level::debug, "Hairpin: received packet but transaction ID doesn't match");
        co_return false;
    }
    catch (const std::exception &ex)
    {
        if (log)
            log->log(stun_log_level::debug, std::format("Hairpin: exception: {}", ex.what()));
        co_return false;
    }
}

/**
 * @brief Run RFC 3489/5780 NAT characterization tests against one STUN server.
 *
 * Sequence: basic binding → change IP+port → change port → optional hairpin test.
 * Results feed @ref stun_utils::analyze_nat_type.
 */
inline asio::awaitable<nat_test_result>
perform_nat_tests(stun_io &io,
                  asio::io_context &io_context,
                  const stun_server_endpoint &server,
                  const nat_detection_config &config,
                  const stun_log_sink *log = nullptr)
{
    nat_test_result results{};

    {
        const auto trans_id = stun_utils::generate_transaction_id();
        const auto packet = stun_utils::create_binding_request(trans_id);

        if (const auto response = co_await query_binding_advanced(
                io, io_context, server, packet, config.individual_test_timeout, log);
            response)
        {
            results.test1_success = true;
            results.test1_addr = response->first;
            if (response->second.has_value())
                results.server_other_addr = *response->second;
        }
        else
            co_return results;
    }

    if (results.test1_success && results.server_other_addr.is_valid() && config.fallback_to_rfc3489)
    {
        const auto trans_id = stun_utils::generate_transaction_id();
        const auto packet = stun_utils::create_change_request(trans_id, stun_constants::change_ip_and_port);

        if (const auto response = co_await query_binding_advanced(
                io, io_context, server, packet, config.individual_test_timeout, log);
            response)
        {
            results.test2_success = true;
            results.test2_addr = response->first;
        }
    }

    if (results.test1_success && config.fallback_to_rfc3489)
    {
        const auto trans_id = stun_utils::generate_transaction_id();
        const auto packet = stun_utils::create_change_request(trans_id, stun_constants::change_port);

        if (const auto response = co_await query_binding_advanced(
                io, io_context, server, packet, config.individual_test_timeout, log);
            response)
        {
            results.test3_success = true;
            results.test3_addr = response->first;

            if (results.test1_addr.is_valid() && results.test3_addr.is_valid())
            {
                results.addresses_differ = (results.test1_addr.address != results.test3_addr.address)
                                           || (results.test1_addr.port != results.test3_addr.port);
            }
        }
    }

    if (results.test1_success && results.test1_addr.is_valid())
    {
        results.hairpin_test_attempted = true;
        results.hairpin_supported = co_await detect_hairpin(
            io_context, server, results.test1_addr, config.individual_test_timeout, log, config.local_lan_addr);
    }

    co_return results;
}

/**
 * @brief Discover public address and classify NAT type (multi-server failover).
 *
 * On success, @c stun_result::detected_nat_type and @c hairpin_supported are set
 * from @ref perform_nat_tests and @ref stun_utils::analyze_nat_type.
 */
inline asio::awaitable<stun_result>
detect_nat_type(stun_io &io,
                asio::io_context &io_context,
                const std::vector<stun_server_endpoint> &servers,
                const nat_detection_config &config,
                const stun_log_sink *log = nullptr)
{
    auto callback = [&](const stun_server_endpoint &server, stun_result &result) -> asio::awaitable<bool>
    {
        const auto test_results = co_await perform_nat_tests(io, io_context, server, config, log);

        if (!test_results.test1_success)
            co_return false;

        result.success = true;
        result.public_addr = test_results.test1_addr;
        result.hairpin_supported = test_results.hairpin_supported;

        if (io.local_endpoint)
        {
            try
            {
                const auto local_endpoint = io.local_endpoint();
                result.detected_nat_type = stun_utils::analyze_nat_type(
                    test_results, local_endpoint.address().to_v4());
                co_return true;
            }
            catch (const std::system_error &)
            {
                if (log)
                    log->log(stun_log_level::debug,
                             std::format("Failed to analyze NAT type with local endpoint for {}:{}",
                                         server.host,
                                         server.port));
            }
        }

        result.detected_nat_type = stun_utils::analyze_nat_type(test_results);
        co_return true;
    };

    co_return co_await try_servers_with_timing(
        servers, callback, "Failed to perform NAT detection with any server");
}

} // namespace stun_discovery
} // namespace clv::netcore

#endif // CLV_NETCORE_STUN_DISCOVERY_HPP
