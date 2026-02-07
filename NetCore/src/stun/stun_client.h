// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_NETCORE_STUN_CLIENT_HPP
#define CLV_NETCORE_STUN_CLIENT_HPP

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <format>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/use_awaitable.hpp>

#include "stun_utils.h"

namespace clv::netcore {

/// Modern C++20 STUN client using ASIO and coroutines
///
/// Thread Safety: This class is NOT thread-safe. All operations must be called from the thread
/// that owns the associated io_context. Each method is designed to be called as a coroutine
/// within a single-threaded executor. For multi-threaded use, wrap each client instance with
/// strand-based synchronization or use thread-local clients.
class stun_client
{
  public: // Types
    /// STUN server endpoint
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

    /// STUN operation result
    struct stun_result
    {
        bool success = false;
        public_address public_addr{};
        nat_type detected_nat_type = nat_type::unknown;
        std::chrono::milliseconds response_time{};
        std::string error_message{};
        bool hairpin_supported = false; // Whether NAT supports hairpinning (set after NAT detection)
    };

    /// Advanced NAT detection parameters
    struct nat_detection_config
    {
        std::chrono::milliseconds individual_test_timeout{2000};
        bool use_rfc5780_attributes = true;                                // Use modern RFC 5780 attributes if available
        bool fallback_to_rfc3489 = true;                                   // Fallback to classic RFC 3489 method
        asio::ip::address_v4 local_lan_addr = asio::ip::address_v4::any(); // Local LAN address for hairpin test
    };

    /// Transaction ID type for type safety
    using transaction_id = std::array<std::uint8_t, stun_constants::transaction_id_size>;

    /// STUN packet type for type safety
    using stun_packet = std::vector<std::uint8_t>;

    /// Log callback: (level, message) - level: 0=debug, 1=warn, 2=error
    using stun_log_fn = std::function<void(int level, std::string_view message)>;

  public: // Constants
    static inline constexpr std::chrono::milliseconds default_address_timeout{5000};
    static inline constexpr std::chrono::milliseconds default_nat_detection_timeout{10000};
    static inline constexpr std::size_t max_stun_response_size = 1024;
    static inline constexpr std::size_t nat_test_count = 3; // RFC 3489/5780 requires 3 tests

    static constexpr int info_level = 0;
    static constexpr int debug_level = 1;
    static constexpr int warn_level = 2;
    static constexpr int error_level = 3;

  public: // API
    /**
     * @brief Construct with automatic port and default servers
     */
    explicit stun_client(asio::io_context &io_context);

    /**
     * @brief Construct with specific local port and default servers
     */
    explicit stun_client(std::uint16_t local_port, asio::io_context &io_context);

    /**
     * @brief Construct with one or more STUN servers (variadic)
     */
    template <typename First, typename... Rest>
    explicit stun_client(asio::io_context &io_context, First &&first, Rest &&...rest);

    /**
     * @brief Construct with local port and one or more STUN servers (variadic)
     */
    template <typename First, typename... Rest>
    explicit stun_client(std::uint16_t local_port,
                         asio::io_context &io_context,
                         First &&first,
                         Rest &&...rest);

    /**
     * @brief Construct with container of STUN servers (vector, array, etc.)
     */
    template <typename ServerContainer>
    explicit stun_client(asio::io_context &io_context, ServerContainer &&servers);

    /**
     * @brief Construct with local port and container of STUN servers
     */
    template <typename ServerContainer>
    explicit stun_client(std::uint16_t local_port,
                         asio::io_context &io_context,
                         ServerContainer &&servers);

    /// Non-copyable but movable (move-assignment is deleted because of reference member io_context_)
    stun_client(const stun_client &) = delete;
    stun_client &operator=(const stun_client &) = delete;
    stun_client(stun_client &&) = default;
    stun_client &operator=(stun_client &&) = delete;

    /// Destructor
    ~stun_client() = default;

    /// Discover public IP address (coroutine)
    asio::awaitable<stun_result>
    discover_public_address(std::chrono::milliseconds timeout = default_address_timeout);

    /**
     * @brief Detect NAT type
     * @details Uses RFC 3489/5780 methodology and default configuration
     * @param timeout Overall timeout for the detection process
     */
    asio::awaitable<stun_result>
    detect_nat_type(std::chrono::milliseconds timeout = default_nat_detection_timeout);

    /**
     * @brief Comprehensive NAT detection using RFC 3489/5780 methodology
     * @details Uses a series of STUN requests to determine the NAT type
     * @param config NAT detection configuration
     */
    asio::awaitable<stun_result>
    detect_nat_type(const nat_detection_config &config);

    /// Get the local binding port
    [[nodiscard]] std::uint16_t local_port() const noexcept;

    /// Get reference to the underlying UDP socket
    /// @warning The socket is owned by this stun_client instance. Callers must ensure
    /// the stun_client lifetime extends for as long as the socket reference is used.
    [[nodiscard]] asio::ip::udp::socket &get_socket() noexcept;

    /// Get server count
    [[nodiscard]] std::size_t server_count() const noexcept;

    /// Get server list
    [[nodiscard]] const std::vector<stun_server_endpoint> &get_servers() const noexcept;

    /// Set optional logging callback for diagnostic messages
    void set_logger(stun_log_fn logger) noexcept;

  private: // Data members
    asio::io_context &io_context_;
    asio::ip::udp::socket socket_;
    std::vector<stun_server_endpoint> servers_;
    std::uint16_t local_port_;
    stun_log_fn logger_;

  private: // Internal methods
    /// Private delegating constructor - handles member initialization only
    stun_client(std::in_place_t, std::uint16_t local_port, asio::io_context &io_context);

    /// Check post-ctor state validity
    void check_state_validity();

    /// Generate default STUN servers if none provided
    void ensure_default_servers();

    /// Common socket I/O with timeout handling
    /// Sends packet and receives response with timeout, then calls parser
    template <typename Parser>
    asio::awaitable<typename Parser::return_type>
    query_server_impl(const stun_server_endpoint &server,
                      const stun_packet &packet,
                      std::chrono::milliseconds timeout,
                      Parser &&parser);

    /// Generic server loop helper - tries operation on each server until success
    /// Callback should return true if operation succeeded, false to try next server
    template <typename Callback>
    asio::awaitable<stun_result>
    try_servers_with_timing(Callback &&callback, std::string_view error_message = "");

    /// Single server query attempt
    asio::awaitable<std::optional<public_address>>
    query_server(const stun_server_endpoint &server, std::chrono::milliseconds timeout);

    /// Advanced query with custom packet and optional other address parsing
    asio::awaitable<std::optional<std::pair<public_address, std::optional<public_address>>>>
    query_server_advanced(const stun_server_endpoint &server,
                          const stun_packet &packet,
                          std::chrono::milliseconds timeout);

    /// Perform comprehensive NAT detection tests
    asio::awaitable<nat_test_result>
    perform_nat_tests(const stun_server_endpoint &server, const nat_detection_config &config);

    /// Detect hairpinning support by attempting to connect to own public address
    /// Returns true if hairpinning is supported, false otherwise
    asio::awaitable<bool>
    detect_hairpin(const stun_server_endpoint &server,
                   const public_address &public_addr,
                   std::chrono::milliseconds timeout,
                   const asio::ip::address_v4 &local_lan_addr = asio::ip::address_v4::any());

    /// Log a diagnostic message if logger is set
    /// level: 0=debug, 1=warn, 2=error
    void log(int level, std::string_view message) const noexcept;
};

// Implementation of stun_client constructors

/// Private constructor: initializes members only.
// Needed to enable member init being distinct from invariant checks.

inline stun_client::stun_client(std::in_place_t, std::uint16_t local_port, asio::io_context &io_context)
    : io_context_{io_context},
      socket_{io_context_, asio::ip::udp::endpoint{asio::ip::udp::v4(), local_port}},
      local_port_{socket_.local_endpoint().port()}
{
}

/// No servers specified, will use defaults
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

// Variadic constructor with at least one server
template <typename First, typename... Rest>
inline stun_client::stun_client(asio::io_context &io_context, First &&first, Rest &&...rest)
    : stun_client(0, io_context, std::forward<First>(first), std::forward<Rest>(rest)...)
{
}

// Variadic constructor with port and at least one server
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

// Container-based constructor
template <typename ServerContainer>
inline stun_client::stun_client(asio::io_context &io_context, ServerContainer &&servers)
    : stun_client(0, io_context, std::forward<ServerContainer>(servers))
{
}

// Container-based constructor with port
template <typename ServerContainer>
inline stun_client::stun_client(std::uint16_t local_port,
                                asio::io_context &io_context,
                                ServerContainer &&servers)
    : stun_client(std::in_place, local_port, io_context)
{
    for (auto &&server : servers)
        servers_.emplace_back(std::move(server));
    ensure_default_servers(); // If someone passes an empty list
    check_state_validity();
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
    if (servers_.empty())
    {
        servers_.emplace_back("stun.l.google.com", 19302);
        servers_.emplace_back("stun1.l.google.com", 19302);
        servers_.emplace_back("stun.stunprotocol.org", 3478);
    }
}

inline auto stun_client::discover_public_address(std::chrono::milliseconds timeout) -> asio::awaitable<stun_result>
{
    auto callback = [this, timeout](const stun_server_endpoint &server, stun_result &result) -> asio::awaitable<bool>
    {
        if (auto addr = co_await query_server(server, timeout))
        {
            result.success = true;
            result.public_addr = *addr;
            co_return true;
        }
        co_return false;
    };

    co_return co_await try_servers_with_timing(callback, std::format("Failed to get response from {} servers", servers_.size()));
}

inline auto stun_client::detect_nat_type(std::chrono::milliseconds timeout) -> asio::awaitable<stun_result>
{
    // Use the generic function with a config based on the timeout
    nat_detection_config config{};
    config.individual_test_timeout = timeout; // Individual means per test

    co_return co_await detect_nat_type(config);
}

inline auto stun_client::detect_nat_type(const nat_detection_config &config) -> asio::awaitable<stun_result>
{
    auto callback = [this, &config](const stun_server_endpoint &server, stun_result &result) -> asio::awaitable<bool>
    {
        const auto test_results = co_await perform_nat_tests(server, config);

        if (test_results.test1_success)
        {
            result.success = true;
            result.public_addr = test_results.test1_addr;
            result.hairpin_supported = test_results.hairpin_supported;

            // Analyze NAT type, passing local address for open internet detection
            try
            {
                auto local_endpoint = socket_.local_endpoint();
                result.detected_nat_type = stun_utils::analyze_nat_type(test_results, local_endpoint.address().to_v4());
                co_return true;
            }
            catch (const std::system_error &)
            {
                log(debug_level, std::format("Failed to analyze NAT type with local endpoint for {}:{}", server.host, server.port));
            }

            // If we can't get local endpoint (rare for an open socket), analyze without it
            try
            {
                result.detected_nat_type = stun_utils::analyze_nat_type(test_results);
                co_return true;
            }
            catch (const std::system_error &)
            {
                log(debug_level, std::format("Failed to analyze NAT type without local endpoint for {}:{}", server.host, server.port));
            }
        }
        co_return false;
    };

    co_return co_await try_servers_with_timing(callback, "Failed to perform NAT detection with any server");
}

// ************************************************************************************************
// Private function implementations
// ************************************************************************************************

/// Parser for simple binding response
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

/// Parser for binding response with other address support
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

/// Helper template to try an operation on each server with timing
/// Callback receives the server and should return true if operation succeeded, false to try next server
template <typename Callback>
inline auto stun_client::try_servers_with_timing(Callback &&callback, std::string_view error_message) -> asio::awaitable<stun_result>
{
    stun_result result{};
    const auto start_time = std::chrono::steady_clock::now();

    for (const auto &server : servers_)
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

template <typename Parser>
inline asio::awaitable<typename Parser::return_type>
stun_client::query_server_impl(const stun_server_endpoint &server,
                               const stun_packet &packet,
                               std::chrono::milliseconds timeout,
                               Parser &&parser)
{
    // Resolve server endpoint
    asio::ip::udp::resolver resolver{io_context_};

    auto [resolve_ec, endpoints] = co_await resolver.async_resolve(
        server.host, std::to_string(server.port), asio::as_tuple(asio::use_awaitable));

    if (resolve_ec || endpoints.empty())
    {
        log(warn_level, std::format("DNS resolution failed for {}:{}", server.host, server.port));
        co_return typename Parser::return_type{};
    }

    const auto server_endpoint = *endpoints.begin();

    // Send request
    auto [send_ec, bytes_sent] = co_await socket_.async_send_to(
        asio::buffer(packet), server_endpoint, asio::as_tuple(asio::use_awaitable));

    if (send_ec || bytes_sent == 0)
    {
        log(error_level, std::format("Failed to send STUN request to {}:{}", server.host, server.port));
        co_return typename Parser::return_type{};
    }

    // Receive response with timeout
    std::array<std::uint8_t, max_stun_response_size> response_buffer{};
    asio::ip::udp::endpoint sender_endpoint;

    // Create a timer for timeout
    asio::steady_timer timer{io_context_};
    timer.expires_after(timeout);

    // Use atomic for thread-safe timeout flag across coroutine suspension
    std::atomic<bool> timeout_occurred{false};
    timer.async_wait([&](std::error_code ec)
    {
        if (!ec)
        {
            timeout_occurred = true;
            socket_.cancel(); // Cancel the receive operation
        }
    });

    auto [recv_ec, bytes_received] = co_await socket_.async_receive_from(
        asio::buffer(response_buffer), sender_endpoint, asio::as_tuple(asio::use_awaitable));

    timer.cancel(); // Cancel timer if receive completed first

    if (recv_ec)
    {
        if (timeout_occurred)
        {
            log(warn_level, std::format("Timeout waiting for STUN response from {}:{}", server.host, server.port));
        }
        else
        {
            log(warn_level, std::format("Receive error from {}:{}: {}", server.host, server.port, recv_ec.message()));
        }
        co_return typename Parser::return_type{};
    }

    if (bytes_received == 0)
    {
        log(debug_level, std::format("Empty response from STUN server {}:{}", server.host, server.port));
        co_return typename Parser::return_type{};
    }

    const auto response_span = std::span{response_buffer.data(), bytes_received};
    co_return parser(response_span);
}

/*
Overview: The function executes a series of three STUN (Session Traversal Utilities for NAT) protocol tests and
          returns the results. Each test sends a different type of request to the STUN server and analyzes how
          the responses differ to classify the NAT type.

          Also does the extra 'hairpin' test.

The Three Tests

Test 1: Basic Binding Request

  Sends a simple STUN binding request to get the client's public IP and port as seen by the server
  Also captures the server's "other address" (alternate address that the server advertises for change-of-address
  tests) This test is mandatory — if it fails, the function returns immediately since subsequent tests depend
  on it.

  Stores: test1_addr (public address) and server_other_addr

Test 2: Change IP and Port Request

  Only runs if Test 1 succeeded AND we have the server's alternate address AND RFC 3489 fallback is enabled
  Sends a request asking the STUN server to respond from a different IP and port
  If the response comes back, it means the NAT allows unsolicited traffic from different addresses (fullcone NAT)

  Stores: test2_addr

Test 3: Change Port Only Request

  Only runs if Test 1 succeeded AND RFC 3489 fallback is enabled
  Sends a request asking the server to respond from the same IP but different port
  Compares test3_addr against test1_addr to detect address-dependent filtering (restricted-cone NAT)
  The addresses_differ flag indicates whether the NAT modified the mapping based on the server's port change

Hairpin Test:

    Checks if NAT supports hairpinning (loopback through external address)
    This test attempts to send a packet to our own public address and see if it loops back
    Sets hairpin_test_attempted to true and hairpin_supported based on the result.
*/
inline asio::awaitable<nat_test_result>
stun_client::perform_nat_tests(const stun_server_endpoint &server, const nat_detection_config &config)
{
    nat_test_result results{};

    // Test 1: Basic binding request
    {
        const auto trans_id = stun_utils::generate_transaction_id();
        const auto packet = stun_utils::create_binding_request(trans_id);

        if (const auto response = co_await query_server_advanced(server, packet, config.individual_test_timeout); response)
        {
            results.test1_success = true;
            results.test1_addr = response->first;
            if (response->second.has_value())
            {
                results.server_other_addr = *response->second;
            }
        }
        else
            co_return results; // Cannot proceed without successful test 1
    }

    // Test 2: Change IP and port request (only if we have other address)
    if (results.test1_success && results.server_other_addr.is_valid() && config.fallback_to_rfc3489)
    {
        const auto trans_id = stun_utils::generate_transaction_id();
        const auto packet = stun_utils::create_change_request(trans_id, stun_constants::change_ip_and_port);

        if (const auto response = co_await query_server_advanced(server, packet, config.individual_test_timeout))
        {
            results.test2_success = true;
            results.test2_addr = response->first;
        }
    }

    // Test 3: Change port only request
    if (results.test1_success && config.fallback_to_rfc3489)
    {
        const auto trans_id = stun_utils::generate_transaction_id();
        const auto packet = stun_utils::create_change_request(trans_id, stun_constants::change_port);

        if (const auto response = co_await query_server_advanced(server, packet, config.individual_test_timeout))
        {
            results.test3_success = true;
            results.test3_addr = response->first;

            // Check if addresses differ
            if (results.test1_addr.is_valid() && results.test3_addr.is_valid())
            {
                results.addresses_differ = (results.test1_addr.address != results.test3_addr.address)
                                           || (results.test1_addr.port != results.test3_addr.port);
            }
        }
    }

    // Hairpin Test: Check if NAT supports hairpinning (loopback through external address)
    // Even Full Cone NATs don't always support hairpin, so we must test explicitly.
    if (results.test1_success && results.test1_addr.is_valid())
    {
        results.hairpin_test_attempted = true;
        results.hairpin_supported = co_await detect_hairpin(server, results.test1_addr, config.individual_test_timeout, config.local_lan_addr);
    }

    co_return results;
} // "It's a trick, get an axe" - Army of Darkness

inline asio::awaitable<std::optional<public_address>>
stun_client::query_server(const stun_server_endpoint &server,
                          std::chrono::milliseconds timeout)
{
    // Generate transaction ID and create packet
    const auto trans_id = stun_utils::generate_transaction_id();
    const auto packet = stun_utils::create_binding_request(trans_id);

    co_return co_await query_server_impl(server, packet, timeout, simple_response_parser{});
}

inline asio::awaitable<std::optional<std::pair<public_address, std::optional<public_address>>>>
stun_client::query_server_advanced(const stun_server_endpoint &server,
                                   const stun_packet &packet,
                                   std::chrono::milliseconds timeout)
{
    co_return co_await query_server_impl(server, packet, timeout, advanced_response_parser{});
} // "I imagined a story where I didn't have to be the damsel." - Dolores Abernathy

inline asio::awaitable<bool>
stun_client::detect_hairpin(const stun_server_endpoint &server,
                            const public_address &public_addr,
                            std::chrono::milliseconds timeout,
                            const asio::ip::address_v4 &local_lan_addr)
{
    // RFC 5780 Section 3.4: Hairpin detection
    // "The client first sends a Binding Request to its STUN server to determine its mapped
    // address. The client then sends a STUN Binding Request to this mapped address from a
    // different port. If the client receives its own request, the NAT hairpins connections."
    //
    // The trick: We need to discover what OUR hairpin test socket's public address is,
    // then send a packet TO that address FROM the same socket. If hairpin works, we'll
    // receive our own packet back.

    if (!public_addr.is_valid())
    {
        log(debug_level, "Cannot perform hairpin detection: invalid public address");
        co_return false;
    }

    try
    {
        // Create a second socket on a different local port for the hairpin test
        asio::ip::udp::socket hairpin_sock{
            io_context_,
            asio::ip::udp::endpoint{asio::ip::udp::v4(), 0}};

        const auto local_port = hairpin_sock.local_endpoint().port();

        log(debug_level, std::format("Hairpin: created test socket on port {}", local_port));

        // Step 1: Query STUN server from hairpin_sock to get ITS public mapping
        // Resolve STUN server address
        asio::ip::udp::resolver resolver{io_context_};
        auto [resolve_ec, resolve_results] = co_await resolver.async_resolve(
            asio::ip::udp::v4(),
            server.host,
            std::to_string(server.port),
            asio::as_tuple(asio::use_awaitable));

        if (resolve_ec || resolve_results.empty())
        {
            log(debug_level, std::format("Hairpin: failed to resolve STUN server {}: {}", server.host, resolve_ec.message()));
            hairpin_sock.close();
            co_return false;
        }

        const auto stun_server_endpoint = *resolve_results.begin();

        const auto trans_id_query = stun_utils::generate_transaction_id();
        const auto query_packet = stun_utils::create_binding_request(trans_id_query);

        auto [send_ec1, sent1] = co_await hairpin_sock.async_send_to(
            asio::buffer(query_packet), stun_server_endpoint, asio::as_tuple(asio::use_awaitable));

        if (send_ec1 || sent1 == 0)
        {
            log(debug_level, std::format("Hairpin: failed to query STUN server: {}", send_ec1.message()));
            hairpin_sock.close();
            co_return false;
        }

        // Receive STUN response to discover hairpin_sock's public mapping
        std::array<std::uint8_t, 1500> stun_resp_buf{};
        asio::ip::udp::endpoint stun_sender;

        asio::steady_timer query_timer{io_context_};
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
            log(debug_level, std::format("Hairpin: failed to get STUN response: {}", recv_ec1.message()));
            hairpin_sock.close();
            co_return false;
        }

        // Parse the STUN response to extract our public address
        auto parse_result = stun_utils::parse_binding_response(std::span{stun_resp_buf.data(), recv1});
        if (!parse_result)
        {
            log(debug_level, "Hairpin: failed to parse STUN response");
            hairpin_sock.close();
            co_return false;
        }

        const auto our_public_addr = parse_result.value();
        log(debug_level, std::format("Hairpin: our test socket's public address is {}:{}", our_public_addr.address.to_string(), our_public_addr.port));

        // Step 2: Now send a packet TO our own public address FROM the same socket
        const auto target_endpoint = asio::ip::udp::endpoint{
            asio::ip::make_address_v4(our_public_addr.address.to_string()),
            our_public_addr.port};

        const auto trans_id_hairpin = stun_utils::generate_transaction_id();
        const auto hairpin_packet = stun_utils::create_binding_request(trans_id_hairpin);

        auto [send_ec2, sent2] = co_await hairpin_sock.async_send_to(
            asio::buffer(hairpin_packet), target_endpoint, asio::as_tuple(asio::use_awaitable));

        if (send_ec2 || sent2 == 0)
        {
            log(debug_level, std::format("Hairpin: send to own address failed: {}", send_ec2.message()));
            hairpin_sock.close();
            co_return false;
        }

        log(debug_level, "Hairpin: sent packet to our own public address, awaiting loopback...");

        // Step 3: Try to receive our own packet back
        asio::steady_timer hairpin_timer{io_context_};
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
            if (timed_out)
            {
                log(debug_level, "Hairpin: timeout - NAT does not support hairpinning");
            }
            else
            {
                log(debug_level, std::format("Hairpin: receive error: {}", recv_ec2.message()));
            }
            co_return false;
        }

        if (received == 0)
        {
            log(debug_level, "Hairpin: received 0 bytes");
            co_return false;
        }

        // Verify we got our own STUN request back by checking transaction ID
        if (received >= 20) // Minimum STUN header size
        {
            // Check if it's a STUN message (first 2 bits must be 00)
            if ((recv_buf[0] & 0xC0) == 0)
            {
                // Extract transaction ID from bytes 8-19
                std::array<std::uint8_t, 12> received_trans_id{};
                std::copy_n(recv_buf.begin() + 8, 12, received_trans_id.begin());

                if (std::equal(trans_id_hairpin.begin(), trans_id_hairpin.end(), received_trans_id.begin()))
                {
                    log(debug_level, std::format("Hairpin: SUCCESS! Received our own STUN request from {}:{} - NAT supports hairpinning", sender.address().to_string(), sender.port()));
                    co_return true;
                }
                else
                {
                    log(debug_level, "Hairpin: received STUN packet but transaction ID doesn't match");
                }
            }
            else
            {
                log(debug_level, "Hairpin: received non-STUN packet");
            }
        }
        else
        {
            log(debug_level, std::format("Hairpin: received packet too small ({} bytes)", received));
        }

        co_return false;
    }
    catch (const std::exception &ex)
    {
        log(debug_level, std::format("Hairpin: exception: {}", ex.what()));
        co_return false;
    }
}

inline void stun_client::log(int level, std::string_view message) const noexcept
{
    if (logger_)
    {
        try
        {
            logger_(level, message);
        }
        catch (...)
        {
            // Silently ignore logger exceptions to avoid cascading failures
        }
    }
}

} // namespace clv::netcore

#endif // CLV_NETCORE_STUN_CLIENT_HPP