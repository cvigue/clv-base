// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_NETCORE_STUN_UTILS_HPP
#define CLV_NETCORE_STUN_UTILS_HPP

#include <algorithm>
#include <array>
#include <asio/ip/address_v4.hpp>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <optional>
#include <random>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <asio.hpp>

#include <result_or.h>
#include "util/byte_packer.h"

namespace clv::netcore {

/// STUN protocol constants from RFC 5389
namespace stun_constants {
constexpr std::uint32_t magic_cookie = 0x2112A442;
constexpr std::size_t header_size = 20;
constexpr std::size_t transaction_id_size = 12;
constexpr std::uint16_t attr_mapped_address = 0x0001;
constexpr std::uint16_t attr_xor_mapped_address = 0x0020;
constexpr std::uint16_t attr_change_request = 0x0003;
constexpr std::uint16_t attr_source_address = 0x0004;
constexpr std::uint16_t attr_changed_address = 0x0005;
constexpr std::uint16_t attr_other_address = 0x802F; // RFC 5780
constexpr std::uint16_t default_port = 3478;

// Change request flags (RFC 3489)
constexpr std::uint32_t change_ip = 0x04;
constexpr std::uint32_t change_port = 0x02;
constexpr std::uint32_t change_ip_and_port = change_ip | change_port;
} // namespace stun_constants

/// Error types for STUN operations
enum class stun_error_code
{
    network_error,
    timeout_error,
    parse_error,
    initialization_error,
    invalid_response,
    no_servers_available
};

/// Custom exception type for STUN errors
class stun_exception : public std::exception
{
  public:
    explicit stun_exception(stun_error_code code, std::string message)
        : code_{code}, message_{std::move(message)}
    {
    }

    [[nodiscard]] const char *what() const noexcept override
    {
        return message_.c_str();
    }
    [[nodiscard]] stun_error_code code() const noexcept
    {
        return code_;
    }

  private:
    stun_error_code code_;
    std::string message_;
};

/// STUN message types from RFC 5389
enum class message_type : std::uint16_t
{
    binding_request = 0x0001,
    binding_response = 0x0101,
    binding_error_response = 0x0111
};

/// NAT type detection results
enum class nat_type
{
    unknown,
    open_internet,        // No NAT
    full_cone,            // Full Cone NAT
    restricted_cone,      // Restricted Cone NAT
    port_restricted_cone, // Port Restricted Cone NAT
    symmetric,            // Symmetric NAT
    blocked               // Blocked NAT
};

[[nodiscard]] constexpr std::string_view to_string(nat_type type) noexcept
{
    switch (type)
    {
    case nat_type::unknown:
        return "Unknown";
    case nat_type::open_internet:
        return "Open Internet";
    case nat_type::full_cone:
        return "Full Cone NAT";
    case nat_type::restricted_cone:
        return "Restricted Cone NAT";
    case nat_type::port_restricted_cone:
        return "Port Restricted Cone NAT";
    case nat_type::symmetric:
        return "Symmetric NAT";
    case nat_type::blocked:
        return "Blocked";
    }
    return "Unknown type";
}

/// Public address discovery result
struct public_address
{
    asio::ip::address_v4 address{};
    std::uint16_t port{};

    [[nodiscard]] bool is_valid() const noexcept
    {
        return !address.is_unspecified() && port != 0;
    }

    [[nodiscard]] std::string to_string() const
    {
        return address.to_string() + ":" + std::to_string(port);
    }
};

/// NAT detection test result
struct nat_test_result
{
    bool test1_success = false; // Basic binding request
    bool test2_success = false; // Change IP and port request
    bool test3_success = false; // Change port only request

    public_address test1_addr{}; // Address from basic request
    public_address test2_addr{}; // Address from change request (if successful)
    public_address test3_addr{}; // Address from port change request

    public_address server_other_addr{}; // OTHER-ADDRESS from server (RFC 5780)
    bool addresses_differ = false;      // Whether test1 and test3 addresses differ

    bool hairpin_test_attempted = false; // Whether hairpin detection was attempted
    bool hairpin_supported = false;      // Whether NAT supports hairpinning (UPnP IGD or similar)
};

/// Transaction ID type for type safety
using transaction_id = std::array<std::uint8_t, stun_constants::transaction_id_size>;

/// STUN packet type for type safety
using stun_packet = std::vector<std::uint8_t>;

/// Utility functions for STUN protocol
namespace stun_utils {

/// Generate a STUN transaction ID
[[nodiscard]] transaction_id generate_transaction_id();

/// Create a STUN binding request packet
[[nodiscard]] stun_packet create_binding_request(const transaction_id &trans_id);

/// Create a STUN binding request with CHANGE-REQUEST attribute (RFC 3489)
[[nodiscard]] stun_packet create_change_request(const transaction_id &trans_id,
                                                std::uint32_t change_flags);

/// Parse STUN response packet using modern error handling
[[nodiscard]] clv::result_or<public_address, stun_error_code>
parse_binding_response(std::span<const std::uint8_t> packet);

/// Parse STUN response and extract OTHER-ADDRESS attribute if present (RFC 5780)
[[nodiscard]] clv::result_or<std::pair<public_address, std::optional<public_address>>, stun_error_code>
parse_binding_response_with_other_address(std::span<const std::uint8_t> packet);

/// Convert IP address to network byte order array
template <std::ranges::range R>
    requires std::same_as<std::ranges::range_value_t<R>, char>
[[nodiscard]] clv::result_or<asio::ip::address_v4, stun_error_code>
parse_ipv4_address(const R &ip_str)
{
    try
    {
        return asio::ip::make_address_v4(std::string_view{std::ranges::data(ip_str), std::ranges::size(ip_str)});
    }
    catch (const std::exception &)
    {
        return stun_error_code::parse_error;
    }
}

/// Validate STUN packet format
[[nodiscard]] bool is_valid_stun_packet(std::span<const std::uint8_t> packet) noexcept;

/// Extract message type from STUN packet
[[nodiscard]] std::optional<message_type> get_message_type(std::span<const std::uint8_t> packet) noexcept;

/// Analyze NAT test results to determine NAT type (RFC 3489 methodology)
[[nodiscard]] nat_type analyze_nat_type(const nat_test_result &test_results,
                                        const std::optional<asio::ip::address_v4> &local_address = std::nullopt);

} // namespace stun_utils

// Implementation details - typically would be in a separate .cpp file
// but kept inline for header-only convenience

inline transaction_id stun_utils::generate_transaction_id()
{
    transaction_id id{};
    std::random_device rd;
    std::mt19937_64 gen{rd()};
    std::uniform_int_distribution<std::uint16_t> dist{0, 255};

    std::ranges::generate(id, [&]
    { return static_cast<std::uint8_t>(dist(gen)); });
    return id;
}

inline stun_packet stun_utils::create_binding_request(const transaction_id &trans_id)
{
    stun_packet packet(stun_constants::header_size);

    // Message type (Binding Request) - network byte order
    packet[0] = 0x00;
    packet[1] = 0x01;

    // Message length (no attributes for basic request)
    packet[2] = 0x00;
    packet[3] = 0x00;

    // Magic cookie - convert to network byte order manually
    const std::uint32_t cookie = stun_constants::magic_cookie;
    packet[4] = static_cast<std::uint8_t>((cookie >> 24) & 0xFF);
    packet[5] = static_cast<std::uint8_t>((cookie >> 16) & 0xFF);
    packet[6] = static_cast<std::uint8_t>((cookie >> 8) & 0xFF);
    packet[7] = static_cast<std::uint8_t>(cookie & 0xFF);

    // Transaction ID
    std::ranges::copy(trans_id, packet.begin() + 8);

    return packet;
}

inline stun_packet stun_utils::create_change_request(const transaction_id &trans_id,
                                                     std::uint32_t change_flags)
{
    // Header + CHANGE-REQUEST attribute (8 bytes: 4 for attribute header + 4 for value)
    stun_packet packet(stun_constants::header_size + 8);

    // Message type (Binding Request) - network byte order
    packet[0] = 0x00;
    packet[1] = 0x01;

    // Message length (8 bytes for CHANGE-REQUEST attribute)
    packet[2] = 0x00;
    packet[3] = 0x08;

    // Magic cookie - convert to network byte order manually
    const std::uint32_t cookie = stun_constants::magic_cookie;
    packet[4] = static_cast<std::uint8_t>((cookie >> 24) & 0xFF);
    packet[5] = static_cast<std::uint8_t>((cookie >> 16) & 0xFF);
    packet[6] = static_cast<std::uint8_t>((cookie >> 8) & 0xFF);
    packet[7] = static_cast<std::uint8_t>(cookie & 0xFF);

    // Transaction ID
    std::ranges::copy(trans_id, packet.begin() + 8);

    // CHANGE-REQUEST attribute
    // Attribute type
    packet[20] = static_cast<std::uint8_t>((stun_constants::attr_change_request >> 8) & 0xFF);
    packet[21] = static_cast<std::uint8_t>(stun_constants::attr_change_request & 0xFF);

    // Attribute length (4 bytes)
    packet[22] = 0x00;
    packet[23] = 0x04;

    // Change flags value
    packet[24] = static_cast<std::uint8_t>((change_flags >> 24) & 0xFF);
    packet[25] = static_cast<std::uint8_t>((change_flags >> 16) & 0xFF);
    packet[26] = static_cast<std::uint8_t>((change_flags >> 8) & 0xFF);
    packet[27] = static_cast<std::uint8_t>(change_flags & 0xFF);

    return packet;
}

inline clv::result_or<public_address, stun_error_code>
stun_utils::parse_binding_response(std::span<const std::uint8_t> packet)
{
    if (packet.size() < stun_constants::header_size)
    {
        return stun_error_code::parse_error;
    }

    // Verify it's a binding response
    if (packet[0] != 0x01 || packet[1] != 0x01)
    {
        return stun_error_code::invalid_response;
    }

    // Verify magic cookie
    const std::uint32_t cookie = bytes_to_uint(packet[4], packet[5], packet[6], packet[7]);

    if (cookie != stun_constants::magic_cookie)
    {
        return stun_error_code::parse_error;
    }

    const std::uint16_t message_length = bytes_to_uint(packet[2], packet[3]);

    std::size_t offset = stun_constants::header_size;

    // Parse attributes
    while (offset + 4 <= packet.size() && offset < stun_constants::header_size + message_length)
    {

        const std::uint16_t attr_type = bytes_to_uint(packet[offset], packet[offset + 1]);
        const std::uint16_t attr_length = bytes_to_uint(packet[offset + 2], packet[offset + 3]);

        offset += 4;

        if (offset + attr_length > packet.size())
        {
            break;
        }

        if (attr_type == stun_constants::attr_mapped_address || attr_type == stun_constants::attr_xor_mapped_address)
        {

            if (attr_length >= 8)
            {
                // Skip reserved byte and address family
                std::uint16_t port = bytes_to_uint(packet[offset + 2], packet[offset + 3]);
                std::uint32_t ip = bytes_to_uint(packet[offset + 4], packet[offset + 5], packet[offset + 6], packet[offset + 7]);

                // XOR with magic cookie if it's XOR-MAPPED-ADDRESS
                if (attr_type == stun_constants::attr_xor_mapped_address)
                {
                    port ^= static_cast<std::uint16_t>(stun_constants::magic_cookie >> 16);
                    ip ^= stun_constants::magic_cookie;
                }

                // Convert to host byte order and create address
                // IP is already in network (big-endian) byte order, so use it directly
                return public_address{
                    .address = asio::ip::address_v4{ip},
                    .port = port};
            }
        }

        // Move to next attribute (padding to 4-byte boundary)
        offset += attr_length;
        offset = (offset + 3) & ~3; // Round up to next 4-byte boundary
    }

    return stun_error_code::parse_error;
}

inline clv::result_or<std::pair<public_address, std::optional<public_address>>, stun_error_code>
stun_utils::parse_binding_response_with_other_address(std::span<const std::uint8_t> packet)
{
    if (packet.size() < stun_constants::header_size)
    {
        return stun_error_code::parse_error;
    }

    // Verify it's a binding response
    if (packet[0] != 0x01 || packet[1] != 0x01)
    {
        return stun_error_code::invalid_response;
    }

    // Verify magic cookie
    const std::uint32_t cookie = (static_cast<std::uint32_t>(packet[4]) << 24) | (static_cast<std::uint32_t>(packet[5]) << 16) | (static_cast<std::uint32_t>(packet[6]) << 8) | static_cast<std::uint32_t>(packet[7]);

    if (cookie != stun_constants::magic_cookie)
    {
        return stun_error_code::parse_error;
    }

    const std::uint16_t message_length = static_cast<std::uint16_t>((static_cast<std::uint16_t>(packet[2]) << 8) | static_cast<std::uint16_t>(packet[3]));
    std::size_t offset = stun_constants::header_size;

    std::optional<public_address> mapped_addr;
    std::optional<public_address> other_addr;

    // Parse attributes
    while (offset + 4 <= packet.size() && offset < stun_constants::header_size + message_length)
    {
        const std::uint16_t attr_type = bytes_to_uint(packet[offset], packet[offset + 1]);
        const std::uint16_t attr_length = bytes_to_uint(packet[offset + 2], packet[offset + 3]);

        offset += 4;

        if (offset + attr_length > packet.size())
        {
            break;
        }

        // Parse MAPPED-ADDRESS or XOR-MAPPED-ADDRESS
        if (attr_type == stun_constants::attr_mapped_address || attr_type == stun_constants::attr_xor_mapped_address)
        {
            if (attr_length >= 8)
            {
                std::uint16_t port = bytes_to_uint(packet[offset + 2], packet[offset + 3]);
                std::uint32_t ip = bytes_to_uint(packet[offset + 4], packet[offset + 5], packet[offset + 6], packet[offset + 7]);

                // XOR with magic cookie if it's XOR-MAPPED-ADDRESS
                if (attr_type == stun_constants::attr_xor_mapped_address)
                {
                    port ^= static_cast<std::uint16_t>(stun_constants::magic_cookie >> 16);
                    ip ^= stun_constants::magic_cookie;
                }

                mapped_addr = public_address{
                    .address = asio::ip::address_v4{ip},
                    .port = port};
            }
        }
        // Parse OTHER-ADDRESS attribute (RFC 5780)
        else if (attr_type == stun_constants::attr_other_address || attr_type == stun_constants::attr_changed_address)
        {
            if (attr_length >= 8)
            {
                std::uint16_t port = bytes_to_uint(packet[offset + 2], packet[offset + 3]);
                std::uint32_t ip = bytes_to_uint(packet[offset + 4], packet[offset + 5], packet[offset + 6], packet[offset + 7]);

                other_addr = public_address{
                    .address = asio::ip::address_v4{ip},
                    .port = port};
            }
        }

        // Move to next attribute (padding to 4-byte boundary)
        offset += attr_length;
        offset = (offset + 3) & ~3; // Round up to next 4-byte boundary
    }

    if (mapped_addr.has_value())
    {
        return std::make_pair(*mapped_addr, other_addr);
    }

    return stun_error_code::parse_error;
}

inline bool stun_utils::is_valid_stun_packet(std::span<const std::uint8_t> packet) noexcept
{
    if (packet.size() < stun_constants::header_size)
    {
        return false;
    }

    // Check magic cookie
    const std::uint32_t cookie = (static_cast<std::uint32_t>(packet[4]) << 24) | (static_cast<std::uint32_t>(packet[5]) << 16) | (static_cast<std::uint32_t>(packet[6]) << 8) | static_cast<std::uint32_t>(packet[7]);

    return cookie == stun_constants::magic_cookie;
}

inline std::optional<message_type> stun_utils::get_message_type(std::span<const std::uint8_t> packet) noexcept
{
    if (packet.size() < 2)
    {
        return std::nullopt;
    }

    const std::uint16_t type = bytes_to_uint(packet[0], packet[1]);

    switch (type)
    {
    case 0x0001:
        return message_type::binding_request;
    case 0x0101:
        return message_type::binding_response;
    case 0x0111:
        return message_type::binding_error_response;
    default:
        return std::nullopt;
    }
}

inline nat_type stun_utils::analyze_nat_type(const nat_test_result &test_results,
                                             const std::optional<asio::ip::address_v4> &local_address)
{
    // Basic analysis based on RFC 3489 methodology

    if (!test_results.test1_success)
    {
        return nat_type::blocked;
    }

    // If we can't do comprehensive tests, make basic determination
    if (!test_results.server_other_addr.is_valid())
    {
        // Check if the public address matches our local address (if provided)
        if (local_address.has_value() && test_results.test1_addr.address == *local_address)
        {
            return nat_type::open_internet;
        }

        return nat_type::full_cone; // Default assumption if we can't test further
    }

    // RFC 3489 NAT detection algorithm
    if (test_results.test2_success)
    {
        // If change IP and port succeeded, we're on open internet
        return nat_type::open_internet;
    }

    if (test_results.test3_success)
    {
        // Change port succeeded but change IP+port failed
        if (test_results.addresses_differ)
        {
            return nat_type::symmetric;
        }
        else
        {
            return nat_type::restricted_cone;
        }
    }
    else
    {
        // Both change IP+port and change port failed
        if (test_results.addresses_differ)
        {
            return nat_type::symmetric;
        }
        else
        {
            // Classic RFC 3489: if both change requests fail, it's typically full cone NAT
            // Port restricted cone would allow the basic request but block change requests
            // However, the distinction requires more sophisticated testing
            return nat_type::full_cone;
        }
    }
}

} // namespace clv::netcore

#endif // CLV_NETCORE_STUN_UTILS_HPP
