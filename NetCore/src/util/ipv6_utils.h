// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_IPV6_UTILS_H
#define CLV_VPN_IPV6_UTILS_H

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <asio/ip/address_v6.hpp>

namespace clv::vpn::ipv6 {

/// @brief Canonical 128-bit IPv6 address in network byte order.
using Ipv6Address = std::array<std::uint8_t, 16>;

/**
 * @brief Parse an IPv6 address string into a 16-byte network-order array.
 *
 * Delegates to asio::ip::make_address_v6 which handles full RFC 5952
 * notation including :: abbreviation and mixed IPv4-suffix
 * (e.g. "::ffff:10.8.0.1").
 *
 * @param str IPv6 string (e.g. "fd00::1", "2001:db8::1")
 * @return 16-byte address in network byte order, or nullopt if invalid
 */
inline std::optional<Ipv6Address> ParseIpv6(std::string_view str)
{
    asio::error_code ec;
    auto v6 = asio::ip::make_address_v6(str, ec);
    if (ec)
        return std::nullopt;
    return v6.to_bytes();
}

/**
 * @brief Parse an IPv6 CIDR notation string.
 * @param cidr CIDR string (e.g. "fd00::/112")
 * @return (address, prefix_length) or nullopt if invalid
 */
inline std::optional<std::pair<Ipv6Address, std::uint8_t>> ParseCidr6(const std::string &cidr)
{
    auto slash = cidr.find('/');
    if (slash == std::string::npos)
        return std::nullopt;

    auto addr = ParseIpv6(std::string_view(cidr).substr(0, slash));
    if (!addr)
        return std::nullopt;

    std::string_view prefix_str(cidr);
    prefix_str.remove_prefix(slash + 1);
    int prefix = 0;
    auto [ptr, ec] = std::from_chars(prefix_str.data(), prefix_str.data() + prefix_str.size(), prefix);
    if (ec != std::errc{} || ptr != prefix_str.data() + prefix_str.size())
        return std::nullopt;
    if (prefix < 0 || prefix > 128)
        return std::nullopt;

    return std::make_pair(*addr, static_cast<std::uint8_t>(prefix));
}

/**
 * @brief Check if an IPv6 address matches a prefix.
 * @param addr Address to check (16 bytes, network order)
 * @param network Prefix network address (16 bytes, network order)
 * @param prefix_len Prefix length in bits (0-128)
 * @return true if addr is within the prefix
 */
inline bool Ipv6MatchesPrefix(const Ipv6Address &addr,
                              const Ipv6Address &network,
                              std::uint8_t prefix_len)
{
    if (prefix_len > 128)
        return false;

    std::uint8_t full_bytes = prefix_len / 8;
    std::uint8_t remaining_bits = prefix_len % 8;

    // Compare full bytes
    if (full_bytes > 0)
    {
        if (std::memcmp(addr.data(), network.data(), full_bytes) != 0)
            return false;
    }

    // Compare remaining bits in the boundary byte
    if (remaining_bits > 0)
    {
        std::uint8_t mask = static_cast<std::uint8_t>(0xFF << (8 - remaining_bits));
        if ((addr[full_bytes] & mask) != (network[full_bytes] & mask))
            return false;
    }

    return true;
}

/**
 * @brief Normalize an IPv6 network address by zeroing host bits.
 * @param network Address to normalize
 * @param prefix_len Prefix length (0-128)
 * @return Normalized address with host bits zeroed
 */
inline Ipv6Address NormalizeNetwork(Ipv6Address network, std::uint8_t prefix_len)
{
    if (prefix_len >= 128)
        return network;

    std::uint8_t full_bytes = prefix_len / 8;
    std::uint8_t remaining_bits = prefix_len % 8;

    // Zero the boundary byte's host bits
    if (remaining_bits > 0)
    {
        std::uint8_t mask = static_cast<std::uint8_t>(0xFF << (8 - remaining_bits));
        network[full_bytes] &= mask;
        ++full_bytes;
    }

    // Zero all subsequent bytes
    std::fill(network.begin() + full_bytes, network.end(), std::uint8_t{0});

    return network;
}

/**
 * @brief Convert an IPv6 address to its string representation.
 *
 * Delegates to asio::ip::address_v6::to_string() which produces
 * abbreviated RFC 5952 form (e.g. "fd00::1").
 *
 * @param addr 16-byte address in network byte order
 * @return Abbreviated string (e.g. "fd00::1", "::1")
 */
inline std::string Ipv6ToString(const Ipv6Address &addr)
{
    return asio::ip::address_v6(addr).to_string();
}

} // namespace clv::vpn::ipv6

#endif // CLV_VPN_IPV6_UTILS_H
