// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_IPV4_UTILS_H
#define CLV_VPN_IPV4_UTILS_H

#include <bit>
#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <asio/ip/address_v4.hpp>

namespace clv::vpn::ipv4 {

/**
 * @brief Parse a dotted-decimal IPv4 address string into a host-byte-order uint32.
 *
 * Delegates to asio::ip::make_address_v4 which uses inet_pton internally.
 *
 * @param ip_str IPv4 string (e.g., "10.8.0.1")
 * @return Host-byte-order address, or nullopt if invalid
 */
inline std::optional<std::uint32_t> ParseIpv4(std::string_view ip_str)
{
    asio::error_code ec;
    auto v4 = asio::ip::make_address_v4(ip_str, ec);
    if (ec)
        return std::nullopt;
    return v4.to_uint();
}

/**
 * @brief Parse CIDR notation into network address and prefix length
 * @param cidr CIDR string (e.g., "10.8.0.0/24")
 * @return (network_addr, prefix_length) in host byte order, or nullopt if invalid
 */
inline std::optional<std::pair<std::uint32_t, std::uint8_t>> ParseCidr(const std::string &cidr)
{
    auto slash_pos = cidr.find('/');
    if (slash_pos == std::string::npos)
        return std::nullopt;

    auto addr = ParseIpv4(std::string_view(cidr).substr(0, slash_pos));
    if (!addr)
        return std::nullopt;

    // Parse prefix length
    std::string_view prefix_str(cidr);
    prefix_str.remove_prefix(slash_pos + 1);
    int prefix = 0;
    auto [ptr, ec] = std::from_chars(prefix_str.data(), prefix_str.data() + prefix_str.size(), prefix);
    if (ec != std::errc{} || ptr != prefix_str.data() + prefix_str.size())
        return std::nullopt;
    if (prefix < 0 || prefix > 32)
        return std::nullopt;

    return std::make_pair(*addr, static_cast<std::uint8_t>(prefix));
}

/**
 * @brief Create network mask from prefix length
 * @param prefix_length Prefix length (0-32)
 * @return Network mask in host byte order
 */
inline std::uint32_t CreateMask(std::uint8_t prefix_length)
{
    if (prefix_length == 0)
        return 0;
    if (prefix_length >= 32)
        return 0xFFFFFFFF;
    return (0xFFFFFFFF << (32 - prefix_length));
}

/**
 * @brief Convert a contiguous network mask (host byte order) to prefix length.
 *
 * Uses std::popcount for a single-instruction conversion on modern CPUs.
 * E.g. 0xFFFFFF00 → 24, 0xFFFF0000 → 16.
 *
 * @param mask Network mask in host byte order (must be contiguous)
 * @return Prefix length (0-32)
 */
inline std::uint8_t MaskToPrefix(std::uint32_t mask)
{
    return static_cast<std::uint8_t>(std::popcount(mask));
}

/**
 * @brief Check if an IP matches a network/prefix
 * @param ip IP address to check (host byte order)
 * @param network Network address (host byte order)
 * @param prefix_length Prefix length (0-32)
 * @return true if IP is within the network
 */
inline bool IpMatchesNetwork(std::uint32_t ip, std::uint32_t network, std::uint8_t prefix_length)
{
    std::uint32_t mask = CreateMask(prefix_length);
    return (ip & mask) == (network & mask);
}

/**
 * @brief Normalize network address by masking off host bits
 * @param network Network address (host byte order)
 * @param prefix_length Prefix length (0-32)
 * @return Normalized network address with host bits zeroed
 */
inline std::uint32_t NormalizeNetwork(std::uint32_t network, std::uint8_t prefix_length)
{
    return network & CreateMask(prefix_length);
}

/**
 * @brief Convert IPv4 address to dotted-decimal string.
 *
 * Delegates to asio::ip::address_v4::to_string().
 *
 * @param ipv4 IPv4 address in host byte order
 * @return String representation (e.g., "10.8.0.2")
 */
inline std::string Ipv4ToString(std::uint32_t ipv4)
{
    return asio::ip::address_v4(ipv4).to_string();
}

/**
 * @brief Calculate number of usable host addresses in a network
 * @param prefix_length Prefix length (0-32)
 * @return Number of usable host IPs (excludes network and broadcast)
 */
inline std::uint32_t CalculateUsableHosts(std::uint8_t prefix_length)
{
    if (prefix_length >= 31)
        return 0; // /31 and /32 have no usable hosts
    std::uint32_t host_bits = 32 - prefix_length;
    return (1u << host_bits) - 2; // Exclude network and broadcast
}

} // namespace clv::vpn::ipv4

#endif // CLV_VPN_IPV4_UTILS_H
