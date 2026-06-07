// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_NFTABLES_CLIENT_H
#define CLV_VPN_NFTABLES_CLIENT_H

#include "netlink_helper.h"

#include <cstdint>
#include <vector>

namespace clv::vpn {

/**
 * @brief Netlink-based nftables client for adding/removing NAT rules.
 *
 * Communicates directly with the kernel's nf_tables subsystem via
 * @c NETLINK_NETFILTER — no shelling out to @c iptables / @c nft.
 *
 * Typical usage (MASQUERADE for a VPN subnet):
 * @code
 *   NfTablesClient nft;
 *   nft.Open();
 *   nft.EnsureMasquerade(NfTablesClient::kIPv4, addr, 24); // creates table + chain + rule
 *   // ... later ...
 *   nft.RemoveMasquerade(NfTablesClient::kIPv4);           // deletes the whole table
 * @endcode
 *
 * The client manages a dedicated nftables table (@c clv_vpn_nat) so it
 * never collides with user-managed rulesets.
 *
 * @note Requires @c CAP_NET_ADMIN.
 *
 * @par Threading
 * Not thread-safe. Intended for single-threaded VPN lifecycle use.
 *
 * @par Testing
 * Requires root and a kernel with nf_tables support. Exercised through
 * integration tests that run the full VPN server lifecycle.
 */
class NfTablesClient
{
  public:
    /** Address-family constants (avoids pulling linux/netfilter.h into callers) */
    static constexpr std::uint8_t kIPv4 = 2;  // NFPROTO_IPV4
    static constexpr std::uint8_t kIPv6 = 10; // NFPROTO_IPV6

    NfTablesClient() = default;
    ~NfTablesClient();

    // Non-copyable, movable
    NfTablesClient(const NfTablesClient &) = delete;
    NfTablesClient &operator=(const NfTablesClient &) = delete;
    NfTablesClient(NfTablesClient &&) noexcept = default;
    NfTablesClient &operator=(NfTablesClient &&) noexcept = default;

    /**
     * @brief Open the netlink socket.
     * @throws std::system_error on failure
     */
    void Open();

    /**
     * @brief Ensure a MASQUERADE rule exists for the given source subnet.
     *
     * Creates (or re-creates) a dedicated nftables table containing a
     * @c postrouting chain with a rule that masquerades traffic from
     * @p source_network / @p prefix_len whose destination is NOT the
     * same subnet.
     *
     * @param family         kIPv4 or kIPv6
     * @param source_network Network address in network byte order
     *                       (4 bytes for IPv4, 16 bytes for IPv6)
     * @param prefix_len     CIDR prefix length
     * @return true if the batch transaction succeeded
     */
    bool EnsureMasquerade(std::uint8_t family, const std::uint8_t *source_network,
                          std::uint8_t prefix_len);

    /**
     * @brief Remove the masquerade table (and all its chains/rules) for the given family.
     * @param family  kIPv4 or kIPv6
     * @return true if the delete transaction succeeded
     */
    bool RemoveMasquerade(std::uint8_t family);

    /**
     * @brief Check if the masquerade table for the given family exists.
     * @param family  kIPv4 or kIPv6
     * @return true if the table exists in the kernel
     */
    bool TableExists(std::uint8_t family);

  private:
    static constexpr const char *CHAIN_NAME = "postrouting";

    /**
     * @brief Send an nftables batch message (begin + payload messages + end).
     * @param batch  Pre-built batch buffer (including BATCH_BEGIN and BATCH_END framing)
     * @return true if the kernel responded without error
     */
    bool SendBatch(const std::vector<std::uint8_t> &batch);

    NetlinkHelper nlh_; ///< Underlying netlink socket
};

} // namespace clv::vpn

#endif // CLV_VPN_NFTABLES_CLIENT_H
