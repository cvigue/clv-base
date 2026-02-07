// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_NFTABLES_CLIENT_H
#define CLV_VPN_NFTABLES_CLIENT_H

#include "netlink_helper.h"

#include <cstdint>

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
 *   nft.EnsureMasquerade("10.8.0.0", 24);  // creates table + chain + rule
 *   // ... later ...
 *   nft.RemoveMasquerade();                 // deletes the whole table
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
     * Creates (or re-creates) an nftables table @c clv_vpn_nat containing
     * a @c postrouting chain with a rule that masquerades traffic from
     * @p source_network / @p prefix_len whose destination is NOT the same
     * subnet.
     *
     * @param source_network Network address in host byte order (e.g., 0x0A080000 for 10.8.0.0)
     * @param prefix_len     CIDR prefix length (e.g., 24)
     * @return true if the batch transaction succeeded
     */
    bool EnsureMasquerade(std::uint32_t source_network, std::uint8_t prefix_len);

    /**
     * @brief Remove the @c clv_vpn_nat table (and all its chains/rules).
     * @return true if the delete transaction succeeded
     */
    bool RemoveMasquerade();

    /**
     * @brief Check if the @c clv_vpn_nat table currently exists.
     * @return true if the table exists in the kernel
     */
    bool TableExists();

    /**
     * @brief Ensure an IPv6 MASQUERADE rule exists for the given source subnet.
     *
     * Creates (or re-creates) an nftables table @c clv_vpn_nat6 containing
     * a @c postrouting chain with a rule that masquerades IPv6 traffic from
     * @p source_network / @p prefix_len whose destination is NOT the same subnet.
     *
     * @param source_network 16-byte network address in network byte order
     * @param prefix_len     CIDR prefix length (e.g., 112)
     * @return true if the batch transaction succeeded
     */
    bool EnsureIpv6Masquerade(const std::uint8_t *source_network, std::uint8_t prefix_len);

    /**
     * @brief Remove the @c clv_vpn_nat6 table (and all its chains/rules).
     * @return true if the delete transaction succeeded
     */
    bool RemoveIpv6Masquerade();

    /**
     * @brief Check if the @c clv_vpn_nat6 table currently exists.
     * @return true if the table exists in the kernel
     */
    bool Ipv6TableExists();

  private:
    /// Managed table names — dedicated to this VPN so we never touch user rules
    static constexpr const char *TABLE_NAME = "clv_vpn_nat";
    static constexpr const char *TABLE_NAME_V6 = "clv_vpn_nat6";
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
