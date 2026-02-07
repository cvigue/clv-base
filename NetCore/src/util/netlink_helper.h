// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_NETLINK_HELPER_H
#define CLV_VPN_NETLINK_HELPER_H

#include <cstddef>
#include <linux/netlink.h>
#include <unique_fd.h>

#include <cstdint>
#include <string>
#include <vector>

namespace clv::vpn {

/**
 * @brief Generic Netlink helper for ovpn-dco communication
 *
 * Provides low-level netlink socket operations for communicating
 * with the ovpn-dco-v2 kernel module.
 */
class NetlinkHelper
{
  public:
    NetlinkHelper();
    ~NetlinkHelper() = default;

    // Non-copyable, movable (defaulted — UniqueFd handles the socket)
    NetlinkHelper(const NetlinkHelper &) = delete;
    NetlinkHelper &operator=(const NetlinkHelper &) = delete;
    NetlinkHelper(NetlinkHelper &&) noexcept = default;
    NetlinkHelper &operator=(NetlinkHelper &&) noexcept = default;

    /**
     * @brief Open netlink socket
     * @param protocol Netlink protocol (default: NETLINK_GENERIC for ovpn-dco;
     *                 use NETLINK_NETFILTER for nftables)
     * @throws std::system_error on socket/bind failure
     */
    void Open(int protocol = NETLINK_GENERIC);

    /**
     * @brief Close netlink socket
     */
    void Close();

    /**
     * @brief Check if socket is open
     */
    bool IsOpen() const
    {
        return static_cast<bool>(fd_);
    }

    /**
     * @brief Get the raw file descriptor (for callers needing direct socket access)
     * @return fd, or -1 if not open
     */
    int RawFd() const
    {
        return fd_.get();
    }

    /**
     * @brief Resolve generic netlink family ID
     * @param family_name Family name (e.g., "ovpn-dco-v2")
     * @return Family ID, or 0 if not found
     */
    uint16_t ResolveFamilyId(const std::string &family_name);

    /**
     * @brief Resolve a multicast group ID from a generic netlink family
     *
     * Sends CTRL_CMD_GETFAMILY and parses CTRL_ATTR_MCAST_GROUPS to find
     * the group matching @p group_name.
     *
     * @param family_name Family name (e.g., "ovpn-dco-v2")
     * @param group_name  Multicast group name (e.g., "peers")
     * @return Multicast group ID, or 0 if not found
     */
    uint32_t ResolveMulticastGroupId(const std::string &family_name,
                                     const std::string &group_name);

    /**
     * @brief Subscribe to a netlink multicast group
     *
     * Calls setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, ...) on the
     * underlying socket.
     *
     * @param group_id Multicast group ID (from ResolveMulticastGroupId)
     * @return true if subscription succeeded
     */
    bool JoinMulticastGroup(uint32_t group_id);

    /**
     * @brief Send netlink message and receive response
     * @param msg Message buffer
     * @return Response buffer, or empty on error
     */
    std::vector<uint8_t> SendAndReceive(const std::vector<uint8_t> &msg);

    /**
     * @brief Send netlink message and receive response (raw pointer version)
     * @param nlh Netlink message header
     * @param len Message length
     * @param response Output vector for response
     * @return true if successful
     */
    bool SendAndReceive(struct nlmsghdr *nlh, size_t len, std::vector<uint8_t> &response);

    /**
     * @brief Add netlink attribute to message
     * @param nlh Netlink message header
     * @param maxlen Maximum buffer size
     * @param offset Current offset in buffer (updated)
     * @param type Attribute type
     * @param data Attribute data
     * @param len Data length
     */
    static void AddAttr(struct nlmsghdr *nlh, size_t maxlen, size_t &offset,
                        uint16_t type, const void *data, size_t len);

    /**
     * @brief Create and bind an rtnetlink (NETLINK_ROUTE) socket.
     * @return RAII file descriptor for the socket
     * @throws std::system_error on socket/bind failure
     */
    static clv::UniqueFd CreateRtnetlinkSocket();

    /**
     * @brief Send a netlink message to the kernel.
     * @param sock      Socket fd (from CreateRtnetlinkSocket or RawFd)
     * @param msg       Message buffer
     * @param msg_len   Message length
     * @param operation Human-readable label for error messages
     * @throws std::system_error on sendto failure
     */
    static void SendNetlinkMessage(int sock, const void *msg, size_t msg_len,
                                   const char *operation);

    /**
     * @brief Receive and validate a netlink ACK response.
     * @param sock      Socket fd
     * @param operation Human-readable label for error messages
     * @throws std::system_error on recv failure or kernel NLMSG_ERROR
     */
    static void ReceiveNetlinkAck(int sock, const char *operation);

  private:
    /// Standard netlink receive buffer (PAGE_SIZE on most systems)
    static constexpr size_t kNlMsgBufSize = 4096;

    /// Larger buffer for generic netlink responses (matches NLMSG_GOODSIZE on 8K-page systems)
    static constexpr size_t kNlMsgBufSizeLarge = 8192;

    clv::UniqueFd fd_;       ///< Netlink socket file descriptor
    uint32_t seq_ = 0;       ///< Sequence number for messages
    uint16_t family_id_ = 0; ///< ovpn-dco-v2 family ID
};

} // namespace clv::vpn

#endif // CLV_VPN_NETLINK_HELPER_H
