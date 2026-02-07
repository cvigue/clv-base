// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "netlink_helper.h"
#include "nla_helpers.h"
#include "unique_fd.h"

#include <array>
#include <cerrno>
#include <cstdint>
#include <string>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/rtnetlink.h>
#include <sys/types.h>
#include <cstring>
#include <stdexcept>
#include <system_error>
#include <unistd.h>
#include <utility>
#include <vector>

namespace clv::vpn {

NetlinkHelper::NetlinkHelper() = default;

void NetlinkHelper::Open(int protocol)
{
    if (IsOpen())
    {
        return; // Already open
    }

    // Local UniqueFd to ensure cleanup if bind fails. Only assign to member fd_ on success.
    clv::UniqueFd sock(::socket(AF_NETLINK, SOCK_RAW, protocol));

    // Bind to automatic port assignment
    struct sockaddr_nl addr{};
    addr.nl_family = AF_NETLINK;
    addr.nl_pad = 0;
    addr.nl_pid = 0; // Kernel assigns PID
    addr.nl_groups = 0;

    if (::bind(sock.get(), reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0)
    {
        throw std::system_error(errno, std::system_category(), "Failed to bind netlink socket");
    }

    fd_ = std::move(sock);
}

void NetlinkHelper::Close()
{
    fd_.reset();
}

uint16_t NetlinkHelper::ResolveFamilyId(const std::string &family_name)
{
    if (!IsOpen())
        return 0;

    // Build CTRL_CMD_GETFAMILY request
    struct
    {
        struct nlmsghdr nlh;
        struct genlmsghdr genlh;
        struct nlattr attr;
        char family[32];
    } req{};

    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr) + sizeof(struct nlattr) + 32);
    req.nlh.nlmsg_type = GENL_ID_CTRL;
    req.nlh.nlmsg_flags = NLM_F_REQUEST;
    req.nlh.nlmsg_seq = ++seq_;
    req.nlh.nlmsg_pid = 0;

    req.genlh.cmd = CTRL_CMD_GETFAMILY;
    req.genlh.version = 1;

    req.attr.nla_len = static_cast<decltype(req.attr.nla_len)>(sizeof(struct nlattr) + family_name.length() + 1);
    req.attr.nla_type = CTRL_ATTR_FAMILY_NAME;
    std::strncpy(req.family, family_name.c_str(), sizeof(req.family) - 1);

    // Send request
    if (send(fd_.get(), &req, req.nlh.nlmsg_len, 0) < 0)
    {
        return 0;
    }

    // Receive response
    std::array<char, kNlMsgBufSize> buffer;
    ssize_t len = recv(fd_.get(), buffer.data(), buffer.size(), 0);
    if (len < 0)
    {
        return 0;
    }

    // Parse response
    struct nlmsghdr *nlh = reinterpret_cast<struct nlmsghdr *>(buffer.data());
    if (!NLMSG_OK(nlh, static_cast<size_t>(len)))
    {
        return 0;
    }

    if (nlh->nlmsg_type == NLMSG_ERROR)
    {
        return 0;
    }

    // Extract family ID from attributes
    struct genlmsghdr *genlh = static_cast<struct genlmsghdr *>(NLMSG_DATA(nlh));
    struct nlattr *attr = reinterpret_cast<struct nlattr *>(reinterpret_cast<char *>(genlh) + GENL_HDRLEN);
    int attrlen = nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);

    while (NLA_OK(attr, attrlen))
    {
        if (attr->nla_type == CTRL_ATTR_FAMILY_ID)
        {
            family_id_ = *reinterpret_cast<uint16_t *>(NLA_DATA(attr));
            return family_id_;
        }
        attr = NLA_NEXT(attr, attrlen);
    }

    return 0;
}

uint32_t NetlinkHelper::ResolveMulticastGroupId(const std::string &family_name,
                                                const std::string &group_name)
{
    if (!IsOpen())
        return 0;

    // Build CTRL_CMD_GETFAMILY request
    struct
    {
        struct nlmsghdr nlh;
        struct genlmsghdr genlh;
        struct nlattr attr;
        char family[32];
    } req{};

    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr) + sizeof(struct nlattr) + 32);
    req.nlh.nlmsg_type = GENL_ID_CTRL;
    req.nlh.nlmsg_flags = NLM_F_REQUEST;
    req.nlh.nlmsg_seq = ++seq_;
    req.nlh.nlmsg_pid = 0;

    req.genlh.cmd = CTRL_CMD_GETFAMILY;
    req.genlh.version = 1;

    req.attr.nla_len = static_cast<decltype(req.attr.nla_len)>(sizeof(struct nlattr) + family_name.length() + 1);
    req.attr.nla_type = CTRL_ATTR_FAMILY_NAME;
    std::strncpy(req.family, family_name.c_str(), sizeof(req.family) - 1);

    if (send(fd_.get(), &req, req.nlh.nlmsg_len, 0) < 0)
        return 0;

    std::array<char, kNlMsgBufSizeLarge> buffer;
    ssize_t len = recv(fd_.get(), buffer.data(), buffer.size(), 0);
    if (len < 0)
        return 0;

    struct nlmsghdr *nlh = reinterpret_cast<struct nlmsghdr *>(buffer.data());
    if (!NLMSG_OK(nlh, static_cast<size_t>(len)) || nlh->nlmsg_type == NLMSG_ERROR)
        return 0;

    // Walk top-level attrs looking for CTRL_ATTR_MCAST_GROUPS
    struct genlmsghdr *genlh = static_cast<struct genlmsghdr *>(NLMSG_DATA(nlh));
    struct nlattr *attr = reinterpret_cast<struct nlattr *>(
        reinterpret_cast<char *>(genlh) + GENL_HDRLEN);
    int attrlen = nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);

    while (NLA_OK(attr, attrlen))
    {
        if (attr->nla_type == CTRL_ATTR_MCAST_GROUPS)
        {
            // Iterate nested group entries
            struct nlattr *grp = reinterpret_cast<struct nlattr *>(NLA_DATA(attr));
            int grplen = attr->nla_len - NLA_HDRLEN;

            while (NLA_OK(grp, grplen))
            {
                // Each group is itself nested: CTRL_ATTR_MCAST_GRP_NAME + GRP_ID
                struct nlattr *entry = reinterpret_cast<struct nlattr *>(NLA_DATA(grp));
                int entrylen = grp->nla_len - NLA_HDRLEN;

                const char *found_name = nullptr;
                uint32_t found_id = 0;

                while (NLA_OK(entry, entrylen))
                {
                    if (entry->nla_type == CTRL_ATTR_MCAST_GRP_NAME)
                        found_name = static_cast<const char *>(NLA_DATA(entry));
                    else if (entry->nla_type == CTRL_ATTR_MCAST_GRP_ID)
                        found_id = *reinterpret_cast<uint32_t *>(NLA_DATA(entry));

                    entry = NLA_NEXT(entry, entrylen);
                }

                if (found_name && group_name == found_name)
                    return found_id;

                grp = NLA_NEXT(grp, grplen);
            }
        }
        attr = NLA_NEXT(attr, attrlen);
    }

    return 0;
}

bool NetlinkHelper::JoinMulticastGroup(uint32_t group_id)
{
    if (!IsOpen() || group_id == 0)
        return false;

    int grp = static_cast<int>(group_id);
    return ::setsockopt(fd_.get(), SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &grp, sizeof(grp)) == 0;
}

std::vector<uint8_t> NetlinkHelper::SendAndReceive(const std::vector<uint8_t> &msg)
{
    if (!IsOpen() || msg.empty())
    {
        return {};
    }

    // Send message
    if (send(fd_.get(), msg.data(), msg.size(), 0) < 0)
    {
        return {};
    }

    // Receive response
    std::vector<uint8_t> buffer(kNlMsgBufSizeLarge);
    ssize_t len = recv(fd_.get(), buffer.data(), buffer.size(), 0);
    if (len < 0)
    {
        return {};
    }

    buffer.resize(len);
    return buffer;
}

bool NetlinkHelper::SendAndReceive(struct nlmsghdr *nlh, size_t len, std::vector<uint8_t> &response)
{
    if (!IsOpen())
    {
        return false;
    }

    // Send message
    if (send(fd_.get(), nlh, len, 0) < 0)
    {
        return false;
    }

    // Receive response
    response.resize(kNlMsgBufSizeLarge);
    ssize_t recv_len = recv(fd_.get(), response.data(), response.size(), 0);
    if (recv_len < 0)
    {
        response.clear();
        return false;
    }

    response.resize(recv_len);
    return true;
}

void NetlinkHelper::AddAttr(struct nlmsghdr *nlh, size_t maxlen, size_t &offset,
                            uint16_t type, const void *data, size_t len)
{
    struct nlattr *attr = (struct nlattr *)(((char *)nlh) + offset);

    if (offset + NLA_HDRLEN + len > maxlen)
    {
        throw std::runtime_error("NetlinkHelper::AddAttr: Buffer overflow");
    }

    attr->nla_type = type;
    attr->nla_len = static_cast<decltype(attr->nla_len)>(NLA_HDRLEN + len);

    if (data && len > 0)
    {
        std::memcpy(NLA_DATA(attr), data, len);
    }

    offset += NLA_ALIGN(attr->nla_len);
}

clv::UniqueFd NetlinkHelper::CreateRtnetlinkSocket()
{
    clv::UniqueFd sock(::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE));

    struct sockaddr_nl local{};
    local.nl_family = AF_NETLINK;

    if (bind(sock.get(), reinterpret_cast<struct sockaddr *>(&local), sizeof(local)) < 0)
    {
        throw std::system_error(errno, std::system_category(), "NetlinkHelper: Failed to bind rtnetlink socket");
    }

    return sock;
}

void NetlinkHelper::SendNetlinkMessage(int sock, const void *msg, size_t msg_len,
                                       const char *operation)
{
    struct sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;

    if (sendto(sock, msg, msg_len, 0, reinterpret_cast<struct sockaddr *>(&kernel), sizeof(kernel)) < 0)
    {
        throw std::system_error(errno, std::system_category(), std::string("NetlinkHelper: Failed to send ") + operation);
    }
}

void NetlinkHelper::ReceiveNetlinkAck(int sock, const char *operation)
{
    std::array<char, 4096> recv_buf;
    ssize_t len = recv(sock, recv_buf.data(), recv_buf.size(), 0);

    if (len < 0)
    {
        throw std::system_error(errno, std::system_category(), std::string("NetlinkHelper: Failed to receive ") + operation + " response");
    }

    auto *nlh = reinterpret_cast<struct nlmsghdr *>(recv_buf.data());
    if (nlh->nlmsg_type == NLMSG_ERROR)
    {
        auto *err = reinterpret_cast<struct nlmsgerr *>(NLMSG_DATA(nlh));
        if (err->error != 0)
        {
            throw std::system_error(-err->error, std::system_category(), std::string("NetlinkHelper: ") + operation + " failed");
        }
    }
}

} // namespace clv::vpn
