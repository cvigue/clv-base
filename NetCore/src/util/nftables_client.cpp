// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "nftables_client.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

// NLA helpers (duplicated from netlink_helper.cpp — identical kernel ABI macros)
#ifndef NLA_ALIGN
#define NLA_ALIGN(len) (((len) + 3) & ~3)
#endif
#ifndef NLA_HDRLEN
#define NLA_HDRLEN NLA_ALIGN(sizeof(struct nlattr))
#endif

namespace clv::vpn {

namespace {

// ---------------------------------------------------------------------------
// Netlink message construction helpers
// ---------------------------------------------------------------------------

/// Append raw bytes to a buffer
void Append(std::vector<std::uint8_t> &buf, const void *data, std::size_t len)
{
    auto *p = static_cast<const std::uint8_t *>(data);
    buf.insert(buf.end(), p, p + len);
}

/// Pad buffer to 4-byte alignment
void PadTo4(std::vector<std::uint8_t> &buf)
{
    while (buf.size() % 4 != 0)
        buf.push_back(0);
}

/// Start an nlmsghdr at the current offset and return its position
std::size_t BeginNlMsg(std::vector<std::uint8_t> &buf, std::uint16_t type,
                       std::uint16_t flags, std::uint32_t seq)
{
    auto pos = buf.size();
    struct nlmsghdr nlh{};
    nlh.nlmsg_len = sizeof(nlh); // patched by EndNlMsg
    nlh.nlmsg_type = type;
    nlh.nlmsg_flags = flags;
    nlh.nlmsg_seq = seq;
    nlh.nlmsg_pid = 0;
    Append(buf, &nlh, sizeof(nlh));
    return pos;
}

/// Finish the nlmsghdr by patching its length
void EndNlMsg(std::vector<std::uint8_t> &buf, std::size_t pos)
{
    auto *nlh = reinterpret_cast<struct nlmsghdr *>(buf.data() + pos);
    nlh->nlmsg_len = static_cast<std::uint32_t>(buf.size() - pos);
}

/// Append an nfgenmsg sub-header
void AppendNfGenMsg(std::vector<std::uint8_t> &buf, std::uint8_t family,
                    std::uint16_t res_id)
{
    struct nfgenmsg nfg{};
    nfg.nfgen_family = family;
    nfg.version = NFNETLINK_V0;
    nfg.res_id = htons(res_id);
    Append(buf, &nfg, sizeof(nfg));
}

/// Append a netlink attribute (NLA) with arbitrary data
void AppendAttr(std::vector<std::uint8_t> &buf, std::uint16_t type,
                const void *data, std::size_t len)
{
    struct nlattr nla{};
    nla.nla_len = static_cast<std::uint16_t>(NLA_HDRLEN + len);
    nla.nla_type = type;
    Append(buf, &nla, sizeof(nla));
    if (data && len > 0)
        Append(buf, data, len);
    PadTo4(buf);
}

/// Append a string attribute (NUL-terminated)
void AppendAttrStr(std::vector<std::uint8_t> &buf, std::uint16_t type,
                   const char *str)
{
    AppendAttr(buf, type, str, std::strlen(str) + 1);
}

/// Append a u32 attribute in host byte order
void AppendAttrU32(std::vector<std::uint8_t> &buf, std::uint16_t type, std::uint32_t val)
{
    val = htonl(val);
    AppendAttr(buf, type, &val, sizeof(val));
}

/// Start a nested attribute, returning its offset for EndNested()
std::size_t BeginNested(std::vector<std::uint8_t> &buf, std::uint16_t type)
{
    auto pos = buf.size();
    struct nlattr nla{};
    nla.nla_len = 0; // patched by EndNested
    nla.nla_type = type | NLA_F_NESTED;
    Append(buf, &nla, sizeof(nla));
    return pos;
}

/// Close a nested attribute by patching its length
void EndNested(std::vector<std::uint8_t> &buf, std::size_t pos)
{
    auto *nla = reinterpret_cast<struct nlattr *>(buf.data() + pos);
    nla->nla_len = static_cast<std::uint16_t>(buf.size() - pos);
    PadTo4(buf);
}

/// Compute the nftables message type from subsystem + message
constexpr std::uint16_t NftMsgType(std::uint16_t msg)
{
    return static_cast<std::uint16_t>((NFNL_SUBSYS_NFTABLES << 8) | msg);
}

/// Build the IPv4 subnet mask from a prefix length (network byte order)
std::uint32_t PrefixToNetmask(std::uint8_t prefix_len)
{
    if (prefix_len == 0)
        return 0;
    return htonl(~((1u << (32 - prefix_len)) - 1));
}

/// Build a 16-byte IPv6 subnet mask from a prefix length
void Ipv6PrefixToNetmask(std::uint8_t prefix_len, std::uint8_t mask[16])
{
    std::memset(mask, 0, 16);
    for (int i = 0; i < 16 && prefix_len > 0; ++i)
    {
        if (prefix_len >= 8)
        {
            mask[i] = 0xFF;
            prefix_len -= 8;
        }
        else
        {
            mask[i] = static_cast<std::uint8_t>(0xFF << (8 - prefix_len));
            prefix_len = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// nftables expression builders
// ---------------------------------------------------------------------------

/// Append a "payload" expression — loads bytes from the packet into a register
///   payload @p base, offset @p off, len @p len → dreg @p dreg
void AppendExprPayload(std::vector<std::uint8_t> &buf,
                       std::uint32_t dreg, std::uint32_t base,
                       std::uint32_t offset, std::uint32_t len)
{
    auto expr_outer = BeginNested(buf, NFTA_LIST_ELEM);
    AppendAttrStr(buf, NFTA_EXPR_NAME, "payload");
    auto data = BeginNested(buf, NFTA_EXPR_DATA);
    AppendAttrU32(buf, NFTA_PAYLOAD_DREG, dreg);
    AppendAttrU32(buf, NFTA_PAYLOAD_BASE, base);
    AppendAttrU32(buf, NFTA_PAYLOAD_OFFSET, offset);
    AppendAttrU32(buf, NFTA_PAYLOAD_LEN, len);
    EndNested(buf, data);
    EndNested(buf, expr_outer);
}

/// Append a "bitwise" expression — dreg = (sreg & mask) ^ xor
///   bitwise sreg → dreg, mask @p mask, xor 0
void AppendExprBitwise(std::vector<std::uint8_t> &buf,
                       std::uint32_t sreg, std::uint32_t dreg,
                       std::uint32_t mask_net, std::uint32_t len)
{
    auto expr_outer = BeginNested(buf, NFTA_LIST_ELEM);
    AppendAttrStr(buf, NFTA_EXPR_NAME, "bitwise");
    auto data = BeginNested(buf, NFTA_EXPR_DATA);
    AppendAttrU32(buf, NFTA_BITWISE_SREG, sreg);
    AppendAttrU32(buf, NFTA_BITWISE_DREG, dreg);
    AppendAttrU32(buf, NFTA_BITWISE_LEN, len);
    // mask: wrapped in NFTA_DATA_VALUE
    {
        auto mask_outer = BeginNested(buf, NFTA_BITWISE_MASK);
        AppendAttr(buf, NFTA_DATA_VALUE, &mask_net, sizeof(mask_net));
        EndNested(buf, mask_outer);
    }
    // xor: all zeros
    {
        std::uint32_t zero = 0;
        auto xor_outer = BeginNested(buf, NFTA_BITWISE_XOR);
        AppendAttr(buf, NFTA_DATA_VALUE, &zero, sizeof(zero));
        EndNested(buf, xor_outer);
    }
    EndNested(buf, data);
    EndNested(buf, expr_outer);
}

/// Append a "bitwise" expression for arbitrary-length mask (e.g., 16-byte IPv6)
///   bitwise sreg → dreg, mask @p mask_bytes, xor zeros
void AppendExprBitwiseBytes(std::vector<std::uint8_t> &buf,
                            std::uint32_t sreg, std::uint32_t dreg,
                            const std::uint8_t *mask_bytes, std::uint32_t len)
{
    auto expr_outer = BeginNested(buf, NFTA_LIST_ELEM);
    AppendAttrStr(buf, NFTA_EXPR_NAME, "bitwise");
    auto data = BeginNested(buf, NFTA_EXPR_DATA);
    AppendAttrU32(buf, NFTA_BITWISE_SREG, sreg);
    AppendAttrU32(buf, NFTA_BITWISE_DREG, dreg);
    AppendAttrU32(buf, NFTA_BITWISE_LEN, len);
    // mask
    {
        auto mask_outer = BeginNested(buf, NFTA_BITWISE_MASK);
        AppendAttr(buf, NFTA_DATA_VALUE, mask_bytes, len);
        EndNested(buf, mask_outer);
    }
    // xor: all zeros
    {
        std::vector<std::uint8_t> zeros(len, 0);
        auto xor_outer = BeginNested(buf, NFTA_BITWISE_XOR);
        AppendAttr(buf, NFTA_DATA_VALUE, zeros.data(), len);
        EndNested(buf, xor_outer);
    }
    EndNested(buf, data);
    EndNested(buf, expr_outer);
}

/// Append a "cmp" expression — compare register against a constant
void AppendExprCmp(std::vector<std::uint8_t> &buf,
                   std::uint32_t sreg, std::uint32_t op,
                   const void *cmp_data, std::size_t cmp_len)
{
    auto expr_outer = BeginNested(buf, NFTA_LIST_ELEM);
    AppendAttrStr(buf, NFTA_EXPR_NAME, "cmp");
    auto data = BeginNested(buf, NFTA_EXPR_DATA);
    AppendAttrU32(buf, NFTA_CMP_SREG, sreg);
    AppendAttrU32(buf, NFTA_CMP_OP, op);
    {
        auto cmp_outer = BeginNested(buf, NFTA_CMP_DATA);
        AppendAttr(buf, NFTA_DATA_VALUE, cmp_data, cmp_len);
        EndNested(buf, cmp_outer);
    }
    EndNested(buf, data);
    EndNested(buf, expr_outer);
}

/// Append a "masq" expression (no attributes needed for basic masquerade)
void AppendExprMasquerade(std::vector<std::uint8_t> &buf)
{
    auto expr_outer = BeginNested(buf, NFTA_LIST_ELEM);
    AppendAttrStr(buf, NFTA_EXPR_NAME, "masq");
    // masq has optional attrs (flags, proto range) but basic MASQUERADE needs none
    EndNested(buf, expr_outer);
}

} // namespace

// ---------------------------------------------------------------------------
// NfTablesClient implementation
// ---------------------------------------------------------------------------

NfTablesClient::~NfTablesClient() = default;

void NfTablesClient::Open()
{
    nlh_.Open(NETLINK_NETFILTER);
}

bool NfTablesClient::SendBatch(const std::vector<std::uint8_t> &batch)
{
    constexpr struct timeval timeout{.tv_sec = 0, .tv_usec = 500000}; // 500ms
    constexpr struct timeval zero{.tv_sec = 0, .tv_usec = 0};

    int fd = nlh_.RawFd();
    if (fd < 0)
        return false;

    // Set a receive timeout so we never block forever.
    // nftables batch transactions may produce zero responses on success
    // (only errors are reported back), so we need a timeout to detect "no error".
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Send the entire batch buffer in one sendmsg
    if (send(fd, batch.data(), batch.size(), 0) < 0)
        return false;

    // Read response — may be NLMSG_ERROR (error or ACK) or may timeout (= success)
    std::vector<std::uint8_t> response(8192);
    ssize_t recv_len = recv(fd, response.data(), response.size(), 0);

    // Remove the timeout so future callers (TableExists) get normal blocking
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &zero, sizeof(zero));

    if (recv_len < 0)
    {
        // EAGAIN/EWOULDBLOCK means the timeout expired with no error → success
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return true;
        return false;
    }

    // Walk all messages in the response - any non-zero error means failure
    response.resize(static_cast<std::size_t>(recv_len));
    auto *nlh = reinterpret_cast<struct nlmsghdr *>(response.data());
    auto remaining = static_cast<std::size_t>(recv_len);

    while (NLMSG_OK(nlh, remaining))
    {
        if (nlh->nlmsg_type == NLMSG_ERROR)
        {
            auto *err = static_cast<struct nlmsgerr *>(NLMSG_DATA(nlh));
            if (err->error != 0)
                return false; // Kernel reported an error
        }
        nlh = NLMSG_NEXT(nlh, remaining);
    }

    return true;
}

bool NfTablesClient::EnsureMasquerade(std::uint32_t source_network, std::uint8_t prefix_len)
{
    // First remove any existing table to make this idempotent
    if (TableExists())
        RemoveMasquerade();

    std::vector<std::uint8_t> buf;
    buf.reserve(2048);
    std::uint32_t seq = 0;

    // ---- BATCH_BEGIN ----
    {
        auto pos = BeginNlMsg(buf, NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, seq++);
        AppendNfGenMsg(buf, AF_UNSPEC, NFNL_SUBSYS_NFTABLES);
        EndNlMsg(buf, pos);
    }

    // ---- NEW TABLE (ip clv_vpn_nat) ----
    {
        auto pos = BeginNlMsg(buf, NftMsgType(NFT_MSG_NEWTABLE), NLM_F_REQUEST | NLM_F_CREATE, seq++);
        AppendNfGenMsg(buf, NFPROTO_IPV4, 0);
        AppendAttrStr(buf, NFTA_TABLE_NAME, TABLE_NAME);
        EndNlMsg(buf, pos);
    }

    // ---- NEW CHAIN (postrouting, type nat, hook postrouting, priority 100) ----
    {
        auto pos = BeginNlMsg(buf, NftMsgType(NFT_MSG_NEWCHAIN), NLM_F_REQUEST | NLM_F_CREATE, seq++);
        AppendNfGenMsg(buf, NFPROTO_IPV4, 0);
        AppendAttrStr(buf, NFTA_CHAIN_TABLE, TABLE_NAME);
        AppendAttrStr(buf, NFTA_CHAIN_NAME, CHAIN_NAME);
        AppendAttrStr(buf, NFTA_CHAIN_TYPE, "nat");

        // Hook spec (nested)
        {
            auto hook_pos = BeginNested(buf, NFTA_CHAIN_HOOK);
            AppendAttrU32(buf, NFTA_HOOK_HOOKNUM, NF_INET_POST_ROUTING);
            AppendAttrU32(buf, NFTA_HOOK_PRIORITY, 100);
            EndNested(buf, hook_pos);
        }

        EndNlMsg(buf, pos);
    }

    // ---- NEW RULE: ip saddr & mask == network → masquerade ----
    //
    // The rule is equivalent to:
    //   nft add rule ip clv_vpn_nat postrouting \
    //       ip saddr & <mask> == <network> \
    //       ip daddr & <mask> != <network> \
    //       masquerade
    //
    // This matches source traffic from the VPN subnet with a destination
    // outside the VPN subnet, and applies masquerade (SNAT to outgoing iface).
    {
        auto pos = BeginNlMsg(buf, NftMsgType(NFT_MSG_NEWRULE), NLM_F_REQUEST | NLM_F_CREATE | NLM_F_APPEND, seq++);
        AppendNfGenMsg(buf, NFPROTO_IPV4, 0);
        AppendAttrStr(buf, NFTA_RULE_TABLE, TABLE_NAME);
        AppendAttrStr(buf, NFTA_RULE_CHAIN, CHAIN_NAME);

        std::uint32_t mask_net = PrefixToNetmask(prefix_len);
        std::uint32_t network_net = htonl(source_network);

        auto exprs = BeginNested(buf, NFTA_RULE_EXPRESSIONS);
        {
            // 1. Load saddr (offset 12 in IPv4 header, 4 bytes) into NFT_REG_1
            AppendExprPayload(buf, NFT_REG_1, NFT_PAYLOAD_NETWORK_HEADER, 12, 4);

            // 2. Bitwise: REG_1 = REG_1 & mask
            AppendExprBitwise(buf, NFT_REG_1, NFT_REG_1, mask_net, 4);

            // 3. Compare: REG_1 == network  (source must be in VPN subnet)
            AppendExprCmp(buf, NFT_REG_1, NFT_CMP_EQ, &network_net, 4);

            // 4. Load daddr (offset 16 in IPv4 header, 4 bytes) into NFT_REG_1
            AppendExprPayload(buf, NFT_REG_1, NFT_PAYLOAD_NETWORK_HEADER, 16, 4);

            // 5. Bitwise: REG_1 = REG_1 & mask
            AppendExprBitwise(buf, NFT_REG_1, NFT_REG_1, mask_net, 4);

            // 6. Compare: REG_1 != network  (destination must NOT be in VPN subnet)
            AppendExprCmp(buf, NFT_REG_1, NFT_CMP_NEQ, &network_net, 4);

            // 7. Masquerade verdict
            AppendExprMasquerade(buf);
        }
        EndNested(buf, exprs);

        EndNlMsg(buf, pos);
    }

    // ---- BATCH_END ----
    {
        auto pos = BeginNlMsg(buf, NFNL_MSG_BATCH_END, NLM_F_REQUEST, seq++);
        AppendNfGenMsg(buf, AF_UNSPEC, NFNL_SUBSYS_NFTABLES);
        EndNlMsg(buf, pos);
    }

    return SendBatch(buf);
}

bool NfTablesClient::RemoveMasquerade()
{
    std::vector<std::uint8_t> buf;
    buf.reserve(512);
    std::uint32_t seq = 0;

    // ---- BATCH_BEGIN ----
    {
        auto pos = BeginNlMsg(buf, NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, seq++);
        AppendNfGenMsg(buf, AF_UNSPEC, NFNL_SUBSYS_NFTABLES);
        EndNlMsg(buf, pos);
    }

    // ---- DELETE TABLE ----
    // Deleting the table removes all chains and rules within it
    {
        auto pos = BeginNlMsg(buf, NftMsgType(NFT_MSG_DELTABLE), NLM_F_REQUEST, seq++);
        AppendNfGenMsg(buf, NFPROTO_IPV4, 0);
        AppendAttrStr(buf, NFTA_TABLE_NAME, TABLE_NAME);
        EndNlMsg(buf, pos);
    }

    // ---- BATCH_END ----
    {
        auto pos = BeginNlMsg(buf, NFNL_MSG_BATCH_END, NLM_F_REQUEST, seq++);
        AppendNfGenMsg(buf, AF_UNSPEC, NFNL_SUBSYS_NFTABLES);
        EndNlMsg(buf, pos);
    }

    return SendBatch(buf);
}

bool NfTablesClient::TableExists()
{
    int fd = nlh_.RawFd();
    if (fd < 0)
        return false;

    // Build a GETTABLE request with ACK
    std::vector<std::uint8_t> buf;
    buf.reserve(256);

    struct nlmsghdr nlh{};
    nlh.nlmsg_type = NftMsgType(NFT_MSG_GETTABLE);
    nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh.nlmsg_seq = 1;
    nlh.nlmsg_pid = 0;
    Append(buf, &nlh, sizeof(nlh));

    AppendNfGenMsg(buf, NFPROTO_IPV4, 0);
    AppendAttrStr(buf, NFTA_TABLE_NAME, TABLE_NAME);

    // Patch nlmsg_len
    auto *hdr = reinterpret_cast<struct nlmsghdr *>(buf.data());
    hdr->nlmsg_len = static_cast<std::uint32_t>(buf.size());

    // Set a timeout so we don't block if nf_tables isn't available
    struct timeval tv{.tv_sec = 2, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (send(fd, buf.data(), buf.size(), 0) < 0)
        return false;

    std::vector<std::uint8_t> response(8192);
    ssize_t recv_len = recv(fd, response.data(), response.size(), 0);

    // Clear timeout
    struct timeval zero{.tv_sec = 0, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &zero, sizeof(zero));

    if (recv_len < 0)
        return false;

    if (static_cast<std::size_t>(recv_len) < sizeof(struct nlmsghdr))
        return false;

    auto *resp = reinterpret_cast<struct nlmsghdr *>(response.data());
    if (resp->nlmsg_type == NLMSG_ERROR)
    {
        auto *err = static_cast<struct nlmsgerr *>(NLMSG_DATA(resp));
        return err->error == 0; // 0 means success (table exists)
    }

    // If we got table data back (not an error), it exists
    return true;
}

bool NfTablesClient::EnsureIpv6Masquerade(const std::uint8_t *source_network, std::uint8_t prefix_len)
{
    // First remove any existing table to make this idempotent
    if (Ipv6TableExists())
        RemoveIpv6Masquerade();

    std::vector<std::uint8_t> buf;
    buf.reserve(2048);
    std::uint32_t seq = 0;

    // ---- BATCH_BEGIN ----
    {
        auto pos = BeginNlMsg(buf, NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, seq++);
        AppendNfGenMsg(buf, AF_UNSPEC, NFNL_SUBSYS_NFTABLES);
        EndNlMsg(buf, pos);
    }

    // ---- NEW TABLE (ip6 clv_vpn_nat6) ----
    {
        auto pos = BeginNlMsg(buf, NftMsgType(NFT_MSG_NEWTABLE), NLM_F_REQUEST | NLM_F_CREATE, seq++);
        AppendNfGenMsg(buf, NFPROTO_IPV6, 0);
        AppendAttrStr(buf, NFTA_TABLE_NAME, TABLE_NAME_V6);
        EndNlMsg(buf, pos);
    }

    // ---- NEW CHAIN (postrouting, type nat, hook postrouting, priority 100) ----
    {
        auto pos = BeginNlMsg(buf, NftMsgType(NFT_MSG_NEWCHAIN), NLM_F_REQUEST | NLM_F_CREATE, seq++);
        AppendNfGenMsg(buf, NFPROTO_IPV6, 0);
        AppendAttrStr(buf, NFTA_CHAIN_TABLE, TABLE_NAME_V6);
        AppendAttrStr(buf, NFTA_CHAIN_NAME, CHAIN_NAME);
        AppendAttrStr(buf, NFTA_CHAIN_TYPE, "nat");

        // Hook spec (nested)
        {
            auto hook_pos = BeginNested(buf, NFTA_CHAIN_HOOK);
            AppendAttrU32(buf, NFTA_HOOK_HOOKNUM, NF_INET_POST_ROUTING);
            AppendAttrU32(buf, NFTA_HOOK_PRIORITY, 100);
            EndNested(buf, hook_pos);
        }

        EndNlMsg(buf, pos);
    }

    // ---- NEW RULE: ip6 saddr & mask == network, ip6 daddr & mask != network → masquerade ----
    //
    // IPv6 header layout:
    //   offset  8: source address (16 bytes)
    //   offset 24: destination address (16 bytes)
    {
        auto pos = BeginNlMsg(buf, NftMsgType(NFT_MSG_NEWRULE), NLM_F_REQUEST | NLM_F_CREATE | NLM_F_APPEND, seq++);
        AppendNfGenMsg(buf, NFPROTO_IPV6, 0);
        AppendAttrStr(buf, NFTA_RULE_TABLE, TABLE_NAME_V6);
        AppendAttrStr(buf, NFTA_RULE_CHAIN, CHAIN_NAME);

        std::uint8_t mask[16];
        Ipv6PrefixToNetmask(prefix_len, mask);

        // Apply mask to network address to get the canonical network
        std::uint8_t network_masked[16];
        for (int i = 0; i < 16; ++i)
            network_masked[i] = source_network[i] & mask[i];

        auto exprs = BeginNested(buf, NFTA_RULE_EXPRESSIONS);
        {
            // 1. Load saddr (offset 8 in IPv6 header, 16 bytes) into NFT_REG_1
            AppendExprPayload(buf, NFT_REG_1, NFT_PAYLOAD_NETWORK_HEADER, 8, 16);

            // 2. Bitwise: REG_1 = REG_1 & mask
            AppendExprBitwiseBytes(buf, NFT_REG_1, NFT_REG_1, mask, 16);

            // 3. Compare: REG_1 == network  (source must be in VPN subnet)
            AppendExprCmp(buf, NFT_REG_1, NFT_CMP_EQ, network_masked, 16);

            // 4. Load daddr (offset 24 in IPv6 header, 16 bytes) into NFT_REG_1
            AppendExprPayload(buf, NFT_REG_1, NFT_PAYLOAD_NETWORK_HEADER, 24, 16);

            // 5. Bitwise: REG_1 = REG_1 & mask
            AppendExprBitwiseBytes(buf, NFT_REG_1, NFT_REG_1, mask, 16);

            // 6. Compare: REG_1 != network  (destination must NOT be in VPN subnet)
            AppendExprCmp(buf, NFT_REG_1, NFT_CMP_NEQ, network_masked, 16);

            // 7. Masquerade verdict
            AppendExprMasquerade(buf);
        }
        EndNested(buf, exprs);

        EndNlMsg(buf, pos);
    }

    // ---- BATCH_END ----
    {
        auto pos = BeginNlMsg(buf, NFNL_MSG_BATCH_END, NLM_F_REQUEST, seq++);
        AppendNfGenMsg(buf, AF_UNSPEC, NFNL_SUBSYS_NFTABLES);
        EndNlMsg(buf, pos);
    }

    return SendBatch(buf);
}

bool NfTablesClient::RemoveIpv6Masquerade()
{
    std::vector<std::uint8_t> buf;
    buf.reserve(512);
    std::uint32_t seq = 0;

    // ---- BATCH_BEGIN ----
    {
        auto pos = BeginNlMsg(buf, NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, seq++);
        AppendNfGenMsg(buf, AF_UNSPEC, NFNL_SUBSYS_NFTABLES);
        EndNlMsg(buf, pos);
    }

    // ---- DELETE TABLE ----
    {
        auto pos = BeginNlMsg(buf, NftMsgType(NFT_MSG_DELTABLE), NLM_F_REQUEST, seq++);
        AppendNfGenMsg(buf, NFPROTO_IPV6, 0);
        AppendAttrStr(buf, NFTA_TABLE_NAME, TABLE_NAME_V6);
        EndNlMsg(buf, pos);
    }

    // ---- BATCH_END ----
    {
        auto pos = BeginNlMsg(buf, NFNL_MSG_BATCH_END, NLM_F_REQUEST, seq++);
        AppendNfGenMsg(buf, AF_UNSPEC, NFNL_SUBSYS_NFTABLES);
        EndNlMsg(buf, pos);
    }

    return SendBatch(buf);
}

bool NfTablesClient::Ipv6TableExists()
{
    int fd = nlh_.RawFd();
    if (fd < 0)
        return false;

    // Build a GETTABLE request with ACK
    std::vector<std::uint8_t> buf;
    buf.reserve(256);

    struct nlmsghdr nlh{};
    nlh.nlmsg_type = NftMsgType(NFT_MSG_GETTABLE);
    nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh.nlmsg_seq = 1;
    nlh.nlmsg_pid = 0;
    Append(buf, &nlh, sizeof(nlh));

    AppendNfGenMsg(buf, NFPROTO_IPV6, 0);
    AppendAttrStr(buf, NFTA_TABLE_NAME, TABLE_NAME_V6);

    // Patch nlmsg_len
    auto *hdr = reinterpret_cast<struct nlmsghdr *>(buf.data());
    hdr->nlmsg_len = static_cast<std::uint32_t>(buf.size());

    // Set a timeout so we don't block if nf_tables isn't available
    struct timeval tv{.tv_sec = 2, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (send(fd, buf.data(), buf.size(), 0) < 0)
        return false;

    std::vector<std::uint8_t> response(8192);
    ssize_t recv_len = recv(fd, response.data(), response.size(), 0);

    // Clear timeout
    struct timeval zero{.tv_sec = 0, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &zero, sizeof(zero));

    if (recv_len < 0)
        return false;

    if (static_cast<std::size_t>(recv_len) < sizeof(struct nlmsghdr))
        return false;

    auto *resp = reinterpret_cast<struct nlmsghdr *>(response.data());
    if (resp->nlmsg_type == NLMSG_ERROR)
    {
        auto *err = static_cast<struct nlmsgerr *>(NLMSG_DATA(resp));
        return err->error == 0; // 0 means success (table exists)
    }

    // If we got table data back (not an error), it exists
    return true;
}

} // namespace clv::vpn
