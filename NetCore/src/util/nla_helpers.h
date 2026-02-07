// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_VPN_NLA_HELPERS_H
#define CLV_VPN_NLA_HELPERS_H

/**
 * @file nla_helpers.h
 * @brief Netlink attribute (NLA) macros and inline helper functions.
 *
 * Provides portable NLA_* macros (guarded with #ifndef for coexistence
 * with kernel headers) and inline NlaPut / NlaBeginNested helpers used
 * by both the VPN client and the DCO server data-channel.
 */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <linux/netlink.h>

// ===================== NLA macros (safe to include alongside kernel headers) =====================

#ifndef NLA_ALIGN
#define NLA_ALIGN(len) (((len) + 3) & ~3)
#endif

#ifndef NLA_HDRLEN
#define NLA_HDRLEN NLA_ALIGN(sizeof(struct nlattr))
#endif

#ifndef NLA_DATA
#define NLA_DATA(nla) ((void *)(((char *)(nla)) + NLA_HDRLEN))
#endif

#ifndef NLA_NEXT
#define NLA_NEXT(nla, attrlen)               \
    ((attrlen) -= NLA_ALIGN((nla)->nla_len), \
     (struct nlattr *)(((char *)(nla)) + NLA_ALIGN((nla)->nla_len)))
#endif

#ifndef NLA_OK
#define NLA_OK(nla, len) \
    ((len) >= (int)sizeof(struct nlattr) && (nla)->nla_len >= sizeof(struct nlattr) && (nla)->nla_len <= (len))
#endif

#ifndef NLA_F_NESTED
#define NLA_F_NESTED (1 << 15)
#endif

// ===================== Inline helpers =====================

namespace clv::vpn {

/**
 * @brief Append a netlink attribute to a buffer with bounds checking.
 * @param buf       Destination buffer
 * @param offset    Current write position (updated on success)
 * @param capacity  Total buffer capacity
 * @param type      NLA attribute type
 * @param data      Attribute payload (may be nullptr for nested headers)
 * @param len       Payload length in bytes
 * @return true on success, false if the attribute would exceed capacity
 */
inline bool NlaPut(char *buf, size_t &offset, size_t capacity,
                   uint16_t type, const void *data, size_t len)
{
    size_t needed = NLA_ALIGN(NLA_HDRLEN + len);
    if (offset + needed > capacity)
        return false;
    auto *attr = reinterpret_cast<struct nlattr *>(buf + offset);
    attr->nla_type = type;
    attr->nla_len = static_cast<decltype(attr->nla_len)>(NLA_HDRLEN + len);
    if (data && len > 0)
        std::memcpy(NLA_DATA(attr), data, len);
    offset += needed;
    return true;
}

/**
 * @brief Begin a nested netlink attribute with bounds checking.
 * @param buf       Destination buffer
 * @param offset    Current write position (updated on success)
 * @param capacity  Total buffer capacity
 * @param type      NLA attribute type (NLA_F_NESTED added automatically)
 * @return Pointer to the nlattr header (caller must set nla_len after children),
 *         or nullptr if the header would exceed capacity
 */
inline nlattr *NlaBeginNested(char *buf, size_t &offset, size_t capacity, uint16_t type)
{
    if (offset + NLA_HDRLEN > capacity)
        return nullptr;
    auto *attr = reinterpret_cast<struct nlattr *>(buf + offset);
    attr->nla_type = type | NLA_F_NESTED;
    offset += NLA_HDRLEN;
    return attr;
}

} // namespace clv::vpn

#endif // CLV_VPN_NLA_HELPERS_H
