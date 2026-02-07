// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include "hash_util.h"

namespace clv::quic {

/// QUIC Connection ID (variable length up to 20 bytes)
struct ConnectionId
{
    std::array<std::uint8_t, 20> data{};
    std::uint8_t length{0};

    [[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept
    {
        return {data.data(), static_cast<std::size_t>(length)};
    }

    auto operator<=>(const ConnectionId &) const = default;
};

struct ConnectionIdHash
{
    [[nodiscard]] std::size_t operator()(const ConnectionId &id) const noexcept
    {
        // Use FNV-1a from hash_util.h
        std::size_t hash = clv::fnv_offset_basis();
        hash ^= id.length;
        hash *= clv::fnv_prime();
        for (std::uint8_t i = 0; i < id.length; ++i)
        {
            hash ^= id.data[i];
            hash *= clv::fnv_prime();
        }
        return hash;
    }
};

struct ConnectionIdEq
{
    [[nodiscard]] bool operator()(const ConnectionId &a, const ConnectionId &b) const noexcept
    {
        if (a.length != b.length)
            return false;
        return std::equal(a.data.begin(), a.data.begin() + a.length, b.data.begin());
    }
};

} // namespace clv::quic

// Provide std::hash specialization
namespace std {
template <>
struct hash<clv::quic::ConnectionId>
{
    std::size_t operator()(const clv::quic::ConnectionId &id) const noexcept
    {
        return clv::quic::ConnectionIdHash{}(id);
    }
};
} // namespace std
