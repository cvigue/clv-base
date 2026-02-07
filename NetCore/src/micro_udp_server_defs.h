// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_NETCORE_MICRO_UDP_SERVER_DEFS_H
#define CLV_NETCORE_MICRO_UDP_SERVER_DEFS_H

#include <asio/as_tuple.hpp>
#include <asio/awaitable.hpp>
#include <asio/ip/udp.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

namespace clv::UdpServerDefs {

// ********************************************************************************************************************
// MicroUdpServer Defs
// ********************************************************************************************************************

using data_type = std::uint8_t;
using buffer_type = std::vector<data_type>;
using data_size = std::size_t;

/// Maximum UDP payload size (conservative; avoid fragmentation)
inline constexpr data_size max_datagram_size = 1472;

/// Function type for sending datagrams back to a remote endpoint
using SendDatagramFnT = std::function<asio::awaitable<void>(buffer_type data,
                                                            asio::ip::udp::endpoint remote)>;

} // namespace clv::UdpServerDefs

#endif // CLV_NETCORE_MICRO_UDP_SERVER_DEFS_H
