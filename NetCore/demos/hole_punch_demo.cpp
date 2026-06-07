// Copyright (c) 2023- Charlie Vigue. All rights reserved.

/**
 * @file hole_punch_demo.cpp
 * @brief NAT hole punching demonstration using STUN and TCP control channel
 *
 * This demo shows how two peers behind NATs can establish direct UDP connectivity
 * using STUN for address discovery and a TCP control channel for coordination.
 *
 * Usage:
 *   hole_punch_demo -s [--port PORT]          # Server mode (listen for peer)
 *   hole_punch_demo <PEER_LAN_ADDR:PORT>      # Client mode (connect to peer)
 *
 * The control channel (TCP) runs over the LAN/VPN to exchange metadata.
 * The data channel (UDP) uses STUN-discovered public addresses.
 */

#include "stun/stun_client.h"
#include "stun/stun_utils.h"
#include "util/byte_packer.h"

#include <algorithm>
#include <asio/as_tuple.hpp>
#include <asio/buffer.hpp>
#include <asio/co_spawn.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/address_v4.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
#include <asio/steady_timer.hpp>
#include <atomic>
#include <cstdint>
#include <iostream>
#include <format>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>
#include <array>
#include <cstring>
#include <exception>
#include <chrono>
#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>

#include "asan_notify.h"

using namespace clv::netcore;

// ============================================================================
// Control Channel Protocol (exchanged over TCP)
// ============================================================================

struct peer_info
{
    asio::ip::address_v4 lan_address{};
    std::uint16_t lan_port{};
    asio::ip::address_v4 public_address{};
    std::uint16_t public_port{};

    [[nodiscard]] std::string to_string() const
    {
        return std::format("LAN: {}:{}, PUBLIC: {}:{}",
                           lan_address.to_string(),
                           lan_port,
                           public_address.to_string(),
                           public_port);
    }

    [[nodiscard]] std::vector<std::uint8_t> serialize() const
    {
        std::vector<std::uint8_t> data(12); // 4+2+4+2 bytes
        const auto lan_bytes = lan_address.to_bytes();
        const auto pub_bytes = public_address.to_bytes();

        std::copy(lan_bytes.begin(), lan_bytes.end(), data.begin());
        data[4] = static_cast<std::uint8_t>((lan_port >> 8) & 0xFF);
        data[5] = static_cast<std::uint8_t>(lan_port & 0xFF);
        std::copy(pub_bytes.begin(), pub_bytes.end(), data.begin() + 6);
        data[10] = static_cast<std::uint8_t>((public_port >> 8) & 0xFF);
        data[11] = static_cast<std::uint8_t>(public_port & 0xFF);

        return data;
    }

    static std::optional<peer_info> deserialize(const std::vector<std::uint8_t> &data)
    {
        if (data.size() < 12)
            return std::nullopt;

        peer_info info;
        std::array<std::uint8_t, 4> lan_bytes{data[0], data[1], data[2], data[3]};
        std::array<std::uint8_t, 4> pub_bytes{data[6], data[7], data[8], data[9]};

        info.lan_address = asio::ip::address_v4{lan_bytes};
        info.lan_port = bytes_to_uint(data[4], data[5]);
        info.public_address = asio::ip::address_v4{pub_bytes};
        info.public_port = bytes_to_uint(data[10], data[11]);

        return info;
    }
};

// ============================================================================
// Utility Functions
// ============================================================================

void print_banner()
{
    std::cout << "==========================================\n";
    std::cout << "    NAT Hole Punching Demo\n";
    std::cout << "    Using STUN + TCP Control Channel\n";
    std::cout << "==========================================\n\n";
}

void print_usage(const char *program_name)
{
    std::cout << "Usage:\n";
    std::cout << "  " << program_name << " -s [--port PORT]        Server mode (listen for peer)\n";
    std::cout << "  " << program_name << " <PEER_LAN_ADDR:PORT>    Client mode (connect to peer)\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << program_name << " -s                      Listen on default port 9999\n";
    std::cout << "  " << program_name << " -s --port 8888          Listen on port 8888\n";
    std::cout << "  " << program_name << " 10.10.1.50:9999         Connect to peer at 10.10.1.50:9999\n";
}

// Get local IP address on the default gateway interface
asio::awaitable<std::optional<asio::ip::address_v4>>
get_local_address(asio::io_context &io_ctx)
{
    try
    {
        // Create a UDP socket and connect to a public address to determine local IP
        asio::ip::udp::socket socket{io_ctx};
        socket.open(asio::ip::udp::v4());

        // Connect to a public DNS server (doesn't need to succeed, just determines route)
        asio::ip::udp::endpoint public_endpoint{asio::ip::make_address_v4("8.8.8.8"), 53};

        auto [ec] = co_await socket.async_connect(public_endpoint, asio::as_tuple(asio::use_awaitable));

        if (!ec)
        {
            auto local_endpoint = socket.local_endpoint();
            socket.close();
            co_return local_endpoint.address().to_v4();
        }

        socket.close();
    }
    catch (const std::exception &)
    {
    }

    co_return std::nullopt;
}

// ============================================================================
// Control Channel (TCP-based)
// ============================================================================

class tcp_control_channel
{
  public:
    /// Send peer info over established TCP connection
    static asio::awaitable<bool> send_peer_info(asio::ip::tcp::socket &socket, const peer_info &info)
    {
        try
        {
            auto data = info.serialize();
            auto [ec, bytes_written] = co_await asio::async_write(
                socket, asio::buffer(data), asio::as_tuple(asio::use_awaitable));

            co_return !ec && bytes_written == data.size();
        }
        catch (const std::exception &)
        {
            co_return false;
        }
    }

    /// Receive peer info from established TCP connection
    static asio::awaitable<std::optional<peer_info>>
    receive_peer_info(asio::ip::tcp::socket &socket)
    {
        try
        {
            std::vector<std::uint8_t> buffer(12);
            auto [ec, bytes_read] = co_await asio::async_read(
                socket, asio::buffer(buffer), asio::as_tuple(asio::use_awaitable));

            if (!ec && bytes_read == 12)
            {
                co_return peer_info::deserialize(buffer);
            }
        }
        catch (const std::exception &)
        {
        }

        co_return std::nullopt;
    }
};

// ============================================================================
// Hole Punching
// ============================================================================

class hole_puncher
{
  public:
    hole_puncher(asio::io_context &io_ctx)
        : io_ctx_{io_ctx}
    {
    }

    /// Perform hole punching using an existing UDP socket
    /// @param peer Peer's address info to punch through to
    /// @param socket Reference to the socket to use for hole punching
    /// @param own_translated Own translated (public) UDP endpoint from STUN
    /// @param local_lan_addr Own local LAN address for display
    asio::awaitable<bool>
    punch_and_listen(const peer_info &peer, asio::ip::udp::socket &socket,
                     const asio::ip::udp::endpoint &own_translated, const asio::ip::address_v4 &local_lan_addr)
    {
        try
        {
            std::cout << "\n[Hole Punch Phase]\n";
            auto local_ep = socket.local_endpoint();
            std::cout << "  Socket Configuration:\n";
            std::cout << "    Local (LAN):         " << local_lan_addr.to_string() << ":" << local_ep.port() << "\n";
            std::cout << "    Public (Translated): " << own_translated.address().to_string() << ":" << own_translated.port() << "\n";
            if (local_ep.port() != own_translated.port())
                std::cout << "    This local UDP port " << local_ep.port() << " is translated by NAT to " << own_translated.port() << "\n\n";

            asio::ip::udp::endpoint peer_endpoint{peer.public_address, peer.public_port};

            std::cout << "  Sending hole punch packets to peer's PUBLIC address:\n";
            std::cout << "    Destination: " << peer.public_address.to_string() << ":" << peer.public_port << "\n";

            // Send initial hole punch packets
            const std::array<std::uint8_t, 4> punch_marker{0xDE, 0xAD, 0xBE, 0xEF};
            for (int i = 0; i < 3; ++i)
            {
                auto [send_ec, bytes_sent] = co_await socket.async_send_to(
                    asio::buffer(punch_marker), peer_endpoint, asio::as_tuple(asio::use_awaitable));

                if (send_ec)
                {
                    std::cout << "  ⚠ Failed to send hole punch packet " << (i + 1) << "\n";
                }
                else
                {
                    std::cout << "  ✓ Sent hole punch packet " << (i + 1) << "\n";
                }
            }

            // Wait for response (with timeout)
            std::cout << "  Waiting for peer response...\n";

            std::array<std::uint8_t, 256> receive_buffer{};
            asio::ip::udp::endpoint sender;

            asio::steady_timer timer{io_ctx_};
            timer.expires_after(std::chrono::seconds(5));

            std::atomic<bool> timeout_occurred{false};
            timer.async_wait([&](const std::error_code &ec)
            {
                if (!ec)
                {
                    timeout_occurred = true;
                    socket.cancel();
                }
            });

            auto [recv_ec, bytes_received] = co_await socket.async_receive_from(
                asio::buffer(receive_buffer), sender, asio::as_tuple(asio::use_awaitable));

            timer.cancel();

            if (recv_ec)
            {
                if (timeout_occurred)
                {
                    std::cout << "  ✗ Timeout waiting for peer response\n";
                }
                else
                {
                    std::cout << "  ✗ Error receiving: " << recv_ec.message() << "\n";
                }
                co_return false;
            }

            std::cout << "  ✓ Received response from peer!\n";
            std::cout << "    Sender Address:port: " << sender.address().to_string() << ":" << sender.port() << "\n";
            std::cout << "    Bytes Received:      " << bytes_received << "\n";
            std::cout << "    ⓘ This confirms peer can reach our translated address (" << peer.public_address.to_string()
                      << ":" << peer.public_port << ")\n";

            // Send acknowledgment
            std::array<std::uint8_t, 4> ack_packet{0xCA, 0xFE, 0xBA, 0xBE};
            auto [ack_ec, ack_sent] = co_await socket.async_send_to(
                asio::buffer(ack_packet), sender, asio::as_tuple(asio::use_awaitable));

            if (!ack_ec)
            {
                std::cout << "  ✓ Sent acknowledgment\n";
            }

            // Exchange test messages
            std::cout << "\n[Data Exchange Phase]\n";

            // Skip any remaining stale marker packets:
            // - Hole punch markers: 0xDE 0xAD 0xBE 0xEF (peer's hole punch packets)
            // - Acknowledgment markers: 0xCA 0xFE 0xBA 0xBE (our own ack responses)
            // Keep filtering until we get a timeout (indicating all markers are flushed)
            std::cout << "  Filtering stale marker packets...\n";
            const std::array<std::uint8_t, 4> hole_punch_marker{0xDE, 0xAD, 0xBE, 0xEF};
            const std::array<std::uint8_t, 4> ack_marker{0xCA, 0xFE, 0xBA, 0xBE};

            int timeout_count = 0;
            for (int attempt = 0; attempt < 30 && timeout_count < 2; ++attempt)
            {
                std::array<std::uint8_t, 256> filter_buffer{};
                asio::ip::udp::endpoint filter_sender;

                asio::steady_timer filter_timer{io_ctx_};
                filter_timer.expires_after(std::chrono::milliseconds(150));

                std::atomic<bool> filter_timeout{false};
                filter_timer.async_wait([&](const std::error_code &ec)
                {
                    if (!ec)
                    {
                        filter_timeout = true;
                        socket.cancel();
                    }
                });

                auto [filter_ec, filter_received] = co_await socket.async_receive_from(
                    asio::buffer(filter_buffer), filter_sender, asio::as_tuple(asio::use_awaitable));

                filter_timer.cancel();

                if (filter_timeout || filter_ec)
                {
                    std::cout << "   - Filtering: " << (filter_timeout ? "Timeout" : filter_ec.message()) << "\n";
                    timeout_count++;
                    continue; // Got timeout, keep trying
                }

                // Reset timeout counter on successful receive
                timeout_count = 0;

                // Skip if this is a hole-punch marker packet (exactly 4 bytes)
                if (filter_received == 4 && filter_buffer[0] == hole_punch_marker[0] && filter_buffer[1] == hole_punch_marker[1] && filter_buffer[2] == hole_punch_marker[2] && filter_buffer[3] == hole_punch_marker[3])
                {
                    std::cout << "   - Filtered hole punch marker packet\n";
                    continue; // Skip hole punch marker
                }

                // Skip if this is an acknowledgment marker packet (exactly 4 bytes)
                if (filter_received == 4 && filter_buffer[0] == ack_marker[0] && filter_buffer[1] == ack_marker[1] && filter_buffer[2] == ack_marker[2] && filter_buffer[3] == ack_marker[3])
                {
                    std::cout << "   - Filtered acknowledgment marker packet\n";
                    continue; // Skip ack marker
                }

                // Non-marker packet: we're done filtering
                // All markers have been consumed, next real message phase can proceed
                break;
            }

            std::cout << "  ✓ Stale marker packets filtered\n\n";

            // Exchange multiple messages
            const std::vector<std::string> messages = {
                "Message 1",
                "Message 2",
                "Message 3: Hello from hole punch demo!"};

            // Exchange multiple messages
            for (size_t i = 0; i < messages.size(); ++i)
            {
                const auto &test_message = messages[i];
                auto [msg_ec, msg_sent] = co_await socket.async_send_to(
                    asio::buffer(test_message), sender, asio::as_tuple(asio::use_awaitable));

                if (!msg_ec)
                {
                    std::cout << "  ✓ Sent message " << (i + 1) << " [" << msg_sent << " bytes]: \"" << test_message << "\"\n";
                }

                // Wait a bit for response
                asio::steady_timer msg_delay{io_ctx_};
                msg_delay.expires_after(std::chrono::milliseconds(150));
                co_await msg_delay.async_wait(asio::use_awaitable);

                // Try to receive message
                std::array<std::uint8_t, 256> msg_buffer{};
                asio::ip::udp::endpoint msg_sender;

                asio::steady_timer msg_timer{io_ctx_};
                msg_timer.expires_after(std::chrono::milliseconds(500));

                std::atomic<bool> msg_timeout{false};
                msg_timer.async_wait([&](const std::error_code &ec)
                {
                    if (!ec)
                    {
                        msg_timeout = true;
                        socket.cancel();
                    }
                });

                auto [recv_msg_ec, msg_received] = co_await socket.async_receive_from(
                    asio::buffer(msg_buffer), msg_sender, asio::as_tuple(asio::use_awaitable));

                msg_timer.cancel();

                if (!recv_msg_ec && msg_received > 0)
                {
                    std::string received(msg_buffer.data(), msg_buffer.data() + msg_received);
                    std::cout << "  ✓ Received message " << (i + 1) << " [" << msg_received << " bytes]: \"" << received << "\"\n";
                }
            }

            std::cout << "\n✅ Hole punching successful!\n";
            co_return true;
        }
        catch (const std::exception &e)
        {
            std::cout << "  ✗ Exception: " << e.what() << "\n";
            co_return false;
        }
    }

  private:
    asio::io_context &io_ctx_;
};

// ============================================================================
// Server Mode
// ============================================================================

asio::awaitable<void> run_server_mode(asio::io_context &io_ctx, std::uint16_t tcp_port)
{
    try
    {
        std::cout << "[Server Mode]\n";

        // Get local address
        auto local_addr = co_await get_local_address(io_ctx);
        if (!local_addr)
        {
            std::cout << "❌ Failed to determine local address\n";
            co_return;
        }

        std::cout << "\n[TCP Control Channel (for handshake)]\n";
        std::cout << "  Listen on: " << local_addr->to_string() << ":" << tcp_port << "\n";
        std::cout << "  (Tell peer to connect here via VPN)\n";

        // Create STUN client - its socket will be used for hole punching
        stun_client stun(io_ctx);
        auto stun_result = co_await stun.discover_public_address(std::chrono::milliseconds{5000});

        if (!stun_result.success)
        {
            std::cout << "❌ STUN discovery failed: " << stun_result.error_message << "\n";
            co_return;
        }

        std::uint16_t local_udp_port = stun.local_port();

        std::cout << "\n[UDP Hole Punch Channel (for data)]\n";
        std::cout << "  Local (LAN):     " << local_addr->to_string() << ":" << local_udp_port << "\n";
        std::cout << "  Translated:      " << stun_result.public_addr.address.to_string() << ":" << stun_result.public_addr.port << "\n";
        std::cout << "  ⓘ Local UDP port " << local_udp_port << " translated by NAT to " << stun_result.public_addr.port << "\n";

        peer_info local_info{
            .lan_address = *local_addr,
            .lan_port = local_udp_port,
            .public_address = stun_result.public_addr.address,
            .public_port = stun_result.public_addr.port};

        // Create TCP listening socket (separate from UDP)
        asio::ip::tcp::acceptor acceptor{
            io_ctx,
            asio::ip::tcp::endpoint{asio::ip::tcp::v4(), tcp_port}};

        std::cout << "\n✓ Listening for peer connection...\n";

        // Accept peer connection
        asio::ip::tcp::socket peer_socket{io_ctx};
        auto [accept_ec] = co_await acceptor.async_accept(peer_socket, asio::as_tuple(asio::use_awaitable));

        if (accept_ec)
        {
            std::cout << "❌ Failed to accept connection: " << accept_ec.message() << "\n";
            co_return;
        }

        auto peer_endpoint = peer_socket.remote_endpoint();
        std::cout << "\n[Peer Connected via Control Channel (TCP/VPN)]\n";
        std::cout << "  Peer's LAN Address: " << peer_endpoint.address().to_string()
                  << ":" << peer_endpoint.port() << "\n";

        // Exchange peer info over TCP control channel
        tcp_control_channel control;

        std::cout << "\n[Control Channel Exchange (TCP/VPN)]\n";
        std::cout << "Sending our address info:\n";
        std::cout << "  Local (LAN):         " << local_info.lan_address.to_string() << ":" << local_info.lan_port << "\n";
        std::cout << "  Public (Translated): " << local_info.public_address.to_string() << ":" << local_info.public_port << "\n";

        if (!co_await control.send_peer_info(peer_socket, local_info))
        {
            std::cout << "❌ Failed to send peer info\n";
            co_return;
        }

        std::cout << "Receiving peer's address info...\n";
        auto remote_info = co_await control.receive_peer_info(peer_socket);

        if (!remote_info)
        {
            std::cout << "❌ Failed to receive peer info\n";
            co_return;
        }

        std::cout << "  Peer's Local (LAN):         " << remote_info->lan_address.to_string() << ":" << remote_info->lan_port << "\n";
        std::cout << "  Peer's Public (Translated): " << remote_info->public_address.to_string() << ":" << remote_info->public_port << "\n";

        std::cout << "  ⓘ Peer's local port " << remote_info->lan_port << " translated to " << remote_info->public_port << "\n";

        peer_socket.close();

        // Now perform hole punching using the STUN socket
        hole_puncher puncher{io_ctx};
        co_await puncher.punch_and_listen(
            *remote_info,
            stun.get_socket(),
            asio::ip::udp::endpoint{stun_result.public_addr.address, stun_result.public_addr.port},
            *local_addr);
    }
    catch (const std::exception &e)
    {
        std::cout << "❌ Server error: " << e.what() << "\n";
    }
}

// ============================================================================
// Client Mode
// ============================================================================

std::pair<std::string, std::uint16_t> parse_peer_endpoint(const std::string &endpoint)
{
    auto colon_pos = endpoint.find_last_of(':');
    if (colon_pos == std::string::npos)
    {
        throw std::invalid_argument("Invalid format. Use <HOST:PORT>");
    }

    std::string host = endpoint.substr(0, colon_pos);
    std::string port_str = endpoint.substr(colon_pos + 1);

    std::uint16_t port = static_cast<std::uint16_t>(std::stoul(port_str));
    return {host, port};
}

asio::awaitable<void>
run_client_mode(asio::io_context &io_ctx, const std::string &peer_endpoint_str)
{
    try
    {
        std::cout << "[Client Mode]\n";

        auto [peer_host, peer_port] = parse_peer_endpoint(peer_endpoint_str);

        std::cout << "Target Peer TCP Address: " << peer_host << ":" << peer_port << " (via VPN)\n";

        // Get local address
        auto local_addr = co_await get_local_address(io_ctx);
        if (!local_addr)
        {
            std::cout << "❌ Failed to determine local address\n";
            co_return;
        }

        // Create STUN client - its socket will be used for hole punching
        stun_client stun{io_ctx};
        auto stun_result = co_await stun.discover_public_address(std::chrono::milliseconds{5000});

        if (!stun_result.success)
        {
            std::cout << "❌ STUN discovery failed: " << stun_result.error_message << "\n";
            co_return;
        }

        std::uint16_t local_udp_port = stun.local_port();

        std::cout << "\n[UDP Hole Punch Channel (for data)]\n";
        std::cout << "  Local (LAN):     " << local_addr->to_string() << ":" << local_udp_port << "\n";
        std::cout << "  Translated:      " << stun_result.public_addr.address.to_string() << ":" << stun_result.public_addr.port << "\n";
        std::cout << "  ⓘ Local UDP port " << local_udp_port << " translated by NAT to " << stun_result.public_addr.port << "\n";

        peer_info local_info{
            .lan_address = *local_addr,
            .lan_port = local_udp_port,
            .public_address = stun_result.public_addr.address,
            .public_port = stun_result.public_addr.port}; // Connect to peer via TCP
        asio::ip::tcp::socket peer_socket{io_ctx};
        asio::ip::tcp::resolver resolver{io_ctx};

        std::cout << "\n[Control Channel Connection]\n";
        std::cout << "Connecting to peer...\n";

        auto [resolve_ec, endpoints] = co_await resolver.async_resolve(
            peer_host, std::to_string(peer_port), asio::as_tuple(asio::use_awaitable));

        if (resolve_ec || endpoints.empty())
        {
            std::cout << "❌ DNS resolution failed: " << resolve_ec.message() << "\n";
            co_return;
        }

        auto [connect_ec] = co_await peer_socket.async_connect(
            *endpoints.begin(),
            asio::as_tuple(asio::use_awaitable));

        if (connect_ec)
        {
            std::cout << "❌ Connection failed: " << connect_ec.message() << "\n";
            co_return;
        }

        std::cout << "✓ Connected to peer\n";

        // Exchange peer info over TCP control channel
        tcp_control_channel control;

        std::cout << "\n[Control Channel Exchange (TCP/VPN)]\n";
        std::cout << "Sending our address info:\n";
        std::cout << "  Local (LAN):         " << local_info.lan_address.to_string() << ":" << local_info.lan_port << "\n";
        std::cout << "  Public (Translated): " << local_info.public_address.to_string() << ":" << local_info.public_port << "\n";

        if (!co_await control.send_peer_info(peer_socket, local_info))
        {
            std::cout << "❌ Failed to send peer info\n";
            co_return;
        }

        std::cout << "Receiving peer's address info...\n";
        auto remote_info = co_await control.receive_peer_info(peer_socket);

        if (!remote_info)
        {
            std::cout << "❌ Failed to receive peer info\n";
            co_return;
        }

        std::cout << "  Peer's Local (LAN):         " << remote_info->lan_address.to_string() << ":" << remote_info->lan_port << "\n";
        std::cout << "  Peer's Public (Translated): " << remote_info->public_address.to_string() << ":" << remote_info->public_port << "\n";
        std::cout << "  ⓘ Peer's local port " << remote_info->lan_port << " translated to " << remote_info->public_port << "\n";

        peer_socket.close();

        // Now perform hole punching using the STUN socket
        hole_puncher puncher{io_ctx};
        co_await puncher.punch_and_listen(
            *remote_info,
            stun.get_socket(),
            asio::ip::udp::endpoint{stun_result.public_addr.address, stun_result.public_addr.port},
            *local_addr);
    }
    catch (const std::exception &e)
    {
        std::cout << "❌ Client error: " << e.what() << "\n";
    }
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char *argv[])
{
    clv_announce_asan();
    print_banner();

    bool server_mode = false;
    std::uint16_t tcp_port = 9999;
    std::string peer_endpoint;

    // Parse arguments
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];

        if (arg == "-s" || arg == "--server")
        {
            server_mode = true;
        }
        else if (arg == "-p" || arg == "--port")
        {
            if (i + 1 >= argc)
            {
                std::cerr << "Error: --port requires an argument\n";
                print_usage(argv[0]);
                return 1;
            }

            try
            {
                tcp_port = static_cast<std::uint16_t>(std::stoul(argv[++i]));
            }
            catch (const std::exception &e)
            {
                std::cerr << "Error parsing port: " << e.what() << "\n";
                print_usage(argv[0]);
                return 1;
            }
        }
        else if (arg == "-h" || arg == "--help")
        {
            print_usage(argv[0]);
            return 0;
        }
        else if (!arg.empty() && arg[0] != '-')
        {
            // Positional argument: peer endpoint
            peer_endpoint = arg;
        }
        else
        {
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    try
    {
        asio::io_context io_context;

        if (peer_endpoint.empty())
        {
            // Server mode (default if no peer specified)
            server_mode = true;
        }

        if (server_mode)
        {
            auto coro = run_server_mode(io_context, tcp_port);
            asio::co_spawn(io_context, std::move(coro), asio::detached);
        }
        else
        {
            auto coro = run_client_mode(io_context, peer_endpoint);
            asio::co_spawn(io_context, std::move(coro), asio::detached);
        }

        io_context.run();

        std::cout << "\n✓ Demo completed\n";
        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "❌ Fatal error: " << e.what() << "\n";
        return 1;
    }
}
