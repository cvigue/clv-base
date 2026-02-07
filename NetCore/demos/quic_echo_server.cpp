// Copyright (c) 2025- Charlie Vigue. All rights reserved.

/**
 * @file quic_echo_server.cpp
 * @brief Simple QUIC echo server demonstration
 *
 * This demo shows basic QUIC server functionality with a simple echo handler.
 * It accepts QUIC connections and echoes back any stream data it receives.
 *
 * Usage:
 *   quic_echo_server [--port PORT]
 *
 * Features demonstrated:
 * - QUIC connection management
 * - Initial packet encryption/decryption
 * - Stream data handling
 * - Connection ID generation
 */

#include "micro_udp_server.h"
#include "micro_udp_server_defs.h"
#include "quic/quic_connection_manager.h"
#include "quic/quic_packet.h"
#include "quic/connection_id.h"

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <format>
#include <iostream>
#include <span>
#include <string>
#include <csignal>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <random>
#include <variant>

#ifdef _WIN32
#include <io.h>
typedef int ssize_t;
#else
#include <unistd.h>
#endif

using namespace clv;
using namespace clv::quic;
using namespace clv::UdpServerDefs;

// Global shutdown signaling
std::atomic<bool> keepRunning{true};
std::condition_variable shutdownCV;
std::mutex shutdownMutex;

void signalHandler(int signum)
{
    std::cout << "\n[Signal] Received signal " << signum << ", shutting down...\n";
    keepRunning = false;
    shutdownCV.notify_all();
}

// ============================================================================
// QUIC Echo Handler
// ============================================================================

/**
 * @brief QUIC echo handler that processes QUIC packets and echoes stream data
 */
struct QuicEchoHandler
{
    std::size_t mPacketCount{0};
    std::size_t mConnectionCount{0};
    QuicConnectionManager mConnManager;

    explicit QuicEchoHandler(asio::io_context &io_ctx)
        : mConnManager(io_ctx, [](std::span<const std::uint8_t>, asio::ip::udp::endpoint)
    {
        // Send function (unused in this simple demo)
        return asio::awaitable<void>{};
    })
    {
    }

    /**
     * @brief Handle an incoming QUIC datagram
     */
    asio::awaitable<bool> HandleDatagram(std::span<const std::uint8_t> data,
                                         asio::ip::udp::endpoint remote,
                                         SendDatagramFnT send_fn,
                                         asio::io_context &io_ctx)
    {
        ++mPacketCount;

        std::cout << std::format("[QUIC] Received {} bytes from {}\n",
                                 data.size(),
                                 remote.address().to_string() + ":" + std::to_string(remote.port()));

        // Try to parse as QUIC packet
        auto parse_result = ParsePacketHeader(data);
        if (!parse_result)
        {
            std::cout << "[QUIC] Failed to parse packet header\n";
            co_return true;
        }

        const auto &parsed = *parse_result;

        // Handle based on header type
        if (std::holds_alternative<LongHeader>(parsed.header))
        {
            const auto &long_hdr = std::get<LongHeader>(parsed.header);

            std::cout << std::format("[QUIC] Parsed Long Header: type={}, dest_cid_len={}, src_cid_len={}\n",
                                     static_cast<int>(long_hdr.type),
                                     long_hdr.dest_conn_id.length,
                                     long_hdr.src_conn_id.length);

            // For Initial packets, we need to create a new connection
            if (long_hdr.type == PacketType::Initial)
            {
                std::cout << "[QUIC] Processing Initial packet\n";

                // Create server-side connection ID
                ConnectionId server_cid = GenerateConnectionId();

                std::cout << std::format("[QUIC] Generated server connection ID (length={})\n",
                                         server_cid.length);

                // Accept new connection
                [[maybe_unused]] auto &conn = mConnManager.AcceptConnection(long_hdr.dest_conn_id, remote);
                ++mConnectionCount;

                std::cout << std::format("[QUIC] Accepted connection #{}\n", mConnectionCount);

                // For now, just log that we received the Initial packet
                // In a real implementation, we would:
                // 1. Decrypt the Initial packet
                // 2. Parse CRYPTO frames
                // 3. Feed to TLS engine
                // 4. Generate Initial/Handshake response
                // 5. Send back via send_fn

                std::cout << "[QUIC] TODO: Process TLS handshake\n";
            }
            else
            {
                std::cout << std::format("[QUIC] TODO: Handle long header packet type {}\n",
                                         static_cast<int>(long_hdr.type));
            }
        }
        else
        {
            const auto &short_hdr = std::get<ShortHeader>(parsed.header);
            std::cout << std::format("[QUIC] Parsed Short Header: dest_cid_len={}\n",
                                     short_hdr.dest_conn_id.length);
            std::cout << "[QUIC] TODO: Handle short header (1-RTT) packet\n";
        }

        co_return true;
    }

    void PrintStats() const
    {
        std::cout << std::format("\n[Stats] Packets: {}, Connections: {}\n",
                                 mPacketCount,
                                 mConnectionCount);
    }

  private:
    /**
     * @brief Generate a random connection ID
     */
    static ConnectionId GenerateConnectionId()
    {
        ConnectionId cid;
        cid.length = 8; // Use 8-byte connection IDs

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);

        for (std::size_t i = 0; i < cid.length; ++i)
        {
            cid.data[i] = static_cast<std::uint8_t>(dis(gen));
        }

        return cid;
    }
};

// ============================================================================
// Main
// ============================================================================

int main(int argc, char *argv[])
{
    // Parse command-line arguments
    unsigned short port = 9002; // Default QUIC port

    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if ((arg == "--port" || arg == "-p") && i + 1 < argc)
        {
            port = static_cast<unsigned short>(std::stoi(argv[++i]));
        }
        else if (arg == "--help" || arg == "-h")
        {
            std::cout << "Usage: quic_echo_server [--port PORT]\n";
            std::cout << "  --port, -p PORT   Port to listen on (default: 9002)\n";
            std::cout << "  --help, -h        Show this help message\n";
            return 0;
        }
    }

    // Set up signal handlers
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    try
    {
        std::cout << std::format("Starting QUIC echo server on port {}...\n", port);

        // Create the server
        asio::io_context io_ctx(2); // Create io_context for handler
        MicroUdpServer<QuicEchoHandler> server(
            port,
            QuicEchoHandler{io_ctx}, // Handler with io_context
            2);                      // 2 threads

        std::cout << std::format("QUIC echo server listening on UDP port {}\n", port);
        std::cout << "Press Ctrl+C to stop\n\n";

        // Wait for shutdown signal
        {
            std::unique_lock<std::mutex> lock(shutdownMutex);
            shutdownCV.wait(lock, []
            { return !keepRunning.load(); });
        }

        std::cout << "\n[Shutdown] Stopping server...\n";
        server.Stop();

        // Print final statistics
        std::cout << "\n[Shutdown] Final statistics:\n";
        // Note: Can't access handler after server stops, so stats would need to be moved out

        std::cout << "[Shutdown] Server stopped\n";
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
