// Copyright (c) 2023- Charlie Vigue. All rights reserved.

/**
 * @file udp_echo_demo.cpp
 * @brief Simple UDP echo server demonstration
 *
 * This demo shows the basic usage of MicroUdpServer with a simple echo handler.
 * It echoes back any datagram it receives to the sender.
 *
 * Usage:
 *   udp_echo_demo [--port PORT]
 *
 * Test with:
 *   echo "hello" | nc -u localhost 9001
 *   # Or for interactive mode:
 *   nc -u localhost 9001
 */

#include "micro_udp_server.h"
#include "asan_notify.h"

#include <iostream>
#include <string>
#include <csignal>
#include <atomic>
#include <condition_variable>
#include <mutex>

#ifdef _WIN32
#include <io.h>
typedef int ssize_t;
#else
#include <unistd.h>
#endif

using namespace clv;
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
// Echo Handler
// ============================================================================

/**
 * @brief Simple echo handler that sends received data back to sender
 */
struct EchoHandler
{
    std::size_t mPacketCount{0};
    std::size_t mByteCount{0};

    /**
     * @brief Handle an incoming datagram by echoing it back
     */
    asio::awaitable<bool> HandleDatagram(std::span<const std::uint8_t> data,
                                         asio::ip::udp::endpoint remote,
                                         SendDatagramFnT send_fn,
                                         [[maybe_unused]] asio::io_context &io_ctx)
    {
        ++mPacketCount;
        mByteCount += data.size();

        // Log the received data
        std::string data_str(reinterpret_cast<const char *>(data.data()), data.size());

        // Trim trailing newline for display
        while (!data_str.empty() && (data_str.back() == '\n' || data_str.back() == '\r'))
            data_str.pop_back();

        std::cout << std::format("[Echo] Received {} bytes from {}: \"{}\"\n",
                                 data.size(),
                                 remote.address().to_string() + ":" + std::to_string(remote.port()),
                                 data_str);

        // Echo it back
        buffer_type response(data.begin(), data.end());
        co_await send_fn(std::move(response), remote);

        std::cout << std::format("[Echo] Sent {} bytes back to {}\n",
                                 data.size(),
                                 remote.address().to_string() + ":" + std::to_string(remote.port()));

        co_return true;
    }

    void PrintStats() const
    {
        std::cout << std::format("\n[Stats] Packets: {}, Bytes: {}\n",
                                 mPacketCount,
                                 mByteCount);
    }
};

// ============================================================================
// Main
// ============================================================================

void printUsage(const char *progName)
{
    std::cout << "Usage: " << progName << " [--port PORT]\n";
    std::cout << "\nOptions:\n";
    std::cout << "  --port PORT    UDP port to listen on (default: 9001)\n";
    std::cout << "\nTest with:\n";
    std::cout << "  echo \"hello\" | nc -u localhost PORT\n";
    std::cout << "  nc -u localhost PORT  # Interactive mode\n";
}

int main(int argc, char *argv[])
{
    clv_announce_asan();

    unsigned short port = 9001;

    // Parse command line arguments
    for (int i = 1; i < argc; ++i)
    {
        std::string_view arg = argv[i];

        if (arg == "--help" || arg == "-h")
        {
            printUsage(argv[0]);
            return 0;
        }
        else if (arg == "--port" && i + 1 < argc)
        {
            port = static_cast<unsigned short>(std::stoi(argv[++i]));
        }
        else
        {
            std::cerr << "Unknown argument: " << arg << "\n";
            printUsage(argv[0]);
            return 1;
        }
    }

    // Set up signal handlers
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    std::cout << "==========================================\n";
    std::cout << "    UDP Echo Server Demo\n";
    std::cout << "    MicroUdpServer Demonstration\n";
    std::cout << "==========================================\n\n";

    try
    {
        EchoHandler handler;

        std::cout << std::format("[Main] Starting UDP echo server on port {}...\n", port);

        MicroUdpServer server(port, std::move(handler));

        std::cout << std::format("[Main] Server listening on UDP port {}\n", server.LocalPort());
        std::cout << "[Main] Press Ctrl+C to stop\n\n";
        std::cout << "Test with: echo \"hello\" | nc -u localhost " << server.LocalPort() << "\n\n";

        // Wait for shutdown signal
        {
            std::unique_lock<std::mutex> lock(shutdownMutex);
            shutdownCV.wait(lock, []
            { return !keepRunning.load(); });
        }

        std::cout << "\n[Main] Stopping server...\n";
        server.Stop();

        // Note: handler was moved into server, so we can't access stats here
        // In a real app, you'd keep a shared_ptr or similar

        std::cout << "[Main] Server stopped cleanly\n";
    }
    catch (const std::exception &e)
    {
        std::cerr << "[Error] " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
