// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "http/http3_proto.h"
#include "http/http3_apirouter.h"
#include "http/http3_async_static_router.h"
#include "http/http3_session_adapter.h"
#include "micro_udp_server.h"
#include "quic/quic_key_extractor.h"
#include "util/udp_connection_multiplexer.h"
#include "nlohmann/json_fwd.hpp"

#include <array>
#include <asio/ip/udp.hpp>
#include <atomic>
#include <csignal>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <filesystem>
#include <condition_variable>
#include <mutex>
#include <memory>
#include <fstream>
#include <random>
#include <span>
#include <sstream>
#include <string>
#include <sys/types.h>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
typedef int ssize_t;
#define pipe _pipe
#define read _read
#define write _write
#define close _close
#else
#include <unistd.h>
#endif

#include <config.h>
#include <config_json_parser.h>
#include <nlohmann/json.hpp>

#include <asio.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>

#include "quic/connection_id.h"
#include "asan_notify.h"

using namespace clv;
using namespace clv::quic;
using namespace clv::http3;
using namespace clv::config;

// Global flag for graceful shutdown
std::atomic<bool> keepRunning{true};
std::condition_variable shutdownCV;
std::mutex shutdownMutex;
static int sig_pipe_fds[2] = {-1, -1};

void signalHandler(int signum)
{
    keepRunning = false;
    if (sig_pipe_fds[1] != -1)
    {
        const unsigned char c = 1;
        auto result_ignored = write(sig_pipe_fds[1], &c, 1);
        static_cast<void>(result_ignored);
    }
}

// Connection ID generator for new QUIC connections
ConnectionId GenerateConnectionId()
{
    ConnectionId cid;
    cid.length = 8;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (std::uint8_t i = 0; i < cid.length; ++i)
    {
        cid.data[i] = static_cast<std::uint8_t>(dis(gen));
    }
    return cid;
}

// Factory that generates server connection IDs and registers sessions under multiple keys
struct QuicSessionFactoryWithMultiKey
{
    using SessionType = Http3Session<ApiRouter, Http3AsyncStaticRouter>;
    using FactoryType = Http3SessionFactory<ApiRouter, Http3AsyncStaticRouter>;

    FactoryType inner_factory;
    UdpConnectionMultiplexer<SessionType, QuicKeyExtractor, QuicSessionFactoryWithMultiKey> *multiplexer;

    QuicSessionFactoryWithMultiKey(
        FactoryType factory,
        UdpConnectionMultiplexer<SessionType, QuicKeyExtractor, QuicSessionFactoryWithMultiKey> *mux)
        : inner_factory(std::move(factory)), multiplexer(mux)
    {
    }

    std::shared_ptr<SessionType> Create(const ConnectionId &client_dcid,
                                        std::span<const uint8_t> initial_packet,
                                        asio::ip::udp::endpoint remote,
                                        asio::io_context &io_ctx)
    {
        // Generate server connection ID
        ConnectionId server_cid = GenerateConnectionId();

        // Create session using server CID as key
        auto session = inner_factory.Create(server_cid, initial_packet, remote, io_ctx);
        if (!session)
        {
            return nullptr;
        }

        // Register session under BOTH client's DCID AND server's generated CID
        // Client uses client_dcid for Initial packets, server_cid for subsequent packets
        multiplexer->RegisterSessionKey(server_cid, session);

        std::cout << "[Server] Created session with server CID: ";
        for (std::uint8_t i = 0; i < server_cid.length; ++i)
        {
            std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)server_cid.data[i];
        }
        std::cout << std::dec << std::endl;

        return session;
    }
};

int main(int argc, char *argv[])
{
    clv_announce_asan();
    try
    {
        // Default config file
        std::string config_file = "server_config.json";
        if (argc > 1)
        {
            config_file = argv[1];
        }

        // Load configuration
        std::cout << "Loading configuration from: " << config_file << std::endl;
        auto cfg = ConfigJsonParser<std::string, int, double, bool>::ParseFile(config_file);

        // Extract config values
        std::string host = cfg["server"]["host"].get<std::string>();
        unsigned short port = static_cast<unsigned short>(cfg["server"]["port"].get<int>());
        int threads = cfg["server"]["threads"].get<int>(4);
        std::string cert_path = cfg["ssl"]["cert_path"].get<std::string>();
        std::string key_path = cfg["ssl"]["key_path"].get<std::string>();
        std::string static_root = cfg["static"]["root_dir"].get<std::string>();
        std::string default_file = cfg["static"]["default_file"].get<std::string>("index.html");
        bool api_enable = cfg["api"]["enable"].get<bool>(true);

        // Verify paths exist
        if (!std::filesystem::exists(cert_path))
        {
            std::cerr << "Error: Certificate file not found: " << cert_path << std::endl;
            return 1;
        }
        if (!std::filesystem::exists(key_path))
        {
            std::cerr << "Error: Private key file not found: " << key_path << std::endl;
            return 1;
        }
        if (!std::filesystem::exists(static_root))
        {
            std::cerr << "Warning: Static root directory not found: " << static_root << std::endl;
            std::cerr << "Creating directory..." << std::endl;
            std::filesystem::create_directories(static_root);
        }

        std::cout << "Configuration loaded successfully:\n";
        std::cout << "  Host: " << host << std::endl;
        std::cout << "  Port: " << port << std::endl;
        std::cout << "  Threads: " << threads << std::endl;
        std::cout << "  SSL Cert: " << cert_path << std::endl;
        std::cout << "  SSL Key: " << key_path << std::endl;
        std::cout << "  Static Root: " << static_root << std::endl;
        std::cout << "  Default File: " << default_file << std::endl;
        std::cout << "  API enabled: " << api_enable << std::endl;

        // Create self-pipe for signal handling
#ifdef _WIN32
        if (_pipe(sig_pipe_fds, 256, _O_BINARY) == -1)
#else
        if (pipe(sig_pipe_fds) == -1)
#endif
        {
            std::cerr << "Failed to create signal pipe" << std::endl;
            return 1;
        }

        signal(SIGINT, signalHandler);
        signal(SIGTERM, signalHandler);

        // Load config JSON for /api/config endpoint
        std::string cfgJson;
        try
        {
            nlohmann::json j;
            std::ifstream cfgf(config_file);
            cfgf >> j;
            cfgJson = j.dump(2);
        }
        catch (const std::exception &)
        {
            std::ostringstream cfgoss;
            cfgoss << "{\n";
            cfgoss << "  \"host\": \"" << host << "\",\n";
            cfgoss << "  \"port\": " << port << ",\n";
            cfgoss << "  \"threads\": " << threads << "\n";
            cfgoss << "}\n";
            cfgJson = cfgoss.str();
        }

        // Create routers using dispatcher pattern
        using RouterDispatchT = Http3RequestDispatcher<ApiRouter, Http3AsyncStaticRouter>;
        std::vector<RouterDispatchT> routers;
        routers.emplace_back(std::in_place_type<ApiRouter>, cfgJson, api_enable);
        routers.emplace_back(std::in_place_type<Http3AsyncStaticRouter>, "/", std::filesystem::path(static_root), default_file);

        std::cout << "\nStarting HTTP/3 QUIC server on " << host << ":" << port << "..." << std::endl;
        std::cout << "  ALPN: h3 (HTTP/3)" << std::endl;
        std::cout << "  API endpoints:" << std::endl;
        std::cout << "    https://" << host << ":" << port << "/api/hello" << std::endl;
        std::cout << "    https://" << host << ":" << port << "/api/config" << std::endl;
        std::cout << "  Static files served from: " << static_root << std::endl;
        std::cout << "\nPress Ctrl+C to stop." << std::endl;

        // Create multiplexer with key extractor and factory
        using SessionType = Http3Session<ApiRouter, Http3AsyncStaticRouter>;
        using MultiplexerType = UdpConnectionMultiplexer<SessionType, QuicKeyExtractor, QuicSessionFactoryWithMultiKey>;

        // Create UDP server and construct the multiplexer in place
        MicroUdpServer<MultiplexerType> server(
            port,
            threads,
            std::in_place,
            QuicSessionFactoryWithMultiKey(
                Http3SessionFactory<ApiRouter, Http3AsyncStaticRouter>(
                    cert_path,
                    key_path,
                    std::move(routers),
                    keepRunning),
                nullptr),
            QuicKeyExtractor{});

        // Now update the factory's multiplexer pointer to point to the actual multiplexer
        server.GetHandler().GetSessionFactory().multiplexer = &server.GetHandler();

        std::cout << "[Server] MicroUdpServer created with UdpConnectionMultiplexer" << std::endl;
        std::cout << "[Server] Using QuicKeyExtractor for packet routing" << std::endl;
        std::cout << "[Server] Using Http3SessionFactory for session creation" << std::endl;

        // Wait for shutdown signal
        char buf;
        ssize_t r = read(sig_pipe_fds[0], &buf, 1);
        (void)r;

        // Stop server
        std::cout << "\nStopping server..." << std::endl;

        // Close pipe
        close(sig_pipe_fds[0]);
        close(sig_pipe_fds[1]);

        std::cout << "Server stopped." << std::endl;
        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}