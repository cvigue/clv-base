// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include "ci_string.h"
#include "nlohmann/json_fwd.hpp"
#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <exception>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <csignal>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <utility>

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
#include <array_deque.h>

#include "micro_tls_server.h"
#include "http/HttpProto.h"
#include "http/HttpRequest.h"
#include "http/HttpResponse.h"
#include "http/HttpStaticRouter.h"
#include "http/HttpDefs.h"
#include "asan_notify.h"

using namespace clv;
using namespace clv::http;
using namespace clv::config;
using namespace clv::ServerDefs;

// Global flag for graceful shutdown
std::atomic<bool> keepRunning{true};
std::condition_variable shutdownCV;
std::mutex shutdownMutex;
static int sig_pipe_fds[2] = {-1, -1};

void signalHandler(int signum)
{
    // Async-signal-safe notification: write a single byte to the self-pipe.
    // Also set the atomic flag for any busy-waiting threads.
    keepRunning = false;
    if (sig_pipe_fds[1] != -1)
    {
        const unsigned char c = 1;
        // Ignore errors; write is async-signal-safe.
        auto result_ignored = write(sig_pipe_fds[1], &c, 1);
        static_cast<void>(result_ignored);
    }
} // "That good ship and true was a bone to be chewed" - Wreck of the Edmund Fitzgerald

// Simple API router with config
struct ApiRouter
{
    std::string mConfigJson;
    bool mEnabled;

    ApiRouter() = default;
    explicit ApiRouter(std::string cfgJson, bool enable)
        : mConfigJson(std::move(cfgJson)), mEnabled(enable)
    {
    }
    asio::awaitable<bool> RouteMsg(HttpRequest msg,
                                   SendingFuncT rfn,
                                   asio::io_context &io_ctx)
    {
        if (mEnabled && msg.url.starts_with("/api/"))
        {
            if (msg.url == "/api/hello")
            {
                std::cout << "[API] Handling /api/hello" << std::endl;
                auto response = HttpResponse(200, std::string_view("Hello from Simple Server!"));
                response.AddHeaderIfAbsent("Content-Type"_cis, "text/plain");
                std::cout << "[API] Sending response" << std::endl;
                co_await rfn(response.AsBuffer());
                std::cout << "[API] Response sent" << std::endl;
                co_return true;
            }

            if (msg.url == "/api/config")
            {
                std::cout << "[API] Handling /api/config" << std::endl;
                auto body = std::string_view(mConfigJson);
                auto response = HttpResponse(200, body);
                response.AddHeaderIfAbsent("Content-Type"_cis, "application/json");
                co_await rfn(response.AsBuffer());
                co_return true;
            }

            // API endpoint not found
            std::cout << "[API] Unknown endpoint: " << msg.url << std::endl;
            auto response = HttpResponse(404, std::string_view("API endpoint not found"));
            response.AddHeaderIfAbsent("Content-Type"_cis, "text/plain");
            co_await rfn(response.AsBuffer());
            co_return true;
        }

        // Not an API route
        co_return false;
    }
};

int main(int argc, char *argv[])
{
    // Announce ASAN only if compiled with AddressSanitizer
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
        int threads = cfg["server"]["threads"].get<int>(4); // default to 4
        std::string cert_path = cfg["ssl"]["cert_path"].get<std::string>();
        std::string key_path = cfg["ssl"]["key_path"].get<std::string>();
        std::string dh_path = cfg["ssl"]["dh_path"].get<std::string>();
        std::string static_root = cfg["static"]["root_dir"].get<std::string>();
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
        if (!std::filesystem::exists(dh_path))
        {
            std::cerr << "Error: DH params file not found: " << dh_path << std::endl;
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
        std::cout << "  Static Root: " << static_root << std::endl;
        std::cout << "  API enabled: " << api_enable << std::endl;

        // Create a self-pipe for safe signal handling and install the handler.
#ifdef _WIN32
        if (_pipe(sig_pipe_fds, 256, _O_BINARY) == -1)
#else
        if (pipe(sig_pipe_fds) == -1)
#endif
        {
            std::cerr << "Failed to create signal pipe" << std::endl;
            return 1;
        }
        // Install signal handler that writes to the pipe (async-signal-safe)
        signal(SIGINT, signalHandler);
        signal(SIGTERM, signalHandler);

        // Create protocol handler with multiple routers (tried in order)
        // HTTP servers automatically start reading after connection
        using ServerProto = HttpServerProto<ApiRouter, HttpStaticRouter>;

        // Load and pretty-print the full server_config.json for /api/config
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
            // Fallback to minimal info if parsing fails
            std::ostringstream cfgoss;
            cfgoss << "{\n";
            cfgoss << "  \"host\": \"" << host << "\",\n";
            cfgoss << "  \"port\": " << port << ",\n";
            cfgoss << "  \"threads\": " << threads << "\n";
            cfgoss << "}\n";
            cfgJson = cfgoss.str();
        }

        ServerProto protoHandler({
            ApiRouter(cfgJson, api_enable),                            // API routes first
            HttpStaticRouter("/", std::filesystem::path(static_root)), // Static files at root URL
        });

        // Create and start the TLS server
        std::cout << "Starting HTTPS server on " << host << ":" << port << "..." << std::endl;
        auto server = MicroTlsServer<ServerProto>(port,
                                                  cert_path,
                                                  key_path,
                                                  dh_path,
                                                  std::move(protoHandler),
                                                  threads);

        std::cout << "Server started successfully!" << std::endl;
        std::cout << "  API endpoints:" << std::endl;
        std::cout << "    https://" << host << ":" << port << "/api/hello" << std::endl;
        std::cout << "    https://" << host << ":" << port << "/api/config" << std::endl;
        std::cout << "  Static files served from: " << static_root << std::endl;
        std::cout << "\nPress Ctrl+C to stop." << std::endl;

        // Wait for shutdown signal via the self-pipe. The signal handler writes
        // a single byte to the pipe to wake us up. This avoids calling
        // non-async-signal-safe functions from the handler.
        char buf;
        // Blocking read; will return when a signal writes into the pipe.
        ssize_t r = read(sig_pipe_fds[0], &buf, 1);
        (void)r; // ignore read errors here; we'll shutdown either way

        // Close the pipe fds
        close(sig_pipe_fds[0]);
        close(sig_pipe_fds[1]);

        std::cout << "\nStopping server..." << std::endl;
        // Request server to stop gracefully
        try
        {
            server.Stop();
        }
        catch (...)
        {
        }
        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
