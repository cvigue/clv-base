// Copyright (c) 2023- Charlie Vigue. All rights reserved.

/**
 * @file stun_test_client.cpp
 * @brief Simple command-line STUN test client for network testing
 *
 * This utility demonstrates the STUN client functionality and can be used
 * to test NAT detection on different networks.
 */

#include "stun/stun_client.h"
#include <asio/as_tuple.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/address_v4.hpp>
#include <asio/ip/udp.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <cstdint>
#include <iostream>
#include <chrono>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <exception>
#include <stdexcept>

#include "asan_notify.h"

using namespace clv::netcore;

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

void print_banner()
{
    std::cout << "==========================================\n";
    std::cout << "    STUN Test Client v1.0\n";
    std::cout << "    RFC 3489/5780 NAT Detection\n";
    std::cout << "==========================================\n\n";
}

void print_usage(const char *program_name)
{
    std::cout << "Usage: " << program_name << " [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -h, --help              Show this help message\n";
    std::cout << "  -s, --server HOST:PORT  Use specific STUN server, can be used multiple times\n"
              << "                          (default: uses built-in servers)\n";
    std::cout << "  -t, --timeout MS        Set timeout in milliseconds (default: 5000)\n";
    std::cout << "  -q, --quick             Quick discovery only (no comprehensive NAT detection)\n";
    std::cout << "  -v, --verbose           Verbose output\n";
    std::cout << "  -c, --comprehensive     Run comprehensive NAT detection (default)\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << program_name << "                            # Quick test with default servers\n";
    std::cout << "  " << program_name << " -c                         # Comprehensive NAT detection\n";
    std::cout << "  " << program_name << " -s stun.l.google.com:19302 # Use specific server\n";
    std::cout << "  " << program_name << " -t 10000 -v                # 10s timeout with verbose output\n\n";
    std::cout << "NAT Types (from best to worst for P2P):\n";
    std::cout << "  🌐 Open Internet      - No NAT, has public IP\n";
    std::cout << "  🔓 Full Cone          - Permissive, any external host can reach you\n";
    std::cout << "  🔒 Restricted Cone    - Filters by source IP only (needs hole punch)\n";
    std::cout << "  🔐 Port Restricted    - Filters by source IP:port (difficult P2P)\n";
    std::cout << "  🔄 Symmetric NAT      - Different ports per destination (needs relay)\n";
    std::cout << "  🚫 Blocked/Firewall   - No UDP connectivity (needs relay)\n\n";
}

void print_nat_type_info(nat_type type)
{
    std::cout << "\nNAT Type Analysis:\n";
    std::cout << "=================\n";

    switch (type)
    {
    case nat_type::open_internet:
        std::cout << "🌐 Open Internet - No NAT detected\n";
        std::cout << "   Your device has a public IP address and can receive\n";
        std::cout << "   connections from anywhere on the internet.\n";
        break;

    case nat_type::full_cone:
        std::cout << "🔓 Full Cone NAT - Most permissive NAT\n";
        std::cout << "   External hosts can connect to you if they know your\n";
        std::cout << "   public IP and port. Good for P2P applications.\n";
        break;

    case nat_type::restricted_cone:
        std::cout << "🔒 Restricted Cone NAT - Moderately restrictive\n";
        std::cout << "   External hosts can only connect if you've previously\n";
        std::cout << "   sent packets to their IP address.\n";
        break;

    case nat_type::port_restricted_cone:
        std::cout << "🔐 Port Restricted Cone NAT - More restrictive\n";
        std::cout << "   External hosts can only connect if you've previously\n";
        std::cout << "   sent packets to their exact IP:port combination.\n";
        break;

    case nat_type::symmetric:
        std::cout << "🔄 Symmetric NAT - Most restrictive\n";
        std::cout << "   Different external destinations see different public\n";
        std::cout << "   IP:port combinations. Difficult for P2P applications.\n";
        break;

    case nat_type::blocked:
        std::cout << "🚫 Blocked/Firewall - No connectivity\n";
        std::cout << "   STUN requests are being blocked by firewall or\n";
        std::cout << "   network configuration.\n";
        break;

    case nat_type::unknown:
    default:
        std::cout << "❓ Unknown NAT Type\n";
        std::cout << "   Unable to determine NAT characteristics.\n";
        break;
    }
}

void print_hairpin_info(bool hairpin_supported)
{
    std::cout << "\nHairpin Detection:\n";
    std::cout << "==================\n";

    if (hairpin_supported)
    {
        std::cout << "✅ Hairpin Supported\n";
        std::cout << "   Your NAT supports hairpinning (loopback to external address).\n";
        std::cout << "   This means devices on your local network can connect to each\n";
        std::cout << "   other using the external IP address. Common in UPnP-enabled\n";
        std::cout << "   routers. Good for local P2P applications.\n";
    }
    else
    {
        std::cout << "❌ Hairpin Not Supported\n";
        std::cout << "   Your NAT does not support hairpinning (loopback to external).\n";
        std::cout << "   Devices on your local network cannot connect via the external\n";
        std::cout << "   IP address. They must use local IP addresses instead.\n";
    }
}

asio::awaitable<void> run_quick_test(stun_client &client, bool verbose)
{
    std::cout << "Running quick public address discovery...\n";

    // Get local endpoint info and actual LAN IP
    auto local_ep = client.get_socket().local_endpoint();

    auto executor = co_await asio::this_coro::executor;
    asio::io_context &io_ctx = static_cast<asio::io_context &>(executor.context());
    auto local_ip = co_await get_local_address(io_ctx);

    std::string local_addr_str = local_ip ? local_ip->to_string() : local_ep.address().to_string();
    std::cout << "\nLocal Socket: " << local_addr_str << ":" << local_ep.port() << "\n";

    auto start_time = std::chrono::steady_clock::now();
    auto result = co_await client.discover_public_address();
    auto end_time = std::chrono::steady_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    if (result.success)
    {
        std::cout << "✅ Success!\n";
        std::cout << "\nAddress Mapping:\n";
        std::cout << "  Local:      " << local_addr_str << ":" << local_ep.port() << "\n";
        std::cout << "  Translated: " << result.public_addr.to_string() << "\n";
        if (local_ep.port() != result.public_addr.port)
            std::cout << "  Local port " << local_ep.port() << " translated by NAT to " << result.public_addr.port << "\n";
        std::cout << "\nResponse Time: " << duration.count() << "ms\n";

        if (verbose)
        {
            std::cout << "Server Response Time: " << result.response_time.count() << "ms\n";
        }
    }
    else
    {
        std::cout << "❌ Failed: " << result.error_message << "\n";
        std::cout << "   Total Time: " << duration.count() << "ms\n";
    }

    co_return;
}

asio::awaitable<void> run_comprehensive_test(stun_client &client, bool verbose, std::chrono::milliseconds timeout)
{
    std::cout << "Running comprehensive NAT detection...\n";

    // Get local endpoint info and actual LAN IP
    auto local_ep = client.get_socket().local_endpoint();

    auto executor = co_await asio::this_coro::executor;
    asio::io_context &io_ctx = static_cast<asio::io_context &>(executor.context());
    auto local_ip = co_await get_local_address(io_ctx);

    std::string local_addr_str = local_ip ? local_ip->to_string() : local_ep.address().to_string();
    std::cout << "\nLocal Socket: " << local_addr_str << ":" << local_ep.port() << "\n";

    stun_client::nat_detection_config config;
    config.individual_test_timeout = timeout; // Each test gets the full timeout
    config.fallback_to_rfc3489 = true;
    config.use_rfc5780_attributes = true;

    // Set the local LAN address for hairpin detection
    if (local_ip)
    {
        config.local_lan_addr = *local_ip;
    }
    else
    {
        config.local_lan_addr = local_ep.address().to_v4();
    }

    if (verbose)
    {
        std::cout << "Configuration:\n";
        std::cout << "  Individual test timeout: " << config.individual_test_timeout.count() << "ms\n";
        std::cout << "  RFC 5780 attributes: " << (config.use_rfc5780_attributes ? "enabled" : "disabled") << "\n";
        std::cout << "  RFC 3489 fallback: " << (config.fallback_to_rfc3489 ? "enabled" : "disabled") << "\n\n";
    }

    auto start_time = std::chrono::steady_clock::now();
    auto result = co_await client.detect_nat_type(config);
    auto end_time = std::chrono::steady_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    if (result.success)
    {
        std::cout << "✅ NAT Detection Complete!\n";
        std::cout << "\nAddress Mapping:\n";
        std::cout << "  Local:      " << local_addr_str << ":" << local_ep.port() << "\n";
        std::cout << "  Translated: " << result.public_addr.to_string() << "\n";
        if (local_ep.port() != result.public_addr.port)
            std::cout << "  Local port " << local_ep.port() << " translated by NAT to " << result.public_addr.port << "\n";
        std::cout << "\nDetected Type: " << to_string(result.detected_nat_type) << "\n";
        std::cout << "Total Time: " << duration.count() << "ms\n";
        std::cout << "Server Response Time: " << result.response_time.count() << "ms\n";

        if (verbose)
        {
            std::cout << "Hairpin Supported: " << (result.hairpin_supported ? "yes" : "no") << "\n";
        }

        print_nat_type_info(result.detected_nat_type);
        print_hairpin_info(result.hairpin_supported);
    }
    else
    {
        std::cout << "❌ NAT Detection Failed: " << result.error_message << "\n";
        std::cout << "   Total Time: " << duration.count() << "ms\n";

        // Try fallback to quick discovery
        std::cout << "\nTrying fallback to quick discovery...\n";
        co_await run_quick_test(client, verbose);
    }
}

asio::awaitable<void> run_tests(bool quick_only, bool verbose, std::chrono::milliseconds timeout,
                                const std::vector<stun_client::stun_server_endpoint> &custom_servers)
{
    try
    {
        auto executor = co_await asio::this_coro::executor;
        asio::io_context &io_ctx = static_cast<asio::io_context &>(executor.context());
        stun_client client(io_ctx, custom_servers); // Use auto port

        // Set up logging in verbose mode
        if (verbose)
        {
            client.set_logger([](int level, std::string_view message)
            {
                const char *level_str = "";
                switch (level)
                {
                case 0:
                    // Verbose, no tagging
                    break;
                case 1:
                    level_str = "[DEBUG]";
                    break;
                case 2:
                    level_str = "[WARN]";
                    break;
                case 3:
                    level_str = "[ERROR]";
                    break;
                default:
                    level_str = "🍿";
                    break;
                }
                std::cout << "  " << level_str << " " << message << "\n";
            });

            std::cout << "Using default STUN servers\n\n";
            for (auto &&server : client.get_servers())
            {
                std::cout << "  " << server.host << ":" << server.port << "\n";
            }
            std::cout << "\n";
        }

        if (quick_only)
        {
            co_await run_quick_test(client, verbose);
        }
        else
        {
            co_await run_comprehensive_test(client, verbose, timeout);
        }
    }
    catch (const std::exception &e)
    {
        std::cout << "❌ Error: " << e.what() << "\n";
    }

    co_return;
}

std::pair<std::string, uint16_t> parse_server_endpoint(const std::string &endpoint)
{
    auto colon_pos = endpoint.find_last_of(':');
    if (colon_pos == std::string::npos)
    {
        throw std::invalid_argument("Invalid server format. Use HOST:PORT");
    }

    std::string host = endpoint.substr(0, colon_pos);
    std::string port_str = endpoint.substr(colon_pos + 1);

    uint16_t port = static_cast<uint16_t>(std::stoul(port_str));

    return {host, port};
}

int main(int argc, char *argv[])
{
    clv_announce_asan();
    print_banner();

    bool quick_only = false;
    bool verbose = false;
    bool comprehensive = false;
    std::chrono::milliseconds timeout{5000};
    std::vector<stun_client::stun_server_endpoint> custom_servers;

    // Parse command line arguments
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help")
        {
            print_usage(argv[0]);
            return 0;
        }
        else if (arg == "-q" || arg == "--quick")
        {
            quick_only = true;
        }
        else if (arg == "-v" || arg == "--verbose")
        {
            verbose = true;
        }
        else if (arg == "-c" || arg == "--comprehensive")
        {
            comprehensive = true;
        }
        else if (arg == "-s" || arg == "--server")
        {
            if (i + 1 >= argc)
            {
                std::cerr << "Error: --server requires a HOST:PORT argument\n";
                return 1;
            }

            try
            {
                auto [host, port] = parse_server_endpoint(argv[++i]);
                custom_servers.emplace_back(host, port);
            }
            catch (const std::exception &e)
            {
                std::cerr << "Error parsing server endpoint: " << e.what() << "\n";
                return 1;
            }
        }
        else if (arg == "-t" || arg == "--timeout")
        {
            if (i + 1 >= argc)
            {
                std::cerr << "Error: --timeout requires a milliseconds argument\n";
                return 1;
            }

            try
            {
                timeout = std::chrono::milliseconds{std::stoul(argv[++i])};
            }
            catch (const std::exception &e)
            {
                std::cerr << "Error parsing timeout: " << e.what() << "\n";
                return 1;
            }
        }
        else
        {
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    // Default to comprehensive if not specified
    if (!quick_only && !comprehensive)
    {
        comprehensive = true;
    }

    // Run the tests
    try
    {
        asio::io_context io_context;

        auto coro = run_tests(!comprehensive, verbose, timeout, custom_servers);
        asio::co_spawn(io_context, std::move(coro), asio::detached);

        io_context.run();

        std::cout << "\nTest completed successfully!\n";
        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Fatal error: " << e.what() << "\n";
        return 1;
    }
}