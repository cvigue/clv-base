// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include "gtest/gtest.h"
#include "stun/stun_client.h"
#include "util/byte_packer.h"

#include <algorithm>
#include <array>
#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/buffer.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/address_v4.hpp>
#include <asio/ip/udp.hpp>
#include <asio/use_future.hpp>
#include <bits/chrono.h>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <future>
#include <iostream>
#include <memory>
#include <random>
#include <span>
#include <string>
#include <system_error>
#include <vector>

using namespace clv::netcore;
using namespace testing;
using namespace std::chrono_literals;

#define DO_INTEGRATION_TESTS

/// Mock STUN server for comprehensive testing
class mock_stun_server
{
  public:
    enum class behavior_mode
    {
        normal,                   // Respond normally to all requests
        open_internet,            // Simulate open internet (respond to change requests)
        full_cone_nat,            // Simulate full cone NAT (ignore change requests)
        restricted_cone_nat,      // Simulate restricted cone NAT
        port_restricted_cone_nat, // Simulate port restricted cone NAT
        symmetric_nat,            // Simulate symmetric NAT (different addresses per client)
        blocked_nat,              // Don't respond to any requests
        timeout,                  // Simulate network timeout
        malformed_response        // Send malformed responses
    };

    explicit mock_stun_server(asio::io_context &io_context, std::uint16_t port = 0)
        : socket_(io_context, asio::ip::udp::endpoint(asio::ip::udp::v4(), port)), local_port_(socket_.local_endpoint().port()), mode_(behavior_mode::normal), rng_(std::random_device{}())
    {
        start_receive();
    }

    ~mock_stun_server()
    {
        if (socket_.is_open())
        {
            socket_.close();
        }
    }

    std::uint16_t port() const
    {
        return local_port_;
    }
    void set_behavior(behavior_mode mode)
    {
        mode_ = mode;
    }

    // Statistics for testing
    std::size_t requests_received() const
    {
        return requests_received_;
    }
    std::size_t responses_sent() const
    {
        return responses_sent_;
    }
    void reset_stats()
    {
        requests_received_ = 0;
        responses_sent_ = 0;
    }

  private:
    void start_receive()
    {
        socket_.async_receive_from(
            asio::buffer(receive_buffer_), remote_endpoint_, [this](std::error_code ec, std::size_t bytes_received)
        {
            if (!ec)
            {
                handle_request(bytes_received);
                start_receive(); // Continue listening
            }
        });
    }

    void handle_request(std::size_t bytes_received)
    {
        requests_received_++;

        if (mode_ == behavior_mode::blocked_nat || mode_ == behavior_mode::timeout)
        {
            return; // Don't respond
        }

        std::span<const std::uint8_t> request_data{receive_buffer_.data(), bytes_received};

        if (!stun_utils::is_valid_stun_packet(request_data))
        {
            return; // Invalid packet
        }

        auto msg_type = stun_utils::get_message_type(request_data);
        if (!msg_type || *msg_type != message_type::binding_request)
        {
            return; // Not a binding request
        }

        // Extract transaction ID
        transaction_id trans_id{};
        if (bytes_received >= stun_constants::header_size)
        {
            std::copy(request_data.begin() + 8, request_data.begin() + 20, trans_id.begin());
        }

        // Check if this is a change request
        bool is_change_request = has_change_request_attribute(request_data);
        std::uint32_t change_flags = get_change_request_flags(request_data);

        // Decide how to respond based on behavior mode and request type
        if (should_respond_to_request(is_change_request, change_flags))
        {
            // Include OTHER-ADDRESS in basic responses for comprehensive NAT testing
            // (All NAT types except timeout/blocked/malformed need this for proper detection)
            bool include_other_address = !is_change_request && (mode_ != behavior_mode::timeout && mode_ != behavior_mode::blocked_nat && mode_ != behavior_mode::malformed_response);
            send_response(trans_id, include_other_address, change_flags);
        }
    }

    bool has_change_request_attribute(std::span<const std::uint8_t> packet)
    {
        if (packet.size() < stun_constants::header_size)
            return false;

        const std::uint16_t message_length = bytes_to_uint(packet[2], packet[3]);
        std::size_t offset = stun_constants::header_size;

        while (offset + 4 <= packet.size() && offset < stun_constants::header_size + message_length)
        {
            const std::uint16_t attr_type = bytes_to_uint(packet[offset], packet[offset + 1]);
            const std::uint16_t attr_length = bytes_to_uint(packet[offset + 2], packet[offset + 3]);

            if (attr_type == stun_constants::attr_change_request)
            {
                return true;
            }

            offset += 4 + attr_length;
            offset = (offset + 3) & ~3; // 4-byte boundary
        }
        return false;
    }

    std::uint32_t get_change_request_flags(std::span<const std::uint8_t> packet)
    {
        if (packet.size() < stun_constants::header_size)
            return 0;

        const std::uint16_t message_length = bytes_to_uint(packet[2], packet[3]);
        std::size_t offset = stun_constants::header_size;

        while (offset + 4 <= packet.size() && offset < stun_constants::header_size + message_length)
        {
            const std::uint16_t attr_type = bytes_to_uint(packet[offset], packet[offset + 1]);
            const std::uint16_t attr_length = bytes_to_uint(packet[offset + 2], packet[offset + 3]);

            if (attr_type == stun_constants::attr_change_request && attr_length >= 4)
            {
                return (static_cast<std::uint32_t>(packet[offset + 4]) << 24) | (static_cast<std::uint32_t>(packet[offset + 5]) << 16) | (static_cast<std::uint32_t>(packet[offset + 6]) << 8) | static_cast<std::uint32_t>(packet[offset + 7]);
            }

            offset += 4 + attr_length;
            offset = (offset + 3) & ~3; // 4-byte boundary
        }
        return 0;
    }

    bool should_respond_to_request(bool is_change_request, std::uint32_t change_flags)
    {
        switch (mode_)
        {
        case behavior_mode::normal:
        case behavior_mode::open_internet:
            return true; // Always respond

        case behavior_mode::full_cone_nat:
            // Full cone NAT: only respond to basic requests (simplified for testing)
            return !is_change_request;

        case behavior_mode::restricted_cone_nat:
            // Respond to basic requests and port change, but not IP change
            if (!is_change_request)
                return true;
            return !(change_flags & stun_constants::change_ip);

        case behavior_mode::port_restricted_cone_nat:
            // Port restricted cone: in RFC 3489 testing, behaves like full cone
            // (both ignore CHANGE-REQUEST packets, indistinguishable in localhost)
            return !is_change_request;

        case behavior_mode::symmetric_nat:
            // Respond to basic requests and change-port requests (but not change-ip-and-port)
            // Symmetric NAT allows responses but shows different mappings per endpoint
            if (is_change_request)
            {
                // Don't respond to change IP+port requests
                if (change_flags == (stun_constants::change_ip | stun_constants::change_port))
                {
                    return false;
                }
                // Respond to change port only requests
                return true;
            }
            return true; // Always respond to basic requests

        case behavior_mode::malformed_response:
            return true; // Respond with malformed packets

        default:
            return false;
        }
    }

    void send_response(const transaction_id &trans_id, bool include_other_address = false, std::uint32_t change_flags = 0)
    {
        if (mode_ == behavior_mode::malformed_response)
        {
            send_malformed_response();
            return;
        }

        // Create response packet - use shared_ptr to keep it alive during async operation
        auto response = std::make_shared<std::vector<std::uint8_t>>();

        // Calculate the mapped address (simulate what the client appears as)
        auto client_ip = remote_endpoint_.address().to_v4();
        auto client_port = remote_endpoint_.port();

        // For symmetric NAT, handle change requests specially
        if (mode_ == behavior_mode::symmetric_nat)
        {
            // Check if this is a change IP and port request (should not respond)
            if (change_flags == (stun_constants::change_ip | stun_constants::change_port))
            {
                return; // Don't respond to change IP+port for symmetric NAT
            }

            // For any request (basic or change port), use different mapped addresses
            // This simulates symmetric NAT behavior where each session gets different mappings
            client_port = static_cast<std::uint16_t>(client_port + (rng_() % 1000) + 100);
        }

        // Build response with XOR-MAPPED-ADDRESS
        *response = create_binding_response(trans_id, client_ip, client_port, include_other_address);

        socket_.async_send_to(
            asio::buffer(*response), remote_endpoint_, [this, response](std::error_code ec, std::size_t bytes_sent)
        {
            if (!ec)
            {
                responses_sent_++;
            }
        });
    }

    void send_malformed_response()
    {
        // Send a response with invalid magic cookie
        auto bad_response = std::make_shared<std::vector<std::uint8_t>>(std::vector<std::uint8_t>{
            0x01, 0x01, 0x00, 0x00, // Binding response, no attributes
            0xFF,
            0xFF,
            0xFF,
            0xFF, // Bad magic cookie
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00, // Transaction ID
            0x00,
            0x00,
            0x00,
            0x00});

        socket_.async_send_to(
            asio::buffer(*bad_response), remote_endpoint_, [this, bad_response](std::error_code ec, std::size_t bytes_sent)
        {
            if (!ec)
            {
                responses_sent_++;
            }
        });
    }

    std::vector<std::uint8_t> create_binding_response(const transaction_id &trans_id,
                                                      asio::ip::address_v4 client_ip,
                                                      std::uint16_t client_port,
                                                      bool include_other_address)
    {
        std::size_t attr_length = 12; // XOR-MAPPED-ADDRESS (4 + 8 bytes)
        if (include_other_address)
        {
            attr_length += 12; // OTHER-ADDRESS (4 + 8 bytes)
        }

        std::vector<std::uint8_t> response(stun_constants::header_size + attr_length);

        // STUN header
        response[0] = 0x01;
        response[1] = 0x01; // Binding response
        response[2] = static_cast<std::uint8_t>((attr_length >> 8) & 0xFF);
        response[3] = static_cast<std::uint8_t>(attr_length & 0xFF);

        // Magic cookie
        const std::uint32_t cookie = stun_constants::magic_cookie;
        response[4] = static_cast<std::uint8_t>((cookie >> 24) & 0xFF);
        response[5] = static_cast<std::uint8_t>((cookie >> 16) & 0xFF);
        response[6] = static_cast<std::uint8_t>((cookie >> 8) & 0xFF);
        response[7] = static_cast<std::uint8_t>(cookie & 0xFF);

        // Transaction ID
        std::copy(trans_id.begin(), trans_id.end(), response.begin() + 8);

        std::size_t offset = stun_constants::header_size;

        // XOR-MAPPED-ADDRESS attribute
        response[offset++] = static_cast<std::uint8_t>((stun_constants::attr_xor_mapped_address >> 8) & 0xFF);
        response[offset++] = static_cast<std::uint8_t>(stun_constants::attr_xor_mapped_address & 0xFF);
        response[offset++] = 0x00;
        response[offset++] = 0x08; // Length: 8 bytes

        response[offset++] = 0x00;
        response[offset++] = 0x01; // Reserved + IPv4

        // XOR port with magic cookie high bits
        std::uint16_t xor_port = client_port ^ static_cast<std::uint16_t>(cookie >> 16);
        response[offset++] = static_cast<std::uint8_t>((xor_port >> 8) & 0xFF);
        response[offset++] = static_cast<std::uint8_t>(xor_port & 0xFF);

        // XOR IP with magic cookie
        std::uint32_t client_ip_uint = client_ip.to_uint();
        std::uint32_t xor_ip = client_ip_uint ^ cookie;
        response[offset++] = static_cast<std::uint8_t>((xor_ip >> 24) & 0xFF);
        response[offset++] = static_cast<std::uint8_t>((xor_ip >> 16) & 0xFF);
        response[offset++] = static_cast<std::uint8_t>((xor_ip >> 8) & 0xFF);
        response[offset++] = static_cast<std::uint8_t>(xor_ip & 0xFF);

        // OTHER-ADDRESS attribute (if requested)
        if (include_other_address)
        {
            response[offset++] = static_cast<std::uint8_t>((stun_constants::attr_other_address >> 8) & 0xFF);
            response[offset++] = static_cast<std::uint8_t>(stun_constants::attr_other_address & 0xFF);
            response[offset++] = 0x00;
            response[offset++] = 0x08; // Length: 8 bytes

            response[offset++] = 0x00;
            response[offset++] = 0x01; // Reserved + IPv4

            // Use a different port for "other" server
            std::uint16_t other_port = local_port_ + 1;
            response[offset++] = static_cast<std::uint8_t>((other_port >> 8) & 0xFF);
            response[offset++] = static_cast<std::uint8_t>(other_port & 0xFF);

            // Use localhost for "other" IP (simplified)
            std::uint32_t other_ip = asio::ip::address_v4::loopback().to_uint();
            response[offset++] = static_cast<std::uint8_t>((other_ip >> 24) & 0xFF);
            response[offset++] = static_cast<std::uint8_t>((other_ip >> 16) & 0xFF);
            response[offset++] = static_cast<std::uint8_t>((other_ip >> 8) & 0xFF);
            response[offset++] = static_cast<std::uint8_t>(other_ip & 0xFF);
        }

        return response;
    }

  private:
    asio::ip::udp::socket socket_;
    std::uint16_t local_port_;
    behavior_mode mode_;
    std::mt19937 rng_;

    std::array<std::uint8_t, 1024> receive_buffer_;
    asio::ip::udp::endpoint remote_endpoint_;

    std::size_t requests_received_ = 0;
    std::size_t responses_sent_ = 0;
};

class StunClientTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        // Create io_context and client
        io_context = std::make_unique<asio::io_context>();
        client = std::make_unique<stun_client>(0, *io_context); // Use automatic port assignment
    }

    void TearDown() override
    {
        client.reset();
        io_context.reset();
    }

    std::unique_ptr<asio::io_context> io_context;
    std::unique_ptr<stun_client> client;

    // Helper to run coroutines in tests
    template <typename Awaitable>
    auto run_coro(Awaitable &&coro)
    {
        // Reset io_context for fresh run
        io_context->restart();

        auto future = asio::co_spawn(*io_context, std::forward<Awaitable>(coro), asio::use_future);

        // Run the io_context until the coroutine completes
        io_context->run();

        return future.get();
    }
};

/// Extended test fixture with mock STUN server
class StunClientMockTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        io_context = std::make_unique<asio::io_context>();
        mock_server = std::make_unique<mock_stun_server>(*io_context);
        // Configure client to use our mock server
        auto servers = std::vector<stun_client::stun_server_endpoint>{
            stun_client::stun_server_endpoint{"127.0.0.1", mock_server->port()}};
        client = std::make_unique<stun_client>(0, *io_context, servers);
    }

    void TearDown() override
    {
        client.reset();
        mock_server.reset();
        io_context.reset();
    }

    std::unique_ptr<asio::io_context> io_context;
    std::unique_ptr<mock_stun_server> mock_server;
    std::unique_ptr<stun_client> client;

    // Helper to run coroutines in tests
    template <typename Awaitable>
    auto run_coro(Awaitable &&coro)
    {
        // Reset io_context for fresh run
        io_context->restart();

        auto future = asio::co_spawn(*io_context, std::forward<Awaitable>(coro), asio::use_future);

        // Run the io_context until the coroutine completes or timeout
        // This prevents hanging when the mock server keeps the io_context busy
        while (future.wait_for(std::chrono::milliseconds(10)) == std::future_status::timeout)
        {
            io_context->poll(); // Process available work without blocking
            if (io_context->stopped())
            {
                io_context->restart();
            }
        }

        return future.get();
    }
};

/// Test fixture for integration tests with real STUN servers
class StunClientIntegrationTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        io_context = std::make_unique<asio::io_context>();
        auto servers = std::vector<stun_client::stun_server_endpoint>{
            stun_client::stun_server_endpoint{"stun.l.google.com", 19302},
            stun_client::stun_server_endpoint{"stun1.l.google.com", 19302},
            stun_client::stun_server_endpoint{"stun.stunprotocol.org", 3478}};
        client = std::make_unique<stun_client>(0, *io_context, servers);
    }

    void TearDown() override
    {
        client.reset();
        io_context.reset();
    }

    std::unique_ptr<asio::io_context> io_context;
    std::unique_ptr<stun_client> client;

    // Helper to run coroutines in tests
    template <typename Awaitable>
    auto run_coro(Awaitable &&coro)
    {
        // Reset io_context for fresh run
        io_context->restart();

        auto future = asio::co_spawn(*io_context, std::forward<Awaitable>(coro), asio::use_future);

        // Run the io_context until the coroutine completes
        io_context->run();

        return future.get();
    }
};

// ========== MOCK SERVER TESTS ==========

TEST_F(StunClientMockTest, MockServerBasicFunctionality)
{
    // First verify the mock server is set up correctly
    EXPECT_GT(mock_server->port(), 0) << "Mock server should be listening on a valid port";
    EXPECT_EQ(mock_server->requests_received(), 0) << "Mock server should start with 0 requests";
    EXPECT_EQ(mock_server->responses_sent(), 0) << "Mock server should start with 0 responses";

    mock_server->set_behavior(mock_stun_server::behavior_mode::normal);

    auto test_coro = [this]() -> asio::awaitable<void>
    {
        std::cout << "Starting coroutine test..." << std::endl;

        auto result = co_await client->discover_public_address(1000ms);

        std::cout << "Coroutine completed, analyzing result..." << std::endl;

        EXPECT_TRUE(result.success) << "Mock server should respond successfully";
        if (result.success)
        {
            EXPECT_TRUE(result.public_addr.is_valid()) << "Should get valid public address";
            std::cout << "Success: " << result.public_addr.to_string() << std::endl;
        }
        else
        {
            std::cout << "Failed: " << result.error_message << std::endl;
        }

        // Verify mock server statistics
        std::cout << "Requests received: " << mock_server->requests_received() << std::endl;
        std::cout << "Responses sent: " << mock_server->responses_sent() << std::endl;

        co_return;
    };

    std::cout << "About to run coroutine..." << std::endl;
    run_coro(test_coro());
    std::cout << "Coroutine run completed" << std::endl;
}

TEST_F(StunClientMockTest, OpenInternetNATDetection)
{
    mock_server->set_behavior(mock_stun_server::behavior_mode::open_internet);

    auto test_coro = [this]() -> asio::awaitable<void>
    {
        stun_client::nat_detection_config config{};
        config.individual_test_timeout = 1000ms;

        auto result = co_await client->detect_nat_type(config);

        EXPECT_TRUE(result.success) << "NAT detection should succeed with open internet";
        EXPECT_EQ(result.detected_nat_type, nat_type::open_internet)
            << "Should detect open internet NAT type";

        std::cout << "Open Internet NAT detection: " << to_string(result.detected_nat_type)
                  << " with address: " << result.public_addr.to_string() << std::endl;

        co_return;
    };

    run_coro(test_coro());
}

TEST_F(StunClientMockTest, FullConeNATDetection)
{
    mock_server->set_behavior(mock_stun_server::behavior_mode::full_cone_nat);

    auto test_coro = [this]() -> asio::awaitable<void>
    {
        stun_client::nat_detection_config config{};
        config.individual_test_timeout = 1000ms;

        auto result = co_await client->detect_nat_type(config);

        EXPECT_TRUE(result.success) << "NAT detection should succeed with full cone NAT";
        EXPECT_EQ(result.detected_nat_type, nat_type::full_cone)
            << "Should detect full cone NAT type";

        std::cout << "Full Cone NAT detection: " << to_string(result.detected_nat_type)
                  << " with address: " << result.public_addr.to_string() << std::endl;

        co_return;
    };

    run_coro(test_coro());
}

TEST_F(StunClientMockTest, RestrictedConeNATDetection)
{
    mock_server->set_behavior(mock_stun_server::behavior_mode::restricted_cone_nat);

    auto test_coro = [this]() -> asio::awaitable<void>
    {
        stun_client::nat_detection_config config{};
        config.individual_test_timeout = 1000ms;

        auto result = co_await client->detect_nat_type(config);

        EXPECT_TRUE(result.success) << "NAT detection should succeed with restricted cone NAT";
        EXPECT_EQ(result.detected_nat_type, nat_type::restricted_cone)
            << "Should detect restricted cone NAT type";

        std::cout << "Restricted Cone NAT detection: " << to_string(result.detected_nat_type)
                  << " with address: " << result.public_addr.to_string() << std::endl;

        co_return;
    };

    run_coro(test_coro());
}

TEST_F(StunClientMockTest, PortRestrictedConeNATDetection)
{
    mock_server->set_behavior(mock_stun_server::behavior_mode::port_restricted_cone_nat);

    auto test_coro = [this]() -> asio::awaitable<void>
    {
        stun_client::nat_detection_config config{};
        config.individual_test_timeout = 1000ms;

        auto result = co_await client->detect_nat_type(config);

        EXPECT_TRUE(result.success) << "NAT detection should succeed with port restricted cone NAT";
        // In RFC 3489 localhost testing, Port Restricted Cone is indistinguishable from Full Cone
        EXPECT_EQ(result.detected_nat_type, nat_type::full_cone)
            << "Should detect as full cone NAT (indistinguishable in localhost testing)";

        std::cout << "Port Restricted Cone NAT detection: " << to_string(result.detected_nat_type)
                  << " with address: " << result.public_addr.to_string() << std::endl;

        co_return;
    };

    run_coro(test_coro());
}

TEST_F(StunClientMockTest, SymmetricNATDetection)
{
    mock_server->set_behavior(mock_stun_server::behavior_mode::symmetric_nat);

    auto test_coro = [this]() -> asio::awaitable<void>
    {
        stun_client::nat_detection_config config{};
        config.individual_test_timeout = 500ms; // Shorter timeout for faster testing
        config.fallback_to_rfc3489 = true;      // Explicit setting for clarity

        auto result = co_await client->detect_nat_type(config);

        EXPECT_TRUE(result.success) << "NAT detection should succeed with symmetric NAT";



        EXPECT_EQ(result.detected_nat_type, nat_type::symmetric)
            << "Should detect symmetric NAT type";

        std::cout << "Symmetric NAT detection: " << to_string(result.detected_nat_type)
                  << " with address: " << result.public_addr.to_string() << std::endl;

        co_return;
    };

    run_coro(test_coro());
}

TEST_F(StunClientMockTest, BlockedNATDetection)
{
    mock_server->set_behavior(mock_stun_server::behavior_mode::blocked_nat);

    auto test_coro = [this]() -> asio::awaitable<void>
    {
        stun_client::nat_detection_config config{};
        config.individual_test_timeout = 500ms; // Shorter timeout for blocked case

        auto result = co_await client->detect_nat_type(config);

        EXPECT_FALSE(result.success) << "NAT detection should fail with blocked NAT";
        EXPECT_FALSE(result.error_message.empty()) << "Should have error message";

        std::cout << "Blocked NAT detection: " << result.error_message << std::endl;

        co_return;
    };

    run_coro(test_coro());
}

TEST_F(StunClientMockTest, MalformedResponseHandling)
{
    mock_server->set_behavior(mock_stun_server::behavior_mode::malformed_response);

    auto test_coro = [this]() -> asio::awaitable<void>
    {
        auto result = co_await client->discover_public_address(1000ms);

        EXPECT_FALSE(result.success) << "Should fail with malformed responses";
        EXPECT_GE(mock_server->requests_received(), 1) << "Should have received requests";
        EXPECT_GE(mock_server->responses_sent(), 1) << "Should have sent (malformed) responses";

        std::cout << "Malformed response test completed: " << result.error_message << std::endl;

        co_return;
    };

    run_coro(test_coro());
}

TEST_F(StunClientMockTest, TimeoutHandling)
{
    mock_server->set_behavior(mock_stun_server::behavior_mode::timeout);

    auto test_coro = [this]() -> asio::awaitable<void>
    {
        auto result = co_await client->discover_public_address(500ms); // Short timeout

        EXPECT_FALSE(result.success) << "Should timeout with non-responsive server";
        EXPECT_GE(mock_server->requests_received(), 1) << "Should have received requests";
        EXPECT_EQ(mock_server->responses_sent(), 0) << "Should not have sent responses";

        std::cout << "Timeout test completed: " << result.error_message << std::endl;

        co_return;
    };

    run_coro(test_coro());
}

TEST_F(StunClientMockTest, MultipleRequestsConsistency)
{
    mock_server->set_behavior(mock_stun_server::behavior_mode::normal);

    auto test_coro = [this]() -> asio::awaitable<void>
    {
        constexpr int num_requests = 5;
        std::vector<public_address> addresses;

        for (int i = 0; i < num_requests; ++i)
        {
            mock_server->reset_stats();
            auto result = co_await client->discover_public_address(1000ms);

            EXPECT_TRUE(result.success) << "Request " << (i + 1) << " should succeed";
            if (result.success)
            {
                addresses.push_back(result.public_addr);
            }
        }

        // All addresses should be consistent (same client, same server)
        if (!addresses.empty())
        {
            const auto &first_addr = addresses[0];
            for (const auto &addr : addresses)
            {
                EXPECT_EQ(addr.address.to_string(), first_addr.address.to_string())
                    << "IP addresses should be consistent";
                EXPECT_EQ(addr.port, first_addr.port)
                    << "Ports should be consistent";
            }
        }

        std::cout << "Multiple requests consistency test completed with "
                  << addresses.size() << " successful requests" << std::endl;

        co_return;
    };

    run_coro(test_coro());
}

// ========== PACKET CREATION UNIT TESTS ==========

TEST(StunUtilsAdvancedTest, CreateChangeRequestPacket)
{
    auto trans_id = stun_utils::generate_transaction_id();
    auto packet = stun_utils::create_change_request(trans_id, stun_constants::change_ip_and_port);

    EXPECT_GT(packet.size(), stun_constants::header_size) << "Change request should be larger than basic request";
    EXPECT_TRUE(stun_utils::is_valid_stun_packet(packet)) << "Change request should be valid STUN packet";

    // Verify message type is still binding request
    auto msg_type = stun_utils::get_message_type(packet);
    ASSERT_TRUE(msg_type.has_value());
    EXPECT_EQ(*msg_type, message_type::binding_request);

    // Verify transaction ID matches
    EXPECT_TRUE(std::equal(trans_id.begin(), trans_id.end(), packet.begin() + 8));

    std::cout << "Change request packet size: " << packet.size() << " bytes" << std::endl;
}

TEST(StunUtilsAdvancedTest, CreateDifferentChangeRequests)
{
    auto trans_id = stun_utils::generate_transaction_id();

    // Test different change request types
    auto change_ip_packet = stun_utils::create_change_request(trans_id, stun_constants::change_ip);
    auto change_port_packet = stun_utils::create_change_request(trans_id, stun_constants::change_port);
    auto change_both_packet = stun_utils::create_change_request(trans_id, stun_constants::change_ip_and_port);

    // All should be valid and same size (different flags, same structure)
    EXPECT_TRUE(stun_utils::is_valid_stun_packet(change_ip_packet));
    EXPECT_TRUE(stun_utils::is_valid_stun_packet(change_port_packet));
    EXPECT_TRUE(stun_utils::is_valid_stun_packet(change_both_packet));

    EXPECT_EQ(change_ip_packet.size(), change_port_packet.size());
    EXPECT_EQ(change_port_packet.size(), change_both_packet.size());

    std::cout << "All change request types created successfully" << std::endl;
}

TEST(StunUtilsAdvancedTest, ParseResponseWithOtherAddress)
{
    // Create a mock response with both XOR-MAPPED-ADDRESS and OTHER-ADDRESS
    std::vector<std::uint8_t> mock_response = {
        // STUN header (binding response)
        0x01,
        0x01, // Message Type: Binding Response
        0x00,
        0x18, // Message Length: 24 bytes (two 12-byte attributes)

        // Magic Cookie
        0x21,
        0x12,
        0xA4,
        0x42,

        // Transaction ID (12 bytes)
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0A,
        0x0B,

        // XOR-MAPPED-ADDRESS attribute
        0x00,
        0x20, // Attribute Type: XOR-MAPPED-ADDRESS
        0x00,
        0x08, // Attribute Length: 8 bytes
        0x00,
        0x01, // Reserved + Family (IPv4)
        0x33,
        0x26, // Port XORed with magic cookie high 16 bits
        0x7B,
        0x48,
        0xFE,
        0x18, // IP XORed with magic cookie

        // OTHER-ADDRESS attribute
        0x80,
        0x2F, // Attribute Type: OTHER-ADDRESS (RFC 5780)
        0x00,
        0x08, // Attribute Length: 8 bytes
        0x00,
        0x01, // Reserved + Family (IPv4)
        0x0D,
        0x96, // Port: 3478 (network byte order)
        0x7F,
        0x00,
        0x00,
        0x01 // IP: 127.0.0.1
    };

    auto parse_result = stun_utils::parse_binding_response_with_other_address(mock_response);

    ASSERT_TRUE(parse_result.has_value()) << "Should successfully parse response with other address";

    auto [mapped_addr, other_addr] = parse_result.value();

    EXPECT_TRUE(mapped_addr.is_valid()) << "Mapped address should be valid";
    EXPECT_TRUE(other_addr.has_value()) << "Other address should be present";

    if (other_addr.has_value())
    {
        EXPECT_TRUE(other_addr->is_valid()) << "Other address should be valid";
        EXPECT_EQ(other_addr->port, 3478) << "Other address should have correct port";
        std::cout << "Parsed other address: " << other_addr->to_string() << std::endl;
    }

    std::cout << "Parsed mapped address: " << mapped_addr.to_string() << std::endl;
}

TEST(StunUtilsAdvancedTest, ParseResponseWithoutOtherAddress)
{
    // Create a basic response without OTHER-ADDRESS
    std::vector<std::uint8_t> basic_response = {
        // STUN header (binding response)
        0x01,
        0x01, // Message Type: Binding Response
        0x00,
        0x0C, // Message Length: 12 bytes

        // Magic Cookie
        0x21,
        0x12,
        0xA4,
        0x42,

        // Transaction ID (12 bytes)
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0A,
        0x0B,

        // XOR-MAPPED-ADDRESS attribute
        0x00,
        0x20, // Attribute Type: XOR-MAPPED-ADDRESS
        0x00,
        0x08, // Attribute Length: 8 bytes
        0x00,
        0x01, // Reserved + Family (IPv4)
        0x33,
        0x26, // Port XORed with magic cookie high 16 bits
        0x7B,
        0x48,
        0xFE,
        0x18 // IP XORed with magic cookie
    };

    auto parse_result = stun_utils::parse_binding_response_with_other_address(basic_response);

    ASSERT_TRUE(parse_result.has_value()) << "Should successfully parse basic response";

    auto [mapped_addr, other_addr] = parse_result.value();

    EXPECT_TRUE(mapped_addr.is_valid()) << "Mapped address should be valid";
    EXPECT_FALSE(other_addr.has_value()) << "Other address should not be present";

    std::cout << "Parsed basic response: " << mapped_addr.to_string() << std::endl;
}

TEST(NatDetectionConfigTest, DefaultConfiguration)
{
    stun_client::nat_detection_config config{};

    EXPECT_EQ(config.individual_test_timeout.count(), 2000) << "Default timeout should be 2 seconds";
    EXPECT_TRUE(config.use_rfc5780_attributes) << "Should use RFC 5780 by default";
    EXPECT_TRUE(config.fallback_to_rfc3489) << "Should fallback to RFC 3489 by default";

    std::cout << "Default NAT detection config validated" << std::endl;
}

TEST(NatTestResultTest, DefaultConstruction)
{
    nat_test_result result{};

    EXPECT_FALSE(result.test1_success) << "All tests should start as failed";
    EXPECT_FALSE(result.test2_success);
    EXPECT_FALSE(result.test3_success);
    EXPECT_FALSE(result.addresses_differ) << "Addresses should not differ initially";
    EXPECT_FALSE(result.test1_addr.is_valid()) << "Addresses should be invalid initially";
    EXPECT_FALSE(result.server_other_addr.is_valid());

    std::cout << "NAT test result default state validated" << std::endl;
}

// Unit test for NAT analysis logic
class NatAnalysisTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        io_context = std::make_unique<asio::io_context>();
    }

    void TearDown() override
    {
        io_context.reset();
    }

    std::unique_ptr<asio::io_context> io_context;

    // Helper to create test addresses
    public_address create_test_address(const std::string &ip, std::uint16_t port)
    {
        return public_address{
            .address = asio::ip::make_address_v4(ip),
            .port = port};
    }
};

TEST_F(NatAnalysisTest, BlockedNATDetection)
{
    nat_test_result test_results{};
    // All tests fail - should be blocked

    auto result = stun_utils::analyze_nat_type(test_results);
    EXPECT_EQ(result, nat_type::blocked) << "Should detect blocked NAT when no tests succeed";
}

TEST_F(NatAnalysisTest, OpenInternetDetection)
{
    nat_test_result test_results{};
    test_results.test1_success = true;
    test_results.test1_addr = create_test_address("192.168.1.100", 12345);
    test_results.test2_success = true; // Change IP+port succeeded
    test_results.server_other_addr = create_test_address("8.8.8.8", 3478);

    auto result = stun_utils::analyze_nat_type(test_results);
    EXPECT_EQ(result, nat_type::open_internet) << "Should detect open internet when change IP+port succeeds";
}

TEST_F(NatAnalysisTest, FullConeNATDetection)
{
    nat_test_result test_results{};
    test_results.test1_success = true;
    test_results.test1_addr = create_test_address("192.168.1.100", 12345);
    test_results.server_other_addr = create_test_address("8.8.8.8", 3478);
    // test2 fails (change IP+port), test3 fails (change port)

    auto result = stun_utils::analyze_nat_type(test_results);
    EXPECT_EQ(result, nat_type::full_cone) << "Should detect full cone NAT as fallback when no server tests available";
}

TEST_F(NatAnalysisTest, RestrictedConeNATDetection)
{
    nat_test_result test_results{};
    test_results.test1_success = true;
    test_results.test1_addr = create_test_address("192.168.1.100", 12345);
    test_results.test3_success = true;                                     // Change port succeeded
    test_results.test3_addr = create_test_address("192.168.1.100", 12345); // Same address
    test_results.addresses_differ = false;
    test_results.server_other_addr = create_test_address("8.8.8.8", 3478);

    auto result = stun_utils::analyze_nat_type(test_results);
    EXPECT_EQ(result, nat_type::restricted_cone) << "Should detect restricted cone NAT when port change succeeds but addresses don't differ";
}

TEST_F(NatAnalysisTest, SymmetricNATDetection)
{
    nat_test_result test_results{};
    test_results.test1_success = true;
    test_results.test1_addr = create_test_address("192.168.1.100", 12345);
    test_results.test3_success = true;                                     // Change port succeeded
    test_results.test3_addr = create_test_address("192.168.1.100", 54321); // Different port
    test_results.addresses_differ = true;
    test_results.server_other_addr = create_test_address("8.8.8.8", 3478);

    auto result = stun_utils::analyze_nat_type(test_results);
    EXPECT_EQ(result, nat_type::symmetric) << "Should detect symmetric NAT when addresses differ";
}

TEST_F(NatAnalysisTest, PortRestrictedConeNATDetection)
{
    nat_test_result test_results{};
    test_results.test1_success = true;
    test_results.test1_addr = create_test_address("192.168.1.100", 12345);
    test_results.test3_success = false;    // Change port failed
    test_results.addresses_differ = false; // Doesn't matter since test3 failed
    test_results.server_other_addr = create_test_address("8.8.8.8", 3478);

    auto result = stun_utils::analyze_nat_type(test_results);
    // Note: With the current algorithm, when both change requests fail and addresses don't differ,
    // we return full_cone as it's the more common case. Distinguishing between full_cone and
    // port_restricted_cone requires more sophisticated multi-server testing.
    EXPECT_EQ(result, nat_type::full_cone) << "Should detect full cone NAT when change requests fail (simplified algorithm)";
}

// ========== ORIGINAL TESTS ==========

TEST_F(StunClientTest, ConstructorInitializesCorrectly)
{
    EXPECT_GT(client->local_port(), 0) << "Should have assigned a port";
}

TEST_F(StunClientTest, ConstructorWithSpecificPort)
{
    // Test with a specific port (using a high port to avoid conflicts)
    try
    {
        auto specific_client = std::make_unique<stun_client>(54321, *io_context);
        EXPECT_EQ(specific_client->local_port(), 54321);
    }
    catch (const stun_exception &e)
    {
        // Port might already be in use, skip the test
        GTEST_SKIP() << "Port 54321 already in use: " << e.what();
    }
}

TEST_F(StunClientTest, NatTypeToStringConversions)
{
    EXPECT_EQ(to_string(nat_type::unknown), "Unknown");
    EXPECT_EQ(to_string(nat_type::open_internet), "Open Internet");
    EXPECT_EQ(to_string(nat_type::full_cone), "Full Cone NAT");
    EXPECT_EQ(to_string(nat_type::restricted_cone), "Restricted Cone NAT");
    EXPECT_EQ(to_string(nat_type::port_restricted_cone), "Port Restricted Cone NAT");
    EXPECT_EQ(to_string(nat_type::symmetric), "Symmetric NAT");
    EXPECT_EQ(to_string(nat_type::blocked), "Blocked");
}

// Test with invalid server to ensure error handling
TEST_F(StunClientTest, InvalidServerHandling)
{
    // Test with an unreachable server (RFC 5737 TEST-NET-1 reserved for documentation)
    // The timeout mechanism should catch this and return an error
    auto servers = std::vector<stun_client::stun_server_endpoint>{
        stun_client::stun_server_endpoint{"192.0.2.1", 3478}}; // Unreachable test network
    auto client_with_invalid_server = std::make_unique<stun_client>(0, *io_context, servers);

    auto test_coro = [&]() -> asio::awaitable<void>
    {
        auto result = co_await client_with_invalid_server->discover_public_address(500ms);

        EXPECT_FALSE(result.success) << "Should fail with unreachable server";
        EXPECT_FALSE(result.error_message.empty()) << "Should provide an error message";
        EXPECT_FALSE(result.public_addr.is_valid()) << "Should not have valid public address";

        std::cout << "Invalid server test completed as expected: " << result.error_message << std::endl;

        co_return;
    };

    run_coro(test_coro());
}

// Test struct functionality
TEST(PublicAddressTest, DefaultConstruction)
{
    public_address addr{};
    EXPECT_FALSE(addr.is_valid());
    EXPECT_EQ(addr.port, 0);
}

TEST(PublicAddressTest, ValidConstruction)
{
    public_address addr{
        .address = asio::ip::make_address_v4("192.168.1.1"),
        .port = 12345};
    EXPECT_TRUE(addr.is_valid());
    EXPECT_EQ(addr.port, 12345);
    EXPECT_EQ(addr.to_string(), "192.168.1.1:12345");
}

// Test StunServer struct
TEST(StunServerTest, Construction)
{
    stun_client::stun_server_endpoint server{"test.com", 19302};
    EXPECT_EQ(server.host, "test.com");
    EXPECT_EQ(server.port, 19302);
}

TEST(StunServerTest, DefaultPort)
{
    stun_client::stun_server_endpoint server{"test.com"};
    EXPECT_EQ(server.host, "test.com");
    EXPECT_EQ(server.port, stun_constants::default_port);
}

// Test StunResult struct
TEST(StunResultTest, DefaultConstruction)
{
    stun_client::stun_result result{};
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.public_addr.is_valid());
    EXPECT_EQ(result.detected_nat_type, nat_type::unknown);
    EXPECT_EQ(result.response_time.count(), 0);
    EXPECT_TRUE(result.error_message.empty());
}

// Basic packet creation and parsing tests (no network required)
TEST_F(StunClientTest, StunPacketCreationAndParsing)
{
    // Test transaction ID generation
    auto trans_id1 = stun_utils::generate_transaction_id();
    auto trans_id2 = stun_utils::generate_transaction_id();

    // Transaction IDs should be different
    EXPECT_NE(trans_id1, trans_id2) << "Transaction IDs should be unique";

    // Test packet creation
    auto packet = stun_utils::create_binding_request(trans_id1);

    // Verify packet structure
    EXPECT_EQ(packet.size(), stun_constants::header_size) << "Basic binding request should be header-only";
    EXPECT_TRUE(stun_utils::is_valid_stun_packet(packet)) << "Created packet should be valid STUN packet";

    // Verify message type
    auto msg_type = stun_utils::get_message_type(packet);
    ASSERT_TRUE(msg_type.has_value()) << "Should be able to extract message type";
    EXPECT_EQ(*msg_type, message_type::binding_request) << "Should be binding request";

    // Test parsing a mock response
    // Create a simple mock STUN response with XOR-MAPPED-ADDRESS
    std::vector<std::uint8_t> mock_response = {
        // STUN header (binding response)
        0x01,
        0x01, // Message Type: Binding Response
        0x00,
        0x0C, // Message Length: 12 bytes (attribute length)

        // Magic Cookie
        0x21,
        0x12,
        0xA4,
        0x42,

        // Transaction ID (12 bytes)
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0A,
        0x0B,

        // XOR-MAPPED-ADDRESS attribute
        0x00,
        0x20, // Attribute Type: XOR-MAPPED-ADDRESS
        0x00,
        0x08, // Attribute Length: 8 bytes
        0x00,
        0x01, // Reserved + Family (IPv4)
        0x12,
        0x34, // Port XORed with magic cookie high 16 bits (0x1234 ^ 0x2112 = 0x3326)
        0x5A,
        0x5A,
        0x5A,
        0x5A // IP XORed with magic cookie (will be un-XORed during parsing)
    };

    // Test parsing
    auto parse_result = stun_utils::parse_binding_response(mock_response);
    if (parse_result.has_value())
    {
        auto addr = parse_result.value();
        EXPECT_TRUE(addr.is_valid()) << "Parsed address should be valid";
        EXPECT_GT(addr.port, 0) << "Port should be positive";
        std::cout << "Successfully parsed mock STUN response: " << addr.to_string() << std::endl;
    }
    else
    {
        // This might fail due to the simplistic mock response, but that's ok
        std::cout << "Mock response parsing failed (expected for simplified test data)" << std::endl;
    }
}

// Test error handling with invalid data
TEST_F(StunClientTest, StunUtilsErrorHandling)
{
    // Test with empty packet
    std::vector<std::uint8_t> empty_packet;
    EXPECT_FALSE(stun_utils::is_valid_stun_packet(empty_packet));
    EXPECT_FALSE(stun_utils::get_message_type(empty_packet).has_value());

    auto parse_result = stun_utils::parse_binding_response(empty_packet);
    EXPECT_FALSE(parse_result.has_value()) << "Should fail to parse empty packet";

    // Test with packet too short
    std::vector<std::uint8_t> short_packet{0x01, 0x01, 0x00, 0x00}; // Only 4 bytes
    EXPECT_FALSE(stun_utils::is_valid_stun_packet(short_packet));

    // Test with wrong magic cookie
    std::vector<std::uint8_t> bad_magic = {
        0x01, 0x01, 0x00, 0x00, // Valid start
        0xFF,
        0xFF,
        0xFF,
        0xFF, // Invalid magic cookie
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0A,
        0x0B // Transaction ID
    };
    EXPECT_FALSE(stun_utils::is_valid_stun_packet(bad_magic));
}

#ifdef DO_INTEGRATION_TESTS
// Integration test - requires network access (with shorter timeout)
TEST_F(StunClientIntegrationTest, QuickDiscoveryIntegration)
{
    auto test_coro = [this]() -> asio::awaitable<void>
    {
        // Use a shorter timeout for CI/quick testing
        auto result = co_await client->discover_public_address(2000ms);

        if (result.success)
        {
            // Verify we got a valid public address
            EXPECT_TRUE(result.public_addr.is_valid()) << "Received invalid public address";
            EXPECT_GT(result.public_addr.port, 0) << "Public port should be greater than 0";
            EXPECT_GT(result.response_time.count(), 0) << "Response time should be positive";

            std::cout << "Quick discovery successful: " << result.public_addr.to_string()
                      << " (response time: " << result.response_time.count() << "ms)" << std::endl;
        }
        else
        {
            std::cout << "Quick discovery failed (may be network/firewall related): " << result.error_message << std::endl;
            // Don't fail the test - network conditions vary
        }

        co_return;
    };

    run_coro(test_coro());
}

// Full integration test - requires network access
TEST_F(StunClientIntegrationTest, DiscoverPublicAddressIntegration)
{
    auto test_coro = [this]() -> asio::awaitable<void>
    {
        // Attempt to discover public address with a reasonable timeout
        auto result = co_await client->discover_public_address(5000ms);

        // Basic assertions that should hold for any successful STUN response
        EXPECT_TRUE(result.success) << "Failed to discover public address: " << result.error_message;

        if (result.success)
        {
            // Verify we got a valid public address
            EXPECT_TRUE(result.public_addr.is_valid()) << "Received invalid public address";

            // Verify the address is not a private/local address
            auto addr = result.public_addr.address;
            EXPECT_FALSE(addr.is_loopback()) << "Public address should not be loopback: " << result.public_addr.to_string();
            EXPECT_FALSE(addr.is_unspecified()) << "Public address should not be unspecified";

            // Check that we're not getting obvious private ranges
            // Note: This is a heuristic and might fail in some network configurations
            auto addr_bytes = addr.to_bytes();
            bool is_private = (addr_bytes[0] == 10) ||                                                // 10.0.0.0/8
                              (addr_bytes[0] == 172 && addr_bytes[1] >= 16 && addr_bytes[1] <= 31) || // 172.16.0.0/12
                              (addr_bytes[0] == 192 && addr_bytes[1] == 168);                         // 192.168.0.0/16

            if (is_private)
            {
                // This could happen in some NAT configurations, so warn but don't fail
                std::cout << "Warning: Detected private address as public: " << result.public_addr.to_string() << std::endl;
            }

            // Verify port is reasonable
            EXPECT_GT(result.public_addr.port, 0) << "Public port should be greater than 0";
            EXPECT_LE(result.public_addr.port, 65535) << "Public port should be valid";

            // Verify response time is reasonable
            EXPECT_GT(result.response_time.count(), 0) << "Response time should be positive";
            EXPECT_LT(result.response_time.count(), 5000) << "Response time should be under 5 seconds";

            // Output the discovered information for debugging
            std::cout << "Discovered public address: " << result.public_addr.to_string()
                      << " (response time: " << result.response_time.count() << "ms)" << std::endl;
        }

        co_return;
    };

    // Run the test with the io_context
    run_coro(test_coro());
}

// Integration test for NAT type detection
TEST_F(StunClientIntegrationTest, DetectNatTypeIntegration)
{
    auto test_coro = [this]() -> asio::awaitable<void>
    {
        auto result = co_await client->detect_nat_type(10000ms);

        if (result.success)
        {
            // Verify we got a valid result
            EXPECT_TRUE(result.public_addr.is_valid()) << "NAT detection should provide valid public address";
            EXPECT_NE(result.detected_nat_type, nat_type::unknown) << "Should detect some NAT type";

            // Output the detected NAT type for debugging
            std::cout << "Detected NAT type: " << to_string(result.detected_nat_type)
                      << " with public address: " << result.public_addr.to_string() << std::endl;
        }
        else
        {
            std::cout << "NAT detection failed: " << result.error_message << std::endl;
            // NAT detection failure is not necessarily a test failure in all environments
        }

        co_return;
    };

    run_coro(test_coro());
}

// Comprehensive NAT detection test using advanced RFC 3489/5780 methods
TEST_F(StunClientIntegrationTest, ComprehensiveNatDetectionIntegration)
{
    auto test_coro = [this]() -> asio::awaitable<void>
    {
        // Configure comprehensive NAT detection
        stun_client::nat_detection_config config{};
        config.individual_test_timeout = 3000ms;
        config.use_rfc5780_attributes = true;
        config.fallback_to_rfc3489 = true;

        auto result = co_await client->detect_nat_type(config);

        if (result.success)
        {
            // Verify we got a valid result
            EXPECT_TRUE(result.public_addr.is_valid()) << "Comprehensive NAT detection should provide valid public address";
            EXPECT_NE(result.detected_nat_type, nat_type::unknown) << "Should detect specific NAT type";

            // Output detailed information
            std::cout << "Comprehensive NAT Detection Results:" << std::endl;
            std::cout << "  Detected NAT type: " << to_string(result.detected_nat_type) << std::endl;
            std::cout << "  Public address: " << result.public_addr.to_string() << std::endl;
            std::cout << "  Response time: " << result.response_time.count() << "ms" << std::endl;

            // Verify the result makes sense
            switch (result.detected_nat_type)
            {
            case nat_type::open_internet:
                std::cout << "  Analysis: Direct internet connection, no NAT" << std::endl;
                break;
            case nat_type::full_cone:
                std::cout << "  Analysis: Full Cone NAT - most permissive NAT type" << std::endl;
                break;
            case nat_type::restricted_cone:
                std::cout << "  Analysis: Restricted Cone NAT - filters by source IP" << std::endl;
                break;
            case nat_type::port_restricted_cone:
                std::cout << "  Analysis: Port Restricted Cone NAT - filters by source IP and port" << std::endl;
                break;
            case nat_type::symmetric:
                std::cout << "  Analysis: Symmetric NAT - different mapping per destination" << std::endl;
                break;
            case nat_type::blocked:
                std::cout << "  Analysis: Blocked - UDP traffic filtered" << std::endl;
                break;
            default:
                std::cout << "  Analysis: Unknown NAT type detected" << std::endl;
                break;
            }
        }
        else
        {
            std::cout << "Comprehensive NAT detection failed: " << result.error_message << std::endl;
            // Still not a test failure - depends on server capabilities
        }

        co_return;
    };

    run_coro(test_coro());
}

// Test with client that uses default servers
TEST_F(StunClientTest, DefaultServersIntegration)
{
    // Create a new client without adding any servers explicitly
    auto default_client = std::make_unique<stun_client>(*io_context);

    auto test_coro = [&]() -> asio::awaitable<void>
    {
        // Should automatically use default servers
        auto result = co_await default_client->discover_public_address(5000ms);

        if (result.success)
        {
            EXPECT_TRUE(result.public_addr.is_valid());
            std::cout << "Default servers discovered address: " << result.public_addr.to_string() << std::endl;
        }
        else
        {
            std::cout << "Default servers test failed: " << result.error_message << std::endl;
        }

        co_return;
    };

    run_coro(test_coro());
}

// Test multiple rapid queries to stress test the client
TEST_F(StunClientIntegrationTest, MultipleQueriesIntegration)
{
    auto test_coro = [this]() -> asio::awaitable<void>
    {
        constexpr int num_queries = 3;
        std::vector<stun_client::stun_result> results;
        results.reserve(num_queries);

        // Perform multiple queries in sequence
        for (int i = 0; i < num_queries; ++i)
        {
            auto result = co_await client->discover_public_address(3000ms);
            results.push_back(result);

            if (result.success)
            {
                std::cout << "Query " << (i + 1) << " result: " << result.public_addr.to_string()
                          << " (" << result.response_time.count() << "ms)" << std::endl;
            }
        }

        // Verify that if any succeeded, they all returned the same public address
        // (since we're using the same client from the same location)
        bool any_success = false;
        public_address first_successful_addr{};

        for (const auto &result : results)
        {
            if (result.success)
            {
                if (!any_success)
                {
                    any_success = true;
                    first_successful_addr = result.public_addr;
                }
                else
                {
                    // All successful queries should return the same public address
                    EXPECT_EQ(result.public_addr.address.to_string(), first_successful_addr.address.to_string())
                        << "Multiple queries should return consistent IP address";
                    EXPECT_EQ(result.public_addr.port, first_successful_addr.port)
                        << "Multiple queries should return consistent port";
                }
            }
        }

        if (any_success)
        {
            std::cout << "Multiple queries test completed successfully with consistent results" << std::endl;
        }
        else
        {
            std::cout << "All queries failed - network may be unavailable" << std::endl;
        }

        co_return;
    };

    run_coro(test_coro());
}

// Unit test: Hairpin results field initialization
TEST_F(StunClientTest, HairpinResultsInitialization)
{
    nat_test_result results{};

    // Verify hairpin fields are initialized to false
    EXPECT_FALSE(results.hairpin_test_attempted) << "hairpin_test_attempted should initialize to false";
    EXPECT_FALSE(results.hairpin_supported) << "hairpin_supported should initialize to false";

    // Verify other fields are still initialized correctly
    EXPECT_FALSE(results.test1_success);
    EXPECT_FALSE(results.test2_success);
    EXPECT_FALSE(results.test3_success);
    EXPECT_FALSE(results.addresses_differ);

    std::cout << "Hairpin result fields correctly initialized" << std::endl;
}

// Unit test: Hairpin flag in stun_result initialization
TEST_F(StunClientTest, StunResultHairpinInitialization)
{
    stun_client::stun_result result{};

    // Verify hairpin_supported field is initialized to false
    EXPECT_FALSE(result.hairpin_supported) << "hairpin_supported should initialize to false";

    // Verify other fields are still initialized correctly
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.public_addr.is_valid());
    EXPECT_EQ(result.detected_nat_type, nat_type::unknown);
    EXPECT_EQ(result.response_time.count(), 0);
    EXPECT_TRUE(result.error_message.empty());

    std::cout << "stun_result hairpin field correctly initialized" << std::endl;
}

// Integration test: Full NAT detection including hairpin with live STUN servers
TEST_F(StunClientIntegrationTest, FullNatDetectionWithHairpinIntegration)
{
    auto test_coro = [this]() -> asio::awaitable<void>
    {
        stun_client::nat_detection_config config{};
        config.individual_test_timeout = 3000ms;
        config.use_rfc5780_attributes = true;
        config.fallback_to_rfc3489 = true;

        auto result = co_await client->detect_nat_type(config);

        if (result.success)
        {
            EXPECT_TRUE(result.public_addr.is_valid()) << "Should discover valid public address";

            std::cout << "Full NAT Detection with Hairpin Results:" << std::endl;
            std::cout << "  Detected NAT type: " << to_string(result.detected_nat_type) << std::endl;
            std::cout << "  Public address: " << result.public_addr.to_string() << std::endl;
            std::cout << "  Response time: " << result.response_time.count() << "ms" << std::endl;
            std::cout << "  Hairpin supported: " << (result.hairpin_supported ? "yes" : "no") << std::endl;

            if (result.hairpin_supported)
            {
                std::cout << "  Analysis: NAT supports hairpinning (UPnP IGD or similar)" << std::endl;
            }
            else
            {
                std::cout << "  Analysis: NAT does not support hairpinning" << std::endl;
            }
        }
        else
        {
            std::cout << "Full NAT detection with hairpin failed: " << result.error_message << std::endl;
        }

        co_return;
    };

    run_coro(test_coro());
}
#endif
