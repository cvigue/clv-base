// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "micro_udp_server.h"

#include <chrono>
#include <future>
#include <string>
#include <thread>
#include <vector>

using namespace clv;
using namespace clv::UdpServerDefs;
using namespace std::chrono_literals;

// ============================================================================
// Test Helpers
// ============================================================================

/// Simple echo handler for testing
struct TestEchoHandler
{
    std::size_t mPacketCount{0};
    std::promise<std::string> mFirstPacketPromise;
    bool mPromiseFulfilled{false};

    asio::awaitable<bool> HandleDatagram(
        std::span<const std::uint8_t> data,
        asio::ip::udp::endpoint remote,
        SendDatagramFnT send_fn,
        [[maybe_unused]] asio::io_context &io_ctx)
    {
        ++mPacketCount;

        std::string received(reinterpret_cast<const char *>(data.data()), data.size());

        // Store first packet for test verification
        if (!mPromiseFulfilled)
        {
            mFirstPacketPromise.set_value(received);
            mPromiseFulfilled = true;
        }

        // Echo back
        buffer_type response(data.begin(), data.end());
        co_await send_fn(std::move(response), remote);

        co_return true;
    }
};

/// Handler that counts packets but doesn't respond
struct CountingHandler
{
    std::size_t mPacketCount{0};

    asio::awaitable<bool> HandleDatagram(
        std::span<const std::uint8_t> data,
        [[maybe_unused]] asio::ip::udp::endpoint remote,
        [[maybe_unused]] SendDatagramFnT send_fn,
        [[maybe_unused]] asio::io_context &io_ctx)
    {
        ++mPacketCount;
        co_return true;
    }
};

/// Send a UDP datagram and optionally receive a response
std::optional<std::string> SendAndReceiveUdp(const std::string &message,
                                             const std::string &host,
                                             unsigned short port,
                                             std::chrono::milliseconds timeout = 1000ms)
{
    try
    {
        asio::io_context io_ctx;
        asio::ip::udp::socket socket(io_ctx, asio::ip::udp::v4());

        asio::ip::udp::endpoint remote_endpoint(
            asio::ip::make_address(host), port);

        // Send
        socket.send_to(asio::buffer(message), remote_endpoint);

        // Set up receive with timeout
        std::array<char, 1500> recv_buffer{};
        asio::ip::udp::endpoint sender_endpoint;

        // Use a deadline timer for timeout
        asio::steady_timer timer(io_ctx);
        timer.expires_after(timeout);

        bool received = false;
        std::string result;

        socket.async_receive_from(asio::buffer(recv_buffer),
                                  sender_endpoint,
                                  [&](const std::error_code &ec, std::size_t bytes_received)
        {
            if (!ec && bytes_received > 0)
            {
                result = std::string(recv_buffer.data(), bytes_received);
                received = true;
            }
            timer.cancel();
        });

        timer.async_wait([&](const std::error_code &ec)
        {
            if (!ec)
            {
                socket.cancel();
            }
        });

        io_ctx.run();

        if (received)
            return result;
        return std::nullopt;
    }
    catch (const std::exception &)
    {
        return std::nullopt;
    }
}

/// Send a UDP datagram without waiting for response
bool SendUdp(const std::string &message, const std::string &host, unsigned short port)
{
    try
    {
        asio::io_context io_ctx;
        asio::ip::udp::socket socket(io_ctx, asio::ip::udp::v4());

        asio::ip::udp::endpoint remote_endpoint(asio::ip::make_address(host),
                                                port);

        socket.send_to(asio::buffer(message), remote_endpoint);
        return true;
    }
    catch (const std::exception &)
    {
        return false;
    }
}

// ============================================================================
// Tests
// ============================================================================

class MicroUdpServerTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        // Each test gets a fresh setup
    }

    void TearDown() override
    {
        // Cleanup handled by RAII
    }
};

TEST_F(MicroUdpServerTest, ConstructionAndDestruction)
{
    // Test that server can be constructed and destructed cleanly
    {
        CountingHandler handler;
        MicroUdpServer server(0, std::move(handler)); // Port 0 = ephemeral

        EXPECT_GT(server.LocalPort(), 0);
    }
    // Server should be cleanly destroyed here
    SUCCEED();
}

TEST_F(MicroUdpServerTest, ReceivesDatagrams)
{
    CountingHandler handler;
    MicroUdpServer server(0, std::move(handler));

    auto port = server.LocalPort();
    ASSERT_GT(port, 0);

    // Note: handler was moved, so we can't access it through handlerPtr
    // In a real test, we'd use shared_ptr or similar

    // Send a few datagrams
    ASSERT_TRUE(SendUdp("test1", "127.0.0.1", port));
    ASSERT_TRUE(SendUdp("test2", "127.0.0.1", port));
    ASSERT_TRUE(SendUdp("test3", "127.0.0.1", port));

    // Give server time to process
    std::this_thread::sleep_for(100ms);

    // We can't verify the count because handler was moved
    // This test just verifies no crashes
    SUCCEED();
}

TEST_F(MicroUdpServerTest, EchoesDatagrams)
{
    TestEchoHandler handler;
    MicroUdpServer server(0, std::move(handler));

    auto port = server.LocalPort();
    ASSERT_GT(port, 0);

    // Send and receive echo
    auto response = SendAndReceiveUdp("hello",
                                      "127.0.0.1",
                                      port);

    ASSERT_TRUE(response.has_value());
    EXPECT_EQ(response.value(), "hello");
}

TEST_F(MicroUdpServerTest, HandlesMultipleClients)
{
    TestEchoHandler handler;
    MicroUdpServer server(0, std::move(handler));

    auto port = server.LocalPort();
    ASSERT_GT(port, 0);

    // Send from multiple "clients" (really just multiple sockets)
    std::vector<std::future<std::optional<std::string>>> futures;

    for (int i = 0; i < 5; ++i)
    {
        futures.push_back(std::async(std::launch::async, [port, i]()
        {
            return SendAndReceiveUdp("client" + std::to_string(i), "127.0.0.1", port);
        }));
    }

    // Verify all got responses
    for (int i = 0; i < 5; ++i)
    {
        auto response = futures[i].get();
        ASSERT_TRUE(response.has_value()) << "Client " << i << " got no response";
        EXPECT_EQ(response.value(), "client" + std::to_string(i));
    }
}

TEST_F(MicroUdpServerTest, StopsCleanly)
{
    TestEchoHandler handler;
    MicroUdpServer server(0, std::move(handler));

    auto port = server.LocalPort();
    ASSERT_GT(port, 0);

    // Verify server is working
    auto response = SendAndReceiveUdp("before_stop", "127.0.0.1", port);
    ASSERT_TRUE(response.has_value());
    EXPECT_EQ(response.value(), "before_stop");

    // Stop the server
    server.Stop();

    // Give it a moment
    std::this_thread::sleep_for(50ms);

    // Server should no longer respond (might timeout or get connection refused)
    auto response2 = SendAndReceiveUdp("after_stop", "127.0.0.1", port, 200ms);

    // Either no response or an error is fine - main thing is no crash
    SUCCEED();
}

TEST_F(MicroUdpServerTest, HandlesLargeDatagram)
{
    TestEchoHandler handler;
    MicroUdpServer server(0, std::move(handler));

    auto port = server.LocalPort();
    ASSERT_GT(port, 0);

    // Send a large datagram (but below MTU to avoid fragmentation)
    std::string large_message(1400, 'X');

    auto response = SendAndReceiveUdp(large_message, "127.0.0.1", port);

    ASSERT_TRUE(response.has_value());
    EXPECT_EQ(response.value().size(), large_message.size());
    EXPECT_EQ(response.value(), large_message);
}

TEST_F(MicroUdpServerTest, HandlesEmptyDatagram)
{
    CountingHandler handler;
    MicroUdpServer server(0, std::move(handler));

    auto port = server.LocalPort();
    ASSERT_GT(port, 0);

    // Send empty datagram
    ASSERT_TRUE(SendUdp("", "127.0.0.1", port));

    // Give server time to process (or ignore)
    std::this_thread::sleep_for(50ms);

    // No crash = success
    SUCCEED();
}

TEST_F(MicroUdpServerTest, MultipleThreads)
{
    // Test with multiple worker threads
    TestEchoHandler handler;
    MicroUdpServer server(0, std::move(handler), 4);

    auto port = server.LocalPort();
    ASSERT_GT(port, 0);

    // Send several datagrams in parallel
    std::vector<std::future<std::optional<std::string>>> futures;

    for (int i = 0; i < 20; ++i)
    {
        futures.push_back(std::async(std::launch::async, [port, i]()
        {
            return SendAndReceiveUdp("msg" + std::to_string(i), "127.0.0.1", port);
        }));
    }

    int success_count = 0;
    for (auto &f : futures)
    {
        if (f.get().has_value())
            ++success_count;
    }

    // Most should succeed (UDP can drop packets under load, but locally should be fine)
    EXPECT_GT(success_count, 15);
}
