// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#include "gtest/gtest.h"

#include <iostream>
#include <string_view>

#include <micro_tls_client.h>
#include <micro_tls_server.h>

#include <buffer_util.h>
#include <auto_thread.h>

using namespace clv;
using namespace std::literals;


struct PingClientHandler
{
    using send_fn = ClientDefs::send_fn;
    using recv_fn = ClientDefs::recv_fn;
    using buffer_type = ClientDefs::buffer_type;
    using close_fn = ClientDefs::close_fn;
    using data_size = ClientDefs::data_size;

    enum class Mode
    {
        PING,
        SEND_CLOSE,
        WAIT_FOR_CLOSE
    };

    ~PingClientHandler()
    {
        // If we expected to close, mCount should be 0 or negative
        // If we were just pinging, the original check applies
        if (mCheckCount && mMode != Mode::WAIT_FOR_CLOSE)
            EXPECT_EQ(mCount, 0);
        // If we were waiting for close, error might have occurred, or shutdown happened.
        // We might check a separate flag like mWasClosedGracefully if needed.
    }

    // Add mode parameter
    PingClientHandler(int pingCount, bool log = false, bool check_count = true, bool send_close_after_pings = false)
        : mCount(pingCount),
          mInitialCount(pingCount), // Store initial count
          mCheckCount(check_count),
          mShouldLog(log),
          mSendClose(send_close_after_pings) // Store flag
    {};

    // --- Add move constructor ---
    PingClientHandler(PingClientHandler &&m) noexcept
        : mCount(m.mCount),
          mInitialCount(m.mInitialCount),
          mCheckCount(m.mCheckCount),
          mShouldLog(m.mShouldLog),
          mSendClose(m.mSendClose),
          mMode(m.mMode),
          mSendFn(std::move(m.mSendFn)),
          mRecvFn(std::move(m.mRecvFn)),
          mShutdownFn(std::move(m.mShutdownFn))
    {
        m.mCount = 0; // Prevent double-checking in destructor
        m.mCheckCount = false;
    }


  public: // ProtoHandler interface
    void OnConnected(recv_fn r_func, send_fn s_func, close_fn closer)
    {
        mRecvFn = r_func;
        mSendFn = s_func;
        mShutdownFn = closer;
        mMode = Mode::PING; // Start in PING mode

        if (mShouldLog)
            std::cout << "PingClientHandler OnConnected\n";
        PingOrCloseImpl(); // Start the process
    }
    void OnRecv(buffer_type &in)
    {
        if (mMode == Mode::WAIT_FOR_CLOSE)
        {
            if (mShouldLog)
                std::cout << "PingClientHandler OnRecv while waiting for close (unexpected): " << std::string(in.data(), in.size()) << std::endl;
            // Server might send something before closing? Ignore for now.
            return;
        }

        if (mCount > 0)
            --mCount;

        if (mShouldLog)
            std::cout << "PingClientHandler OnRecv got: " << std::string(in.data(), in.size()) << std::endl;

        // Decide next action based on count and whether we need to send CLOSE
        PingOrCloseImpl();
    }
    void OnSend([[maybe_unused]] data_size sent)
    {
        if (mShouldLog)
        {
            if (mMode == Mode::SEND_CLOSE)
                std::cout << "PingClientHandler OnSend: CLOSE went out OK\n";
            else
                std::cout << "PingClientHandler OnSend: ping went out OK\n";
        }

        if (mMode == Mode::SEND_CLOSE)
        {
            // We've sent CLOSE, now just wait for the server to disconnect us
            mMode = Mode::WAIT_FOR_CLOSE;
            if (mShouldLog)
                std::cout << "PingClientHandler now waiting for server close.\n";
            // Don't request more data here.
        }
        else
            mRecvFn(42);
    }
    void OnError(const std::exception &ex)
    {
        if (mShouldLog)
            std::cout << "PingClientHandler OnError: " << ex.what() << std::endl;

        if (mMode == Mode::WAIT_FOR_CLOSE)
        {
            if (mShouldLog)
                std::cout << "PingClientHandler received error, likely server-initiated close.\n";
        }
        else
            mShutdownFn();

        mMode = Mode::WAIT_FOR_CLOSE; // Ensure no more actions
    };

  public: // Instance management
    void PingOrCloseImpl()
    {
        if (!mSendFn)
            return; // Cannot send

        if (mCount > 0) // Still pings left?
        {
            mMode = Mode::PING;
            auto msg = buffer_type("ping");
#ifdef __cpp_lib_format
            if (mShouldLog)
                std::cout << std::format("PingClientHandler Sending[{}]: {}\n", mCount, std::string(msg.data(), msg.size()));
#endif
            mSendFn(msg);
        }
        else if (mSendClose && mMode != Mode::SEND_CLOSE && mMode != Mode::WAIT_FOR_CLOSE) // Pings finished, and should send CLOSE?
        {
            mMode = Mode::SEND_CLOSE;
            auto msg = buffer_type("CLOSE");
            if (mShouldLog)
                std::cout << "PingClientHandler Sending: CLOSE\n";
            mSendFn(msg);
            // After sending CLOSE, we transition to WAIT_FOR_CLOSE in OnSend
        }
        else if (mMode != Mode::WAIT_FOR_CLOSE) // Pings finished, not sending CLOSE, or already sent CLOSE?
        {
            // Normal shutdown requested by client
            if (mShouldLog)
                std::cout << "PingClientHandler requests shutdown (finished pings/no close needed)" << std::endl;
            mShutdownFn();
        }
        // If in WAIT_FOR_CLOSE mode, do nothing here.
    }

    int mCount = 0;
    int mInitialCount = 0; // Store initial count
    bool mCheckCount = true;
    bool mShouldLog = false;
    bool mSendClose = false; // Flag to send CLOSE message
    Mode mMode = Mode::PING; // Current state
    send_fn mSendFn;
    recv_fn mRecvFn;
    close_fn mShutdownFn;
};

struct EchoServerHandler
{
    using data_size = ServerDefs::data_size;
    using buffer_type = ServerDefs::buffer_type;

    EchoServerHandler(const EchoServerHandler &m)
        : mCount(m.mCount), mShouldLog(m.mShouldLog) {};

    EchoServerHandler(EchoServerHandler &&m)
        : mCount(m.mCount), mShouldLog(m.mShouldLog)
    {
        m.mCount = 0;
    }

    EchoServerHandler(int expected, bool log = false)
        : mCount(expected), mShouldLog(log) {};

    template <typename SocketT>
    asio::awaitable<void> HandleSession(SocketT &socket, asio::io_context &ioCtx)
    {
        if (mShouldLog)
            std::cout << "EchoServerHandler HandleSession started\n";

        try
        {
            while (true)
            {
                // Read data
                buffer_type readBuffer;
                auto buffer_space = readBuffer.allocate_tail(42);
                std::size_t bytes_read = co_await socket.async_read_some(
                    asio::buffer(buffer_space.data(), buffer_space.size()),
                    asio::use_awaitable);

                if (bytes_read == 0)
                    co_return; // Connection closed

                readBuffer.free_tail(42 - bytes_read);

                if (mShouldLog)
                    std::cout << "EchoServerHandler received: "
                              << std::string(readBuffer.data(), readBuffer.size())
                              << std::endl;

                // Check for CLOSE command
                if (readBuffer == "CLOSE"sv)
                {
                    if (mShouldLog)
                        std::cout << "EchoServerHandler received CLOSE command, shutting down session.\n";
                    co_return;
                }

                // Echo back if count allows
                if (mCount > 0 || mCount == -1)
                {
                    if (mCount != -1)
                        --mCount;

                    co_await asio::async_write(socket,
                                               asio::buffer(readBuffer.data(), readBuffer.size()),
                                               asio::use_awaitable);
                }
                else
                {
                    // No more echoes allowed, close
                    co_return;
                }
            }
        }
        catch (const std::exception &e)
        {
            if (mShouldLog)
                std::cerr << "EchoServerHandler error: " << e.what() << std::endl;
        }
    }

    int mCount = 0;
    bool mShouldLog = false;
};

TEST(MicroTlsServerTests, BasicEchoTest)
{
    auto s = MicroTlsServer(6666,
                            "cert.pem",
                            "pvtkey.pem",
                            "dh2048.pem",
                            EchoServerHandler(0));
}

TEST(micro_tls, one_ping_vasily)
{
    auto s = MicroTlsServer(6686,
                            "cert.pem",
                            "pvtkey.pem",
                            "dh2048.pem",
                            EchoServerHandler(1, true));

    auto c = MicroTlsClient<PingClientHandler>("cert.pem", 1, true);
    EXPECT_NO_THROW(c.Connect("127.0.0.1", "6686")); // <-- will throw if client encounters a problem
}

TEST(micro_tls, ping_x3)
{
    auto s = MicroTlsServer(6667,
                            "cert.pem",
                            "pvtkey.pem",
                            "dh2048.pem",
                            EchoServerHandler(3),
                            2);

    auto c = MicroTlsClient<PingClientHandler>("cert.pem", 3);
    EXPECT_NO_THROW(c.Connect("127.0.0.1", "6667")); // <-- will throw if client encounters a problem
}

TEST(micro_tls, ping_x10)
{
    auto s = MicroTlsServer(6668,
                            "cert.pem",
                            "pvtkey.pem",
                            "dh2048.pem",
                            EchoServerHandler(100),
                            2);

    auto c = MicroTlsClient<PingClientHandler>("cert.pem", 10);
    EXPECT_NO_THROW(c.Connect("127.0.0.1", "6668")); // <-- will throw if client encounters a problem
}

TEST(micro_tls, ping_x2_x3)
{
    auto s = MicroTlsServer(6669,
                            "cert.pem",
                            "pvtkey.pem",
                            "dh2048.pem",
                            EchoServerHandler(2),
                            2);

    auto c1 = MicroTlsClient<PingClientHandler>("cert.pem", 2);
    EXPECT_NO_THROW(c1.Connect("127.0.0.1", "6669")); // <-- will throw if client encounters a problem
    auto c2 = MicroTlsClient<PingClientHandler>("cert.pem", 2);
    EXPECT_NO_THROW(c2.Connect("127.0.0.1", "6669")); // <-- will throw if client encounters a problem
    auto c3 = MicroTlsClient<PingClientHandler>("cert.pem", 2);
    EXPECT_NO_THROW(c3.Connect("127.0.0.1", "6669")); // <-- will throw if client encounters a problem
}

TEST(micro_tls, ping_client_mt10x10)
{
    auto s = MicroTlsServer(6670,
                            "cert.pem",
                            "pvtkey.pem",
                            "dh2048.pem",
                            EchoServerHandler(10),
                            6);

    std::vector<AutoThread<>> threads;
    for (auto i = 0; i < 10; ++i)
    {
        threads.emplace_back([]
        {
                                auto c = MicroTlsClient<PingClientHandler>("cert.pem", 10);
                                c.Connect("127.0.0.1", "6670"); });
    }
}

TEST(micro_tls, ping_client_mt_pause_50)
{
    auto s = MicroTlsServer(6671,
                            "cert.pem",
                            "pvtkey.pem",
                            "dh2048.pem",
                            EchoServerHandler(100),
                            6);

    // Little pause to ensure the server stays running while idle
    std::this_thread::sleep_for(100ms);

    std::vector<AutoThread<>> threads;
    for (auto i = 0; i < 50; ++i)
    {
        threads.emplace_back([]
        {
                                 auto c = MicroTlsClient<PingClientHandler>("cert.pem", 100);
                                 c.Connect("127.0.0.1", "6671"); });
    }
}

TEST(micro_tls, bad_cert)
{
    auto s = MicroTlsServer(6672,
                            "cert.pem",
                            "pvtkey.pem",
                            "dh2048.pem",
                            EchoServerHandler(0),
                            2);

    auto fn = MicroTlsClient<PingClientHandler>::cert_check_fn([](auto, auto &) -> bool
    { return false; });

    auto c = MicroTlsClient<PingClientHandler>("cert.pem", 0, true);
    EXPECT_FALSE(c.Connect("127.0.0.1", "6672", fn));
}

TEST(micro_tls, cert_check)
{
    auto s = MicroTlsServer(6673,
                            "cert.pem",
                            "pvtkey.pem",
                            "dh2048.pem",
                            EchoServerHandler(1),
                            2);

    auto fn = MicroTlsClient<PingClientHandler>::cert_check_fn([](auto, auto &) -> bool
    { return true; });

    auto c = MicroTlsClient<PingClientHandler>("cert.pem", 1, true);
    EXPECT_TRUE(c.Connect("127.0.0.1", "6673", fn));
}

TEST(micro_tls, server_handler_close)
{
    auto s = MicroTlsServer(6674,
                            "cert.pem",
                            "pvtkey.pem",
                            "dh2048.pem",
                            EchoServerHandler(-1, true), // Allow infinite echoes until CLOSE
                            2);

    // Client will send 1 ping, then the CLOSE command.
    auto c = MicroTlsClient<PingClientHandler>("cert.pem", 1, true, false, true); // pingCount=1, log=true, check_count=false, send_close=true

    // Connect should succeed initially. The handlers will exchange ping/pong once.
    // Then the client sends CLOSE.
    EXPECT_NO_THROW(c.Connect("127.0.0.1", "6674"));
}

struct DeadlockClientHandler
{
    using send_fn = ClientDefs::send_fn;
    using recv_fn = ClientDefs::recv_fn;
    using buffer_type = ClientDefs::buffer_type;
    using close_fn = ClientDefs::close_fn;
    using data_size = ClientDefs::data_size;

    std::promise<void> connected_promise;
    std::promise<void> shutdown_initiated_promise;
    bool mShouldLog = false;
    bool mOnErrorCalled = false;

    DeadlockClientHandler(bool log = false)
        : mShouldLog(log)
    {
    }

    // --- Add move constructor ---
    DeadlockClientHandler(DeadlockClientHandler &&m) noexcept
        : connected_promise(std::move(m.connected_promise)),
          shutdown_initiated_promise(std::move(m.shutdown_initiated_promise)),
          mShouldLog(m.mShouldLog),
          mOnErrorCalled(m.mOnErrorCalled),
          mSendFn(std::move(m.mSendFn)),
          mRecvFn(std::move(m.mRecvFn)),
          mShutdownFn(std::move(m.mShutdownFn))
    {
    }

    void OnConnected(recv_fn r_func, send_fn s_func, close_fn closer)
    {
        if (mShouldLog)
            std::cout << "DeadlockClientHandler OnConnected" << std::endl;
        mRecvFn = r_func;
        mSendFn = s_func;
        mShutdownFn = closer;

        // Send a message to trigger server echo
        auto msg = buffer_type("deadlock_trigger");
        mSendFn(msg);

        // Request a receive (we don't expect to get it if deadlock occurs)
        mRecvFn(128);
        connected_promise.set_value(); // Signal that connection and initial send occurred
    }

    void OnRecv(buffer_type &in)
    {
        // We should ideally not get here if the deadlock happens quickly.
        if (mShouldLog)
            std::cout << "DeadlockClientHandler OnRecv (unexpected): " << std::string(in.data(), in.size()) << std::endl;
        // If we do get here, it means the server's echo completed before destruction.
        // Still call shutdown to ensure the test finishes.
        if (mShutdownFn)
            mShutdownFn();
    }

    void OnSend([[maybe_unused]] data_size sent)
    {
        // This is the crucial part: Initiate shutdown *immediately* after sending.
        // This increases the chance that the server's async_write (echo)
        // is pending when the Session destructor runs.
        if (mShouldLog)
            std::cout << "DeadlockClientHandler OnSend: trigger sent, initiating shutdown." << std::endl;
        if (mShutdownFn)
        {
            mShutdownFn();
            shutdown_initiated_promise.set_value(); // Signal shutdown was called
        }
    }

    void OnError(const std::exception &ex)
    {
        // This might get called if the server forcefully closes due to deadlock/timeout,
        // or if the shutdown process itself causes an error report.
        if (mShouldLog)
            std::cout << "DeadlockClientHandler OnError: " << ex.what() << std::endl;
        mOnErrorCalled = true;
        // Ensure promises are set if error happens early
        connected_promise.set_value();
        shutdown_initiated_promise.set_value();
    };

    send_fn mSendFn;
    recv_fn mRecvFn;
    close_fn mShutdownFn;
};

TEST(micro_tls, potential_destructor_deadlock)
{
    // Server handler that just echoes
    auto s = MicroTlsServer(6678, // Use a different port
                            "cert.pem",
                            "pvtkey.pem",
                            "dh2048.pem",
                            EchoServerHandler(-1, true), // Echo infinitely
                            1);                          // Only 1 server thread needed

    // Client handler designed to trigger the deadlock
    DeadlockClientHandler client_handler(true);
    auto connected_future = client_handler.connected_promise.get_future();
    auto shutdown_initiated_future = client_handler.shutdown_initiated_promise.get_future();

    // Run client connection in a separate thread
    AutoThread<> client_thread([&client_handler]()
    {
        try {
            // Note: Client constructor takes handler by value, making a copy.
            // We use the original handler's promises/futures.
            auto c = MicroTlsClient<DeadlockClientHandler>("cert.pem", std::move(client_handler));
            // Connect might return true/false or throw depending on implementation
            c.Connect("127.0.0.1", "6678");
             std::cout << "Client Connect() returned." << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Client thread exception: " << e.what() << std::endl;
            // Ensure promises are set if Connect throws early
             client_handler.connected_promise.set_value();
             client_handler.shutdown_initiated_promise.set_value();
        } catch (...) {
             std::cerr << "Client thread unknown exception." << std::endl;
             client_handler.connected_promise.set_value();
             client_handler.shutdown_initiated_promise.set_value();
        } });

    // Wait for the client to connect and send the first message
    auto connected_status = connected_future.wait_for(std::chrono::seconds(1));
    EXPECT_EQ(connected_status, std::future_status::ready) << "Client failed to connect and send initial message.";

    // Wait for the client to initiate shutdown (after sending)
    auto shutdown_status = shutdown_initiated_future.wait_for(std::chrono::seconds(1));
    EXPECT_EQ(shutdown_status, std::future_status::ready) << "Client failed to initiate shutdown.";

    // Now, the server *might* be deadlocked in the Session destructor's poll_one loop.
    // We expect the client thread to eventually finish (either normally or via error).
    // The server object 's' going out of scope should trigger its destructor,
    // which should join the server thread. If the server thread is deadlocked,
    // the test will hang here until the test runner times out.

    // We rely on the AutoThread destructor of client_thread to join.
    // If the server deadlocks, the client might hang waiting for OnRecv or OnError.
    // If the server *doesn't* deadlock, the client thread should exit cleanly.

    // GTest doesn't have a built-in way to assert "does not hang",
    // but if the test completes within the runner's timeout, it implies no deadlock occurred *this time*.
    // A consistent hang on this test indicates the deadlock is being triggered.
    std::cout << "Test proceeding past client shutdown initiation. Waiting for threads to join." << std::endl;

    // The destruction of 's' and 'client_thread' will happen automatically.
    // If the server thread deadlocks, the ~AutoThread() for 's's mWorkThreads will hang.
}