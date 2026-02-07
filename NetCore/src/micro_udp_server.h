// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_NETCORE_MICRO_UDP_SERVER_H
#define CLV_NETCORE_MICRO_UDP_SERVER_H

#include <algorithm>
#include <array>
#include <asio/as_tuple.hpp>
#include <asio/awaitable.hpp>
#include <asio/buffer.hpp>
#include <asio/detail/concurrency_hint.hpp>
#include <asio/error.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <atomic>
#include <exception>
#include <functional>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <spdlog/spdlog.h>

#include <asio.hpp>
#include <asio/co_spawn.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/detached.hpp>
#include <asio/experimental/awaitable_operators.hpp>

#include "auto_thread.h"
#include "micro_udp_server_defs.h"

namespace clv {

// ********************************************************************************************************************
// MicroUdpServer
// ********************************************************************************************************************

/**
    @brief Small UDP server using C++20 Coroutines
    @details Implements a lightweight UDP datagram server that provides basic UDP plumbing
    with configurable datagram handling. Uses C++20 coroutines (`co_await`) for asynchronous
    operations. Designed as a foundation for QUIC and other datagram-based protocols.

    @tparam DatagramHandlerT Type of the datagram handler that processes incoming packets.
    @note The datagram handler must conform to this interface:
    @code
        struct SampleDatagramHandler
        {
            /// Handle an incoming datagram
            /// @param data The received datagram bytes
            /// @param remote The sender's endpoint
            /// @param send_fn Callback to send a response
            /// @param io_ctx Reference to the io_context
            /// @return true if handled, false otherwise (for chaining handlers)
            asio::awaitable<bool> HandleDatagram(std::span<const std::uint8_t> data,
                                                 asio::ip::udp::endpoint remote,
                                                 UdpServerDefs::SendDatagramFnT send_fn,
                                                 asio::io_context& io_ctx);
        };
    @endcode
 */
template <typename DatagramHandlerT>
struct MicroUdpServer
{
    using data_type = UdpServerDefs::data_type;
    using buffer_type = UdpServerDefs::buffer_type;
    using data_size = UdpServerDefs::data_size;
    using SendDatagramFnT = UdpServerDefs::SendDatagramFnT;

    using ExHandlerFnT = std::function<bool(std::exception_ptr)>;

    ~MicroUdpServer();

    MicroUdpServer(unsigned short port, DatagramHandlerT &&handler);

    MicroUdpServer(unsigned short port, DatagramHandlerT &&handler, int threads);

    MicroUdpServer(unsigned short port,
                   DatagramHandlerT &&handler,
                   int threads,
                   ExHandlerFnT exh);

    /// Construct handler in place from arguments
    template <typename... Args>
    MicroUdpServer(unsigned short port, int threads, std::in_place_t, Args &&...args);

    /// Non-copyable, non-movable (owns io_context and threads)
    MicroUdpServer(const MicroUdpServer &) = delete;
    MicroUdpServer &operator=(const MicroUdpServer &) = delete;
    MicroUdpServer(MicroUdpServer &&) = delete;
    MicroUdpServer &operator=(MicroUdpServer &&) = delete;

  public:
    /// Request the server to stop: close socket and stop the io_context.
    void Stop() noexcept;

    /// Get the local port the server is bound to
    [[nodiscard]] unsigned short LocalPort() const noexcept;

    /// Get reference to the io_context (for advanced usage)
    [[nodiscard]] asio::io_context &IoContext() noexcept;

    /// Get reference to the handler (for advanced usage)
    [[nodiscard]] DatagramHandlerT &GetHandler() noexcept;

  private:
    using ThreadT = AutoThread<>;

    asio::awaitable<void> ReceiveLoop();
    asio::awaitable<void> SendDatagram(buffer_type data, asio::ip::udp::endpoint remote);
    void Run() noexcept;
    [[nodiscard]] bool IsRunning() const noexcept;
    static auto MakeException(std::string_view msg, const std::error_code &error);
    static bool DefExHandler(std::exception_ptr);

  private:                             // Destruction is in reverse order and order matters here
    DatagramHandlerT mHandler;         ///< The handler for incoming datagrams
    std::atomic<bool> mRunning{true};  ///< Keep running flag
    ExHandlerFnT mExceptionHandler;    ///< Called if receive loop throws
    asio::io_context mIoCtx;           ///< The asio reactor
    asio::ip::udp::socket mSocket;     ///< The UDP socket
    std::vector<ThreadT> mWorkThreads; ///< Pool of self-joining threads
};

// ********************************************************************************************************************
// MicroUdpServer implementation
// ********************************************************************************************************************

/**
    @brief Destructor for the MicroUdpServer class template.
    @details Relies on member destruction order to cleanly shut down. Sets mRunning to false,
    then closes the socket (cancelling pending operations), allowing the receive loop to exit.
    With no more work, io_context.run() returns naturally, allowing worker threads to exit.
 */
template <typename DatagramHandlerT>
inline MicroUdpServer<DatagramHandlerT>::~MicroUdpServer()
{
    Stop();
}

/**
    @brief Construct a new MicroUdpServer with default settings
    @param port The UDP port to bind to
    @param handler The datagram handler instance
 */
template <typename DatagramHandlerT>
inline MicroUdpServer<DatagramHandlerT>::MicroUdpServer(unsigned short port,
                                                        DatagramHandlerT &&handler)
    : MicroUdpServer(port, std::move(handler), 1, DefExHandler)
{
}

/**
    @brief Construct a new MicroUdpServer with specified thread count
    @param port The UDP port to bind to
    @param handler The datagram handler instance
    @param threads Number of worker threads for the io_context
 */
template <typename DatagramHandlerT>
inline MicroUdpServer<DatagramHandlerT>::MicroUdpServer(unsigned short port,
                                                        DatagramHandlerT &&handler,
                                                        int threads)
    : MicroUdpServer(port, std::move(handler), threads, DefExHandler)
{
}

/**
    @brief Construct a new MicroUdpServer with handler constructed in place
    @param port The UDP port to bind to
    @param threads Number of worker threads for the io_context
    @param args Arguments forwarded to handler constructor
 */
template <typename DatagramHandlerT>
template <typename... Args>
MicroUdpServer<DatagramHandlerT>::MicroUdpServer(unsigned short port,
                                                 int threads,
                                                 std::in_place_t,
                                                 Args &&...args)
    : mHandler(std::forward<Args>(args)...),
      mRunning(true),
      mExceptionHandler(DefExHandler),
      mIoCtx(threads < 2 ? 1 : ASIO_CONCURRENCY_HINT_DEFAULT),
      mSocket(mIoCtx, asio::ip::udp::endpoint(asio::ip::udp::v4(), port))
{
    // Spawn the receive loop coroutine
    asio::co_spawn(mIoCtx, ReceiveLoop(), asio::detached);

    // Start worker threads
    for (int i = 0; i < threads; ++i)
    {
        mWorkThreads.emplace_back([this]
        { Run(); });
    }
}

/**
    @brief Construct a new MicroUdpServer with all parameters
    @param port The UDP port to bind to
    @param handler The datagram handler instance
    @param threads Number of worker threads for the io_context
    @param exh Exception handler for unhandled exceptions in receive loop
 */
template <typename DatagramHandlerT>
MicroUdpServer<DatagramHandlerT>::MicroUdpServer(unsigned short port,
                                                 DatagramHandlerT &&handler,
                                                 int threads,
                                                 ExHandlerFnT exh)
    : mHandler(std::move(handler)),
      mRunning(true),
      mExceptionHandler(std::move(exh)),
      mIoCtx(threads < 2 ? 1 : ASIO_CONCURRENCY_HINT_DEFAULT),
      mSocket(mIoCtx, asio::ip::udp::endpoint(asio::ip::udp::v4(), port))
{
    // Spawn the receive loop coroutine
    co_spawn(mIoCtx, ReceiveLoop(), asio::detached);

    // Start worker threads
    for (auto i = 0; i < std::clamp(threads, 1, std::numeric_limits<int>::max()); ++i)
        mWorkThreads.emplace_back(&MicroUdpServer<DatagramHandlerT>::Run, this);
}

/**
    @brief Stop the server gracefully
    @details Sets the running flag to false and closes the socket, which cancels
    any pending async operations and allows the receive loop to exit.
 */
template <typename DatagramHandlerT>
inline void MicroUdpServer<DatagramHandlerT>::Stop() noexcept
{
    mRunning = false;
    std::error_code ec;
    mSocket.close(ec); // Lint warning on ec is spurious until asio implements no_really_really_close_I_mean_it() :)
    mIoCtx.stop();
}

/**
    @brief Get the local port the server is bound to
    @return The port number
 */
template <typename DatagramHandlerT>
inline unsigned short MicroUdpServer<DatagramHandlerT>::LocalPort() const noexcept
{
    std::error_code ec;
    auto endpoint = mSocket.local_endpoint(ec);
    return ec ? 0 : endpoint.port();
}

/**
    @brief Get reference to the io_context
    @return Reference to the internal io_context
 */
template <typename DatagramHandlerT>
inline asio::io_context &MicroUdpServer<DatagramHandlerT>::IoContext() noexcept
{
    return mIoCtx;
}

/**
    @brief Get reference to the handler
    @return Reference to the handler instance
 */
template <typename DatagramHandlerT>
inline DatagramHandlerT &MicroUdpServer<DatagramHandlerT>::GetHandler() noexcept
{
    return mHandler;
}

/**
    @brief Check if the server is still running
    @return true if running, false if stopped
 */
template <typename DatagramHandlerT>
inline bool MicroUdpServer<DatagramHandlerT>::IsRunning() const noexcept
{
    return mRunning.load(std::memory_order_acquire);
}

/**
    @brief The main receive loop coroutine
    @details Continuously receives datagrams and dispatches them to the handler.
    Each datagram is processed in its own spawned coroutine to allow concurrent handling.
 */
template <typename DatagramHandlerT>
asio::awaitable<void> MicroUdpServer<DatagramHandlerT>::ReceiveLoop()
{
    // Receive buffer - reused for each datagram
    std::array<data_type, UdpServerDefs::max_datagram_size> recv_buffer{};

    while (IsRunning())
    {
        try
        {
            asio::ip::udp::endpoint remote_endpoint;

            // Wait for a datagram
            auto [ec, bytes_received] = co_await mSocket.async_receive_from(
                asio::buffer(recv_buffer),
                remote_endpoint,
                asio::as_tuple(asio::use_awaitable));

            if (ec)
            {
                if (ec == asio::error::operation_aborted || !IsRunning())
                {
                    // Socket was closed or server stopped
                    break;
                }
                // Log error but continue receiving
                spdlog::warn("[MicroUdpServer] Receive error: {}", ec.message());
                continue;
            }

            if (bytes_received == 0)
            {
                continue; // Empty datagram, ignore
            }

            // Create a span view of the received data
            std::span<const data_type> data_view(recv_buffer.data(), bytes_received);

            // Create send function for this handler invocation
            // Capture `this` and the remote endpoint
            SendDatagramFnT send_fn = [this, remote_endpoint](buffer_type data,
                                                              asio::ip::udp::endpoint dest)
                -> asio::awaitable<void>
            {
                co_await SendDatagram(std::move(data), dest);
            };

            // Invoke the handler
            // Note: We could spawn this as a separate coroutine for true concurrency,
            // but for QUIC we want to process packets in order per connection.
            // The connection manager layer can parallelize if needed.
            try
            {
                co_await mHandler.HandleDatagram(data_view,
                                                 remote_endpoint,
                                                 send_fn,
                                                 mIoCtx);
            }
            catch (const std::exception &e)
            {
                spdlog::error("[MicroUdpServer] Handler error: {}", e.what());
            }
        }
        catch (const std::exception &e)
        {
            if (!IsRunning())
                break;
            spdlog::error("[MicroUdpServer] Receive loop error: {}", e.what());
            if (mExceptionHandler)
            {
                if (!mExceptionHandler(std::current_exception()))
                    break; // Handler said to stop
            }
        }
    }
}

/**
    @brief Send a datagram to a remote endpoint
    @param data The datagram bytes to send
    @param remote The destination endpoint
 */
template <typename DatagramHandlerT>
asio::awaitable<void> MicroUdpServer<DatagramHandlerT>::SendDatagram(
    buffer_type data,
    asio::ip::udp::endpoint remote)
{
    if (!IsRunning())
        co_return;

    auto [ec, bytes_sent] = co_await mSocket.async_send_to(
        asio::buffer(data),
        remote,
        asio::as_tuple(asio::use_awaitable));

    if (ec)
    {
        spdlog::error("[MicroUdpServer] Send error to {}: {}",
                      remote.address().to_string() + ":" + std::to_string(remote.port()),
                      ec.message());
    }
}

/**
    @brief Worker thread function
    @details Runs the io_context event loop until stopped.
 */
template <typename DatagramHandlerT>
inline void MicroUdpServer<DatagramHandlerT>::Run() noexcept
{
    try
    {
        mIoCtx.run();
    }
    catch (const std::exception &e)
    {
        spdlog::error("[MicroUdpServer] Thread error: {}", e.what());
        if (mExceptionHandler)
            mExceptionHandler(std::current_exception());
    }
}

/**
    @brief Create an informative exception from a message and error code
    @param msg Context message
    @param error The error code
    @return A runtime_error with combined message
 */
template <typename DatagramHandlerT>
inline auto MicroUdpServer<DatagramHandlerT>::MakeException(std::string_view msg,
                                                            const std::error_code &error)
{
    return std::runtime_error(std::string(msg) + ": " + error.message());
}

/**
    @brief Default exception handler
    @param eptr The exception pointer
    @return true to continue, false to stop
 */
template <typename DatagramHandlerT>
inline bool MicroUdpServer<DatagramHandlerT>::DefExHandler(std::exception_ptr eptr)
{
    try
    {
        if (eptr)
            std::rethrow_exception(eptr);
    }
    catch (const std::exception &e)
    {
        spdlog::error("[MicroUdpServer] Unhandled exception: {}", e.what());
    }
    return true; // Continue running
}

} // namespace clv

#endif // CLV_NETCORE_MICRO_UDP_SERVER_H
