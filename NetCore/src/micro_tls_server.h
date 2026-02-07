// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_HTTPCORE_MICRO_TLS_SERVER_H
#define CLV_HTTPCORE_MICRO_TLS_SERVER_H

#include <algorithm>
#include <asio/awaitable.hpp>
#include <asio/detail/concurrency_hint.hpp>
#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ssl/context.hpp>
#include <asio/ssl/stream.hpp>
#include <asio/ssl/stream_base.hpp>
#include <cstddef>
#include <exception>
#include <functional>
#include <filesystem>
#include <limits>
#include <stdexcept>

#include <asio.hpp>
#include <asio/ssl.hpp>
#include <asio/co_spawn.hpp>                         // Include for co_spawn
#include <asio/use_awaitable.hpp>                    // Include for use_awaitable
#include <asio/detached.hpp>                         // Include for asio::detached
#include <asio/experimental/awaitable_operators.hpp> // For operator&&

#include "array_deque.h"
#include "exception_help.h"
#include "auto_thread.h"

#include <spdlog/spdlog.h>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace clv {

// ********************************************************************************************************************
// MicroTlsServer
// ********************************************************************************************************************

namespace ServerDefs {
using data_type = char;
using buffer_type = ArrayDeque<data_type>;
using data_size = std::size_t; ///< Used to represent size of things
} // namespace ServerDefs

/**
    @brief Small TLS server using C++20 Coroutines
    @details Implements a small TLS server that provides basic TLS plumbing along with configurable
    certificates and verification. Uses C++20 coroutines (`co_await`) for asynchronous operations.
    Also has a configurable data protocol handler that deals with higher level concerns.
    @tparam ServerHandlerT Type of the protocol handler that will be used to handle data.
    @note The protocol handler will conform to this interface:
    @code
        struct SampleProtoHandler
        {
            template <typename SocketT>
            asio::awaitable<void> HandleSession(SocketT &socket, reactor &io_ctx)
        };
    @endcode
 */
template <typename ServerHandlerT>
struct MicroTlsServer
{
    using data_type = ServerDefs::data_type;
    using buffer_type = ServerDefs::buffer_type;
    using data_size = ServerDefs::data_size;

    using ExHandlerFnT = std::function<bool(std::exception_ptr)>;
    using SslPasswdCbT = std::function<std::string(size_t, asio::ssl::context::password_purpose)>;

    ~MicroTlsServer();
    MicroTlsServer(unsigned short port,
                   std::filesystem::path certChainFile,
                   std::filesystem::path pvtKeyFile,
                   std::filesystem::path dhFile,
                   ServerHandlerT &&zygoteHandler);

    MicroTlsServer(unsigned short port,
                   std::filesystem::path certChainFile,
                   std::filesystem::path pvtKeyFile,
                   std::filesystem::path dhFile,
                   ServerHandlerT &&zygoteHandler,
                   int threads);

    MicroTlsServer(unsigned short port,
                   std::filesystem::path certChainFile,
                   std::filesystem::path pvtKeyFile,
                   std::filesystem::path dhFile,
                   ServerHandlerT &&zygoteHandler,
                   int threads,
                   ExHandlerFnT exh);

    MicroTlsServer(unsigned short port,
                   std::filesystem::path certChainFile,
                   std::filesystem::path pvtKeyFile,
                   std::filesystem::path dhFile,
                   ServerHandlerT &&zygoteHandler,
                   int threads,
                   SslPasswdCbT pwdCb);

    MicroTlsServer(unsigned short port,
                   std::filesystem::path certChainFile,
                   std::filesystem::path pvtKeyFile,
                   std::filesystem::path dhFile,
                   ServerHandlerT &&zygoteHandler,
                   int threads,
                   ExHandlerFnT exh,
                   SslPasswdCbT pwdCb);

  public:
    /// Request the server to stop: close acceptor and stop the io_context.
    void Stop() noexcept;

  private:
    using ThreadT = AutoThread<>;
    using WorkGuardT = asio::executor_work_guard<asio::io_context::executor_type>;

    asio::awaitable<void> Accept();
    asio::awaitable<void> HandleSession(asio::ssl::stream<asio::ip::tcp::socket> socket);
    void Run() noexcept;
    bool IsRunning() const noexcept;
    auto &IoCtx() noexcept;
    static auto MakeException(std::string_view msg, const std::error_code &error);
    static bool defExHandler(std::exception_ptr);
    static std::string defSslPwCb(size_t, asio::ssl::context::password_purpose);

  private:                             // Destruction is in reverse order and order matters here
    ServerHandlerT mZygoteHandler;     ///< The handler to copy into each session
    bool mRunning = true;              ///< Keep running flag
    ExHandlerFnT mExceptionHandler;    ///< This handler will be called if a session throws an exception
    SslPasswdCbT mSslPwCb;             ///< Password callback for SSL context
    asio::ssl::context mSslCtx;        ///< The asio SSL context for the server
    asio::io_context mIoCtx;           ///< The asio reactor
    std::vector<ThreadT> mWorkThreads; ///< Pool of self joining threads
    asio::ip::tcp::acceptor mAcceptor; ///< Connection acceptor
};

// ********************************************************************************************************************
// MicroTlsServer implementation
// ********************************************************************************************************************

/**
    @brief Destructor for the MicroTlsServer class template.
    @details Relies on member destruction order to cleanly shut down. The mAcceptor
    is destroyed first (reverse declaration order), which cancels pending accepts and
    allows the Accept() coroutine to complete. With no more work, io_context.run()
    returns naturally, allowing worker threads to exit and be joined cleanly.
 */
template <typename ServerHandlerT>
inline MicroTlsServer<ServerHandlerT>::~MicroTlsServer()
{
    mRunning = false;
}

/**
  @brief Construct a new MicroTlsServer with default thread count and callbacks
  @tparam ServerHandlerT The protocol handler type that will be installed
  @param port The port to listen / accept on
  @param certChainFile The certificate to present to clients
  @param pvtKeyFile The signing key
  @param dhFile DH file in pem format, for DH key exchange
  @param zygoteHandler The protocol handler instance that will be installed
*/
template <typename ServerHandlerT>
inline MicroTlsServer<ServerHandlerT>::MicroTlsServer(unsigned short port,
                                                      std::filesystem::path certChainFile,
                                                      std::filesystem::path pvtKeyFile,
                                                      std::filesystem::path dhFile,
                                                      ServerHandlerT &&zygoteHandler)
    : MicroTlsServer(port,
                     certChainFile,
                     pvtKeyFile,
                     dhFile,
                     std::move(zygoteHandler),
                     1,
                     defExHandler,
                     defSslPwCb)
{
}

/**
  @brief Construct a new MicroTlsServer with default thread count and callbacks
  @tparam ServerHandlerT The protocol handler type that will be installed
  @param port The port to listen / accept on
  @param certChainFile The certificate to present to clients
  @param pvtKeyFile The signing key
  @param dhFile DH file in pem format, for DH key exchange
  @param zygoteHandler The protocol handler instance that will be installed
  @param threads the number of threads to inject into the ASIO reactor
*/
template <typename ServerHandlerT>
inline MicroTlsServer<ServerHandlerT>::MicroTlsServer(unsigned short port,
                                                      std::filesystem::path certChainFile,
                                                      std::filesystem::path pvtKeyFile,
                                                      std::filesystem::path dhFile,
                                                      ServerHandlerT &&zygoteHandler,
                                                      int threads)
    : MicroTlsServer(port,
                     certChainFile,
                     pvtKeyFile,
                     dhFile,
                     std::move(zygoteHandler),
                     threads,
                     defExHandler,
                     defSslPwCb)
{
}

/**
  @brief Construct a new MicroTlsServer with optional SSL password callback
  @tparam ServerHandlerT The protocol handler type that will be installed
  @param port The port to listen / accept on
  @param certChainFile The certificate to present to clients
  @param pvtKeyFile The signing key
  @param dhFile DH file in pem format, for DH key exchange
  @param zygoteHandler The protocol handler instance that will be installed
  @param threads the number of threads to inject into the ASIO reactor
  @param pwdCb SSL password callback for encrypted private keys
*/
template <typename ServerHandlerT>
inline MicroTlsServer<ServerHandlerT>::MicroTlsServer(unsigned short port,
                                                      std::filesystem::path certChainFile,
                                                      std::filesystem::path pvtKeyFile,
                                                      std::filesystem::path dhFile,
                                                      ServerHandlerT &&zygoteHandler,
                                                      int threads,
                                                      SslPasswdCbT pwdCb)
    : MicroTlsServer(port,
                     certChainFile,
                     pvtKeyFile,
                     dhFile,
                     std::move(zygoteHandler),
                     threads,
                     defExHandler,
                     pwdCb)
{
}

/**
  @brief Construct a new MicroTlsServer with optional exception handler
  @tparam ServerHandlerT The protocol handler type that will be installed
  @param port The port to listen / accept on
  @param certChainFile The certificate to present to clients
  @param pvtKeyFile The signing key
  @param dhFile DH file in pem format, for DH key exchange
  @param zygoteHandler The protocol handler instance that will be installed
  @param threads the number of threads to inject into the ASIO reactor
  @param exh Exception handler, see defExHandler
*/
template <typename ServerHandlerT>
inline MicroTlsServer<ServerHandlerT>::MicroTlsServer(unsigned short port,
                                                      std::filesystem::path certChainFile,
                                                      std::filesystem::path pvtKeyFile,
                                                      std::filesystem::path dhFile,
                                                      ServerHandlerT &&zygoteHandler,
                                                      int threads,
                                                      ExHandlerFnT exh)
    : MicroTlsServer(port,
                     certChainFile,
                     pvtKeyFile,
                     dhFile,
                     std::move(zygoteHandler),
                     threads,
                     exh,
                     defSslPwCb)
{
}

/**
  @brief Construct a new MicroTlsServer with all parameters
  @tparam ServerHandlerT The protocol handler type that will be installed
  @param port The port to listen / accept on
  @param certChainFile The certificate to present to clients
  @param pvtKeyFile The signing key
  @param dhFile DH file in pem format, for DH key exchange
  @param zygoteHandler The protocol handler instance that will be installed
  @param threads the number of threads to inject into the ASIO reactor
  @param exh Exception handler, see defExHandler
  @param pwdCb SSL password callback for encrypted private keys
*/
template <typename ServerHandlerT>
MicroTlsServer<ServerHandlerT>::MicroTlsServer(unsigned short port,
                                               std::filesystem::path certChainFile,
                                               std::filesystem::path pvtKeyFile,
                                               std::filesystem::path dhFile,
                                               ServerHandlerT &&zygoteHandler,
                                               int threads,
                                               ExHandlerFnT exh,
                                               SslPasswdCbT pwdCb)
    : mZygoteHandler(std::move(zygoteHandler)),
      mRunning(true),
      mExceptionHandler(exh),
      mSslPwCb(pwdCb),
      mSslCtx(asio::ssl::context::sslv23),
      mIoCtx(threads < 2 ? 1 : ASIO_CONCURRENCY_HINT_DEFAULT),
      mAcceptor(mIoCtx, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port))
{
    mSslCtx.set_options(asio::ssl::context::default_workarounds
                        | asio::ssl::context::no_sslv2
                        | asio::ssl::context::single_dh_use);
    mSslCtx.set_password_callback(mSslPwCb);
    mSslCtx.use_certificate_chain_file(certChainFile.string());
    mSslCtx.use_private_key_file(pvtKeyFile.string(), asio::ssl::context::pem);
    mSslCtx.use_tmp_dh_file(dhFile.string());

    co_spawn(mIoCtx, Accept(), asio::detached);

    for (auto i = 0; i < std::clamp(threads, 1, std::numeric_limits<int>::max()); ++i)
        mWorkThreads.emplace_back(&MicroTlsServer<ServerHandlerT>::Run, this);
}

/**
    @brief Handle a complete session: handshake and protocol processing
    @details This function is called for each accepted connection. It performs the TLS handshake
    and then delegates to the protocol handler's HandleSession method. The session lives on
    the coroutine stack and is automatically cleaned up when the coroutine completes.
    @param socket The SSL socket for this session
 */
template <typename ServerHandlerT>
inline asio::awaitable<void>
MicroTlsServer<ServerHandlerT>::HandleSession(asio::ssl::stream<asio::ip::tcp::socket> socket)
{
    try
    {
        // Perform TLS handshake
        co_await socket.async_handshake(asio::ssl::stream_base::server, asio::use_awaitable);

        // Create a copy of the protocol handler for this session
        ServerHandlerT handler = mZygoteHandler;

        // Let the protocol handler drive the session
        co_await handler.HandleSession(socket, mIoCtx);
    }
    catch (const std::exception &e)
    {
        spdlog::error("[MicroTlsServer] Session error: {}", e.what());
    }
}

/**
    @brief Posts an accept job to the work queue along with a completion handler.
    @details Posts an accept job to the work queue along with a completion handler. Upon
    completion either the error is transformed into an informative exception and forwarded
    rather than thrown, or a session is created from the socket and Session::Start is
    called on it.
*/
template <typename ServerHandlerT>
asio::awaitable<void> MicroTlsServer<ServerHandlerT>::Accept()
{
    try
    {
        while (IsRunning())
        {
            auto socket = co_await mAcceptor.async_accept(asio::use_awaitable);

            // Spawn a coroutine to handle this session
            // The session lives on the coroutine's stack
            asio::co_spawn(mIoCtx,
                           HandleSession(asio::ssl::stream<asio::ip::tcp::socket>(std::move(socket),
                                                                                  mSslCtx)),
                           [this](std::exception_ptr ep)
            {
                if (ep && IsRunning())
                {
                    try
                    {
                        std::rethrow_exception(ep);
                    }
                    catch (...)
                    {
                        mExceptionHandler(std::current_exception());
                    }
                }
            });
        }

        mAcceptor.close();
    }
    catch (const std::system_error &e)
    {
        // Forward Asio errors to the handler
        if (IsRunning())
            mExceptionHandler(std::make_exception_ptr(MakeException("MicroTlsServer::Accept", e.code())));
    }
    catch (...)
    {
        // Catch-all for any other exceptions
        mExceptionHandler(std::current_exception());
    }
}

/**
    @brief ServerState run loop.
    @details Each worker thread is sent into this function where a few error handling
    things are set up and then the io_context reactor is called. This reactor will then
    parcel out work items to the thread(s) as needed. If a work item causes an exception, it
    will bubble up to here and be caught, captured in an exception ptr, and forwarded to the
    designated exception handler. This handler can do as it sees fit, and if it decides to
    eventually return control back here it should return true if it wants the thread to
    continue or false for the thread (and just this thread) to exit.
*/
template <typename ServerHandlerT>
void MicroTlsServer<ServerHandlerT>::Run() noexcept
{
    // Run the io_context. If an exception escapes a handler it will be
    // forwarded to the exception handler. If the exception handler returns
    // true we will loop and call run() again, otherwise we shut down this
    // thread's run loop.
    while (true)
    {
        std::exception_ptr exp;
        try
        {
            mIoCtx.run();
            // run() returned normally -> reactor drained or stopped; exit loop
            break;
        }
        catch (...)
        {
            exp = std::current_exception();
        }

        // If the exception handler says to continue, loop and call run()
        // again. Otherwise exit.
        if (!mExceptionHandler(exp))
            break;
    }
}

template <typename ServerHandlerT>
void MicroTlsServer<ServerHandlerT>::Stop() noexcept
{
    mRunning = false;

    // Close acceptor to cancel pending accepts
    try
    {
        mAcceptor.close();
    }
    catch (...)
    {
    }

    // Stop the io_context, which will cause all pending async operations to complete
    // and all session coroutines to finish
    // Stop the io_context, which will cause all pending async operations to complete
    // and all session coroutines to finish
    mIoCtx.stop();
}

/**
    @brief Checks if the MicroTlsServer is running.
    @tparam ServerHandlerT The type of the server handler.
    @return true if the server is running, false otherwise.
    @note This function is marked as noexcept, meaning it does not throw exceptions.
 */
template <typename ServerHandlerT>
inline bool MicroTlsServer<ServerHandlerT>::IsRunning() const noexcept
{
    return mRunning;
}

/**
    @brief Returns a reference to the io_context object.
    @tparam ServerHandlerT The type of the server handler.
    @return A reference to the io_context object.
 */
template <typename ServerHandlerT>
inline auto &MicroTlsServer<ServerHandlerT>::IoCtx() noexcept
{
    return mIoCtx;
}

/**
    @brief Creates an extended exception from an error code.
    @tparam ServerHandlerT The type of the server handler.
    @param msg A message describing the context of the error.
    @param error The error code to create the exception from.
    @return An extended exception object.
 */
template <typename ServerHandlerT>
inline auto MicroTlsServer<ServerHandlerT>::MakeException(std::string_view msg,
                                                          const std::error_code &error)
{
    return ExtendedExFromError<std::runtime_error>(msg, error);
}

/**
    @brief Default exception handler that does nothing.
    @tparam ServerHandlerT The type of the server handler.
    @param An exception pointer (not used).
    @return true always, indicating that the server should continue running.
 */
template <typename ServerHandlerT>
inline bool MicroTlsServer<ServerHandlerT>::defExHandler(std::exception_ptr)
{
    return true;
}

/**
    @brief Default SSL password callback that returns an empty string.
    @tparam ServerHandlerT The type of the server handler.
    @param The maximum length of the password (not used).
    @param The password purpose context (not used).
    @return An empty string, indicating no password is needed.
 */
template <typename ServerHandlerT>
inline std::string
MicroTlsServer<ServerHandlerT>::defSslPwCb(size_t,
                                           asio::ssl::context::password_purpose)
{
    return std::string();
}

} // namespace clv

#endif // CLV_HTTPCORE_MICRO_TLS_SERVER_H