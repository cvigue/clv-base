// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_BASE_MICRO_TLS_CLIENT_H_
#define CLV_BASE_MICRO_TLS_CLIENT_H_

#include <cstddef>
#include <functional>
#include <filesystem>
#include <openssl/tls1.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <asio.hpp>
#include <asio/ssl.hpp>
#include <asio/co_spawn.hpp>                         // Include for co_spawn
#include <asio/use_awaitable.hpp>                    // Include for use_awaitable
#include <asio/detached.hpp>                         // Include for asio::detached
#include <asio/experimental/awaitable_operators.hpp> // For operator&&

#include "exception_help.h"
#include "array_deque.h"

namespace clv {

// ********************************************************************************************************************
// Client
// ********************************************************************************************************************

namespace ClientDefs {
using data_type = char;
using buffer_type = ArrayDeque<data_type>;
using data_size = std::size_t;                    ///< Used to represent size of things
using send_fn = std::function<void(buffer_type)>; ///< Function type used to send data
using recv_fn = std::function<void(data_size)>;   ///< Function type used to receive data
using close_fn = std::function<void()>;           ///< Function type for shutting down the session
} // namespace ClientDefs

/**
  @brief Small TLS client using C++20 Coroutines
  @details Implements a small TLS client that provides basic TLS plumbing along with configurable
  certificates and verification. Uses C++20 coroutines (`co_await`) for asynchronous operations.
  Also has a configurable data protocol handler that deals with higher level concerns.
  @tparam ProtoHandlerT Type of the protocol handler that will be used to handle data.
  @note The protocol handler will conform to this interface:

      struct SampleProtoHandler
      {
          using send_fn = ClientDefs::send_fn;
          using recv_fn = ClientDefs::recv_fn;
          using close_fn = ClientDefs::close_fn;
          using data_size = ClientDefs::data_size;

          void OnConnected(recv_fn r_func, send_fn s_func, close_fn closer);
          void OnRecv(buffer_type &in);
          void OnSend(data_size sent);
          void OnError(const std::exception &ex);
      };
*/
template <typename ProtoHandlerT>
struct MicroTlsClient
{
    using data_type = ClientDefs::data_type;
    using buffer_type = ClientDefs::buffer_type;
    using send_fn = ClientDefs::send_fn;
    using recv_fn = ClientDefs::recv_fn;
    using close_fn = ClientDefs::close_fn;
    using data_size = ClientDefs::data_size;
    using cert_check_fn = std::optional<std::function<bool(bool, asio::ssl::verify_context &)>>;

  public:
    template <typename... ArgsT>
    MicroTlsClient(const std::filesystem::path &cert, ArgsT &&...args);

    bool Connect(std::string_view host,
                 std::string_view service,
                 cert_check_fn certCheck = std::nullopt);

  private:
    asio::awaitable<void> Start(std::string_view host,
                                std::string_view service,
                                cert_check_fn certCheck = std::nullopt);

    // Verification function remains synchronous
    bool VerifyCertificate(bool preverified, asio::ssl::verify_context &ctx);

    asio::awaitable<void> Disconnect();

    // Coroutine to handle sending data
    asio::awaitable<void> SendCoroutine(buffer_type data);

    // Coroutine to handle receiving data
    asio::awaitable<void> RecvCoroutine(data_size size);

    template <typename... ArgsT>
    auto CatchWrapper(asio::awaitable<void> (MicroTlsClient::*fn)(ArgsT...),
                      std::string_view context_msg,
                      ArgsT &&...args) noexcept -> asio::awaitable<void>;

  private:
    ProtoHandlerT mHandler;                           ///< Protocol handler instance
    asio::io_context mIoCtx;                          ///< Asio IO context for async operations
    asio::ssl::context mSslCtx;                       ///< SSL context for TLS
    asio::ssl::stream<asio::ip::tcp::socket> mSocket; ///< SSL stream for the socket
    bool mConnectedOk = false;                        ///< Flag set when connection is established
};


/**
    @brief Runs the given member function inside a try catch block.
    @tparam ProtoHandlerT The type of the protocol handler.
    @tparam ArgsT The types of the arguments to be passed to the member function.
    @param fn The member function pointer to be called.
    @param context_msg A string view representing the context message for error handling.
    @param args The arguments to be passed to the member function.
    @details This function is a coroutine that runs the given member function pointer inside a
    try-catch block. If an exception occurs, it calls the OnError method of the protocol
    handler with the exception. This eliminates several boilerplate try-catch blocks
    throughout the code. The function is templated to allow for different types of member
    functions and arguments.
 */
template <typename ProtoHandlerT>
template <typename... ArgsT>
auto MicroTlsClient<ProtoHandlerT>::CatchWrapper(asio::awaitable<void> (MicroTlsClient::*fn)(ArgsT...),
                                                 std::string_view context_msg,
                                                 ArgsT &&...args) noexcept -> asio::awaitable<void>
{
    try
    {
        // Explicitly call the member function pointer on the current object using the provided arguments
#if defined(__GNUC__) && __GNUC__ == 15
        // WORKAROUND: GCC 15 ICE in gimple_add_tmp_var (gimplify.cc:834) when co_return co_await is
        // applied directly to a member-function-pointer call expression.  Materialising the awaitable
        // in a named variable avoids the crash.  Remove once the upstream GCC bug is fixed.
        auto awaitable = (this->*fn)(std::forward<ArgsT>(args)...);
        co_return co_await std::move(awaitable);
#else
        co_return co_await (this->*fn)(std::forward<ArgsT>(args)...);
#endif
    }
    catch (const std::system_error &e)
    {
        mHandler.OnError(RuntimeExFrom(context_msg, e.code()));
    }
    catch (...)
    {
        mHandler.OnError(std::runtime_error(std::string(context_msg))); // Construct string
    }
}

/**
    @brief Construct a new MicroTlsClient<> object
    @tparam ProtoHandlerT type of the protocol handler
    @tparam ArgsT forwarding arguments to the protocol handler
    @details This constructor initializes the TLS context and socket. It also sets up the
    certificate verification paths. The certificate can be specified as a path to a file.
    @param cert Path to the certificate file. If empty, default system paths are used.
    @param args Arguments for the protocol handler instance.
*/
template <typename ProtoHandlerT>
template <typename... ArgsT>
inline MicroTlsClient<ProtoHandlerT>::MicroTlsClient(const std::filesystem::path &cert,
                                                     ArgsT &&...args)
    : mHandler(std::forward<ArgsT>(args)...),
      mIoCtx(),
      mSslCtx(asio::ssl::context::tls_client), // Use tls_client method
      mSocket(mIoCtx, mSslCtx),
      mConnectedOk(false)
{
    // Setup default paths for verification if no specific cert is given
    if (!cert.empty())
        mSslCtx.load_verify_file(cert.string());
    else
        mSslCtx.set_default_verify_paths();

    mSocket.set_verify_mode(asio::ssl::verify_peer);
}

/**
    @brief Connect to a remote host and service.
    @details This function calls the Start coroutine and then runs the io_context.
             It will block until the connection to the server ends whether due to
             an error or successful completion of all transactions.
    @tparam ProtoHandlerT the protocol handler type
    @param host address where the service is available
    @param service service to connect to, usually a port number
    @param certCheck optional certificate validation function
    @return bool @c true if the connection was successful and the termination was
            clean, @c false otherwise.
    @note This function is blocking and will not return until the connection is closed.
*/
template <typename ProtoHandlerT>
inline bool MicroTlsClient<ProtoHandlerT>::Connect(std::string_view host,
                                                   std::string_view service,
                                                   cert_check_fn certCheck)
{
    co_spawn(mIoCtx,
             CatchWrapper(&MicroTlsClient::Start,
                          "MicroTlsClient::Start",
                          std::move(host),
                          std::move(service),
                          std::move(certCheck)),
             asio::detached);
    mIoCtx.run();
    return mConnectedOk;
}

/**
  @brief Main entry point coroutine to connect, handshake, and run the communication loop.
  @tparam ProtoHandlerT the protocol handler type
  @param host address where the service is available
  @param service service to connect to, usually a port number
  @param certCheck optional certificate validation function
  @details Resolves endpoint, connects the socket, sets verification callback, and then
  calls CommLoop coroutine. Catches exceptions and forwards them to the handler.
  This coroutine should be launched using asio::co_spawn.
*/
template <typename ProtoHandlerT>
inline asio::awaitable<void>
MicroTlsClient<ProtoHandlerT>::Start(std::string_view host,
                                     std::string_view service,
                                     cert_check_fn certCheck)
{
    // Set SNI hostname if applicable (important for many TLS ser  if (!host.empty())
    SSL_set_tlsext_host_name(mSocket.native_handle(), host.data());

    // Setup verification callback
    auto defCertCheck = [this](auto pv, auto &ctx) -> bool
    { return VerifyCertificate(pv, ctx); };

    mSocket.set_verify_callback(certCheck ? *certCheck : defCertCheck);

    // Resolve endpoints
    asio::ip::tcp::resolver resolver(mIoCtx);
    auto endpoints = co_await resolver.async_resolve(host, service, asio::use_awaitable);

    // Connect socket
    co_await asio::async_connect(mSocket.lowest_layer(), endpoints, asio::use_awaitable);

    // Perform the TLS handshake
    co_await mSocket.async_handshake(asio::ssl::stream_base::client, asio::use_awaitable);

    close_fn proto_close = [this]() -> void
    { asio::co_spawn(mIoCtx,
                     CatchWrapper(&MicroTlsClient::Disconnect,
                                  "MicroTlsClient::Disconnect"),
                     asio::detached); };
    send_fn proto_send = [this](buffer_type request) -> void
    { asio::co_spawn(mIoCtx,
                     CatchWrapper(&MicroTlsClient::SendCoroutine,
                                  "MicroTlsClient::SendCoroutine",
                                  std::move(request)),
                     asio::detached); };
    recv_fn proto_recv = [this](data_size read_size) -> void
    { asio::co_spawn(mIoCtx,
                     CatchWrapper(&MicroTlsClient::RecvCoroutine,
                                  "MicroTlsClient::RecvCoroutine",
                                  std::move(read_size)),
                     asio::detached); };

    mHandler.OnConnected(proto_recv, proto_send, proto_close);
    mConnectedOk = true;
}

/**
  @brief Stops the associated io_context
  @details This function stops the io_context, effectively disconnecting the client.
  @tparam ProtoHandlerT the protocol handler type
*/
template <typename ProtoHandlerT>
inline asio::awaitable<void> MicroTlsClient<ProtoHandlerT>::Disconnect()
{
    mIoCtx.stop();
    mSocket.lowest_layer().close();
    co_return; // Suppress warning
}

/**
    @brief Default certificate verification callback.
    @param preverified Result of default verification.
    @param ctx Verification context.
    @return bool @c true if the certificate is acceptable, @c false otherwise.
    @note This is not a correct implementation of RFC 2818 hostname verification,
    but it seems like the specific implementation is likely to be different for
    each application. Thus the callback is passed to the constructor and can be
    customized by the user. It is expected that the user will implement the
    hostname verification logic in the callback.
*/
template <typename ProtoHandlerT>
inline bool MicroTlsClient<ProtoHandlerT>::VerifyCertificate(bool preverified,
                                                             asio::ssl::verify_context &ctx)
{
    // For the generic case we just return the preverified value
    // This is not a correct implementation of RFC 2818 hostname verification
    return preverified;
}

/**
    @brief Coroutine to send a message to the server.
    @details Writes the data to the socket and calls handler's OnSend upon completion.
             Handles write errors and forwards them to the handler.
    @tparam ProtoHandlerT the protocol handler type
    @param data The buffer containing the data to send.
*/
template <typename ProtoHandlerT>
inline asio::awaitable<void>
MicroTlsClient<ProtoHandlerT>::SendCoroutine(buffer_type data)
{
    std::size_t bytes_written = co_await asio::async_write(
        mSocket,
        asio::buffer(data.data(), data.size()),
        asio::use_awaitable);

    mHandler.OnSend(bytes_written);
}

/**
    @brief Coroutine to receive data from the server.
    @details Reads data from the socket and calls handler's OnRecv upon completion. Handles read
    errors and forwards them to the protocol handler. This function allocates space in the buffer
    for the incoming data and adjusts the size of the buffer to match the actual number of bytes
    read.
    @tparam ProtoHandlerT the protocol handler type
    @param bytes_to_receive The number of bytes to receive.
    @return asio::awaitable<void>
*/
template <typename ProtoHandlerT>
inline asio::awaitable<void>
MicroTlsClient<ProtoHandlerT>::RecvCoroutine(data_size bytes_to_receive)
{
    auto msg = buffer_type();

    // Allocate space and read data
    auto buffer_space = msg.allocate_tail(bytes_to_receive);
    std::size_t bytes_read = co_await mSocket.async_read_some(
        asio::buffer(buffer_space.data(), buffer_space.size()),
        asio::use_awaitable);
    msg.free_tail(bytes_to_receive - bytes_read); // Adjust buffer size to actual bytes read

    mHandler.OnRecv(msg);
}

} // namespace clv

#endif // CLV_BASE_MICRO_TLS_CLIENT_H_