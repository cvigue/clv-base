// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include <asio/awaitable.hpp>
#include <asio/buffer.hpp>
#include <asio/io_context.hpp>
#include <cstddef>
#include <exception>
#include <string>
#include <vector>
#include <variant>
#include <string_view>

#include <spdlog/spdlog.h>

#include <asio.hpp>
#include <asio/co_spawn.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/detached.hpp>

#include <array_deque.h>
#include <ci_string.h>

#include "HttpDefs.h"
#include "HttpRequest.h"
#include "HttpResponse.h"
namespace clv::http {

using std::literals::operator""sv;

/**
    @brief The HttpRequestDispatcher struct is a dispatcher for HTTP requests.
    @details The HttpRequestDispatcher struct is a dispatcher for HTTP requests. It is
    derived from std::variant and can hold any of the routers included in the template
    parameter list. It uses std::visit to call the RouteMsg function of the router that
    it currently holds. All routers are async and take io_context as a parameter.
    @see HttpRequest uses HttpRequestDispatcher to route incoming requests.
    @tparam RoutersT The router types to include in the dispatcher
*/
template <typename... RoutersT>
struct HttpRequestDispatcher final : std::variant<RoutersT...>
{
    using std::variant<RoutersT...>::variant;
    using std::variant<RoutersT...>::operator=;

    /**
       @brief Dispatch the message to the router inside the variant. Returns an awaitable.
       @details All routers are async and take io_context as the last parameter.
       @param msg The HTTP request message
       @param rfn The send function
       @param io_ctx The io_context for async operations
       @return awaitable<bool> indicating if the request was handled
     */
    asio::awaitable<bool> RouteMsg(HttpRequest msg,
                                   SendingFuncT rfn,
                                   asio::io_context &io_ctx)
    {
        co_return co_await std::visit(
            [&msg, &rfn, &io_ctx](auto &&router) -> asio::awaitable<bool>
        {
            // All routers are async and take io_context
            co_return co_await router.RouteMsg(msg, rfn, io_ctx);
        },
            *this);
    }
};

/**
    @brief Handles HTTP requests and routes them to the appropriate responder
    @details Coroutine-native protocol handler that directly drives the I/O loop.
    Reads requests, parses them, dispatches to routers, and writes responses.
    Supports HTTP/1.1 keep-alive.
    @tparam RoutersT The router types to handle requests (all must be async)
*/
template <typename... RoutersT>
class HttpServerProto
{
    // Constants & types
    static constexpr size_type bufferDefaultSize = 4000u;
    using RouterDispatchT = HttpRequestDispatcher<RoutersT...>;
    using reactor = asio::io_context;

  public:
    HttpServerProto(std::vector<RouterDispatchT> &&routers)
        : mRouters(std::move(routers))
    {
    }

    /**
        @brief Handle a complete session with HTTP request/response cycles
        @details Drives the I/O loop: read, parse, dispatch, write, check keep-alive.
        Continues until connection closes or error occurs. The coroutine mechanism is
        responsible for suspending and resuming as async operations complete and maintaining
        session state during suspension. No manual state persistence is needed.
        @tparam SocketT The socket type (typically asio::ssl::stream<asio::ip::tcp::socket>)
        @param socket The connected socket
        @param io_ctx The io_context for async operations
        @return awaitable that completes when session ends
    */
    template <typename SocketT>
    asio::awaitable<void> HandleSession(SocketT &socket, reactor &io_ctx)
    {
        HttpRequestParser parser;
        buffer_type readBuffer;

        try
        {
            while (true)
            {
                // Read data from socket
                auto buffer_space = readBuffer.allocate_tail(bufferDefaultSize);
                std::size_t bytes_read = co_await socket.async_read_some(
                    asio::buffer(buffer_space.data(), buffer_space.size()),
                    asio::use_awaitable);

                if (bytes_read == 0)
                {
                    co_return; // Connection closed
                }

                readBuffer.free_tail(bufferDefaultSize - bytes_read);

                // Parse the request
                if (!parser.Parse(readBuffer))
                {
                    // Need more data - continue reading
                    continue;
                }

                // We have a complete request - clear the buffer for next request
                HttpRequest request = parser.GetRequest();
                readBuffer.clear();

                // Dispatch to routers
                bool handled = false;
                for (auto &router : mRouters)
                {
                    handled = co_await router.RouteMsg(
                        request,
                        [&socket](buffer_type buf) -> asio::awaitable<void>
                    {
                        co_await asio::async_write(socket,
                                                   asio::buffer(buf.data(), buf.size()),
                                                   asio::use_awaitable);
                    },
                        io_ctx);
                    if (handled)
                        break;
                }

                if (!handled)
                {
                    // No router handled it - send 404
                    auto response = HttpResponse(404, "Not Found"sv).AsBuffer();
                    co_await asio::async_write(socket,
                                               asio::buffer(response.data(), response.size()),
                                               asio::use_awaitable);
                }

                // Check if we should close the connection
                if (request.protoVer.empty() || request.protoVer == "HTTP/1.0")
                    co_return; // HTTP/1.0 - close after response

                if (auto it = request.headers.find("Connection"_cis);
                    it != request.headers.end() && it->second == "close")
                    co_return; // Client requested close

                // HTTP/1.1 keep-alive - reset parser and continue
                parser = HttpRequestParser();
            }
        }
        catch (const std::exception &e)
        {
            // End of file is normal - client closed connection
            std::string err_msg = e.what();
            if (err_msg.find("End of file") == std::string::npos)
            {
                spdlog::warn("[HttpServerProto] Error: {}", err_msg);
            }
            // Let connection close naturally
        }
    }

  private: // Data
    std::vector<RouterDispatchT> mRouters;
};

} // namespace clv::http