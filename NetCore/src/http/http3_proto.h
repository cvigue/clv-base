// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#pragma once

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <concepts>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace clv::http3 {

/**
 * @brief Dispatcher for HTTP/3 request routers using variant+visit pattern
 * @details Similar to HTTP/1.x HttpRequestDispatcher, this provides a type-safe
 *          way to compose multiple routers and try them in sequence.
 *          Supports both synchronous routers (ApiRouter) and async routers
 *          (Http3AsyncStaticRouter) through compile-time dispatch.
 * @tparam RoutersT The router types to include in the dispatcher
 */
template <typename... RoutersT>
struct Http3RequestDispatcher final : std::variant<RoutersT...>
{
    using std::variant<RoutersT...>::variant;
    using std::variant<RoutersT...>::operator=;

    /**
     * @brief Route a request through the contained router
     * @details Uses std::visit to dispatch to the appropriate router's RouteMsg.
     *          Handles both synchronous routers (returning optional<vector<uint8_t>>)
     *          and async routers (returning awaitable<bool> with stream_writer callback).
     * @tparam StreamWriterFn Callback type: void(std::vector<uint8_t>)
     * @param path The request path
     * @param stream_writer Callback to receive response data
     * @param io_ctx The io_context for async operations
     * @return awaitable<bool> - true if request was handled, false otherwise
     */
    template <typename StreamWriterFn>
    asio::awaitable<bool> RouteMsg(const std::string &path,
                                   StreamWriterFn stream_writer,
                                   asio::io_context &io_ctx)
    {
        co_return co_await std::visit(
            [&](auto &&router) -> asio::awaitable<bool>
        {
            // Check if this is a synchronous router (has RouteMsg returning optional)
            // This matches ApiRouter::RouteMsg(const std::string&)
            if constexpr (requires {
                              { router.RouteMsg(path) } -> std::convertible_to<std::optional<std::vector<std::uint8_t>>>;
                          })
            {
                auto response = router.RouteMsg(path);
                if (response)
                {
                    stream_writer(std::move(*response));
                    co_return true;
                }
                co_return false;
            }
            // Otherwise, assume async router with callback interface
            // This matches Http3AsyncStaticRouter::RouteMsg(path, stream_writer, io_ctx)
            else
            {
                co_return co_await router.RouteMsg(path, stream_writer, io_ctx);
            }
        },
            *this);
    }
};

} // namespace clv::http3
