// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#pragma once

#include "async_static_file_router.h"
#include "HttpDefs.h"
#include "HttpRequest.h"
#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <filesystem>
#include <string_view>
#include <utility>

namespace clv::http {

/**
    @brief Asynchronous static file router for HTTP/1.x using ASIO stream descriptors
    @details Wrapper around AsyncStaticFileRouter providing HTTP/1.x-specific interface.
    Serves static files asynchronously without blocking the ASIO reactor.
    Streams file data in chunks, sending data incrementally as it's read.
*/
struct HttpStaticRouter
{
    HttpStaticRouter(std::string_view urlPath,
                     std::filesystem::path filePath)
        : router(urlPath, std::move(filePath))
    {
    }

    asio::awaitable<bool> RouteMsg(HttpRequest msg,
                                   SendingFuncT rfn,
                                   asio::io_context &io_ctx)
    {
        return router.RouteHttp1(std::move(msg), std::move(rfn), io_ctx);
    }

  private:
    AsyncStaticFileRouter router;
};

} // namespace clv::http