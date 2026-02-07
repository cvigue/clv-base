// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#pragma once

#include "async_static_file_router.h"
#include "http3_fwd.h"
#include "http3_frame.h"
#include "qpack.h"

#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <spdlog/spdlog.h>
#include <vector>

namespace clv::http3 {

/**
 * @brief Async static file router for HTTP/3
 * @details Wraps AsyncStaticFileRouter and formats responses as HTTP/3 frames.
 *          Uses async file I/O with streaming to avoid blocking and memory bloat.
 */
class Http3AsyncStaticRouter
{
  public:
    Http3AsyncStaticRouter(std::string_view urlPrefix,
                           std::filesystem::path rootDir,
                           std::string_view defaultFile = "index.html")
        : router_(urlPrefix, std::move(rootDir), defaultFile)
    {
    }

    /**
     * @brief Route an HTTP/3 request and stream the response asynchronously
     * @param path The request path
     * @param stream_writer Callback to write HTTP/3 frames to the stream
     * @param io_ctx The io_context for async operations
     * @return awaitable<bool> - true if the request was handled, false otherwise
     */
    asio::awaitable<bool> RouteMsg(const std::string &path,
                                   std::function<void(std::vector<std::uint8_t>)> stream_writer,
                                   asio::io_context &io_ctx)
    {
        spdlog::debug("[Static] Request for: {}", path);

        auto send_headers = [stream_writer](std::string_view mime_type, size_t content_length) -> asio::awaitable<void>
        {
            // Build HTTP/3 HEADERS frame
            QpackEncoder encoder;
            std::vector<HeaderField> headers = {
                {":status", "200"},
                {"content-type", std::string(mime_type)},
                {"content-length", std::to_string(content_length)}};

            auto encoded_headers = encoder.Encode(headers);

            std::vector<std::uint8_t> headers_data;
            auto type_bytes = EncodeVarintToVector(static_cast<std::uint64_t>(FrameType::Headers));
            auto length_bytes = EncodeVarintToVector(encoded_headers.size());
            headers_data.insert(headers_data.end(), type_bytes.begin(), type_bytes.end());
            headers_data.insert(headers_data.end(), length_bytes.begin(), length_bytes.end());
            headers_data.insert(headers_data.end(), encoded_headers.begin(), encoded_headers.end());

            stream_writer(std::move(headers_data));
            co_return;
        };

        auto send_chunk = [stream_writer](std::span<const std::uint8_t> data) -> asio::awaitable<void>
        {
            // Build HTTP/3 DATA frame
            std::vector<std::uint8_t> data_frame;
            auto type_bytes = EncodeVarintToVector(static_cast<std::uint64_t>(FrameType::Data));
            auto length_bytes = EncodeVarintToVector(data.size());
            data_frame.insert(data_frame.end(), type_bytes.begin(), type_bytes.end());
            data_frame.insert(data_frame.end(), length_bytes.begin(), length_bytes.end());
            data_frame.insert(data_frame.end(), data.begin(), data.end());

            stream_writer(std::move(data_frame));
            co_return;
        };

        bool handled = co_await router_.RouteRequest(path, send_headers, send_chunk, io_ctx);

        if (handled)
        {
            spdlog::debug("[Static] Successfully served: {}", path);
        }
        else
        {
            spdlog::debug("[Static] File not found or invalid path: {}", path);
        }

        co_return handled;
    }

  private:
    http::AsyncStaticFileRouter router_;
};

} // namespace clv::http3
