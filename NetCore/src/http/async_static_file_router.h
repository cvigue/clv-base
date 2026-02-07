// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#pragma once

#include "HttpDefs.h"
#include "HttpRequest.h"
#include "HttpResponse.h"
#include "ci_string.h"
#include "util/MimeType.h"
#include "util/static_file_resolver.h"
#include <algorithm>
#include <asio/awaitable.hpp>
#include <asio/buffer.hpp>
#include <asio/error_code.hpp>
#include <asio/io_context.hpp>
#include <asio/use_awaitable.hpp>
#include <buffer_util.h>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <spdlog/spdlog.h>
#include <filesystem>
#include <functional>
#include <optional>
#include <scope_guard.h>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unique_fd.h>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <asio/stream_file.hpp>
using file_descriptor = asio::stream_file;
#else
#include <asio/posix/stream_descriptor.hpp>
#include <fcntl.h>
#include <unistd.h>
using file_descriptor = asio::posix::stream_descriptor;
#endif

namespace clv::http {

/**
 * @brief Async static file router with protocol-agnostic core
 * @details Serves static files asynchronously using ASIO stream descriptors.
 *          Streams files in chunks without loading entire file into memory.
 *          Can be used for HTTP/1.x, HTTP/2, and HTTP/3.
 */
class AsyncStaticFileRouter
{
  public:
    /// Callback type for sending response headers
    using HeaderSenderFn = std::function<asio::awaitable<void>(std::string_view mime_type, size_t content_length)>;

    /// Callback type for sending response data chunks
    using ChunkSenderFn = std::function<asio::awaitable<void>(std::span<const std::uint8_t>)>;

    /**
     * @brief Constructor
     * @param urlPath The URL path prefix to match (e.g., "/static" or "/")
     * @param filePath The filesystem directory to serve files from
     * @param defaultFile Default file to serve for directory requests (default: "index.html")
     * @throws std::runtime_error if the filePath does not exist or is not a directory
     */
    AsyncStaticFileRouter(std::string_view urlPath,
                          std::filesystem::path filePath,
                          std::string_view defaultFile = "index.html")
        : mUrlPath(util::StaticFileResolver::NormalizeUrlPrefix(urlPath)),
          mFilePath(std::move(filePath)),
          mDefaultFile(defaultFile)
    {
        if (!std::filesystem::exists(mFilePath) || !std::filesystem::is_directory(mFilePath))
        {
            throw std::runtime_error("AsyncStaticFileRouter: Invalid file path - must be an existing directory");
        }
    }

    /**
     * @brief Route a request and stream the file asynchronously
     * @param requestPath The request URL path
     * @param send_headers Callback to send response headers (mime type, content length)
     * @param send_chunk Callback to send data chunks
     * @param io_ctx The io_context for async operations
     * @return awaitable<bool> - true if the request was handled, false otherwise
     * @details This is protocol-agnostic - the callbacks handle formatting for HTTP/1.x, HTTP/2, or HTTP/3
     */
    asio::awaitable<bool> RouteRequest(const std::string &requestPath,
                                       HeaderSenderFn send_headers,
                                       ChunkSenderFn send_chunk,
                                       asio::io_context &io_ctx)
    {
        auto filePath = ResolveFile(requestPath);
        if (!filePath)
        {
            co_return false;
        }

        try
        {
            co_await StreamFile(*filePath, send_headers, send_chunk, io_ctx);
            co_return true;
        }
        catch (const std::exception &e)
        {
            spdlog::error("[AsyncStaticFileRouter] StreamFile error for '{}': {}",
                          filePath->string(),
                          e.what());
            co_return false;
        }
    }

    /**
     * @brief Route an HTTP/1.x request (convenience method)
     * @param msg The HTTP request message
     * @param rfn The function to call to send the response
     * @param io_ctx The io_context for async operations
     * @return awaitable<bool> - true if the request was handled, false otherwise
     */
    asio::awaitable<bool> RouteHttp1(HttpRequest msg,
                                     SendingFuncT rfn,
                                     asio::io_context &io_ctx)
    {
        if (msg.method != "GET")
        {
            co_return false;
        }

        auto send_headers = [rfn](std::string_view mime_type, size_t content_length) -> asio::awaitable<void>
        {
            HttpResponse response(200);
            response.AddHeaderIfAbsent("Content-Type"_cis, std::string(mime_type));
            response.AddHeaderIfAbsent("Content-Length"_cis, std::to_string(content_length));
            auto headerBuffer = response.AsBuffer();
            co_await rfn(std::move(headerBuffer));
        };

        auto send_chunk = [rfn](std::span<const std::uint8_t> data) -> asio::awaitable<void>
        {
            buffer_type chunk;
            clv::append(chunk, data.begin(), data.end());
            co_await rfn(std::move(chunk));
        };

        co_return co_await RouteRequest(msg.url, send_headers, send_chunk, io_ctx);
    }

  private:
    std::optional<std::filesystem::path> ResolveFile(const std::string &requestUrl)
    {
        return util::StaticFileResolver::Resolve(requestUrl, mUrlPath, mFilePath, mDefaultFile);
    }

    asio::awaitable<void> StreamFile(const std::filesystem::path &filePath,
                                     HeaderSenderFn send_headers,
                                     ChunkSenderFn send_chunk,
                                     asio::io_context &io_ctx)
    {
        auto file = co_await OpenFile(filePath, io_ctx);
        auto file_guard = scope_exit([&file]()
        { file.close(); });

        auto fileSize = std::filesystem::file_size(filePath);
        auto mimeType = MimeType::GetMimeType(filePath);

        // Send headers
        co_await send_headers(mimeType, fileSize);

        // Stream file content in chunks
        std::vector<std::uint8_t> chunk_buffer(MAX_CHUNK_SIZE);
        size_t totalRead = 0;
        while (totalRead < fileSize)
        {
            size_t to_read = std::min<size_t>(MAX_CHUNK_SIZE, fileSize - totalRead);
            size_t bytes_read = co_await ReadFileChunk(file, chunk_buffer, to_read);

            co_await send_chunk(std::span<const std::uint8_t>(chunk_buffer.data(), bytes_read));
            totalRead += bytes_read;
        }
    }

    asio::awaitable<file_descriptor> OpenFile(const std::filesystem::path &filePath,
                                              asio::io_context &io_ctx)
    {
        file_descriptor file(io_ctx);
#ifdef _WIN32
        file.open(filePath.string(), file_descriptor::read_only);
        if (!file.is_open())
        {
            throw std::runtime_error("Cannot open file: " + filePath.string());
        }
#else
        clv::UniqueFd fd(::open(filePath.string().c_str(), O_RDONLY));
        file.assign(fd.release()); // throws asio::system_error on failure
#endif
        co_return std::move(file);
    }

    asio::awaitable<size_t> ReadFileChunk(file_descriptor &file,
                                          std::vector<std::uint8_t> &buffer,
                                          size_t max_bytes)
    {
        auto bytes_read = co_await file.async_read_some(
            asio::buffer(buffer.data(), max_bytes),
            asio::use_awaitable);

        co_return bytes_read;
    }

  private:
    std::string mUrlPath;
    std::filesystem::path mFilePath;
    std::string mDefaultFile;

    static constexpr size_t MAX_CHUNK_SIZE = 65536; // 64KB chunks for streaming
};

} // namespace clv::http
