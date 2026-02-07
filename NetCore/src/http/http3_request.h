// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_NETCORE_HTTP_HTTP3_REQUEST_H
#define CLV_NETCORE_HTTP_HTTP3_REQUEST_H

#include "http3_frame.h"
#include "qpack.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include <spdlog/spdlog.h>

namespace clv::http3 {

// HTTP/3 request parser
struct Http3Request
{
    std::string method;
    std::string path;
    std::string authority;
    std::string scheme;
    std::unordered_map<std::string, std::string> headers;
    std::vector<std::uint8_t> body;
};

// Parse HTTP/3 stream data into request
inline std::optional<Http3Request> ParseHttp3Request(std::span<const std::uint8_t> stream_data)
{
    Http3Request request;
    std::size_t offset = 0;

    // Parse frames from stream
    while (offset < stream_data.size())
    {
        auto frame_result = http3::ParseFrame(stream_data.subspan(offset));
        if (!frame_result)
        {
            break; // Incomplete or malformed frame
        }

        auto [parsed_frame, consumed] = *frame_result;
        offset += consumed;

        // Handle frame types
        if (parsed_frame.type == http3::FrameType::Headers)
        {
            auto &headers_frame = std::get<HeadersFrame>(parsed_frame.frame);

            // Debug: print header block bytes
            spdlog::trace("[HTTP/3] HEADERS frame, block size={} bytes", headers_frame.header_block.size());

            // Decode QPACK headers
            QpackDecoder decoder;
            auto decoded_headers = decoder.Decode(headers_frame.header_block);
            if (!decoded_headers)
            {
                throw std::runtime_error("Failed to decode QPACK headers");
            }

            // Extract pseudo-headers and regular headers
            for (const auto &field : *decoded_headers)
            {
                if (field.name == ":method")
                    request.method = field.value;
                else if (field.name == ":path")
                    request.path = field.value;
                else if (field.name == ":authority")
                    request.authority = field.value;
                else if (field.name == ":scheme")
                    request.scheme = field.value;
                else
                    request.headers[field.name] = field.value;
            }
        }
        else if (parsed_frame.type == http3::FrameType::Data)
        {
            auto &data_frame = std::get<DataFrame>(parsed_frame.frame);
            request.body.insert(request.body.end(), data_frame.payload.begin(), data_frame.payload.end());
        }
    }

    // Validate required pseudo-headers
    if (request.method.empty() || request.path.empty())
    {
        return std::nullopt;
    }

    return request;
}

} // namespace clv::http3

#endif // CLV_NETCORE_HTTP_HTTP3_REQUEST_H