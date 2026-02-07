// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#ifndef CLV_NETCORE_HTTP_HTTP3_APIROUTER_H
#define CLV_NETCORE_HTTP_HTTP3_APIROUTER_H

#include "http3_fwd.h"
#include "http3_frame.h"
#include "qpack.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>
#include <optional>

#include <spdlog/spdlog.h>

namespace clv::http3 {

// Simple API router for HTTP/3
struct ApiRouter
{
    std::string mConfigJson;
    bool mEnabled;

    ApiRouter() = default;
    explicit ApiRouter(std::string cfgJson, bool enable)
        : mConfigJson(std::move(cfgJson)), mEnabled(enable)
    {
    }

    // Route API requests and generate QPACK-encoded response
    std::optional<std::vector<std::uint8_t>> RouteMsg(const std::string &path)
    {
        if (!mEnabled || !path.starts_with("/api/"))
        {
            return std::nullopt;
        }

        spdlog::debug("[API] Handling: {}", path);

        std::string response_body;
        std::string content_type;

        if (path == "/api/hello")
        {
            response_body = "Hello from HTTP/3 QUIC Server!";
            content_type = "text/plain";
        }
        else if (path == "/api/config")
        {
            response_body = mConfigJson;
            content_type = "application/json";
        }
        else
        {
            // API endpoint not found
            response_body = "API endpoint not found";
            content_type = "text/plain";
        }

        // Build HTTP/3 response with QPACK-encoded headers
        QpackEncoder encoder;
        std::vector<HeaderField> headers = {
            {":status", "200"},
            {"content-type", content_type},
            {"content-length", std::to_string(response_body.size())}};

        auto encoded_headers = encoder.Encode(headers);

        // Create HEADERS frame
        HeadersFrame headers_frame;
        headers_frame.header_block = std::move(encoded_headers);

        // Encode HEADERS frame
        std::vector<std::uint8_t> response;
        auto type_bytes = EncodeVarintToVector(static_cast<std::uint64_t>(http3::FrameType::Headers));
        auto length_bytes = EncodeVarintToVector(headers_frame.header_block.size());
        response.insert(response.end(), type_bytes.begin(), type_bytes.end());
        response.insert(response.end(), length_bytes.begin(), length_bytes.end());
        response.insert(response.end(), headers_frame.header_block.begin(), headers_frame.header_block.end());

        // Create DATA frame
        DataFrame data_frame;
        data_frame.payload.assign(response_body.begin(), response_body.end());

        // Encode DATA frame
        type_bytes = EncodeVarintToVector(static_cast<std::uint64_t>(http3::FrameType::Data));
        length_bytes = EncodeVarintToVector(data_frame.payload.size());
        response.insert(response.end(), type_bytes.begin(), type_bytes.end());
        response.insert(response.end(), length_bytes.begin(), length_bytes.end());
        response.insert(response.end(), data_frame.payload.begin(), data_frame.payload.end());

        return response;
    }
};

} // namespace clv::http3

#endif // CLV_NETCORE_HTTP_HTTP3_APIROUTER_H