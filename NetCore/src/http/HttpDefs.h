// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#ifndef CLV_HTTPCORE_HTTPDEFS_H
#define CLV_HTTPCORE_HTTPDEFS_H

#include <cstddef>
#include <unordered_map>
#include <string>
#include <functional>

#include <asio/awaitable.hpp>

#include <array_deque.h>
#include <ci_string.h>

namespace clv::http {

// Types
using data_type = char;
using buffer_type = ArrayDeque<data_type>;

using size_type = std::size_t;

using SendingFuncT = std::function<asio::awaitable<void>(buffer_type)>;

// Helpers
template <typename TypeT>
concept HttpHeaderValueConvertibleType = std::is_same_v<TypeT, bool>
                                         || std::is_same_v<TypeT, int>
                                         || std::is_same_v<TypeT, unsigned long>
                                         || std::is_same_v<TypeT, std::size_t>
                                         || std::is_same_v<TypeT, long>
                                         || std::is_same_v<TypeT, float>
                                         || std::is_same_v<TypeT, double>
                                         || std::is_same_v<TypeT, std::string>;

template <typename TypeT>
constexpr bool HttpHeaderValueConvertibleType_v = HttpHeaderValueConvertibleType<TypeT>;

// Map of HTTP code to corresponding message
inline const std::unordered_map<int, std::string> CodeLookupDict = {
    {100, "Continue"},
    {101, "Switching Protocols"},
    {102, "Processing"},
    {103, "Early Hints"},
    {200, "OK"},
    {201, "Created"},
    {202, "Accepted"},
    {203, "Non-Authoritative Information"},
    {204, "No Content"},
    {205, "Reset Content"},
    {206, "Partial Content"},
    {207, "Multi-Status"},
    {208, "Already Reported"},
    {226, "IM Used"},
    {300, "Multiple Choices"},
    {301, "Moved Permanently"},
    {302, "Found"},
    {303, "See Other"},
    {304, "Not Modified"},
    {305, "Use Proxy"},
    {306, "Switch Proxy"},
    {307, "Temporary Redirect"},
    {308, "Permanent Redirect"},
    {400, "Bad Request"},
    {401, "Unauthorized"},
    {402, "Payment Required"},
    {403, "Forbidden"},
    {404, "Not Found"},
    {405, "Method Not Allowed"},
    {406, "Not Acceptable"},
    {407, "Proxy Authentication Required"},
    {408, "Request Timeout"},
    {409, "Conflict"},
    {410, "Gone"},
    {411, "Length Required"},
    {412, "Precondition Failed"},
    {413, "Payload Too Large"},
    {414, "URI Too Long"},
    {415, "Unsupported Media Type"},
    {416, "Range Not Satisfiable"},
    {417, "Expectation Failed"},
    {418, "I'm a teapot"},
    {421, "Misdirected Request"},
    {422, "Unprocessable Entity"},
    {423, "Locked"},
    {424, "Failed Dependency"},
    {425, "Too Early"},
    {426, "Upgrade Required"},
    {428, "Precondition Required"},
    {429, "Too Many Requests"},
    {431, "Request Header Fields Too Large"},
    {451, "Unavailable For Legal Reasons"},
    {500, "Internal Server Error"},
    {501, "Not Implemented"},
    {502, "Bad Gateway"},
    {503, "Service Unavailable"},
    {504, "Gateway Timeout"},
    {505, "HTTP Version Not Supported"},
    {506, "Variant Also Negotiates"},
    {507, "Insufficient Storage"},
    {508, "Loop Detected"},
    {510, "Not Extended"},
    {511, "Network Authentication Required"}};

} // namespace clv::http

#endif // CLV_HTTPCORE_HTTPDEFS_H
