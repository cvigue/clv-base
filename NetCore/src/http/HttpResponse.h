// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLV_HTTPCORE_HTTPRESPONSE_H
#define CLV_HTTPCORE_HTTPRESPONSE_H

#include <cstddef>
#include <chrono>
#include <format>
#include <string>
#include <string_view>
#include <optional>

#include "HttpDefs.h"
#include "buffer_util.h"

namespace clv::http {

using std::literals::operator""sv;

/**
    @brief The HttpResponse struct is a container for the HTTP response
    @details The HttpResponse struct is a container for the HTTP response. It is constructed
    from a status code and a buffer_type or string_view that is passed by value. The
    HttpResponse object owns the data and is responsible for freeing it when it goes out of
    scope. The HttpResponse object provides methods to set and get the status code,
    headers, and body of the response.
    @see HttpResponseParser
*/
struct HttpResponse
{
    constexpr static inline auto HTTP_VERSION = "HTTP/1.1"sv;

    ~HttpResponse() = default;
    HttpResponse() = default;
    HttpResponse(const HttpResponse &) = default;
    HttpResponse(HttpResponse &&) = default;
    HttpResponse &operator=(const HttpResponse &) = default;
    HttpResponse &operator=(HttpResponse &&) = default;

    HttpResponse(int statusCode, buffer_type body);
    HttpResponse(int statusCode, std::string_view body = ""sv);

    void SetStatusCode(int statusCode);
    int StatusCode() const;
    void AddHeaderIfAbsent(const ci_string &key, std::string value);
    void RemoveHeader(const ci_string &key);
    template <typename TypeT>
        requires HttpHeaderValueConvertibleType_v<TypeT>
    TypeT GetHeaderValue(ci_string key) const;
    template <typename TypeT>
        requires HttpHeaderValueConvertibleType_v<TypeT>
    TypeT GetHeaderValue(ci_string key, TypeT defValue) const noexcept;
    void SetBody(buffer_type body);
    const buffer_type &Body() const noexcept;
    buffer_type AsBuffer();

  private:
    template <typename TypeT>
        requires HttpHeaderValueConvertibleType_v<TypeT>
    std::optional<TypeT> GetHeaderValueImpl(ci_string key) const noexcept;

  private:
    int mStatusCode;
    std::unordered_map<ci_string, std::string> mHeaders;
    buffer_type mBody;
};

/**
    @brief The HttpResponseParser struct is a parser for HTTP responses
    @details The HttpResponseParser struct is a parser for HTTP responses. It is constructed
    from a buffer_type::const_view that is passed by value. The HttpResponseParser object
    owns the data and is responsible for freeing it when it goes out of scope.
*/
struct HttpResponseParser
{
    ~HttpResponseParser() = default;
    HttpResponseParser() = default;
    HttpResponseParser(const HttpResponseParser &) = default;
    HttpResponseParser(HttpResponseParser &&) = default;
    HttpResponseParser &operator=(const HttpResponseParser &) = default;
    HttpResponseParser &operator=(HttpResponseParser &&) = default;
    HttpResponseParser(buffer_type httpData);

    bool Parse(buffer_type httpData);

    HttpResponse &GetResponse() noexcept;
    const HttpResponse &GetResponse() const noexcept;

  private:
    HttpResponse mResponse;
};

// ============================================================================================
// Inline Implementations - HttpResponse
// ============================================================================================

/**
    @brief Construct a new HttpResponse object
    @param statusCode The HTTP status code
    @param body The body of the response
*/
inline HttpResponse::HttpResponse(int statusCode, buffer_type body)
    : mStatusCode(statusCode), mBody()
{
    mBody = std::move(body);
}
/**
    @brief Construct a new HttpResponse object
    @param statusCode The HTTP status code
    @param body The optional body of the response
*/
inline HttpResponse::HttpResponse(int statusCode, std::string_view body)
    : mStatusCode(statusCode),
      mBody(body.data(), body.size())
{
}
/**
    @brief Set the status code of the response
    @param statusCode The HTTP status code
*/
inline void HttpResponse::SetStatusCode(int statusCode)
{
    // Validate code
    if (CodeLookupDict.find(statusCode) == CodeLookupDict.end())
        throw std::runtime_error("HttpResponse: Invalid status code");
    mStatusCode = statusCode;
}
/**
    @brief Get the status code of the response
    @return int The status code of the response
*/
inline int HttpResponse::StatusCode() const
{
    return mStatusCode;
}
/**
    @brief Add a header if it is not already present
    @param key The header key
    @param value The header value
*/
inline void HttpResponse::AddHeaderIfAbsent(const ci_string &key, std::string value)
{
    if (mHeaders.find(key) == mHeaders.end())
        mHeaders[key] = value;
}
/**
    @brief Remove a header
    @param key The header key
*/
inline void HttpResponse::RemoveHeader(const ci_string &key)
{
    mHeaders.erase(key);
}
/**
    @brief Get the value of a header
    @param key The header key
    @return TypeT The value of the header
*/
template <typename TypeT>
    requires HttpHeaderValueConvertibleType_v<TypeT>
inline TypeT HttpResponse::GetHeaderValue(ci_string key) const
{
    if (auto value = GetHeaderValueImpl<TypeT>(key); value)
        return *value;
    throw std::runtime_error("HttpResponse: Header not found");
}
/**
    @brief Get the value of a header
    @param key The header key
    @param defValue The default value to return if the header is not found
    @return TypeT The value of the header
*/
template <typename TypeT>
    requires HttpHeaderValueConvertibleType_v<TypeT>
inline TypeT HttpResponse::GetHeaderValue(ci_string key, TypeT defValue) const noexcept
{
    if (auto value = GetHeaderValueImpl<TypeT>(key); value)
        return *value;
    return defValue;
}
/**
    @brief Get the value of a header
    @param key The header key
    @return std::optional<TypeT> The value of the header
    @note This is a private helper function
*/
template <typename TypeT>
    requires HttpHeaderValueConvertibleType_v<TypeT>
inline std::optional<TypeT>
HttpResponse::GetHeaderValueImpl(ci_string key) const noexcept
{
    if (auto found = mHeaders.find(key); found != mHeaders.end())
    {
        auto value = found->second;

        if constexpr (std::is_same_v<bool, TypeT>)
            return value == "1" || value == "true";
        else if constexpr (std::is_same_v<int, TypeT>)
            return std::stoi(value);
        else if constexpr (std::is_same_v<unsigned long, TypeT>)
            return std::stoul(value);
        else if constexpr (std::is_same_v<std::size_t, TypeT>)
            return std::stoull(value);
        else if constexpr (std::is_same_v<long, TypeT>)
            return std::stol(value);
        else if constexpr (std::is_same_v<float, TypeT>)
            return std::stof(value);
        else if constexpr (std::is_same_v<double, TypeT>)
            return std::stod(value);
        else if constexpr (std::is_same_v<std::string, TypeT>)
            return value;
    }
    return std::nullopt;
}
/**
    @brief Set the body of the response
    @param body The body of the response
*/
inline void HttpResponse::SetBody(buffer_type body)
{
    mBody = std::move(body);
}
/**
    @brief Get the body of the response
    @return const buffer_type& The body of the response
*/
inline const buffer_type &HttpResponse::Body() const noexcept
{
    return mBody;
}
/**
    @brief Get the response as a buffer
    @return buffer_type The response as a buffer
*/
inline buffer_type HttpResponse::AsBuffer()
{
    auto constexpr header_space_alloc = std::size_t(200);
    auto buffer = buffer_type(mBody.size() + header_space_alloc);

    append(buffer, HTTP_VERSION);
    append(buffer, " ");
    append(buffer, std::to_string(mStatusCode));
    append(buffer, " ");
    append(buffer, CodeLookupDict.at(mStatusCode));
    append(buffer, "\r\n");

    // The responder is responsible for setting needed headers, but we do set a few to
    // defaults if the responder doesn't set them.
    // EX date: Sun, 09 Mar 2025 03:06:58.212770342 UTC
    auto date_str = std::format("{:%a, %d %b %Y %H:%M:%S %Z}", std::chrono::system_clock::now());
    AddHeaderIfAbsent("Date"_cis, date_str);
    AddHeaderIfAbsent("Content-Length"_cis, std::to_string(mBody.size()));

    for (auto &&[key, value] : mHeaders)
    {
        buffer.set_tailroom(std::max(buffer.tailroom(), key.size() + value.size() + 4));
        append(buffer, key);
        append(buffer, ": ");
        append(buffer, value);
        append(buffer, "\r\n");
    }

    append(buffer, "\r\n");
    append(buffer, mBody);

    return buffer;
}

// ============================================================================================
// Inline Implementations - HttpResponseParser
// ============================================================================================

/**
    @brief Construct a new HttpResponseParser object
    @param httpData The HTTP data to parse
    @throws std::runtime_error if the HTTP data is invalid
*/
inline HttpResponseParser::HttpResponseParser(buffer_type httpData)
    : mResponse()
{
    if (!Parse(httpData))
        throw std::runtime_error("HttpResponseParser: Failed to parse HTTP response");
}
/**
    @brief Parse the HTTP data
    @param httpData The HTTP data to parse
    @return bool True if the HTTP data was parsed successfully
*/
inline bool HttpResponseParser::Parse(buffer_type httpData)
{
    // Get the HTTP version and code
    constexpr auto eolMarker = std::string_view("\r\n");
    auto eol = std::search(httpData.begin(),
                           httpData.end(),
                           eolMarker.begin(),
                           eolMarker.end());
    if (eol == httpData.end())
        return false;
    auto statusLine = std::string_view(httpData.data(), eol - httpData.begin());
    httpData.free_head(eol - httpData.begin() + 2);
    auto space = statusLine.find(' ');
    if (space == std::string_view::npos)
        return false;
    mResponse.SetStatusCode(std::stoi(std::string(statusLine.substr(space + 1))));

    // Get the headers
    while (!httpData.empty())
    {
        eol = std::search(httpData.begin(),
                          httpData.end(),
                          eolMarker.begin(),
                          eolMarker.end());
        if (eol == httpData.end())
            return false;
        auto headerLine = std::string_view(httpData.data(), eol - httpData.begin());
        httpData.free_head(eol - httpData.begin() + 2);
        if (headerLine.empty())
            break;
        auto sep = headerLine.find(':');
        if (sep == std::string_view::npos)
            return false;
        auto key = ci_string(to_ci_str(headerLine.substr(0, sep)));
        while (headerLine[sep + 1] == ' ')
            sep++;
        auto value = headerLine.substr(sep + 1);
        mResponse.AddHeaderIfAbsent(key, std::string(value));
    }

    // Copy the remaining data for the body
    mResponse.SetBody(httpData);
    return true;
}
/**
    @brief Get the response
    @return HttpResponse& The response
*/
inline HttpResponse &HttpResponseParser::GetResponse() noexcept
{
    return mResponse;
}
/**
    @brief Get the response
    @return HttpResponse The response
*/
inline const HttpResponse &HttpResponseParser::GetResponse() const noexcept
{
    return mResponse;
}

} // namespace clv::http

#endif // CLV_HTTPCORE_HTTPRESPONSE_H