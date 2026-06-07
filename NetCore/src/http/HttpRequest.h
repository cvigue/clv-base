// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#ifndef CLV_HTTPCORE_HTTPREQUEST_H
#define CLV_HTTPCORE_HTTPREQUEST_H

#include <cstddef>
#include <unordered_map>
#include <string>
#include <string_view>

#include <array_deque.h>
#include <ci_string.h>
#include <buffer_util.h>

#include "HttpDefs.h"

namespace clv::http {

using std::string_literals::operator""s;

// https://en.wikipedia.org/wiki/URL

// TODO: Consider a HttpException or HttpThrow that would roll in more info

/**
    @brief The HttpRequest struct is a container for the parsed HTTP request
    @details The HttpRequest struct is a container for the parsed HTTP request. It contains
    the method, URL, query parameters, fragment, protocol version, headers, and body. It
    is returned as a result of calling HttpRequestParser::GetRequest(). Also AsBuffer()
    can be used to convert the HttpRequest back into a buffer_type for sending.
    @see HttpRequestParser::GetRequest()
*/
struct HttpRequest
{
    std::string method;
    std::string url;
    std::unordered_map<ci_string, std::string> query;
    std::string fragment;
    std::string protoVer;
    std::unordered_map<ci_string, std::string> headers;
    buffer_type body;

    auto AsBuffer();
};

/**
    @brief The HttpRequestParser struct is a container for the parsed HTTP request or response
    @details The HttpRequestParser struct is a container for the parsed HTTP request or response.
    It is constructed from a buffer_type that is passed by value. The buffer_type is then passed
    by reference to the Request and Headers constructors which parse and consume the buffer without
    copying it. The Request and Headers store the data without owning it, so the buffer copy must
    remain valid for the life of the HttpRequestParser object.

    The buffer_type that was passed in is finally completely consumed by the HttpRequestParser
    body. This simply means the begin and end markers of the buffer are equal, the underlying
    data is not modified or copied. The HttpRequestParser stored the parsed data in the
    HttpRequest object that it owns.
*/
struct HttpRequestParser
{
    /**
        @brief Construct a new empty HttpRequestParser object
    */
    HttpRequestParser() = default;
    /**
        @brief Construct a new Http Request Parser:: Http Request Parser object
        @param httpData The HTTP request data to parse
    */
    HttpRequestParser(buffer_type httpData);
    /**
        @brief Check if a header key exists
        @param key The header key to look up, case insensitive
        @return true if the key exists
        @return false if the key does not exist
    */
    bool HeaderValueExists(ci_string key);
    /**
        @brief Parse the HTTP request data
        @param httpData The HTTP request data to parse
        @return true if the parsing was successful and complete
        @note Should continue calling Parse until it returns true or a parse exception
        is thrown. If the connection is closed before the body is complete, the
        parsing was a failure.
    */
    bool Parse(buffer_type httpData);
    /**
        @brief Get the value of a header key
        @tparam TypeT Type to convert the header value to
        @param key The header key to look up, case insensitive
        @param defValue Value to return if the key is not found
        @return requires the TypeT to be a valid header value type
    */
    template <typename TypeT>
        requires HttpHeaderValueConvertibleType<TypeT>
    auto GetHeaderValue(ci_string key, TypeT defValue);
    /**
        @brief Get the parsed HTTP request
        @return HttpRequest the parsed HTTP request
    */
    HttpRequest GetRequest();
    /**
        @brief Get the size of the body data so far
        @return size_type the size of the body data
    */
    size_type GetBodySize();
    /**
        @brief Check if the body is complete
        @return true
        @return false
        @details Check if the body is complete by checking if the size matches the
        content-length header value, if present.
    */
    bool IsBodyComplete();

  private: // Types
    enum class ParseState
    {
        Begin,
        Body,
        Complete
    };

  private: // Helpers
    static std::string_view ParseMethod(buffer_type &reqLine);
    static std::string_view ParseUrl(buffer_type &reqLine);
    static std::unordered_map<ci_string, std::string> ParseQuery(buffer_type &reqLine);
    static std::string_view ParseFragment(buffer_type &reqLine);
    static std::string_view ParseVersion(buffer_type &reqLine);
    static std::unordered_map<ci_string, std::string> ParseHeaders(buffer_type &httpData);

  private: // Data
    ParseState mParseState = ParseState::Begin;
    HttpRequest mParsedRequest;
};

// ============================================================================================
// Inline implementations for HttpRequest
// ============================================================================================

/**
    @brief Convert the HttpRequest to a buffer_type for sending
    @return buffer_type The HTTP request as a buffer_type
 */
inline auto HttpRequest::AsBuffer()
{
    auto buffer = buffer_type(body.size() + 200);

    append(buffer, method);
    append(buffer, " ");
    append(buffer, url);
    if (!query.empty())
    {
        append(buffer, "?");
        for (auto &q : query)
        {
            append(buffer, q.first);
            append(buffer, "=");
            append(buffer, q.second);
            append(buffer, "&");
        }
        buffer.free_tail(1);
    }
    if (!fragment.empty())
    {
        append(buffer, "#");
        append(buffer, fragment);
    }
    append(buffer, " ");
    append(buffer, protoVer);
    append(buffer, "\r\n");

    if (auto found = headers.find("Content-Length"_cis); found == headers.end())
        headers["Content-Length"_cis] = std::to_string(body.size());

    for (auto &h : headers)
    {
        append(buffer, h.first);
        append(buffer, ": ");
        append(buffer, h.second);
        append(buffer, "\r\n");
    }

    append(buffer, "\r\n");
    append(buffer, body);

    return buffer;
}

// ============================================================================================
// Inline implementations for HttpRequestParser
// ============================================================================================

inline HttpRequestParser::HttpRequestParser(buffer_type httpData)
    : mParseState(ParseState::Begin), mParsedRequest()
{
    Parse(httpData);
}

inline bool HttpRequestParser::HeaderValueExists(ci_string key)
{
    return mParsedRequest.headers.find(key) != mParsedRequest.headers.end();
}

inline bool HttpRequestParser::Parse(buffer_type httpData)
{
    while (!httpData.empty())
    {
        switch (mParseState)
        {
        case ParseState::Begin:
            mParsedRequest.method = ParseMethod(httpData);
            mParsedRequest.url = ParseUrl(httpData);
            mParsedRequest.query = ParseQuery(httpData);
            mParsedRequest.fragment = ParseFragment(httpData);
            mParsedRequest.protoVer = ParseVersion(httpData);
            mParsedRequest.headers = ParseHeaders(httpData);
            mParseState = ParseState::Body;
        case ParseState::Body:
            append(mParsedRequest.body, httpData.data(), httpData.size());
            httpData.free_head(httpData.size());
            mParseState = IsBodyComplete() ? ParseState::Complete : ParseState::Body;
            break;
        case ParseState::Complete:
            return true;
        }
    }
    return mParseState == ParseState::Complete;
}

template <typename TypeT>
    requires HttpHeaderValueConvertibleType<TypeT>
inline auto HttpRequestParser::GetHeaderValue(ci_string key, TypeT defValue)
{
    if (auto found = mParsedRequest.headers.find(key);
        found != mParsedRequest.headers.end())
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
    return defValue;
}

inline HttpRequest HttpRequestParser::GetRequest()
{
    return mParsedRequest;
}

inline size_type HttpRequestParser::GetBodySize()
{
    return mParsedRequest.body.size();
}

inline bool HttpRequestParser::IsBodyComplete()
{
    return GetHeaderValue("Content-Length", size_type(0)) <= GetBodySize();
}

// ======================================================================================
// Inline implementations for private helper functions
// ======================================================================================

inline std::string_view
HttpRequestParser::ParseMethod(buffer_type &reqLine)
{
    auto endMethod = std::find(reqLine.begin(), reqLine.end(), ' ');
    if (endMethod == reqLine.end())
        throw std::runtime_error("ParseMethod: No METHOD found in request");
    auto method = std::string_view(reqLine.data(), endMethod - reqLine.begin());
    reqLine.free_head(endMethod - reqLine.begin());
    return method;
}
inline std::string_view
HttpRequestParser::ParseUrl(buffer_type &reqLine)
{
    while (isspace(reqLine.front()))
        reqLine.pop_front();
    constexpr auto urlTermTokens = std::string_view(" ?");
    auto endUrl = std::find_first_of(reqLine.begin(),
                                     reqLine.end(),
                                     urlTermTokens.begin(),
                                     urlTermTokens.end());
    if (endUrl == reqLine.end())
        throw std::runtime_error("ParseUrl: No URL found in request");
    auto url = std::string_view(reqLine.data(), endUrl - reqLine.begin());
    reqLine.free_head(endUrl - reqLine.begin());
    return url;
}
inline std::unordered_map<ci_string, std::string>
HttpRequestParser::ParseQuery(buffer_type &reqLine)
{
    auto rq = std::unordered_map<ci_string, std::string>();
    constexpr auto urlTermTokens = std::string_view(" ?");
    auto beginQuery = std::find_first_of(reqLine.begin(),
                                         reqLine.end(),
                                         urlTermTokens.begin(),
                                         urlTermTokens.end());
    if (*beginQuery == '?')
    {
        ++beginQuery;
        constexpr auto queryTerm = std::string_view(" #");
        auto endQuery = std::find_first_of(reqLine.begin(),
                                           reqLine.end(),
                                           queryTerm.begin(),
                                           queryTerm.end());
        if (endQuery == reqLine.end())
            throw std::runtime_error("ParseQuery: No end of query marker found");
        for (auto cp = beginQuery; cp < endQuery;)
        {
            auto endKey = std::find(cp, endQuery, '=');
            if (endKey == endQuery)
                throw std::runtime_error("ParseQuery: No end of key marker found");
            auto endVal = std::find_first_of(endKey,
                                             endQuery,
                                             queryTerm.begin(),
                                             queryTerm.end());
            if (endVal == reqLine.end() && !(*endVal == ' ' || *endVal == '#'))
                throw std::runtime_error("ParseQuery: No end of value marker found");
            auto key = reqLine.const_view(beginQuery, endKey);
            auto value = reqLine.const_view(endKey + 1, endVal);
            rq[{key.data(), key.size()}] = {value.data(), value.size()};
            cp = endVal + 1;
        }
        reqLine.free_head(endQuery - reqLine.begin());
    }
    return rq;
}
inline std::string_view
HttpRequestParser::ParseFragment(buffer_type &reqLine)
{
    while (isspace(reqLine.front()))
        reqLine.pop_front();
    constexpr auto urlTermTokens = std::string_view(" #");
    auto beginFrag = std::find_first_of(reqLine.begin(),
                                        reqLine.end(),
                                        urlTermTokens.begin(),
                                        urlTermTokens.end());
    if (*beginFrag == '#')
    {
        ++beginFrag;
        auto endFrag = std::find(beginFrag, reqLine.end(), ' ');
        if (endFrag == reqLine.end())
            throw std::runtime_error("ParseFragment: No end of fragment marker found");
        auto fragment = std::string_view(reqLine.data() + 1, endFrag - reqLine.begin());
        while (isspace(fragment.back()))
            fragment = fragment.substr(0, fragment.size() - 1);
        reqLine.free_head(endFrag - reqLine.begin());
        return fragment;
    }
    return std::string_view();
}
inline std::string_view
HttpRequestParser::ParseVersion(buffer_type &reqLine)
{
    while (isspace(reqLine.front()))
        reqLine.pop_front();

    constexpr auto eolMark = std::string_view("\r\n");
    auto eol = std::search(reqLine.begin(), reqLine.end(), eolMark.begin(), eolMark.end());
    if (eol == reqLine.end())
        throw std::runtime_error("ParseHeaders: No EOL for header line");

    auto version = std::string_view(reqLine.data(), eol - reqLine.begin());
    reqLine.free_head(eol - reqLine.begin() + eolMark.size());
    return version;
}
inline std::unordered_map<ci_string, std::string>
HttpRequestParser::ParseHeaders(buffer_type &httpData)
{
    constexpr auto eohMark = std::string_view("\r\n\r\n");
    constexpr auto eolMark = std::string_view("\r\n");

    auto headers = std::unordered_map<ci_string, std::string>();

    auto headerEnd = std::search(httpData.begin(),
                                 httpData.end(),
                                 eohMark.begin(),
                                 eohMark.end());
    if (headerEnd != httpData.end())
    {
        auto data_remaining = headerEnd - httpData.begin() + eolMark.size();

        while (data_remaining > 0)
        {
            // Current header line
            auto eol = std::search(httpData.begin(), httpData.end(), eolMark.begin(), eolMark.end());
            if (eol == httpData.end())
                throw std::runtime_error("ParseHeaders: No EOL for header line");
            auto headerLine = std::string_view(httpData.data(), eol - httpData.begin());
            // KV separator
            auto sep = std::find(headerLine.begin(), headerLine.end(), ':');
            if (sep == headerLine.end())
                throw std::runtime_error("ParseHeaders: No separator "s.append(headerLine));
            auto key = std::string_view(headerLine.begin(), sep);
            auto value = std::string_view(sep + 1, headerLine.end());
            while (isspace(value.front()))
                value = value.substr(1);
            // Insert in map and move on until done
            headers[{key.data(), key.size()}] = {value.data(), value.size()};
            data_remaining -= headerLine.size() + eolMark.size();
            httpData.free_head(headerLine.size() + eolMark.size());
        }
    }
    httpData.free_head(2); // Remove the start of body marker
    return headers;
}

} // namespace clv::http

#endif // CLV_HTTPCORE_HTTPREQUEST_H