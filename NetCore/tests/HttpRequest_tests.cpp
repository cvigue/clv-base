// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#include "gtest/gtest.h"

#include <http/HttpRequest.h>

using namespace clv;
using namespace clv::http;
using std::literals::operator""sv;

TEST(HttpRequestParser, Simple)
{
    HttpRequestParser msg(buffer_type("GET / HTTP/1.1\r\n"
                                      "Host: example.com\r\n"
                                      "User-Agent: test-agent\r\n"
                                      "Accept: */*\r\n"
                                      "\r\n"));

    auto request = msg.GetRequest();

    EXPECT_EQ(request.method, "GET"sv);
    EXPECT_EQ(request.url, "/"sv);
    EXPECT_EQ(request.protoVer, "HTTP/1.1"sv);
    EXPECT_EQ(request.query.size(), 0);
    EXPECT_EQ(request.fragment, ""sv);
    EXPECT_EQ(request.headers.size(), 3);
    EXPECT_EQ(request.body.size(), 0);
}

TEST(HttpRequestParser, Query)
{
    HttpRequestParser msg(buffer_type("GET /?test=1 HTTP/1.1\r\n"
                                      "Host: example.com\r\n"
                                      "User-Agent: test-agent\r\n"
                                      "Accept: */*\r\n"
                                      "\r\n"));

    auto request = msg.GetRequest();

    EXPECT_EQ(request.method, "GET"sv);
    EXPECT_EQ(request.url, "/"sv);
    EXPECT_EQ(request.protoVer, "HTTP/1.1"sv);
    EXPECT_EQ(request.query.size(), 1);
    EXPECT_EQ(request.query["test"], "1");
    EXPECT_EQ(request.fragment, ""sv);
    EXPECT_EQ(request.headers.size(), 3);
    EXPECT_EQ(request.headers["Host"], "example.com");
    EXPECT_EQ(request.headers["User-Agent"], "test-agent");
    EXPECT_EQ(request.headers["Accept"], "*/*");
    EXPECT_EQ(request.body.size(), 0);
}

TEST(HttpRequestParser, QueryAndFragment)
{
    HttpRequestParser msg(buffer_type("GET /?test=1#fragment HTTP/1.1\r\n"
                                      "Host: example.com\r\n"
                                      "User-Agent: test-agent\r\n"
                                      "Accept: */*\r\n"
                                      "\r\n"));

    EXPECT_EQ(msg.GetHeaderValue("User-Agent", "bob"s), "test-agent"s);
    auto request = msg.GetRequest();

    EXPECT_EQ(request.method, "GET"sv);
    EXPECT_EQ(request.url, "/"sv);
    EXPECT_EQ(request.protoVer, "HTTP/1.1"sv);
    EXPECT_EQ(request.query.size(), 1);
    EXPECT_EQ(request.query["test"], "1");
    EXPECT_EQ(request.fragment, "fragment"sv);
    EXPECT_EQ(request.headers.size(), 3);
    EXPECT_EQ(request.headers["Host"], "example.com");
    EXPECT_EQ(request.headers["User-Agent"], "test-agent");
    EXPECT_EQ(request.headers["Accept"], "*/*");
    EXPECT_EQ(request.body.size(), 0);
}

TEST(HttpRequestParser, QueryAndFragmentAndExtra)
{
    HttpRequestParser msg(buffer_type("GET /?test=1#fragment HTTP/1.1\r\n"
                                      "Host: example.com\r\n"
                                      "User-Agent: test-agent\r\n"
                                      "Accept: */*\r\n"
                                      "\r\n"
                                      "Body data"));

    EXPECT_EQ(msg.GetHeaderValue("Content-Length", 9), 9);
    auto request = msg.GetRequest();

    EXPECT_EQ(request.method, "GET"sv);
    EXPECT_EQ(request.url, "/"sv);
    EXPECT_EQ(request.protoVer, "HTTP/1.1"sv);
    EXPECT_EQ(request.query.size(), 1);
    EXPECT_EQ(request.query["test"], "1");
    EXPECT_EQ(request.fragment, "fragment"sv);
    EXPECT_EQ(request.headers.size(), 3);
    EXPECT_EQ(request.headers["Host"], "example.com");
    EXPECT_EQ(request.headers["User-Agent"], "test-agent");
    EXPECT_EQ(request.headers["Accept"], "*/*");
    EXPECT_EQ(request.body.size(), 9);
}

TEST(HttpRequestParser, QueryAndFragmentAndContentLength)
{
    HttpRequestParser msg(buffer_type("GET /?test=1#fragment HTTP/1.1\r\n"
                                      "Host: example.com\r\n"
                                      "User-Agent: test-agent\r\n"
                                      "Accept: */*\r\n"
                                      "Content-Length: 9\r\n"
                                      "\r\n"
                                      "Body data"));

    EXPECT_EQ(msg.GetHeaderValue("Content-Length", 0), 9);
    auto request = msg.GetRequest();

    EXPECT_EQ(request.method, "GET"sv);
    EXPECT_EQ(request.url, "/"sv);
    EXPECT_EQ(request.protoVer, "HTTP/1.1"sv);
    EXPECT_EQ(request.query.size(), 1);
    EXPECT_EQ(request.query["test"], "1");
    EXPECT_EQ(request.fragment, "fragment"sv);
    EXPECT_EQ(request.headers.size(), 4);
    EXPECT_EQ(request.headers["Host"], "example.com");
    EXPECT_EQ(request.headers["User-Agent"], "test-agent");
    EXPECT_EQ(request.headers["Accept"], "*/*");
    EXPECT_EQ(request.headers["Content-Length"], "9");
    EXPECT_EQ(request.body.size(), 9);
}

TEST(HttpRequestParser, QueryAndFragmentAndContentLengthSplitBody)
{
    HttpRequestParser msg(buffer_type("GET /?test=1#fragment HTTP/1.1\r\n"
                                      "Host: example.com\r\n"
                                      "User-Agent: test-agent\r\n"
                                      "Accept: */*\r\n"
                                      "Content-Length: 9\r\n"
                                      "\r\n"
                                      "Body "));

    msg.Parse(buffer_type("data"));

    EXPECT_EQ(msg.GetHeaderValue("Content-Length", 0), 9);
    auto request = msg.GetRequest();

    EXPECT_EQ(request.method, "GET"sv);
    EXPECT_EQ(request.url, "/"sv);
    EXPECT_EQ(request.protoVer, "HTTP/1.1"sv);
    EXPECT_EQ(request.query.size(), 1);
    EXPECT_EQ(request.query["test"], "1");
    EXPECT_EQ(request.fragment, "fragment"sv);
    EXPECT_EQ(request.headers.size(), 4);
    EXPECT_EQ(request.headers["Host"], "example.com");
    EXPECT_EQ(request.headers["User-Agent"], "test-agent");
    EXPECT_EQ(request.headers["Accept"], "*/*");
    EXPECT_EQ(request.headers["Content-Length"], "9");
    EXPECT_EQ(request.body.size(), 9);
}
