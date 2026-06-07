// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#include "gtest/gtest.h"

#include <string>
#include <ci_string.h>
#include <http/HttpDefs.h>
#include <http/HttpResponse.h>

using namespace clv;
using namespace clv::http;


TEST(HttpResponse, Constructor)
{
    HttpResponse response(200, buffer_type("Hello, World!"));

    response.AsBuffer(); // Force default headers

    EXPECT_EQ(response.StatusCode(), 200);
    EXPECT_EQ(response.Body().size(), 13);
    EXPECT_EQ(response.Body()[0], 'H');
    EXPECT_EQ(response.Body()[12], '!');
    EXPECT_NO_THROW(response.GetHeaderValue<std::string>("Date"_cis));   // Added automatically
    EXPECT_NO_THROW(response.GetHeaderValue<int>("Content-Length"_cis)); // Added automatically
    EXPECT_EQ(response.GetHeaderValue("Content-Length"_cis, 0), 13);
}

TEST(HttpResponse, AddHeaderIfAbsent)
{
    HttpResponse response(200, buffer_type("Hello, World!"));

    response.AsBuffer();

    response.AddHeaderIfAbsent("Content-Type", "text/plain");
    EXPECT_EQ(response.StatusCode(), 200);
    EXPECT_EQ(response.Body().size(), 13);
    EXPECT_EQ(response.Body()[0], 'H');
    EXPECT_EQ(response.Body()[12], '!');
    EXPECT_NO_THROW(response.GetHeaderValue<std::string>("Date"_cis));   // Added automatically
    EXPECT_NO_THROW(response.GetHeaderValue<int>("Content-Length"_cis)); // Added automatically
    EXPECT_EQ(response.GetHeaderValue("Content-Length"_cis, 0), 13);
    EXPECT_NO_THROW(response.GetHeaderValue<std::string>("Content-Type"_cis));
    EXPECT_EQ(response.GetHeaderValue<std::string>("Content-Type"_cis), "text/plain");
}

TEST(HttpResponse, Parse)
{
    auto parser = HttpResponseParser(buffer_type("HTTP/1.1 200 OK\r\n"
                                                 "Date: Sun, 09 Mar 2025 03:06:58.212770342 UTC\r\n"
                                                 "Content-Length: 13\r\n\r\n"
                                                 "Hello, World!"));

    auto response = parser.GetResponse();

    EXPECT_EQ(response.StatusCode(), 200);
    EXPECT_EQ(response.Body().size(), 13);
    EXPECT_EQ(response.Body()[0], 'H');
    EXPECT_EQ(response.Body()[12], '!');
    EXPECT_NO_THROW(response.GetHeaderValue<std::string>("Date"_cis));
    EXPECT_NO_THROW(response.GetHeaderValue<int>("Content-Length"_cis));
    EXPECT_EQ(response.GetHeaderValue("Content-Length"_cis, 0), 13);
}

TEST(HttpResponse, ParseWithHeaders)
{
    auto parser = HttpResponseParser(buffer_type("HTTP/1.1 200 OK\r\n"
                                                 "Date: Sun, 09 Mar 2025 03:06:58.212770342 UTC\r\n"
                                                 "Content-Length: 13\r\n"
                                                 "Content-Type: text/plain\r\n\r\n"
                                                 "Hello, World!"));

    auto response = parser.GetResponse();
    response.AddHeaderIfAbsent("Content-Type", "magic/magic"); // Should not change the value

    EXPECT_EQ(response.StatusCode(), 200);
    EXPECT_EQ(response.Body().size(), 13);
    EXPECT_EQ(response.Body()[0], 'H');
    EXPECT_EQ(response.Body()[12], '!');
    EXPECT_NO_THROW(response.GetHeaderValue<std::string>("Date"_cis));
    EXPECT_NO_THROW(response.GetHeaderValue<int>("Content-Length"_cis));
    EXPECT_EQ(response.GetHeaderValue("Content-Length"_cis, 0), 13);
    EXPECT_NO_THROW(response.GetHeaderValue<std::string>("Content-Type"_cis));
    EXPECT_EQ(response.GetHeaderValue<std::string>("Content-Type"_cis), "text/plain");
}

TEST(HttpResponse, ParseWithHeadersWs)
{
    auto parser = HttpResponseParser(buffer_type("HTTP/1.1   200    OK\r\n"
                                                 "Date: Sun, 09 Mar 2025 03:06:58.212770342 UTC\r\n"
                                                 "Content-Length:   13\r\n"
                                                 "Content-Type:   text/plain\r\n\r\n"
                                                 "Hello, World!"));

    auto response = parser.GetResponse();
    response.AddHeaderIfAbsent("Content-Type", "magic/magic"); // Should not change the value

    EXPECT_EQ(response.StatusCode(), 200);
    EXPECT_EQ(response.Body().size(), 13);
    EXPECT_EQ(response.Body()[0], 'H');
    EXPECT_EQ(response.Body()[12], '!');
    EXPECT_NO_THROW(response.GetHeaderValue<std::string>("Date"_cis));
    EXPECT_NO_THROW(response.GetHeaderValue<int>("Content-Length"_cis));
    EXPECT_EQ(response.GetHeaderValue("Content-Length"_cis, 0), 13);
    EXPECT_NO_THROW(response.GetHeaderValue<std::string>("Content-Type"_cis));
    EXPECT_EQ(response.GetHeaderValue<std::string>("Content-Type"_cis), "text/plain");
}