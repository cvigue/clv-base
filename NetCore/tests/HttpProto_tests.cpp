// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include "gtest/gtest.h"

#include <http/HttpProto.h>

#include <asio.hpp>

using namespace clv;
using namespace clv::http;

using namespace std::literals;

struct HttpEchoRouter
{
    asio::awaitable<bool> RouteMsg(HttpRequest msg,
                                   SendingFuncT rfn,
                                   asio::io_context &io_ctx)
    {
        if (msg.method == "GET")
        {
            auto echo = HttpResponse(200, msg.body);
            co_await rfn(echo.AsBuffer());
            co_return true;
        }
        co_return false;
    }
};

// TODO: These tests need to be rewritten for the new coroutine-native interface
// The protocol handler now uses HandleSession() which requires a real socket
// Integration tests (MicroTlsServerTests) cover the full stack

// Placeholder test to prevent empty test suite
TEST(HttpProto_tests, PlaceholderTest)
{
    EXPECT_TRUE(true);
}
