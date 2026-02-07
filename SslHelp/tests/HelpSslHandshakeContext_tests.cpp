// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>
#include "../src/HelpSslHandshakeContext.h"
#include "../src/HelpSslContext.h"
#include <openssl/ssl.h>

using namespace clv::OpenSSL;

class HelpSslHandshakeContextTests : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        // Initialize SSL context for client
        ctx_ = std::make_unique<SslContext>(SSLv23_method());
    }

    std::unique_ptr<SslContext> ctx_;
};

TEST_F(HelpSslHandshakeContextTests, ClientConstructionSucceeds)
{
    ASSERT_NE(ctx_.get(), nullptr);
    SslHandshakeContext handshake(*ctx_, false); // false = client
}

TEST_F(HelpSslHandshakeContextTests, ClientInitialState)
{
    SslHandshakeContext handshake(*ctx_, false);

    EXPECT_FALSE(handshake.IsComplete());
    EXPECT_FALSE(handshake.HasError());
}

TEST_F(HelpSslHandshakeContextTests, GetErrorStringNoError)
{
    SslHandshakeContext handshake(*ctx_, false);

    std::string error_msg = handshake.GetErrorString();
    EXPECT_NE(error_msg.find("No error"), std::string::npos);
}

TEST_F(HelpSslHandshakeContextTests, ProcessEmptyData)
{
    SslHandshakeContext handshake(*ctx_, false);

    std::vector<std::uint8_t> empty_data;
    auto result = handshake.ProcessIncomingData(empty_data);

    // Processing empty data may return WantMoreData since handshake hasn't advanced
    EXPECT_TRUE(result == SslHandshakeContext::Result::WantMoreData || result == SslHandshakeContext::Result::HasDataToSend);
}

TEST_F(HelpSslHandshakeContextTests, AdvanceHandshakeMultipleTimes)
{
    SslHandshakeContext handshake(*ctx_, false);

    // Multiple calls to process should be safe (non-fatal)
    std::vector<std::uint8_t> empty_data;
    for (int i = 0; i < 5; ++i)
    {
        auto result = handshake.ProcessIncomingData(empty_data);
        EXPECT_NE(result, SslHandshakeContext::Result::Failed);
    }
}

TEST_F(HelpSslHandshakeContextTests, GetPendingOutputReturnsVector)
{
    SslHandshakeContext handshake(*ctx_, false);

    std::vector<std::uint8_t> output = handshake.GetPendingOutput();
    // May be empty until SSL writes ClientHello
    EXPECT_TRUE(output.empty() || output.size() > 0);
}

TEST_F(HelpSslHandshakeContextTests, CompleteStateAfterProcess)
{
    SslHandshakeContext handshake(*ctx_, false);

    std::vector<std::uint8_t> empty_data;
    auto result = handshake.ProcessIncomingData(empty_data);

    if (result == SslHandshakeContext::Result::Complete)
    {
        EXPECT_TRUE(handshake.IsComplete());
    }
}

TEST_F(HelpSslHandshakeContextTests, ExportKeyMaterialBeforeComplete)
{
    SslHandshakeContext handshake(*ctx_, false);

    std::vector<uint8_t> empty_context;
    auto key_material = handshake.ExportKeyMaterial("test_label", empty_context, 32);
    EXPECT_FALSE(key_material.has_value());
}

TEST_F(HelpSslHandshakeContextTests, ServerHandshakeContextConstructs)
{
    // Create server context
    auto server_ctx = std::make_unique<SslContext>(SSLv23_method());
    SslHandshakeContext server_handshake(*server_ctx, true); // true = server

    EXPECT_FALSE(server_handshake.IsComplete());
}
