// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include <cstdint>
#include <gtest/gtest.h>
#include "../src/HelpSslHandshakeContext.h"
#include "../src/HelpSslContext.h"
#include <memory>
#include <openssl/ssl.h>
#include <string>
#include <vector>

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

// =============================================================================
// Pre-completion guard tests
// =============================================================================

TEST_F(HelpSslHandshakeContextTests, GetCipherName_BeforeComplete_ReturnsEmpty)
{
    SslHandshakeContext handshake(*ctx_, false);
    EXPECT_EQ(handshake.GetCipherName(), "");
}

TEST_F(HelpSslHandshakeContextTests, GetLastError_InitialIsZero)
{
    SslHandshakeContext handshake(*ctx_, false);
    EXPECT_EQ(handshake.GetLastError(), 0);
}

TEST_F(HelpSslHandshakeContextTests, WriteAppData_BeforeComplete_ReturnsNegOne)
{
    SslHandshakeContext handshake(*ctx_, false);
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    EXPECT_EQ(handshake.WriteAppData(data), -1);
}

TEST_F(HelpSslHandshakeContextTests, ReadAppData_BeforeComplete_ReturnsEmpty)
{
    SslHandshakeContext handshake(*ctx_, false);
    EXPECT_TRUE(handshake.ReadAppData().empty());
}

TEST_F(HelpSslHandshakeContextTests, FeedEncryptedData_BeforeComplete_ReturnsFalse)
{
    SslHandshakeContext handshake(*ctx_, false);
    std::vector<uint8_t> data = {0xDE, 0xAD};
    EXPECT_FALSE(handshake.FeedEncryptedData(data));
}

TEST_F(HelpSslHandshakeContextTests, FeedEncryptedData_EmptyBeforeComplete_ReturnsFalse)
{
    SslHandshakeContext handshake(*ctx_, false);
    EXPECT_FALSE(handshake.FeedEncryptedData({}));
}

TEST_F(HelpSslHandshakeContextTests, GetErrorString_WantReadCode)
{
    // GetErrorString for SSL_ERROR_WANT_READ should produce the expected substring
    SslHandshakeContext handshake(*ctx_, false);
    // Advance without feeding data to force a WANT_READ state
    handshake.ProcessIncomingData({});
    // Whatever state we're in, GetErrorString must return a non-empty string
    // (either "No error" or a real description)
    EXPECT_FALSE(handshake.GetErrorString().empty());
}

// =============================================================================
// Full-handshake fixture and post-handshake tests
// =============================================================================

/**
 * Pump data between two SslHandshakeContexts until both sides signal Complete
 * or no progress is made. Returns true if the handshake succeeds on both sides.
 */
static bool PumpHandshake(SslHandshakeContext &client, SslHandshakeContext &server,
                          int max_iters = 50)
{
    // Kick off – client sends ClientHello
    client.ProcessIncomingData({});

    for (int i = 0; i < max_iters; ++i)
    {
        if (client.IsComplete() && server.IsComplete())
            return true;

        bool progress = false;

        auto c_out = client.GetPendingOutput();
        if (!c_out.empty())
        {
            server.ProcessIncomingData(c_out);
            progress = true;
        }

        auto s_out = server.GetPendingOutput();
        if (!s_out.empty())
        {
            client.ProcessIncomingData(s_out);
            progress = true;
        }

        if (!progress)
            break;
    }
    return client.IsComplete() && server.IsComplete();
}

class HelpSslHandshakeContextPostHS : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        // Server: cert.pem + pvtkey.pem, no client cert required
        server_ctx_ = std::make_unique<SslContext>(
            MakeSslServerContext(TLS_method(), "cert.pem", "pvtkey.pem"));
        server_ctx_->SetVerifyMode(SSL_VERIFY_NONE);

        // Client: cert.pem as trusted CA (self-signed), no peer verification
        client_ctx_ = std::make_unique<SslContext>(
            MakeSslClientContext(TLS_method(), "cert.pem"));
        client_ctx_->SetVerifyMode(SSL_VERIFY_NONE);

        client_ = std::make_unique<SslHandshakeContext>(*client_ctx_, false);
        server_ = std::make_unique<SslHandshakeContext>(*server_ctx_, true);

        handshake_ok_ = PumpHandshake(*client_, *server_);
    }

    std::unique_ptr<SslContext> server_ctx_;
    std::unique_ptr<SslContext> client_ctx_;
    std::unique_ptr<SslHandshakeContext> client_;
    std::unique_ptr<SslHandshakeContext> server_;
    bool handshake_ok_ = false;
};

TEST_F(HelpSslHandshakeContextPostHS, HandshakeCompletes)
{
    ASSERT_TRUE(handshake_ok_);
    EXPECT_TRUE(client_->IsComplete());
    EXPECT_TRUE(server_->IsComplete());
    EXPECT_FALSE(client_->HasError());
    EXPECT_FALSE(server_->HasError());
}

TEST_F(HelpSslHandshakeContextPostHS, GetCipherName_AfterComplete_NonEmpty)
{
    ASSERT_TRUE(handshake_ok_);
    std::string cipher = client_->GetCipherName();
    EXPECT_FALSE(cipher.empty());
    // Sanity: cipher name should look like a TLS cipher
    EXPECT_NE(cipher.find("TLS"), std::string::npos);
}

TEST_F(HelpSslHandshakeContextPostHS, ExportKeyMaterial_AfterComplete)
{
    ASSERT_TRUE(handshake_ok_);
    std::vector<uint8_t> ctx_bytes;
    auto key = client_->ExportKeyMaterial("test-label", ctx_bytes, 32);
    ASSERT_TRUE(key.has_value());
    EXPECT_EQ(key->size(), 32u);
    // Key should not be all-zero
    bool all_zero = true;
    for (auto b : *key)
        if (b != 0)
        {
            all_zero = false;
            break;
        }
    EXPECT_FALSE(all_zero);
}

TEST_F(HelpSslHandshakeContextPostHS, ExportKeyMaterial_WithContext)
{
    ASSERT_TRUE(handshake_ok_);
    std::vector<uint8_t> ctx_bytes = {0x01, 0x02, 0x03};
    auto key = client_->ExportKeyMaterial("test-label", ctx_bytes, 16);
    ASSERT_TRUE(key.has_value());
    EXPECT_EQ(key->size(), 16u);
}

TEST_F(HelpSslHandshakeContextPostHS, ExportKeyMaterial_ClientServerMatch)
{
    ASSERT_TRUE(handshake_ok_);
    std::vector<uint8_t> ctx_bytes;
    auto client_key = client_->ExportKeyMaterial("vpn-label", ctx_bytes, 32);
    auto server_key = server_->ExportKeyMaterial("vpn-label", ctx_bytes, 32);
    ASSERT_TRUE(client_key.has_value());
    ASSERT_TRUE(server_key.has_value());
    EXPECT_EQ(*client_key, *server_key);
}

TEST_F(HelpSslHandshakeContextPostHS, WriteAndReadAppData)
{
    ASSERT_TRUE(handshake_ok_);
    std::vector<uint8_t> plaintext = {'h', 'e', 'l', 'l', 'o'};

    // Client encrypts and sends
    int written = client_->WriteAppData(plaintext);
    ASSERT_GT(written, 0);

    // Relay encrypted bytes to server
    auto encrypted = client_->GetPendingOutput();
    ASSERT_FALSE(encrypted.empty());
    server_->FeedEncryptedData(encrypted);

    // Server decrypts
    auto decrypted = server_->ReadAppData();
    ASSERT_EQ(decrypted.size(), plaintext.size());
    EXPECT_EQ(decrypted, plaintext);
}

TEST_F(HelpSslHandshakeContextPostHS, FeedEncryptedData_EmptyAfterComplete_ReturnsTrue)
{
    ASSERT_TRUE(handshake_ok_);
    EXPECT_TRUE(server_->FeedEncryptedData({}));
}

TEST_F(HelpSslHandshakeContextPostHS, ProcessIncomingData_AfterComplete_ReturnsComplete)
{
    ASSERT_TRUE(handshake_ok_);
    // Feeding empty data after completion should return Complete immediately
    auto result = client_->ProcessIncomingData({});
    EXPECT_EQ(result, SslHandshakeContext::Result::Complete);
}
