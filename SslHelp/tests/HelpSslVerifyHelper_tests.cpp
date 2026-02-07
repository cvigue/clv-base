// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>
#include <fstream>
#include <openssl/obj_mac.h>
#include <openssl/ssl.h>
#include <string>
#include <utility>
#include <vector>
#include "HelpSslX509.h"
#include "HelpSslTrustStore.h"
#include "HelpSslVerifyHelper.h"
#include "HelpSslContext.h"

using namespace clv::OpenSSL;

// ================================================================================================
// SslVerifyHelper Tests
// ================================================================================================

TEST(SslVerifyHelper, construct)
{
    auto ctx = SslContext(TLS_server_method());
    SslTrustStore store;

    EXPECT_NO_THROW(SslVerifyHelper helper(ctx, store));
}

TEST(SslVerifyHelper, set_expected_peer_identity)
{
    auto ctx = SslContext(TLS_server_method());
    SslTrustStore store;
    SslVerifyHelper helper(ctx, store);

    EXPECT_NO_THROW(helper.SetExpectedPeerIdentity("peer-a.example.com"));
}

TEST(SslVerifyHelper, require_extended_key_usage)
{
    auto ctx = SslContext(TLS_server_method());
    SslTrustStore store;
    SslVerifyHelper helper(ctx, store);

    EXPECT_NO_THROW(helper.RequireExtendedKeyUsage(true, true));
    EXPECT_NO_THROW(helper.RequireExtendedKeyUsage(true, false));
    EXPECT_NO_THROW(helper.RequireExtendedKeyUsage(false, true));
}

TEST(SslVerifyHelper, set_strict_mode)
{
    auto ctx = SslContext(TLS_server_method());
    SslTrustStore store;
    SslVerifyHelper helper(ctx, store);

    EXPECT_NO_THROW(helper.SetStrictMode(true));
    EXPECT_NO_THROW(helper.SetStrictMode(false));
}

TEST(SslVerifyHelper, set_verify_callback)
{
    auto ctx = SslContext(TLS_server_method());
    SslTrustStore store;
    SslVerifyHelper helper(ctx, store);

    bool callback_called = false;
    helper.SetVerifyCallback([&callback_called](const SslX509 &cert, int depth, int preverify_ok)
    {
        callback_called = true;
        return true;
    });

    // Can't easily test callback invocation without full TLS handshake
    EXPECT_FALSE(callback_called); // Not called yet
}

TEST(SslVerifyHelper, multiple_helpers_different_contexts)
{
    auto ctx1 = SslContext(TLS_server_method());
    auto ctx2 = SslContext(TLS_client_method());

    SslTrustStore store1;
    SslTrustStore store2;

    SslVerifyHelper helper1(ctx1, store1);
    SslVerifyHelper helper2(ctx2, store2);

    helper1.SetExpectedPeerIdentity("peer-a");
    helper2.SetExpectedPeerIdentity("peer-b");

    // Should not interfere with each other
    EXPECT_NO_THROW(helper1.SetStrictMode(true));
    EXPECT_NO_THROW(helper2.SetStrictMode(false));
}

TEST(SslVerifyHelper, context_verification_setup)
{
    auto ctx = SslContext(TLS_server_method());
    SslTrustStore store;

    // Load CA certificate
    std::ifstream file("cert.pem");
    ASSERT_TRUE(file.good());
    auto ca_cert = SslX509(std::move(file));
    store.AddTrustedCA(ca_cert);

    // Create helper (should configure ctx properly)
    SslVerifyHelper helper(ctx, store);
    helper.RequireExtendedKeyUsage(true, true);
    helper.SetExpectedPeerIdentity("test.example.com");

    // Verify SSL_CTX was configured
    // Note: Can't easily check internal state without TLS connection
    EXPECT_NE(ctx.Get(), nullptr);
}

TEST(SslVerifyHelper, callback_with_logic)
{
    auto ctx = SslContext(TLS_server_method());
    SslTrustStore store;
    SslVerifyHelper helper(ctx, store);

    int callback_count = 0;
    bool last_result = false;

    helper.SetVerifyCallback([&](const SslX509 &cert, int depth, int preverify_ok)
    {
        callback_count++;

        // Example logic: only accept depth 0 (end entity)
        if (depth == 0)
        {
            last_result = true;
            return true;
        }

        last_result = false;
        return false;
    });

    // Callback not invoked until TLS handshake
    EXPECT_EQ(callback_count, 0);
}

TEST(SslVerifyHelper, strict_vs_non_strict)
{
    auto ctx1 = SslContext(TLS_server_method());
    auto ctx2 = SslContext(TLS_server_method());

    SslTrustStore store1;
    SslTrustStore store2;

    SslVerifyHelper helper1(ctx1, store1);
    SslVerifyHelper helper2(ctx2, store2);

    // Setup strict mode
    helper1.SetStrictMode(true);
    helper1.SetVerifyCallback([](const SslX509 &, int, int)
    { return false; });

    // Setup non-strict mode
    helper2.SetStrictMode(false);
    helper2.SetVerifyCallback([](const SslX509 &, int, int)
    { return false; });

    // Both configured successfully
    EXPECT_NE(ctx1.Get(), nullptr);
    EXPECT_NE(ctx2.Get(), nullptr);
}

// ================================================================================================
// Integration with Context Tests
// ================================================================================================

TEST(SslVerifyHelper, server_context_integration)
{
    // Simulate server setup
    auto ctx = SslContext(TLS_server_method());

    // Load server cert and key (using test cert as both)
    ctx.UseCertificateChainFile("cert.pem");
    ctx.UsePrivateKeyFile("key.pem");

    // Setup trust store
    SslTrustStore store;
    store.LoadCAFile("cert.pem");

    // Setup verification
    SslVerifyHelper helper(ctx, store);
    helper.RequireExtendedKeyUsage(false, true); // Require client auth
    helper.SetStrictMode(true);

    EXPECT_NE(ctx.Get(), nullptr);
}

TEST(SslVerifyHelper, client_context_integration)
{
    // Simulate client setup
    auto ctx = SslContext(TLS_client_method());

    // Setup trust store (client validates server)
    SslTrustStore store;
    store.LoadCAFile("cert.pem");

    // Setup verification
    SslVerifyHelper helper(ctx, store);
    helper.SetExpectedPeerIdentity("server.example.com");
    helper.RequireExtendedKeyUsage(true, false); // Require server auth
    helper.SetStrictMode(true);

    EXPECT_NE(ctx.Get(), nullptr);
}

TEST(SslVerifyHelper, authorization_callback)
{
    auto ctx = SslContext(TLS_server_method());
    SslTrustStore store;
    SslVerifyHelper helper(ctx, store);

    // Simulated authorized peers list
    std::vector<std::string> authorized_peers = {
        "peer-a.mesh.local",
        "peer-b.mesh.local",
        "peer-c.mesh.local"};

    helper.SetVerifyCallback([authorized_peers](const SslX509 &cert, int depth, int preverify_ok)
    {
        if (depth == 0)
        {
            std::string peer_id = cert.GetCommonName();

            // Check if peer is in authorized list
            for (const auto &authorized : authorized_peers)
            {
                if (peer_id == authorized)
                    return true;
            }

            // Not authorized
            return false;
        }

        // Accept CA certificates
        return preverify_ok != 0;
    });

    EXPECT_NE(ctx.Get(), nullptr);
}

TEST(SslVerifyHelper, key_usage_validation_callback)
{
    auto ctx = SslContext(TLS_server_method());
    SslTrustStore store;
    SslVerifyHelper helper(ctx, store);

    helper.SetVerifyCallback([](const SslX509 &cert, int depth, int preverify_ok)
    {
        if (depth == 0)
        {
            // For VPN, require Digital Signature and Key Encipherment
            bool has_dig_sig = cert.HasKeyUsage(0);
            bool has_key_enc = cert.HasKeyUsage(2);

            if (!has_dig_sig || !has_key_enc)
                return false;

            // Also require both server and client auth
            bool has_server = cert.HasExtendedKeyUsage(NID_server_auth);
            bool has_client = cert.HasExtendedKeyUsage(NID_client_auth);

            return has_server && has_client;
        }

        return true;
    });

    EXPECT_NE(ctx.Get(), nullptr);
}
