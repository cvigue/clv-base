// Copyright (c) 2026- Charlie Vigue. All rights reserved.
//
// clv::quic TlsContext tests — Phase 1 Step 3. Verifies server and
// client SSL_CTX construction against the existing NetCore test
// certificate (tests/data/cert.pem + key.pem) and the ngtcp2_crypto
// configuration paths. The actual TLS handshake is exercised in
// Step 5 once Connection wiring exists.

#include "quic/tls_context.h"

#include <gtest/gtest.h>

#include <filesystem>

namespace {

// Test fixtures are copied alongside test_netcore_quic at build time
// (see NetCore/CMakeLists.txt netcore_test_data list). gtest_discover_tests
// sets WORKING_DIRECTORY to the binary's directory, so plain filenames work.
// Matches the convention used by quic_tls_tests.cpp — cert.pem + pvtkey.pem
// is the unencrypted pairing; key.pem is passphrase-protected.
const std::filesystem::path kCert{"cert.pem"};
const std::filesystem::path kKey{"pvtkey.pem"};

TEST(Quic2TlsContext, ServerLoadsCertAndKey)
{
    ASSERT_TRUE(std::filesystem::exists(kCert)) << "cert.pem missing from CWD";
    ASSERT_TRUE(std::filesystem::exists(kKey)) << "key.pem missing from CWD";

    auto ctx = clv::quic::TlsContext::MakeServer(kCert, kKey, {"clv-mesh/1"});
    EXPECT_EQ(ctx.role(), clv::quic::TlsContext::Role::Server);
    EXPECT_NE(ctx.native_handle(), nullptr);
    ASSERT_EQ(ctx.alpns().size(), 1u);
    EXPECT_EQ(ctx.alpns()[0], "clv-mesh/1");
}

TEST(Quic2TlsContext, ClientConstructsWithAlpn)
{
    auto ctx = clv::quic::TlsContext::MakeClient({"clv-mesh/1", "h3"});
    EXPECT_EQ(ctx.role(), clv::quic::TlsContext::Role::Client);
    EXPECT_NE(ctx.native_handle(), nullptr);
    ASSERT_EQ(ctx.alpns().size(), 2u);
    EXPECT_EQ(ctx.alpns()[1], "h3");
}

TEST(Quic2TlsContext, ServerMissingCertThrows)
{
    EXPECT_THROW(clv::quic::TlsContext::MakeServer("does-not-exist.pem", kKey, {"clv-mesh/1"}),
                 std::runtime_error);
}

TEST(Quic2TlsContext, OversizedAlpnThrows)
{
    // 256 bytes exceeds the RFC 7301 per-id limit (1 byte length prefix).
    std::string huge(256, 'x');
    EXPECT_THROW(clv::quic::TlsContext::MakeClient({huge}), std::runtime_error);
}

} // namespace
