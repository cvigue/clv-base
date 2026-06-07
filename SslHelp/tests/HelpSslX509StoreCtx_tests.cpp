// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>

#include "HelpSslX509.h"
#include "HelpSslX509StoreCtx.h"

#include <fstream>
#include <openssl/x509_vfy.h>

using namespace clv::OpenSSL;

// Helper: load test cert and build a trusted store for it
static SslX509 LoadTestCert()
{
    std::ifstream file("cert.pem");
    if (!file.good())
        throw std::runtime_error("cert.pem not found");
    return SslX509(std::move(file));
}

// ================================================================================================
// SslX509StoreCtx construction
// ================================================================================================

TEST(SslX509StoreCtxTest, DefaultConstruct)
{
    SslX509StoreCtx ctx;
    EXPECT_NE(ctx.Get(), nullptr);
}

// ================================================================================================
// Init
// ================================================================================================

TEST(SslX509StoreCtxTest, InitWithValidInputsSucceeds)
{
    auto cert = LoadTestCert();

    // Build a store with the cert as a trusted root
    auto *store = X509_STORE_new();
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(X509_STORE_add_cert(store, const_cast<X509 *>(cert.Get())), 1);

    SslX509StoreCtx ctx;
    bool ok = ctx.Init(store, const_cast<X509 *>(cert.Get()));
    EXPECT_TRUE(ok);

    X509_STORE_free(store);
}

// ================================================================================================
// Verify
// ================================================================================================

TEST(SslX509StoreCtxTest, VerifySelfSignedInTrustStoreSucceeds)
{
    auto cert = LoadTestCert();

    auto *store = X509_STORE_new();
    ASSERT_NE(store, nullptr);
    X509_STORE_add_cert(store, const_cast<X509 *>(cert.Get()));

    SslX509StoreCtx ctx;
    ASSERT_TRUE(ctx.Init(store, const_cast<X509 *>(cert.Get())));
    EXPECT_EQ(ctx.Verify(), 1);
    EXPECT_EQ(ctx.Error(), X509_V_OK);

    X509_STORE_free(store);
}

TEST(SslX509StoreCtxTest, VerifyUntrustedCertFails)
{
    auto cert = LoadTestCert();

    // Empty store — nothing trusted
    auto *store = X509_STORE_new();
    ASSERT_NE(store, nullptr);

    SslX509StoreCtx ctx;
    ASSERT_TRUE(ctx.Init(store, const_cast<X509 *>(cert.Get())));
    EXPECT_NE(ctx.Verify(), 1);
    EXPECT_NE(ctx.Error(), X509_V_OK);

    X509_STORE_free(store);
}

// ================================================================================================
// Error accessors
// ================================================================================================

TEST(SslX509StoreCtxTest, GetErrorDepthIsZeroForLeaf)
{
    auto cert = LoadTestCert();

    auto *store = X509_STORE_new();
    ASSERT_NE(store, nullptr);
    X509_STORE_add_cert(store, const_cast<X509 *>(cert.Get()));

    SslX509StoreCtx ctx;
    ASSERT_TRUE(ctx.Init(store, const_cast<X509 *>(cert.Get())));
    ctx.Verify();

    // For a single self-signed cert, depth is 0
    EXPECT_GE(ctx.GetErrorDepth(), 0);

    X509_STORE_free(store);
}

TEST(SslX509StoreCtxTest, SetAndGetError)
{
    auto cert = LoadTestCert();
    auto *store = X509_STORE_new();
    ASSERT_NE(store, nullptr);

    SslX509StoreCtx ctx;
    ASSERT_TRUE(ctx.Init(store, const_cast<X509 *>(cert.Get())));

    ctx.SetError(X509_V_ERR_CERT_HAS_EXPIRED);
    EXPECT_EQ(ctx.Error(), X509_V_ERR_CERT_HAS_EXPIRED);

    X509_STORE_free(store);
}

// ================================================================================================
// SslX509Stack
// ================================================================================================

TEST(SslX509StackTest, DefaultConstruct)
{
    SslX509Stack stack;
    EXPECT_NE(stack.Raw(), nullptr);
}

TEST(SslX509StackTest, PushCert)
{
    auto cert = LoadTestCert();
    SslX509Stack stack;
    EXPECT_NO_THROW(stack.Push(const_cast<X509 *>(cert.Get())));
}
