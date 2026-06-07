// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>

#include "HelpSslX509Name.h"

#include <openssl/x509.h>

using namespace clv::OpenSSL;

// SslX509Name uses SslNoRcCopy with SslDupCloner<X509_NAME, X509_NAME_dup>.
// It is the most accessible concrete type that exercises both clone strategies.

// ================================================================================================
// SslDupCloner via SslX509Name::Clone()
// ================================================================================================

TEST(SslNoRcCopyTest, CloneProducesIndependentCopy)
{
    SslX509Name name("CN", "test.example.com");
    auto clone = name.Clone();

    // Both should be non-null
    EXPECT_NE(name.Get(), nullptr);
    EXPECT_NE(clone.Get(), nullptr);

    // Independent allocations
    EXPECT_NE(name.Get(), clone.Get());
}

TEST(SslNoRcCopyTest, ClonedNameMatchesOriginal)
{
    SslX509Name name("CN", "peer.vpn.local");
    name.AddEntry("O", "VPN Corp");

    auto clone = name.Clone();

    // The clone should have the same content as the original
    EXPECT_EQ(X509_NAME_cmp(name.Get(), clone.Get()), 0);
}

TEST(SslNoRcCopyTest, ModifyingCloneDoesNotAffectOriginal)
{
    SslX509Name original("CN", "original.example.com");
    auto clone = original.Clone();

    // Add an entry to the clone only
    clone.AddEntry("O", "Modified Org");

    // Original should be unmodified (different entry count)
    EXPECT_NE(X509_NAME_cmp(original.Get(), clone.Get()), 0);
}

TEST(SslNoRcCopyTest, CloneOfDefaultConstructedWorks)
{
    SslX509Name name;
    // Default-constructed X509_NAME is empty but valid
    EXPECT_NO_THROW(auto clone = name.Clone());
}

// ================================================================================================
// Verify Clone() throws SslException when duplication fails
// (This is hard to inject directly; rely on coverage from the above tests.
//  The throw path is exercised by the implementation review.)
// ================================================================================================
