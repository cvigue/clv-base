// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#include "gtest/gtest.h"

#include <HelpSslAsn1.h>

using namespace clv::OpenSSL;


TEST(HelpSslAsn1, nullptr_test)
{
    auto asn1int = SslAsn1Integer(nullptr); // Can intentionally nullptr it
}

TEST(HelpSslAsn1, null_ptr_test)
{
    EXPECT_ANY_THROW(SslAsn1Integer((ASN1_INTEGER *)0)); // Rejects failed allocations
}

TEST(HelpSslAsn1, integer_inout)
{
    auto asn1int = SslAsn1Integer(int64_t(42));
    EXPECT_EQ(42, asn1int.AsInt());
    EXPECT_EQ(42u, asn1int.AsUint());
}

TEST(HelpSslAsn1, octet_string)
{
    auto ssl_str = SslAsn1OctetString("Hello OpenSSL");
    EXPECT_EQ("Hello OpenSSL", ssl_str.AsString());
}

TEST(HelpSslAsn1, octet_string_view)
{
    auto ssl_str = SslAsn1OctetString("Hello OpenSSL");
    EXPECT_EQ("Hello OpenSSL", ssl_str.AsStringView());
}

TEST(HelpSslAsn1, string)
{
    auto ssl_str = SslAsn1String("Hello OpenSSL");
    EXPECT_EQ("Hello OpenSSL", ssl_str.AsString());
}

TEST(HelpSslAsn1, string_view)
{
    auto ssl_str = SslAsn1String("Hello OpenSSL");
    EXPECT_EQ("Hello OpenSSL", ssl_str.AsStringView());
}

TEST(HelpSslAsn1, random64)
{
    auto rand1 = SslAsn1Integer::Random64();
    auto rand2 = SslAsn1Integer::Random64();

    // Should create valid integers
    EXPECT_NE(rand1.Get(), nullptr);
    EXPECT_NE(rand2.Get(), nullptr);

    // Should be different (highly likely with 64-bit random)
    EXPECT_NE(rand1.AsUint(), rand2.AsUint());

    // Should be able to retrieve as uint64
    EXPECT_NO_THROW(rand1.AsUint());
}

TEST(HelpSslAsn1, large_integers)
{
    // Test with large values
    uint64_t large_val = 0xFFFFFFFFFFFFFFFFULL;
    auto asn1int = SslAsn1Integer(large_val);
    EXPECT_EQ(large_val, asn1int.AsUint());
}

TEST(HelpSslAsn1, negative_integers)
{
    int64_t negative = -12345;
    auto asn1int = SslAsn1Integer(negative);
    EXPECT_EQ(negative, asn1int.AsInt());
}
