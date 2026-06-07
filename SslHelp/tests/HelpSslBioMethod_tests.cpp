// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include "gtest/gtest.h"

#include <HelpSslBioMethod.h>

using namespace clv::OpenSSL;

TEST(SslBioMethod, nullptr_assign)
{
    auto bio = SslBioMethod(nullptr);
    EXPECT_EQ(bio.Get(), nullptr);
}

TEST(SslBioMethod, null_assign)
{
    EXPECT_THROW(SslBioMethod((BIO_METHOD *)0), SslException);
}

TEST(SslBioMethod, method_construct)
{
    auto bio = SslBioMethod(BIO_TYPE_SOURCE_SINK, "Bob");
    EXPECT_NE(bio.Get(), nullptr);
}

TEST(SslBioMethod, move_construct)
{
    auto bio = SslBioMethod(BIO_TYPE_SOURCE_SINK, "Bob");
    auto bio2 = std::move(bio);
    EXPECT_EQ(bio.Get(), nullptr);
    EXPECT_NE(bio2.Get(), nullptr);
    EXPECT_NE(bio.Get(), bio2.Get());
}
