// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include "HelpSslException.h"
#include "gtest/gtest.h"

#include <HelpSslBio.h>
#include <openssl/bio.h>
#include <openssl/types.h>
#include <string>

using namespace clv::OpenSSL;

/* These leave some memory in play even though BIO_vfree is called as it should be

    ==1084715== HEAP SUMMARY:
    ==1084715==     in use at exit: 2,468 bytes in 49 blocks
    ==1084715==   total heap usage: 286 allocs, 237 frees, 121,646 bytes allocated
    ==1084715==
    ==1084715== LEAK SUMMARY:
    ==1084715==    definitely lost: 0 bytes in 0 blocks
    ==1084715==    indirectly lost: 0 bytes in 0 blocks
    ==1084715==      possibly lost: 0 bytes in 0 blocks
    ==1084715==    still reachable: 2,468 bytes in 49 blocks
    ==1084715==         suppressed: 0 bytes in 0 blocks
    ==1084715== Reachable blocks (those to which a pointer was found) are not shown.

*/

TEST(SslBio, nullptr_assign)
{
    auto bio = SslBio(nullptr);
    EXPECT_EQ(bio.Get(), nullptr);
}

TEST(SslBio, null_assign)
{
    EXPECT_THROW(SslBio((BIO *)0), SslException);
}

TEST(SslBio, method_construct)
{
    auto bio = SslBio(BIO_s_mem());
    EXPECT_NE(bio.Get(), nullptr);
}

TEST(SslBio, copy_construct)
{
    auto buffer = std::string("Hello OpenSSL");
    auto bio = SslBio(BIO_new_mem_buf(buffer.data(), -1));
    auto bio2 = bio;
    char out[64] = {0};
    EXPECT_GT(BIO_read(bio2.Get(), out, sizeof(out) / sizeof(out[0])), 0);
    EXPECT_EQ(buffer, out);
}

TEST(SslBio, mem_bio)
{
    auto buffer = std::string("Hello OpenSSL");
    auto bio = SslBio(BIO_new_mem_buf(buffer.data(), -1));
    char out[64] = {0};
    EXPECT_GT(BIO_read(bio.Get(), out, sizeof(out) / sizeof(out[0])), 0);
    EXPECT_EQ(buffer, out);
}