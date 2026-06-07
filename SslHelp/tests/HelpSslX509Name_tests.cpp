// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#include "gtest/gtest.h"

#include <HelpSslX509Name.h>

using namespace clv::OpenSSL;

TEST(HelpSslX509Name, default_construct)
{
    auto name = SslX509Name();
    EXPECT_NE(name.Get(), nullptr);
}

TEST(HelpSslX509Name, nullptr_construct)
{
    auto name = SslX509Name(nullptr);
    EXPECT_EQ(name.Get(), nullptr);
}

TEST(HelpSslX509Name, single_entry_constructor)
{
    auto name = SslX509Name("CN", "example.com");
    EXPECT_NE(name.Get(), nullptr);
}

TEST(HelpSslX509Name, add_entry)
{
    auto name = SslX509Name();
    name.AddEntry("CN", "example.com");
    name.AddEntry("O", "Example Organization");
    name.AddEntry("C", "US");
    EXPECT_NE(name.Get(), nullptr);
}

TEST(HelpSslX509Name, map_constructor)
{
    SslX509Name::KeyValueStrListT entries = {
        {"CN", "example.com"},
        {"O", "Example Org"},
        {"C", "US"}};
    auto name = SslX509Name(entries);
    EXPECT_NE(name.Get(), nullptr);
}

TEST(HelpSslX509Name, clone)
{
    auto name1 = SslX509Name("CN", "example.com");
    name1.AddEntry("O", "Test Org");

    auto name2 = name1.Clone();
    EXPECT_NE(name2.Get(), nullptr);
    EXPECT_NE(name1.Get(), name2.Get()); // Different pointers
}

TEST(HelpSslX509Name, wrap_existing)
{
    X509_NAME *raw_name = X509_NAME_new();
    ASSERT_NE(raw_name, nullptr);

    X509_NAME_add_entry_by_txt(raw_name, "CN", MBSTRING_UTF8, (const unsigned char *)"test.com", -1, -1, 0);

    auto name = SslX509Name(raw_name);
    EXPECT_EQ(name.Get(), raw_name);
}

TEST(HelpSslX509Name, add_entry_validation)
{
    auto name = SslX509Name();

    // Valid entries
    EXPECT_NO_THROW(name.AddEntry("CN", "common.name"));
    EXPECT_NO_THROW(name.AddEntry("O", "Organization"));
    EXPECT_NO_THROW(name.AddEntry("OU", "Organizational Unit"));
    EXPECT_NO_THROW(name.AddEntry("C", "US"));
    EXPECT_NO_THROW(name.AddEntry("ST", "California"));
    EXPECT_NO_THROW(name.AddEntry("L", "San Francisco"));
}

TEST(HelpSslX509Name, multiple_entries_same_key)
{
    auto name = SslX509Name();

    // Multiple OU entries should be allowed
    EXPECT_NO_THROW(name.AddEntry("OU", "Engineering"));
    EXPECT_NO_THROW(name.AddEntry("OU", "Security"));
}
