// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>

#include <util/static_file_resolver.h>

#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;
using clv::util::StaticFileResolver;

// ================================================================================================
// Test fixture — creates a temporary directory tree
// ================================================================================================

class StaticFileResolverTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        root = fs::temp_directory_path() / ("sfr_test_" + std::string(::testing::UnitTest::GetInstance()->current_test_info()->name()));
        fs::create_directories(root);

        // root/index.html
        write(root / "index.html", "<html>home</html>");
        // root/page.html
        write(root / "page.html", "page content");
        // root/sub/nested.html
        fs::create_directories(root / "sub");
        write(root / "sub" / "nested.html", "nested");
    }

    void TearDown() override
    {
        fs::remove_all(root);
    }

    static void write(const fs::path &p, std::string_view content)
    {
        std::ofstream f(p);
        f << content;
    }

    fs::path root;
};

// ================================================================================================
// Happy path
// ================================================================================================

TEST_F(StaticFileResolverTest, ResolveExistingFile)
{
    auto result = StaticFileResolver::Resolve("/static/page.html", "/static", root);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->filename().string(), "page.html");
}

TEST_F(StaticFileResolverTest, ResolveNestedFile)
{
    auto result = StaticFileResolver::Resolve("/static/sub/nested.html", "/static", root);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->filename().string(), "nested.html");
}

TEST_F(StaticFileResolverTest, ResolveDefaultFileForRoot)
{
    auto result = StaticFileResolver::Resolve("/static", "/static", root);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->filename().string(), "index.html");
}

TEST_F(StaticFileResolverTest, ResolveDefaultFileForTrailingSlash)
{
    auto result = StaticFileResolver::Resolve("/static/", "/static", root);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->filename().string(), "index.html");
}

TEST_F(StaticFileResolverTest, CustomDefaultFile)
{
    write(root / "home.html", "alt home");
    auto result = StaticFileResolver::Resolve("/static", "/static", root, "home.html");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->filename().string(), "home.html");
}

// ================================================================================================
// Prefix mismatch
// ================================================================================================

TEST_F(StaticFileResolverTest, WrongPrefix)
{
    auto result = StaticFileResolver::Resolve("/assets/page.html", "/static", root);
    EXPECT_FALSE(result.has_value());
}

TEST_F(StaticFileResolverTest, EmptyUrl)
{
    auto result = StaticFileResolver::Resolve("", "/static", root);
    EXPECT_FALSE(result.has_value());
}

// ================================================================================================
// Security: directory traversal
// ================================================================================================

TEST_F(StaticFileResolverTest, DotDotInPathRejected)
{
    // Create a file one level above root to ensure we'd find it if not blocked
    write(root.parent_path() / "secret.txt", "should not be served");

    auto result = StaticFileResolver::Resolve("/static/../secret.txt", "/static", root);
    EXPECT_FALSE(result.has_value());
}

TEST_F(StaticFileResolverTest, DotDotInSubpathRejected)
{
    auto result = StaticFileResolver::Resolve("/static/sub/../../secret.txt", "/static", root);
    EXPECT_FALSE(result.has_value());
}

// ================================================================================================
// Security: null byte in URL
// ================================================================================================

TEST_F(StaticFileResolverTest, NullByteRejected)
{
    std::string url = "/static/page.html";
    url[8] = '\0'; // inject null byte
    auto result = StaticFileResolver::Resolve(url, "/static", root);
    EXPECT_FALSE(result.has_value());
}

// ================================================================================================
// Non-existent / non-regular file
// ================================================================================================

TEST_F(StaticFileResolverTest, NonExistentFileReturnsNullopt)
{
    auto result = StaticFileResolver::Resolve("/static/missing.html", "/static", root);
    EXPECT_FALSE(result.has_value());
}

TEST_F(StaticFileResolverTest, DirectoryNotServedAsFile)
{
    // /static/sub is a directory, not a regular file
    auto result = StaticFileResolver::Resolve("/static/sub", "/static", root);
    // Either returns nullopt or falls back to index.html — either way, not the dir itself
    if (result.has_value())
        EXPECT_NE(result->filename().string(), "sub");
}

// ================================================================================================
// NormalizeUrlPrefix
// ================================================================================================

TEST(NormalizeUrlPrefixTest, AlreadyNormalized)
{
    // "/api" — starts with "/", no trailing slash → unchanged
    EXPECT_EQ(StaticFileResolver::NormalizeUrlPrefix("/api"), "/api");
}

TEST(NormalizeUrlPrefixTest, NoLeadingSlash_AddsSlash)
{
    EXPECT_EQ(StaticFileResolver::NormalizeUrlPrefix("api"), "/api");
    EXPECT_EQ(StaticFileResolver::NormalizeUrlPrefix("static/files"), "/static/files");
}

TEST(NormalizeUrlPrefixTest, TrailingSlash_Removed)
{
    EXPECT_EQ(StaticFileResolver::NormalizeUrlPrefix("/api/"), "/api");
    EXPECT_EQ(StaticFileResolver::NormalizeUrlPrefix("/static/files/"), "/static/files");
}

TEST(NormalizeUrlPrefixTest, NoLeadingSlashAndTrailingSlash_BothFixed)
{
    EXPECT_EQ(StaticFileResolver::NormalizeUrlPrefix("api/"), "/api");
}

TEST(NormalizeUrlPrefixTest, RootSlash_Preserved)
{
    // Root "/" — must not strip the only slash
    EXPECT_EQ(StaticFileResolver::NormalizeUrlPrefix("/"), "/");
}

TEST(NormalizeUrlPrefixTest, EmptyString_BecomesSlash)
{
    // Empty → no leading slash → prepend "/" → "/"
    EXPECT_EQ(StaticFileResolver::NormalizeUrlPrefix(""), "/");
}

TEST(NormalizeUrlPrefixTest, DeepPath_Preserved)
{
    EXPECT_EQ(StaticFileResolver::NormalizeUrlPrefix("/a/b/c"), "/a/b/c");
    EXPECT_EQ(StaticFileResolver::NormalizeUrlPrefix("a/b/c/"), "/a/b/c");
}
