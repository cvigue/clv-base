// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#include "gtest/gtest.h"

#include <http/HttpStaticRouter.h>
#include <filesystem>
#include <fstream>
#include <asio.hpp>

using namespace clv;
using namespace clv::http;

class HttpStaticRouterTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        // Create a temporary directory for testing
        testDir = std::filesystem::temp_directory_path() / "http_static_router_test";
        std::filesystem::create_directories(testDir);

        // Create test files
        auto indexFile = testDir / "index.html";
        std::ofstream indexStream(indexFile);
        indexStream << "<html><body><h1>Hello World from Static Router</h1></body></html>";
        indexStream.close();

        auto textFile = testDir / "test.txt";
        std::ofstream textStream(textFile);
        textStream << "This is a test file from the static router.\n";
        textStream << "Line 2: Testing async file serving.\n";
        textStream.close();

        auto jsonFile = testDir / "data.json";
        std::ofstream jsonStream(jsonFile);
        jsonStream << R"({"name": "StaticRouter", "version": "1.0", "status": "active"})";
        jsonStream.close();

        auto subDir = testDir / "subdir";
        std::filesystem::create_directories(subDir);
        auto subFile = subDir / "nested.html";
        std::ofstream subStream(subFile);
        subStream << "<html><body>Nested static file</body></html>";
        subStream.close();
    }

    void TearDown() override
    {
        // Clean up test directory
        std::filesystem::remove_all(testDir);
    }

    std::filesystem::path testDir;
};

TEST_F(HttpStaticRouterTest, ConstructorValidatesDirectory)
{
    // Should work with valid directory
    EXPECT_NO_THROW(HttpStaticRouter("/static", testDir));

    // Should throw with non-existent directory
    auto nonExistentDir = testDir / "does_not_exist";
    EXPECT_THROW(HttpStaticRouter("/static", nonExistentDir), std::runtime_error);

    // Should throw with file instead of directory
    auto filePath = testDir / "test.txt";
    EXPECT_THROW(HttpStaticRouter("/static", filePath), std::runtime_error);
}
