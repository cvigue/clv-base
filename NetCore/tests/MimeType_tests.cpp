// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include "gtest/gtest.h"

#include <MimeType.h>
#include <filesystem>

using namespace clv::http;

class MimeTypeTest : public ::testing::Test
{
};

TEST_F(MimeTypeTest, HandlesCommonExtensions)
{
    EXPECT_EQ(MimeType::GetMimeType(".html"), "text/html");
    EXPECT_EQ(MimeType::GetMimeType(".css"), "text/css");
    EXPECT_EQ(MimeType::GetMimeType(".js"), "application/javascript");
    EXPECT_EQ(MimeType::GetMimeType(".json"), "application/json");
    EXPECT_EQ(MimeType::GetMimeType(".png"), "image/png");
    EXPECT_EQ(MimeType::GetMimeType(".jpg"), "image/jpeg");
    EXPECT_EQ(MimeType::GetMimeType(".pdf"), "application/pdf");
}

TEST_F(MimeTypeTest, HandlesExtensionsWithoutDot)
{
    EXPECT_EQ(MimeType::GetMimeType("html"), "text/html");
    EXPECT_EQ(MimeType::GetMimeType("css"), "text/css");
    EXPECT_EQ(MimeType::GetMimeType("js"), "application/javascript");
}

TEST_F(MimeTypeTest, HandlesFilePaths)
{
    std::filesystem::path htmlFile = "test.html";
    std::filesystem::path cssFile = "styles.css";
    std::filesystem::path jsFile = "script.js";

    EXPECT_EQ(MimeType::GetMimeType(htmlFile), "text/html");
    EXPECT_EQ(MimeType::GetMimeType(cssFile), "text/css");
    EXPECT_EQ(MimeType::GetMimeType(jsFile), "application/javascript");
}

TEST_F(MimeTypeTest, ReturnsDefaultForUnknownTypes)
{
    EXPECT_EQ(MimeType::GetMimeType(".unknown"), "application/octet-stream");
    EXPECT_EQ(MimeType::GetMimeType(".xyz"), "application/octet-stream");
    EXPECT_EQ(MimeType::GetMimeType(""), "application/octet-stream");
}

TEST_F(MimeTypeTest, TextTypeDetection)
{
    EXPECT_TRUE(MimeType::IsTextType("text/html"));
    EXPECT_TRUE(MimeType::IsTextType("text/plain"));
    EXPECT_TRUE(MimeType::IsTextType("application/javascript"));
    EXPECT_TRUE(MimeType::IsTextType("application/json"));
    EXPECT_TRUE(MimeType::IsTextType("image/svg+xml"));

    EXPECT_FALSE(MimeType::IsTextType("image/png"));
    EXPECT_FALSE(MimeType::IsTextType("video/mp4"));
    EXPECT_FALSE(MimeType::IsTextType("application/pdf"));
}

TEST_F(MimeTypeTest, ImageTypeDetection)
{
    EXPECT_TRUE(MimeType::IsImageType("image/png"));
    EXPECT_TRUE(MimeType::IsImageType("image/jpeg"));
    EXPECT_TRUE(MimeType::IsImageType("image/gif"));
    EXPECT_TRUE(MimeType::IsImageType("image/svg+xml"));

    EXPECT_FALSE(MimeType::IsImageType("text/html"));
    EXPECT_FALSE(MimeType::IsImageType("video/mp4"));
    EXPECT_FALSE(MimeType::IsImageType("application/pdf"));
}