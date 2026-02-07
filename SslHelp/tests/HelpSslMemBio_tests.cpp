// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>
#include "../src/HelpSslMemBio.h"
#include <vector>

using namespace clv::OpenSSL;

class HelpSslMemBioTests : public ::testing::Test
{
  protected:
    SslMemBio bios_;
};

TEST_F(HelpSslMemBioTests, BIOsCreatedSuccessfully)
{
    // BIOs are created successfully - verified by being able to write/read
    std::vector<std::uint8_t> data = {1, 2, 3};
    EXPECT_EQ(bios_.WriteInput(data), 3);
}

TEST_F(HelpSslMemBioTests, WriteToInputBio)
{
    std::vector<std::uint8_t> data = {1, 2, 3, 4, 5};
    int written = bios_.WriteInput(data);

    EXPECT_EQ(written, 5);
}

TEST_F(HelpSslMemBioTests, WriteToInputBioEmptyData)
{
    std::vector<std::uint8_t> data;
    int written = bios_.WriteInput(data);

    EXPECT_EQ(written, 0);
}

TEST_F(HelpSslMemBioTests, ReadFromOutputBio)
{
    // This would require actual SSL I/O to populate output BIO
    // For now, just verify the function doesn't crash
    std::vector<std::uint8_t> output = bios_.ReadOutput();
    // Empty until SSL writes to it
    EXPECT_EQ(output.size(), 0);
}

TEST_F(HelpSslMemBioTests, WriteInputMultipleTimes)
{
    std::vector<std::uint8_t> data1 = {1, 2, 3};
    std::vector<std::uint8_t> data2 = {4, 5};

    int written1 = bios_.WriteInput(data1);
    int written2 = bios_.WriteInput(data2);

    EXPECT_EQ(written1, 3);
    EXPECT_EQ(written2, 2);
}

TEST_F(HelpSslMemBioTests, LargeDatagram)
{
    std::vector<std::uint8_t> large_data(10000);
    for (size_t i = 0; i < large_data.size(); ++i)
    {
        large_data[i] = static_cast<std::uint8_t>(i % 256);
    }

    int written = bios_.WriteInput(large_data);
    EXPECT_EQ(written, 10000);
}
