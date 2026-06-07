// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#include "gtest/gtest.h"

#include <cstring>
#include <HelpSslCustomBio.h>

using namespace clv;
using namespace clv::OpenSSL;

constexpr char CustomBioTypeName[] = "CustomBIOType";
/**
     @brief A custom BIO type for unit testing purposes.
     @details Uses the new CRTP-based SslCustomBio pattern.
     */
class UnitTestBioType : public SslCustomBio<UnitTestBioType, BIO_TYPE_SOURCE_SINK, CustomBioTypeName>
{
  public:
    friend BioMethodStatics<UnitTestBioType>;

    UnitTestBioType()
        : SslCustomBio<UnitTestBioType, BIO_TYPE_SOURCE_SINK, CustomBioTypeName>(),
          mData()
    {
    }

    /**
         @brief Read data from the BIO.
         @param out The buffer to store the read data.
         @param size The maximum number of bytes to read.
         @return The number of bytes read.
    */
    int read(char *out, int size)
    {
        auto read_size = std::min(size, static_cast<int>(mData.size()));
        std::copy(mData.data(), mData.data() + read_size, out);
        return read_size;
    }

    /**
         @brief Write data to the BIO.
         @param in The buffer containing the data to be written.
         @param size The number of bytes to write.
         @return The number of bytes written.
    */
    int write(const char *in, int size)
    {
        auto write_size = std::min(size, static_cast<int>(mData.size()));
        std::copy(in, in + write_size, mData.data());
        return write_size;
    }

    /**
         @brief Handle control operations on the BIO.
         @param cmd The control command.
         @param larg Long argument.
         @param parg Pointer argument.
         @return The result of the control operation.
    */
    long ctrl(int cmd, long larg, void *parg)
    {
        if (cmd == BIO_CTRL_FLUSH)
            return 1;
        return 0;
    }

    /**
         @brief Write a null-terminated string to the BIO.
         @param str The string to write.
         @return The number of bytes written.
    */
    int puts(const char *str)
    {
        return write(str, static_cast<int>(strlen(str)));
    }

  private:
    std::array<char, 1024> mData;
};

TEST(SslCustomBio, init)
{
    auto cb = UnitTestBioType();
}

TEST(SslCustomBio, init_2x)
{
    auto cb1 = UnitTestBioType();
    auto cb2 = UnitTestBioType();
}

TEST(SslCustomBio, BIO_get_data)
{
    auto cb = UnitTestBioType();
    EXPECT_NE(nullptr, BIO_get_data(cb.Get()));
}

TEST(SslCustomBio, BIO_find_type)
{
    auto cb = UnitTestBioType();
    EXPECT_NE(nullptr, BIO_find_type(cb.Get(), BIO_TYPE_SOURCE_SINK));
    EXPECT_EQ(nullptr, BIO_find_type(cb.Get(), BIO_TYPE_FILTER));
}

TEST(SslCustomBio, read_write)
{
    auto cb = UnitTestBioType();
    EXPECT_EQ(BIO_write(cb.Get(), "ping", 4), 4);
    char buffer[128] = {0};
    EXPECT_EQ(BIO_read(cb.Get(), buffer, 4), 4);
    EXPECT_EQ(std::string("ping"), std::string(buffer));
}
