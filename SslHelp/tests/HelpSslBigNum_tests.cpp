// Copyright (c) 2023- Charlie Vigue. All rights reserved.


#include "gtest/gtest.h"

#include <cmath>

#include <HelpSslBigNum.h>

using namespace clv::OpenSSL;

TEST(HelpSslBigNum, size_1)
{
    auto bn = SslBigNum(42);
    EXPECT_EQ(bn.Size(), 1);
}

TEST(HelpSslBigNum, as_uint)
{
    auto bn = SslBigNum(42);
    EXPECT_EQ(bn.AsUint(), 42);
}

TEST(HelpSslBigNum, size_2)
{
    auto bn = SslBigNum(0x4242);
    EXPECT_EQ(bn.Size(), 2);
}

TEST(HelpSslBigNum, size_4)
{
    auto bn = SslBigNum(0x42424242);
    EXPECT_EQ(bn.Size(), 4);
}

TEST(HelpSslBigNum, size_8)
{
    auto bn = SslBigNum(0x4242424242424242);
    EXPECT_EQ(bn.Size(), 8);
}

TEST(HelpSslBigNum, secure_size_8)
{
    auto bn = SslSecureBigNum(0x4242424242424242);
    EXPECT_EQ(bn.Size(), 8);
}

TEST(HelpSslBigNum, secure_add_prohibited)
{
    auto bna = SslSecureBigNum(42);
    auto bnb = SslBigNum(24);
    // auto bnr = bna + bnb; // Won't compile due to secure and insecure mismatch
    // EXPECT_EQ(bna.AsUint(), 42);
    // EXPECT_EQ(bnb.AsUint(), 24);
    // EXPECT_EQ(bnr.AsUint(), 66);
}

TEST(HelpSslBigNum, secure_add)
{
    auto bna = SslSecureBigNum(42);
    auto bnb = SslSecureBigNum(24);
    auto bnr = bna + bnb;
    EXPECT_EQ(bna.AsUint(), 42);
    EXPECT_EQ(bnb.AsUint(), 24);
    EXPECT_EQ(bnr.AsUint(), 66);
}

TEST(HelpSslBigNum, secure_sub)
{
    auto bna = SslSecureBigNum(42);
    auto bnb = SslSecureBigNum(24);
    auto bnr = bna - bnb;
    EXPECT_EQ(bna.AsUint(), 42);
    EXPECT_EQ(bnb.AsUint(), 24);
    EXPECT_EQ(bnr.AsUint(), 18);
}

TEST(HelpSslBigNum, secure_mul)
{
    auto bna = SslSecureBigNum(42);
    auto bnb = SslSecureBigNum(24);
    auto bnr = bna * bnb;
    EXPECT_EQ(bna.AsUint(), 42);
    EXPECT_EQ(bnb.AsUint(), 24);
    EXPECT_EQ(bnr.AsUint(), 1008);
}

TEST(HelpSslBigNum, secure_div)
{
    auto bna = SslSecureBigNum(42);
    auto bnb = SslSecureBigNum(6);
    auto bnr = bna / bnb;
    EXPECT_EQ(bna.AsUint(), 42);
    EXPECT_EQ(bnb.AsUint(), 6);
    EXPECT_EQ(bnr.AsUint(), 7);
}

TEST(HelpSslBigNum, lshift_operator)
{
    auto bn = SslBigNum(1);
    EXPECT_EQ(bn.AsUint(), 1);

    for (int i = 0; i < 64; ++i)
    {
        EXPECT_EQ(bn << i, SslBigNum(static_cast<uint64_t>(pow(2, i))));
    }
}

TEST(HelpSslBigNum, rshift_operator)
{
    auto bn = SslBigNum(0x8000000000000000);

    for (int i = 0; i < 64; ++i)
    {
        EXPECT_EQ(bn >> i, SslBigNum(static_cast<uint64_t>(pow(2, 63 - i))));
    }
}

TEST(HelpSslBigNum, addself_operator)
{
    auto bna = SslBigNum(0);
    bna += SslBigNum(1);
    EXPECT_EQ(bna, SslBigNum(1));
}

TEST(HelpSslBigNum, subself_operator)
{
    auto bna = SslBigNum(1);
    bna -= SslBigNum(1);
    EXPECT_EQ(bna, SslBigNum(0));
}

TEST(HelpSslBigNum, mulself_operator)
{
    auto bna = SslBigNum(1);
    bna *= SslBigNum(2);
    EXPECT_EQ(bna, SslBigNum(2));
}

TEST(HelpSslBigNum, divself_operator)
{
    auto bna = SslBigNum(2);
    bna /= SslBigNum(2);
    EXPECT_EQ(bna, SslBigNum(1));
}

// ================================================================================================
// Bit manipulation tests - Critical tests for ChkBit, SetBit, ClrBit
// ================================================================================================

TEST(HelpSslBigNum, chkbit_basic)
{
    // Test that ChkBit correctly identifies set and unset bits
    auto bn = SslBigNum(0b10101010); // Binary: 10101010 = 170

    // Bits that should be set (1)
    EXPECT_TRUE(bn.ChkBit(1)); // Bit 1 is set
    EXPECT_TRUE(bn.ChkBit(3)); // Bit 3 is set
    EXPECT_TRUE(bn.ChkBit(5)); // Bit 5 is set
    EXPECT_TRUE(bn.ChkBit(7)); // Bit 7 is set

    // Bits that should be clear (0)
    EXPECT_FALSE(bn.ChkBit(0)); // Bit 0 is clear
    EXPECT_FALSE(bn.ChkBit(2)); // Bit 2 is clear
    EXPECT_FALSE(bn.ChkBit(4)); // Bit 4 is clear
    EXPECT_FALSE(bn.ChkBit(6)); // Bit 6 is clear
}

TEST(HelpSslBigNum, chkbit_single_bit)
{
    // Test each individual bit position
    for (int i = 0; i < 64; i++)
    {
        auto bn = SslBigNum(0);
        bn.SetBit(i);

        // The bit we set should be true
        EXPECT_TRUE(bn.ChkBit(i)) << "Bit " << i << " should be set";

        // All other bits should be false
        for (int j = 0; j < 64; j++)
        {
            if (j != i)
            {
                EXPECT_FALSE(bn.ChkBit(j)) << "Bit " << j << " should be clear when only bit " << i << " is set";
            }
        }
    }
}

TEST(HelpSslBigNum, setbit_basic)
{
    auto bn = SslBigNum(0);
    EXPECT_EQ(bn.AsUint(), 0);

    bn.SetBit(0);
    EXPECT_EQ(bn.AsUint(), 1);

    bn.SetBit(1);
    EXPECT_EQ(bn.AsUint(), 3);

    bn.SetBit(2);
    EXPECT_EQ(bn.AsUint(), 7);

    bn.SetBit(3);
    EXPECT_EQ(bn.AsUint(), 15);
}

TEST(HelpSslBigNum, setbit_high_bits)
{
    auto bn = SslBigNum(0);

    // Set bit 63 (highest bit in 64-bit number)
    bn.SetBit(63);
    EXPECT_EQ(bn.AsUint(), 0x8000000000000000ULL);
    EXPECT_TRUE(bn.ChkBit(63));

    // Set bit 62
    bn.SetBit(62);
    EXPECT_EQ(bn.AsUint(), 0xC000000000000000ULL);
    EXPECT_TRUE(bn.ChkBit(62));
    EXPECT_TRUE(bn.ChkBit(63));
}

TEST(HelpSslBigNum, clrbit_basic)
{
    auto bn = SslBigNum(0xFF); // All bits 0-7 set
    EXPECT_EQ(bn.AsUint(), 255);

    bn.ClrBit(0);
    EXPECT_EQ(bn.AsUint(), 254);
    EXPECT_FALSE(bn.ChkBit(0));

    bn.ClrBit(1);
    EXPECT_EQ(bn.AsUint(), 252);
    EXPECT_FALSE(bn.ChkBit(1));

    bn.ClrBit(7);
    EXPECT_EQ(bn.AsUint(), 124);
    EXPECT_FALSE(bn.ChkBit(7));
}

TEST(HelpSslBigNum, setbit_clrbit_roundtrip)
{
    // Test setting and clearing bits
    auto bn = SslBigNum(0);

    for (int i = 0; i < 32; i++)
    {
        bn.SetBit(i);
        EXPECT_TRUE(bn.ChkBit(i)) << "Bit " << i << " should be set after SetBit";
    }

    for (int i = 0; i < 32; i++)
    {
        bn.ClrBit(i);
        EXPECT_FALSE(bn.ChkBit(i)) << "Bit " << i << " should be clear after ClrBit";
    }

    EXPECT_EQ(bn.AsUint(), 0);
}

TEST(HelpSslBigNum, chkbit_pattern_test)
{
    // Test with known bit patterns
    auto bn = SslBigNum(0x5555555555555555ULL); // Alternating bits: 0101010101...

    for (int i = 0; i < 64; i++)
    {
        if (i % 2 == 0)
        {
            EXPECT_TRUE(bn.ChkBit(i)) << "Even bit " << i << " should be set";
        }
        else
        {
            EXPECT_FALSE(bn.ChkBit(i)) << "Odd bit " << i << " should be clear";
        }
    }
}

TEST(HelpSslBigNum, chkbit_all_ones)
{
    auto bn = SslBigNum(0xFFFFFFFFFFFFFFFFULL); // All bits set

    for (int i = 0; i < 64; i++)
    {
        EXPECT_TRUE(bn.ChkBit(i)) << "Bit " << i << " should be set in all-ones value";
    }
}

TEST(HelpSslBigNum, chkbit_all_zeros)
{
    auto bn = SslBigNum(0); // All bits clear

    for (int i = 0; i < 64; i++)
    {
        EXPECT_FALSE(bn.ChkBit(i)) << "Bit " << i << " should be clear in all-zeros value";
    }
}

TEST(HelpSslBigNum, setbit_idempotent)
{
    // Setting the same bit multiple times should be idempotent
    auto bn = SslBigNum(0);

    bn.SetBit(5);
    auto value1 = bn.AsUint();

    bn.SetBit(5);
    auto value2 = bn.AsUint();

    bn.SetBit(5);
    auto value3 = bn.AsUint();

    EXPECT_EQ(value1, value2);
    EXPECT_EQ(value2, value3);
    EXPECT_EQ(value1, 32); // 2^5 = 32
}

TEST(HelpSslBigNum, secure_bit_operations)
{
    // Test that bit operations work with secure big numbers too
    auto bn = SslSecureBigNum(0);

    bn.SetBit(10);
    EXPECT_TRUE(bn.ChkBit(10));
    EXPECT_EQ(bn.AsUint(), 1024);

    bn.ClrBit(10);
    EXPECT_FALSE(bn.ChkBit(10));
    EXPECT_EQ(bn.AsUint(), 0);
}
