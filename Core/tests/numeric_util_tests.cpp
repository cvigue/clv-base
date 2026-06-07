// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include <gtest/gtest.h>

#include <limits>
#include <tuple>

#include "numeric_util.h"

using namespace clv;

// Define pairs of (Dest, Src) to test various permutations
using NumericPairs = testing::Types<
    std::tuple<int32_t, int32_t>,   // same type
    std::tuple<uint8_t, int16_t>,   // signed -> unsigned
    std::tuple<int8_t, int16_t>,    // signed -> signed (downcast)
    std::tuple<int16_t, uint32_t>,  // unsigned -> signed
    std::tuple<uint16_t, uint32_t>, // unsigned -> unsigned
    std::tuple<int16_t, uint64_t>,  // signed -> unsigned
    std::tuple<float, int32_t>,     // fp -> signed (downcast)
    std::tuple<float, double>,      // fp -> fp
    std::tuple<double, double>,     // fp -> fp
    std::tuple<double, int8_t>>;    // fp -> signed (downcast)

template <typename T>
class NumericUtilTypedTest : public testing::Test
{
};

TYPED_TEST_SUITE(NumericUtilTypedTest, NumericPairs);

// Helper templates to compare numeric limits safely (avoid signed/unsigned
// promotion surprises by comparing with a common floating point type).
template <typename A, typename B>
constexpr bool src_lower_than_dest()
{
    return static_cast<long double>(std::numeric_limits<A>::lowest()) < static_cast<long double>(std::numeric_limits<B>::lowest());
}

template <typename A, typename B>
constexpr bool src_max_greater_than_dest()
{
    return static_cast<long double>(std::numeric_limits<A>::max()) > static_cast<long double>(std::numeric_limits<B>::max());
}

TYPED_TEST(NumericUtilTypedTest, ClampBehavior)
{
    using Dest = std::tuple_element_t<0, TypeParam>;
    using Src = std::tuple_element_t<1, TypeParam>;

    if constexpr (std::is_same_v<Dest, Src>)
    {
        EXPECT_EQ(clamp_to_type<Dest>(Dest(123)), Dest(123));
        EXPECT_EQ(clamp_to_type<Dest>(std::numeric_limits<Dest>::min()),
                  std::numeric_limits<Dest>::min());
        EXPECT_EQ(clamp_to_type<Dest>(std::numeric_limits<Dest>::max()),
                  std::numeric_limits<Dest>::max());
    }
    else if constexpr (std::is_unsigned_v<Dest> && std::is_signed_v<Src>)
    {
        // signed -> unsigned: negatives become 0, overflow clamps to max
        EXPECT_EQ(clamp_to_type<Dest>(Src(-1)), Dest(0));
        using Big = std::make_unsigned_t<Src>;
        Big big_val = static_cast<Big>(std::numeric_limits<Dest>::max()) + Big(1);
        EXPECT_EQ(clamp_to_type<Dest>(static_cast<Src>(big_val)), std::numeric_limits<Dest>::max());
        EXPECT_EQ(clamp_to_type<Dest>(Src(42)), Dest(42));
    }
    else if constexpr (std::is_signed_v<Dest> && std::is_unsigned_v<Src>)
    {
        // unsigned -> signed: if src > signed max -> clamp to signed max
        using Big = std::make_unsigned_t<Src>;
        Big too_big = static_cast<Big>(std::numeric_limits<Dest>::max()) + Big(1);
        EXPECT_EQ(clamp_to_type<Dest>(static_cast<Src>(too_big)), std::numeric_limits<Dest>::max());
        EXPECT_EQ(clamp_to_type<Dest>(static_cast<Src>(32000)), Dest(32000));
    }
    else if constexpr (std::is_signed_v<Dest> && std::is_signed_v<Src>)
    {
        // signed -> signed: clamp to dest limits. Only test clamping if
        // the source type can represent values outside the destination
        // range; avoid casting huge floating point limits into smaller
        // integer types (undefined behavior).
        if constexpr (src_lower_than_dest<Src, Dest>())
        {
            Src low = std::numeric_limits<Src>::lowest();
            EXPECT_EQ(clamp_to_type<Dest>(low), std::numeric_limits<Dest>::lowest());
        }
        if constexpr (src_max_greater_than_dest<Src, Dest>())
        {
            Src high = std::numeric_limits<Src>::max();
            EXPECT_EQ(clamp_to_type<Dest>(high), std::numeric_limits<Dest>::max());
        }
    }
    else if constexpr (std::is_unsigned_v<Dest> && std::is_unsigned_v<Src>)
    {
        // unsigned -> unsigned: clamp if > max
        Src big = static_cast<Src>(std::numeric_limits<Dest>::max()) + Src(1);
        EXPECT_EQ(clamp_to_type<Dest>(big), std::numeric_limits<Dest>::max());
        EXPECT_EQ(clamp_to_type<Dest>(static_cast<Src>(32000)), Dest(32000));
    }
    else
    {
        // General case: clamp to dest limits if source can exceed them
        if constexpr (src_lower_than_dest<Src, Dest>())
        {
            Src low = std::numeric_limits<Src>::lowest();
            EXPECT_EQ(clamp_to_type<Dest>(low), std::numeric_limits<Dest>::lowest());
        }
        if constexpr (src_max_greater_than_dest<Src, Dest>())
        {
            Src high = std::numeric_limits<Src>::max();
            EXPECT_EQ(clamp_to_type<Dest>(high), std::numeric_limits<Dest>::max());
        }
    }
}

TYPED_TEST(NumericUtilTypedTest, SafeCastBehavior)
{
    using Dest = std::tuple_element_t<0, TypeParam>;
    using Src = std::tuple_element_t<1, TypeParam>;

    // A simple value that should safely convert in most cases
    Src safe_val = static_cast<Src>(42);
    EXPECT_EQ(safe_cast<Dest>(safe_val), static_cast<Dest>(42));

    // If Source can exceed Destination max, conversion should throw
    if constexpr (src_max_greater_than_dest<Src, Dest>())
    {
        Src too_big = std::numeric_limits<Src>::max();
        EXPECT_THROW(safe_cast<Dest>(too_big), std::range_error);
    }

    // If Source can be lower than Destination lowest, conversion should throw
    if constexpr (src_lower_than_dest<Src, Dest>())
    {
        Src too_low = std::numeric_limits<Src>::lowest();
        EXPECT_THROW(safe_cast<Dest>(too_low), std::range_error);
    }

    // Negative to unsigned (signed -> unsigned) should throw for negative values
    if constexpr (std::is_unsigned_v<Dest> && std::is_signed_v<Src>)
    {
        Src neg = Src(-1);
        EXPECT_THROW(safe_cast<Dest>(neg), std::range_error);
    }

    // Floating precision loss: convert a high-precision value
    if constexpr (std::is_floating_point_v<Src> && std::is_floating_point_v<Dest>)
    {
        // Use a value that typically loses precision when casting double->float
        Src precise = static_cast<Src>(1.234567890123456789);
        if (static_cast<Dest>(precise) != precise)
        {
            EXPECT_THROW(safe_cast<Dest>(precise), std::range_error);
        }
        else
        {
            EXPECT_EQ(safe_cast<Dest>(precise), static_cast<Dest>(precise));
        }
    }
}

TEST(NumericUtil, Is42)
{
    auto t = safe_cast<short>(static_cast<unsigned char>(42));
    auto u = short(42);
    EXPECT_EQ(t, u);
}

// ---------------------------------------------------------------------------
// can_hold typed tests
// ---------------------------------------------------------------------------

TYPED_TEST(NumericUtilTypedTest, CanHoldBehavior)
{
    using Dest = std::tuple_element_t<0, TypeParam>;
    using Src = std::tuple_element_t<1, TypeParam>;

    // A value that fits in both types should always return true.
    EXPECT_TRUE(can_hold<Dest>(static_cast<Src>(42)));

    // If source max cannot be represented in Dest, can_hold must return false.
    if constexpr (src_max_greater_than_dest<Src, Dest>())
        EXPECT_FALSE(can_hold<Dest>(std::numeric_limits<Src>::max()));

    // If source lowest cannot be represented in Dest, can_hold must return false.
    if constexpr (src_lower_than_dest<Src, Dest>())
        EXPECT_FALSE(can_hold<Dest>(std::numeric_limits<Src>::lowest()));

    // Negative source value into unsigned Dest must always return false.
    if constexpr (std::is_unsigned_v<Dest> && std::is_signed_v<Src>)
        EXPECT_FALSE(can_hold<Dest>(Src(-1)));
}

// ---------------------------------------------------------------------------
// checked_cast typed tests
// ---------------------------------------------------------------------------

TYPED_TEST(NumericUtilTypedTest, CheckedCastBehavior)
{
    using Dest = std::tuple_element_t<0, TypeParam>;
    using Src = std::tuple_element_t<1, TypeParam>;

    // In-range value should produce the correct result.
    auto result = checked_cast<Dest>(static_cast<Src>(42));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, static_cast<Dest>(42));

    // Out-of-range value should produce nullopt.
    if constexpr (src_max_greater_than_dest<Src, Dest>())
    {
        auto bad = checked_cast<Dest>(std::numeric_limits<Src>::max());
        EXPECT_FALSE(bad.has_value());
    }

    if constexpr (std::is_unsigned_v<Dest> && std::is_signed_v<Src>)
    {
        auto neg = checked_cast<Dest>(Src(-1));
        EXPECT_FALSE(neg.has_value());
    }
}

// ---------------------------------------------------------------------------
// would_narrow / can_hold standalone tests (also exercise constexpr paths)
// ---------------------------------------------------------------------------

TEST(NumericUtil, WouldNarrow_IntegralCases)
{
    // ssize_t -> int: large value narrows, small value does not.
    EXPECT_TRUE(would_narrow<int>(static_cast<long long>(std::numeric_limits<int>::max()) + 1));
    EXPECT_FALSE(would_narrow<int>(static_cast<long long>(42)));
    EXPECT_FALSE(would_narrow<int>(static_cast<long long>(-1)));

    // Negative signed -> unsigned.
    EXPECT_TRUE(would_narrow<unsigned int>(-1));
    EXPECT_FALSE(would_narrow<unsigned int>(0u));

    // uint32_t value fitting in uint16_t.
    EXPECT_FALSE(would_narrow<std::uint16_t>(static_cast<std::uint32_t>(0xFFFFu)));
    EXPECT_TRUE(would_narrow<std::uint16_t>(static_cast<std::uint32_t>(0x1'0000u)));
}

TEST(NumericUtil, CheckedCast_StandaloneIntegral)
{
    // Valid cast.
    auto a = checked_cast<int>(42LL);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(*a, 42);

    // ssize_t too large for int.
    auto b = checked_cast<int>(static_cast<long long>(std::numeric_limits<int>::max()) + 1LL);
    EXPECT_FALSE(b.has_value());

    // value_or pattern used in production code.
    int remaining = checked_cast<int>(static_cast<long>(256)).value_or(0);
    EXPECT_EQ(remaining, 256);
}

TEST(NumericUtil, CheckedCast_FloatingPoint)
{
    // Integer exactly representable as float.
    auto exact = checked_cast<float>(3.0);
    ASSERT_TRUE(exact.has_value());
    EXPECT_EQ(*exact, 3.0f);

    // High-precision double loses information in float.
    double precise = 1.234567890123456789;
    if (static_cast<float>(precise) != static_cast<double>(static_cast<float>(precise)))
    {
        auto lossy = checked_cast<float>(precise);
        EXPECT_FALSE(lossy.has_value());
    }
}

// Verify constexpr evaluation compiles.
static_assert(can_hold<int>(42LL), "42LL fits in int");
static_assert(!can_hold<int>(5'000'000'000LL), "5e9 does not fit in int");
static_assert(can_hold<unsigned>(0u), "0u fits in unsigned");
static_assert(!can_hold<unsigned>(-1), "negative does not fit in unsigned");
static_assert(would_narrow<std::uint8_t>(256), "256 narrows into uint8_t");
