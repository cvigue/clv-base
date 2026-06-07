// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include "rate_limiter.h"

#include <gtest/gtest.h>

#include <chrono>

using clv::RateLimiter;

// ============================================================================
// RateLimiter tests
// ============================================================================

TEST(RateLimiterTest, Due_FirstCallReturnsTrue)
{
    RateLimiter<> limiter;
    auto now = std::chrono::steady_clock::now();
    EXPECT_TRUE(limiter.Due(now));
}

TEST(RateLimiterTest, Due_SecondCallWithinInterval_ReturnsFalse)
{
    RateLimiter<> limiter;
    auto now = std::chrono::steady_clock::now();

    EXPECT_TRUE(limiter.Due(now));
    EXPECT_FALSE(limiter.Due(now));
}

TEST(RateLimiterTest, Due_AfterInterval_ReturnsTrue)
{
    RateLimiter<> limiter;
    auto t0 = std::chrono::steady_clock::now();
    limiter.Due(t0);

    auto t1 = t0 + std::chrono::seconds{2};
    EXPECT_TRUE(limiter.Due(t1));
}

TEST(RateLimiterTest, Due_CustomInterval)
{
    RateLimiter<> limiter{std::chrono::seconds{5}};
    auto t0 = std::chrono::steady_clock::now();

    EXPECT_TRUE(limiter.Due(t0));

    // 3 seconds later — still within 5s interval
    auto t1 = t0 + std::chrono::seconds{3};
    EXPECT_FALSE(limiter.Due(t1));

    // 6 seconds after initial — past the 5s interval
    auto t2 = t0 + std::chrono::seconds{6};
    EXPECT_TRUE(limiter.Due(t2));
}

TEST(RateLimiterTest, Due_OverrideInterval)
{
    RateLimiter<> limiter{std::chrono::seconds{10}};
    auto t0 = std::chrono::steady_clock::now();

    EXPECT_TRUE(limiter.Due(t0));

    // Use a shorter override interval
    auto t1 = t0 + std::chrono::seconds{2};
    EXPECT_TRUE(limiter.Due(t1, std::chrono::seconds{1}));

    // Default interval still at 10s — should fail at 3s since last was 2s
    auto t2 = t0 + std::chrono::seconds{3};
    EXPECT_FALSE(limiter.Due(t2));
}

TEST(RateLimiterTest, Due_RepeatedCalls_ResetsTimestamp)
{
    RateLimiter<> limiter{std::chrono::seconds{1}};
    auto t0 = std::chrono::steady_clock::now();

    EXPECT_TRUE(limiter.Due(t0));

    auto t1 = t0 + std::chrono::seconds{2};
    EXPECT_TRUE(limiter.Due(t1));

    // 0.5s after t1 — within interval from t1
    auto t2 = t1 + std::chrono::milliseconds{500};
    EXPECT_FALSE(limiter.Due(t2));

    // 1.5s after t1 — past interval from t1
    auto t3 = t1 + std::chrono::milliseconds{1500};
    EXPECT_TRUE(limiter.Due(t3));
}

TEST(RateLimiterTest, SuppressedCount)
{
    RateLimiter<> limiter{std::chrono::seconds{1}};
    auto t0 = std::chrono::steady_clock::now();

    EXPECT_TRUE(limiter.Due(t0));
    EXPECT_FALSE(limiter.Due(t0));
    EXPECT_FALSE(limiter.Due(t0));

    EXPECT_EQ(limiter.SuppressedCount(), 2);
    EXPECT_EQ(limiter.SuppressedCount(), 0); // count resets after retrieval
}