#include <gtest/gtest.h>
#include <thread>

#include "quic/quic_congestion.h"

#include "numeric_util.h"

using namespace clv::quic;
using namespace std::chrono_literals;

using clv::safe_cast;

class CongestionControllerTests : public ::testing::Test
{
  protected:
    CongestionConfig config_;

    void SetUp() override
    {
        config_.initial_window = 12000; // 10 packets * 1200 bytes
        config_.minimum_window = 2400;  // 2 packets * 1200 bytes
        config_.loss_reduction_factor = 0.5;
    }
};

TEST_F(CongestionControllerTests, InitialState)
{
    CongestionController cc(config_);

    EXPECT_EQ(cc.GetCongestionWindow(), 12000u);
    EXPECT_EQ(cc.GetBytesInFlight(), 0u);
    EXPECT_EQ(cc.GetSlowStartThreshold(), UINT64_MAX);
    EXPECT_TRUE(cc.CanSend());
    EXPECT_EQ(cc.GetAvailableWindow(), 12000u);
    EXPECT_TRUE(cc.InSlowStart());
}

TEST_F(CongestionControllerTests, OnPacketSent)
{
    CongestionController cc(config_);

    cc.OnPacketSent(1200);
    EXPECT_EQ(cc.GetBytesInFlight(), 1200u);
    EXPECT_TRUE(cc.CanSend());
    EXPECT_EQ(cc.GetAvailableWindow(), 10800u);

    cc.OnPacketSent(1200);
    EXPECT_EQ(cc.GetBytesInFlight(), 2400u);
    EXPECT_EQ(cc.GetAvailableWindow(), 9600u);
}

TEST_F(CongestionControllerTests, CannotSendWhenWindowFull)
{
    CongestionController cc(config_);

    // Fill the window
    for (int i = 0; i < 10; ++i)
    {
        cc.OnPacketSent(1200);
    }

    EXPECT_EQ(cc.GetBytesInFlight(), 12000u);
    EXPECT_FALSE(cc.CanSend());
    EXPECT_EQ(cc.GetAvailableWindow(), 0u);
}

TEST_F(CongestionControllerTests, SlowStartGrowth)
{
    CongestionController cc(config_);
    auto now = std::chrono::steady_clock::now();

    // Send 10 packets (fill initial window)
    for (int i = 0; i < 10; ++i)
    {
        cc.OnPacketSent(1200);
    }

    uint64_t initial_cwnd = cc.GetCongestionWindow();

    // ACK 5 packets - in slow start, cwnd grows by acked bytes
    cc.OnPacketsAcked(6000, now);

    EXPECT_EQ(cc.GetCongestionWindow(), initial_cwnd + 6000);
    EXPECT_EQ(cc.GetBytesInFlight(), 6000u);
    EXPECT_TRUE(cc.InSlowStart());
}

TEST_F(CongestionControllerTests, CongestionAvoidanceGrowth)
{
    CongestionController cc(config_);
    auto now = std::chrono::steady_clock::now();

    // Force into congestion avoidance by setting ssthresh low
    cc.OnPacketSent(1200);
    cc.OnPacketsLost(1200, 1, now);

    // ssthresh should be 12000 * 0.5 = 6000
    EXPECT_EQ(cc.GetSlowStartThreshold(), 6000u);
    EXPECT_EQ(cc.GetCongestionWindow(), 6000u);
    EXPECT_FALSE(cc.InSlowStart());

    // In congestion avoidance, growth is linear
    // Wait to exit recovery period
    std::this_thread::sleep_for(150ms);
    now = std::chrono::steady_clock::now();

    uint64_t cwnd_before = cc.GetCongestionWindow();
    cc.OnPacketSent(1200);
    cc.OnPacketsAcked(1200, now);

    // Growth should be much slower than slow start
    // increase = (1200 * 1200) / 6000 = 240
    EXPECT_GT(cc.GetCongestionWindow(), cwnd_before);
    EXPECT_LT(cc.GetCongestionWindow(), cwnd_before + 1200);
}

TEST_F(CongestionControllerTests, PacketLoss)
{
    CongestionController cc(config_);
    auto now = std::chrono::steady_clock::now();

    // Build up window in slow start
    for (int i = 0; i < 20; ++i)
    {
        cc.OnPacketSent(1200);
        if (i % 5 == 0)
        {
            cc.OnPacketsAcked(1200, now);
        }
    }

    uint64_t cwnd_before = cc.GetCongestionWindow();

    // Lose 2 packets
    cc.OnPacketsLost(2400, 10, now);

    // Should enter recovery and reduce window
    EXPECT_EQ(cc.GetSlowStartThreshold(), safe_cast<uint64_t>(safe_cast<double>(cwnd_before) * 0.5));
    EXPECT_EQ(cc.GetCongestionWindow(), safe_cast<uint64_t>(safe_cast<double>(cwnd_before) * 0.5));
    EXPECT_TRUE(cc.InRecovery(now));
}

TEST_F(CongestionControllerTests, RecoveryPreventsWindowGrowth)
{
    CongestionController cc(config_);
    auto now = std::chrono::steady_clock::now();

    cc.OnPacketSent(1200);
    cc.OnPacketsLost(1200, 1, now);

    uint64_t cwnd_in_recovery = cc.GetCongestionWindow();

    // ACK during recovery should not grow window
    cc.OnPacketSent(1200);
    cc.OnPacketsAcked(1200, now);

    EXPECT_EQ(cc.GetCongestionWindow(), cwnd_in_recovery);
}

TEST_F(CongestionControllerTests, RecoveryExitsAfterTime)
{
    CongestionController cc(config_);
    auto now = std::chrono::steady_clock::now();

    cc.OnPacketSent(1200);
    cc.OnPacketsLost(1200, 1, now);

    EXPECT_TRUE(cc.InRecovery(now));

    // Wait for recovery period (100ms)
    std::this_thread::sleep_for(150ms);
    auto later = std::chrono::steady_clock::now();

    EXPECT_FALSE(cc.InRecovery(later));
}

TEST_F(CongestionControllerTests, MinimumWindowEnforced)
{
    CongestionController cc(config_);
    auto now = std::chrono::steady_clock::now();

    // Force window below minimum
    cc.OnPacketSent(1200);
    config_.loss_reduction_factor = 0.1; // Very aggressive reduction
    cc.SetConfig(config_);
    cc.OnPacketsLost(1200, 1, now);

    // Should not go below minimum
    EXPECT_GE(cc.GetCongestionWindow(), config_.minimum_window);
}

TEST_F(CongestionControllerTests, PersistentCongestion)
{
    CongestionController cc(config_);
    auto now = std::chrono::steady_clock::now();

    // Build up window
    for (int i = 0; i < 20; ++i)
    {
        cc.OnPacketSent(1200);
        if (i % 2 == 0)
        {
            cc.OnPacketsAcked(1200, now);
        }
    }

    EXPECT_GT(cc.GetCongestionWindow(), config_.minimum_window);

    // Persistent congestion resets to minimum
    cc.OnPersistentCongestion();

    EXPECT_EQ(cc.GetCongestionWindow(), config_.minimum_window);
    EXPECT_FALSE(cc.InRecovery(now));
}

TEST_F(CongestionControllerTests, MaximumWindowEnforced)
{
    CongestionConfig small_config = config_;
    small_config.maximum_window = 20000;
    CongestionController cc(small_config);
    auto now = std::chrono::steady_clock::now();

    // Try to grow beyond maximum
    for (int i = 0; i < 100; ++i)
    {
        cc.OnPacketSent(1200);
        cc.OnPacketsAcked(1200, now);
    }

    EXPECT_LE(cc.GetCongestionWindow(), small_config.maximum_window);
}

TEST_F(CongestionControllerTests, BytesInFlightTracking)
{
    CongestionController cc(config_);
    auto now = std::chrono::steady_clock::now();

    // Send 5 packets
    for (int i = 0; i < 5; ++i)
    {
        cc.OnPacketSent(1200);
    }
    EXPECT_EQ(cc.GetBytesInFlight(), 6000u);

    // ACK 3 packets
    cc.OnPacketsAcked(3600, now);
    EXPECT_EQ(cc.GetBytesInFlight(), 2400u);

    // Lose 2 packets
    cc.OnPacketsLost(2400, 5, now);
    EXPECT_EQ(cc.GetBytesInFlight(), 0u);
}

TEST_F(CongestionControllerTests, Reset)
{
    CongestionController cc(config_);
    auto now = std::chrono::steady_clock::now();

    // Modify state
    cc.OnPacketSent(5000);
    cc.OnPacketsLost(1000, 1, now);

    EXPECT_NE(cc.GetCongestionWindow(), config_.initial_window);
    EXPECT_NE(cc.GetBytesInFlight(), 0u);

    // Reset should restore initial state
    cc.Reset();

    EXPECT_EQ(cc.GetCongestionWindow(), config_.initial_window);
    EXPECT_EQ(cc.GetBytesInFlight(), 0u);
    EXPECT_EQ(cc.GetSlowStartThreshold(), UINT64_MAX);
    EXPECT_TRUE(cc.InSlowStart());
}

TEST_F(CongestionControllerTests, MultiplePacketsSentAndAcked)
{
    CongestionController cc(config_);
    auto now = std::chrono::steady_clock::now();

    // Simulate burst of sends
    uint64_t total_sent = 0;
    for (int i = 0; i < 8; ++i)
    {
        cc.OnPacketSent(1200);
        total_sent += 1200;
    }

    EXPECT_EQ(cc.GetBytesInFlight(), total_sent);

    // ACK half
    cc.OnPacketsAcked(4800, now);

    EXPECT_EQ(cc.GetBytesInFlight(), 4800u);
    // In slow start, window grows by acked amount
    EXPECT_EQ(cc.GetCongestionWindow(), config_.initial_window + 4800);
}

TEST_F(CongestionControllerTests, LossDoesNotAffectRecoveryTwice)
{
    CongestionController cc(config_);
    auto now = std::chrono::steady_clock::now();

    cc.OnPacketSent(1200);
    cc.OnPacketsLost(1200, 1, now);

    uint64_t cwnd_after_first_loss = cc.GetCongestionWindow();

    // Second loss during recovery should not further reduce
    cc.OnPacketSent(1200);
    cc.OnPacketsLost(1200, 2, now);

    EXPECT_EQ(cc.GetCongestionWindow(), cwnd_after_first_loss);
}
