// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include "http/http3_connection_handler.h"
#include "http/http3_apirouter.h"
#include "http/http3_async_static_router.h"
#include "quic/quic_ack.h"
#include "quic/quic_congestion.h"
#include "quic/quic_crypto.h"
#include "quic/quic_frame.h"
#include "quic/quic_loss_detection.h"
#include "quic/quic_reliability.h"
#include "quic/quic_tls.h"

using namespace clv::http3;
using namespace clv::quic;
using namespace std::chrono_literals;

// ================================================================================================
// PerLevelState Tests
// ================================================================================================

class PerLevelStateTests : public ::testing::Test
{
  protected:
    PerLevelState state_;
};

TEST_F(PerLevelStateTests, InitialState)
{
    // PerLevelState no longer has ack_gen - it's in AckManager
    EXPECT_EQ(state_.packet_tracker.UnackedCount(), 0u);
    EXPECT_EQ(state_.loss_detector.UnackedCount(), 0u);
    EXPECT_TRUE(state_.pending_retransmits.empty());
}

TEST_F(PerLevelStateTests, PacketTrackerIntegration)
{
    // Simulate sending packets
    for (int i = 0; i < 3; ++i)
    {
        PacketTracker::SentPacket packet;
        packet.packet_number = i;
        packet.sent_time = std::chrono::steady_clock::now();
        packet.bytes_sent = 1200;
        packet.ack_eliciting = true;
        packet.frames.push_back(clv::quic::Frame{CryptoFrame{}});

        state_.packet_tracker.OnPacketSent(packet);
    }

    EXPECT_EQ(state_.packet_tracker.UnackedCount(), 3u);
}

TEST_F(PerLevelStateTests, LossDetectorIntegration)
{
    auto now = std::chrono::steady_clock::now();

    // Send packets
    for (int i = 0; i < 3; ++i)
    {
        SentPacket packet;
        packet.packet_number = i;
        packet.sent_time = now;
        packet.bytes_sent = 1200;
        packet.ack_eliciting = true;
        packet.frames.push_back(clv::quic::Frame{CryptoFrame{}});

        state_.loss_detector.OnPacketSent(packet);
    }

    EXPECT_EQ(state_.loss_detector.UnackedCount(), 3u);
}

TEST_F(PerLevelStateTests, PendingRetransmitsAccumulation)
{
    CryptoFrame crypto_frame;
    crypto_frame.offset = 0;
    crypto_frame.data = {0x01, 0x02, 0x03};

    state_.pending_retransmits.push_back(clv::quic::Frame{crypto_frame});
    state_.pending_retransmits.push_back(clv::quic::Frame{PingFrame{}});

    EXPECT_EQ(state_.pending_retransmits.size(), 2u);
}

// ================================================================================================
// Helper Functions Tests
// ================================================================================================

class ConnectionHandlerHelperTests : public ::testing::Test
{
};

TEST_F(ConnectionHandlerHelperTests, LevelToIndex_Initial)
{
    using TestHandler = ConnectionHandler<ApiRouter, Http3AsyncStaticRouter>;
    EXPECT_EQ(TestHandler::LevelToIndex(EncryptionLevel::Initial), 0u);
}

TEST_F(ConnectionHandlerHelperTests, LevelToIndex_Handshake)
{
    using TestHandler = ConnectionHandler<ApiRouter, Http3AsyncStaticRouter>;
    EXPECT_EQ(TestHandler::LevelToIndex(EncryptionLevel::Handshake), 1u);
}

TEST_F(ConnectionHandlerHelperTests, LevelToIndex_Application)
{
    using TestHandler = ConnectionHandler<ApiRouter, Http3AsyncStaticRouter>;
    EXPECT_EQ(TestHandler::LevelToIndex(EncryptionLevel::Application), 2u);
}

TEST_F(ConnectionHandlerHelperTests, QuicLevelToIndex_Initial)
{
    using TestHandler = ConnectionHandler<ApiRouter, Http3AsyncStaticRouter>;
    EXPECT_EQ(TestHandler::QuicLevelToIndex(QuicEncryptionLevel::Initial), 0u);
}

TEST_F(ConnectionHandlerHelperTests, QuicLevelToIndex_Handshake)
{
    using TestHandler = ConnectionHandler<ApiRouter, Http3AsyncStaticRouter>;
    EXPECT_EQ(TestHandler::QuicLevelToIndex(QuicEncryptionLevel::Handshake), 1u);
}

TEST_F(ConnectionHandlerHelperTests, QuicLevelToIndex_Application)
{
    using TestHandler = ConnectionHandler<ApiRouter, Http3AsyncStaticRouter>;
    EXPECT_EQ(TestHandler::QuicLevelToIndex(QuicEncryptionLevel::Application), 2u);
}

// ================================================================================================
// ACK Processing Integration Tests
// ================================================================================================

class AckProcessingIntegrationTests : public ::testing::Test
{
  protected:
    PerLevelState state_;

    void SetUp() override
    {
        // Send some packets
        for (int i = 0; i < 5; ++i)
        {
            PacketTracker::SentPacket pkt;
            pkt.packet_number = i;
            pkt.sent_time = std::chrono::steady_clock::now();
            pkt.bytes_sent = 1200;
            pkt.ack_eliciting = true;
            pkt.frames.push_back(clv::quic::Frame{CryptoFrame{}});

            state_.packet_tracker.OnPacketSent(pkt);

            SentPacket loss_pkt;
            loss_pkt.packet_number = i;
            loss_pkt.sent_time = pkt.sent_time;
            loss_pkt.bytes_sent = 1200;
            loss_pkt.ack_eliciting = true;
            loss_pkt.frames = pkt.frames;

            state_.loss_detector.OnPacketSent(loss_pkt);
        }
    }
};

TEST_F(AckProcessingIntegrationTests, AckRemovesPacketsFromTracking)
{
    EXPECT_EQ(state_.packet_tracker.UnackedCount(), 5u);
    EXPECT_EQ(state_.loss_detector.UnackedCount(), 5u);

    // ACK packets 0-2
    AckFrame ack;
    ack.largest_acknowledged = 2;
    ack.ack_delay = 0;
    ack.ranges = {{0, 3}}; // (start, length)

    state_.packet_tracker.OnAckReceived(ack);

    // Convert to AckRangeSet for LossDetector
    AckRangeSet ack_ranges;
    for (const auto &[start, length] : ack.ranges)
    {
        if (length > 0)
        {
            ack_ranges.AddRange(start, start + length - 1);
        }
    }

    auto now = std::chrono::steady_clock::now();
    [[maybe_unused]] auto lost_frames = state_.loss_detector.OnAckReceived(
        ack_ranges,
        now,
        std::chrono::microseconds(ack.ack_delay));

    // Should have fewer unacked packets now
    EXPECT_LT(state_.packet_tracker.UnackedCount(), 5u);
    EXPECT_LT(state_.loss_detector.UnackedCount(), 5u);
}

TEST_F(AckProcessingIntegrationTests, GapInAcksTriggersPotentialLoss)
{
    // Send more packets to make the gap more significant for loss detection
    // Loss detection typically requires a threshold (default 3 packet numbers)
    for (int i = 5; i < 10; ++i)
    {
        PacketTracker::SentPacket pkt;
        pkt.packet_number = i;
        pkt.sent_time = std::chrono::steady_clock::now();
        pkt.bytes_sent = 1200;
        pkt.ack_eliciting = true;
        pkt.frames.push_back(clv::quic::Frame{CryptoFrame{}});

        state_.packet_tracker.OnPacketSent(pkt);

        SentPacket loss_pkt;
        loss_pkt.packet_number = i;
        loss_pkt.sent_time = pkt.sent_time;
        loss_pkt.bytes_sent = 1200;
        loss_pkt.ack_eliciting = true;
        loss_pkt.frames = pkt.frames;

        state_.loss_detector.OnPacketSent(loss_pkt);
    }

    // ACK packets 0-1 and 7-9 (gap at 2-6, large enough for loss detection)
    AckFrame ack;
    ack.largest_acknowledged = 9;
    ack.ack_delay = 0;
    ack.ranges = {
        {7, 3}, // packets 7-9
        {0, 2}  // packets 0-1
    };

    AckRangeSet ack_ranges;
    for (const auto &[start, length] : ack.ranges)
    {
        if (length > 0)
        {
            ack_ranges.AddRange(start, start + length - 1);
        }
    }

    auto now = std::chrono::steady_clock::now();
    auto lost_frames = state_.loss_detector.OnAckReceived(
        ack_ranges,
        now,
        std::chrono::microseconds(ack.ack_delay));

    // Gap should trigger loss detection (packets 2-6 are missing and gap > threshold)
    EXPECT_FALSE(lost_frames.empty());
}

// ================================================================================================
// Congestion Control Integration Tests
// ================================================================================================

class CongestionControlIntegrationTests : public ::testing::Test
{
  protected:
    CongestionController congestion_;
};

TEST_F(CongestionControlIntegrationTests, InitialWindowAllowsSends)
{
    EXPECT_TRUE(congestion_.CanSend());
    EXPECT_GT(congestion_.GetCongestionWindow(), 0u);
    EXPECT_EQ(congestion_.GetBytesInFlight(), 0u);
}

TEST_F(CongestionControlIntegrationTests, OnPacketSentIncrementsBytesInFlight)
{
    congestion_.OnPacketSent(1200);
    EXPECT_EQ(congestion_.GetBytesInFlight(), 1200u);

    congestion_.OnPacketSent(1200);
    EXPECT_EQ(congestion_.GetBytesInFlight(), 2400u);
}

TEST_F(CongestionControlIntegrationTests, OnPacketsAckedDecreasesBytesInFlight)
{
    congestion_.OnPacketSent(1200);
    congestion_.OnPacketSent(1200);
    EXPECT_EQ(congestion_.GetBytesInFlight(), 2400u);

    auto now = std::chrono::steady_clock::now();
    congestion_.OnPacketsAcked(1200, now);

    EXPECT_EQ(congestion_.GetBytesInFlight(), 1200u);
}

TEST_F(CongestionControlIntegrationTests, WindowFullBlocksSends)
{
    // Fill the window
    uint64_t cwnd = congestion_.GetCongestionWindow();
    congestion_.OnPacketSent(cwnd);

    EXPECT_FALSE(congestion_.CanSend());
    EXPECT_EQ(congestion_.GetAvailableWindow(), 0u);
}

TEST_F(CongestionControlIntegrationTests, OnPacketsLostReducesWindow)
{
    uint64_t initial_cwnd = congestion_.GetCongestionWindow();

    auto now = std::chrono::steady_clock::now();
    congestion_.OnPacketsLost(1200, 0, now);

    uint64_t new_cwnd = congestion_.GetCongestionWindow();
    EXPECT_LT(new_cwnd, initial_cwnd);
}

TEST_F(CongestionControlIntegrationTests, AckIncreasesWindowInSlowStart)
{
    uint64_t initial_cwnd = congestion_.GetCongestionWindow();
    EXPECT_TRUE(congestion_.InSlowStart());

    auto now = std::chrono::steady_clock::now();
    congestion_.OnPacketSent(1200);
    congestion_.OnPacketsAcked(1200, now);

    uint64_t new_cwnd = congestion_.GetCongestionWindow();
    EXPECT_GT(new_cwnd, initial_cwnd);
}

// ================================================================================================
// Loss Detection Timeout Tests
// ================================================================================================

class LossDetectionTimeoutTests : public ::testing::Test
{
  protected:
    PerLevelState state_;
};

TEST_F(LossDetectionTimeoutTests, TimeoutDetectsLostPackets)
{
    auto past = std::chrono::steady_clock::now() - std::chrono::seconds(2);

    // Send packets in the past
    for (int i = 0; i < 3; ++i)
    {
        SentPacket packet;
        packet.packet_number = i;
        packet.sent_time = past;
        packet.bytes_sent = 1200;
        packet.ack_eliciting = true;

        CryptoFrame crypto;
        crypto.offset = 0;
        crypto.data = {0x01, 0x02, 0x03};
        packet.frames.push_back(clv::quic::Frame{crypto});

        state_.loss_detector.OnPacketSent(packet);
    }

    EXPECT_EQ(state_.loss_detector.UnackedCount(), 3u);

    auto now = std::chrono::steady_clock::now();
    auto lost_frames = state_.loss_detector.CheckForTimeout(now);

    EXPECT_FALSE(lost_frames.empty());
    EXPECT_EQ(state_.loss_detector.UnackedCount(), 0u);
}

TEST_F(LossDetectionTimeoutTests, RecentPacketsNotTimedOut)
{
    auto now = std::chrono::steady_clock::now();

    // Send recent packets
    for (int i = 0; i < 3; ++i)
    {
        SentPacket packet;
        packet.packet_number = i;
        packet.sent_time = now;
        packet.bytes_sent = 1200;
        packet.ack_eliciting = true;
        packet.frames.push_back(clv::quic::Frame{PingFrame{}});

        state_.loss_detector.OnPacketSent(packet);
    }

    auto lost_frames = state_.loss_detector.CheckForTimeout(now);

    EXPECT_TRUE(lost_frames.empty());
    EXPECT_EQ(state_.loss_detector.UnackedCount(), 3u);
}

// ================================================================================================
// Full Integration Scenario Tests
// ================================================================================================

class FullIntegrationTests : public ::testing::Test
{
  protected:
    std::array<PerLevelState, 3> level_state_;
    CongestionController congestion_;

    void SendPacket(std::size_t level_idx, uint64_t packet_number)
    {
        auto &state = level_state_[level_idx];
        auto now = std::chrono::steady_clock::now();

        PacketTracker::SentPacket pkt;
        pkt.packet_number = packet_number;
        pkt.sent_time = now;
        pkt.bytes_sent = 1200;
        pkt.ack_eliciting = true;
        pkt.frames.push_back(clv::quic::Frame{CryptoFrame{}});

        state.packet_tracker.OnPacketSent(pkt);

        SentPacket loss_pkt;
        loss_pkt.packet_number = packet_number;
        loss_pkt.sent_time = now;
        loss_pkt.bytes_sent = 1200;
        loss_pkt.ack_eliciting = true;
        loss_pkt.frames = pkt.frames;

        state.loss_detector.OnPacketSent(loss_pkt);

        congestion_.OnPacketSent(1200);
    }

    void AckPacket(std::size_t level_idx, uint64_t packet_number)
    {
        auto &state = level_state_[level_idx];
        auto now = std::chrono::steady_clock::now();

        // Note: AckGenerator is now in AckManager, not directly in PerLevelState
        // This test focuses on packet tracking and loss detection

        AckFrame ack;
        ack.largest_acknowledged = packet_number;
        ack.ack_delay = 0;
        ack.ranges = {{packet_number, 1}};

        state.packet_tracker.OnAckReceived(ack);

        AckRangeSet ack_ranges;
        ack_ranges.AddRange(packet_number, packet_number);

        [[maybe_unused]] auto lost_frames = state.loss_detector.OnAckReceived(
            ack_ranges,
            now,
            std::chrono::microseconds(ack.ack_delay));

        congestion_.OnPacketsAcked(1200, now);
    }
};

TEST_F(FullIntegrationTests, SendReceiveCycle)
{
    // Send 3 packets on Initial level
    SendPacket(0, 0);
    SendPacket(0, 1);
    SendPacket(0, 2);

    EXPECT_EQ(level_state_[0].packet_tracker.UnackedCount(), 3u);
    EXPECT_EQ(level_state_[0].loss_detector.UnackedCount(), 3u);
    EXPECT_EQ(congestion_.GetBytesInFlight(), 3600u);

    // ACK all packets
    AckPacket(0, 0);
    AckPacket(0, 1);
    AckPacket(0, 2);

    // Verify congestion window reduced after ACKs
    EXPECT_LT(congestion_.GetBytesInFlight(), 3600u);
}

TEST_F(FullIntegrationTests, MultiLevelOperation)
{
    // Send on all three levels
    SendPacket(0, 0); // Initial
    SendPacket(1, 0); // Handshake
    SendPacket(2, 0); // Application

    EXPECT_EQ(level_state_[0].packet_tracker.UnackedCount(), 1u);
    EXPECT_EQ(level_state_[1].packet_tracker.UnackedCount(), 1u);
    EXPECT_EQ(level_state_[2].packet_tracker.UnackedCount(), 1u);
    EXPECT_EQ(congestion_.GetBytesInFlight(), 3600u);

    // ACK on different levels
    AckPacket(0, 0);
    AckPacket(1, 0);
    AckPacket(2, 0);

    // Note: ACK tracking is now in AckManager, not PerLevelState
    // Verify packets were ACKed by checking unacked counts
    EXPECT_EQ(level_state_[0].packet_tracker.UnackedCount(), 0u);
    EXPECT_EQ(level_state_[1].packet_tracker.UnackedCount(), 0u);
    EXPECT_EQ(level_state_[2].packet_tracker.UnackedCount(), 0u);
}

TEST_F(FullIntegrationTests, CongestionWindowLimitsTransmission)
{
    // Fill the congestion window
    uint64_t cwnd = congestion_.GetCongestionWindow();
    uint64_t packets_to_send = (cwnd / 1200) + 1;

    for (uint64_t i = 0; i < packets_to_send; ++i)
    {
        SendPacket(2, i);
    }

    // Should hit congestion window limit
    EXPECT_FALSE(congestion_.CanSend());
}
