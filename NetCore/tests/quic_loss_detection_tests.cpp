// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "quic/quic_loss_detection.h"
#include "quic/quic_ack.h"

#include <gtest/gtest.h>
#include <thread>

using namespace clv::quic;

// ================================================================================================
// Loss Detection Tests
// ================================================================================================

TEST(LossDetectorTests, InitialState)
{
    LossDetector detector;

    EXPECT_EQ(detector.GetLargestAcked(), 0u);
    EXPECT_EQ(detector.UnackedCount(), 0u);
    EXPECT_GT(detector.GetSmoothedRtt().count(), 0);
}

TEST(LossDetectorTests, OnPacketSent)
{
    LossDetector detector;

    SentPacket packet;
    packet.packet_number = 1;
    packet.sent_time = std::chrono::steady_clock::now();
    packet.ack_eliciting = true;
    packet.bytes_sent = 1200;

    detector.OnPacketSent(std::move(packet));

    EXPECT_EQ(detector.UnackedCount(), 1u);
}

TEST(LossDetectorTests, OnAckReceived_SinglePacket)
{
    LossDetector detector;

    // Send packet 1
    SentPacket packet;
    packet.packet_number = 1;
    packet.sent_time = std::chrono::steady_clock::now();
    packet.ack_eliciting = true;
    detector.OnPacketSent(std::move(packet));

    EXPECT_EQ(detector.UnackedCount(), 1u);

    // ACK packet 1
    AckRangeSet ack_ranges;
    ack_ranges.AddPacketNumber(1);

    auto now = std::chrono::steady_clock::now();
    auto lost_frames = detector.OnAckReceived(ack_ranges, now, std::chrono::microseconds{0});

    EXPECT_TRUE(lost_frames.empty());
    EXPECT_EQ(detector.UnackedCount(), 0u);
    EXPECT_EQ(detector.GetLargestAcked(), 1u);
}

TEST(LossDetectorTests, OnAckReceived_MultiplePackets)
{
    LossDetector detector;

    // Send packets 1, 2, 3
    for (std::uint64_t pn = 1; pn <= 3; ++pn)
    {
        SentPacket packet;
        packet.packet_number = pn;
        packet.sent_time = std::chrono::steady_clock::now();
        packet.ack_eliciting = true;
        detector.OnPacketSent(std::move(packet));
    }

    EXPECT_EQ(detector.UnackedCount(), 3u);

    // ACK packets 1, 2, 3
    AckRangeSet ack_ranges;
    ack_ranges.AddRange(1, 3);

    auto now = std::chrono::steady_clock::now();
    auto lost_frames = detector.OnAckReceived(ack_ranges, now, std::chrono::microseconds{0});

    EXPECT_TRUE(lost_frames.empty());
    EXPECT_EQ(detector.UnackedCount(), 0u);
    EXPECT_EQ(detector.GetLargestAcked(), 3u);
}

TEST(LossDetectorTests, PacketThresholdLoss)
{
    LossDetectionConfig config;
    config.packet_threshold = 3;
    LossDetector detector(config);

    // Send packets 1-10
    for (std::uint64_t pn = 1; pn <= 10; ++pn)
    {
        SentPacket packet;
        packet.packet_number = pn;
        packet.sent_time = std::chrono::steady_clock::now();
        packet.ack_eliciting = true;

        // Add a CRYPTO frame to make it retransmittable
        CryptoFrame crypto;
        crypto.offset = 0;
        crypto.data = {0x01, 0x02, 0x03};
        packet.frames.push_back(crypto);

        detector.OnPacketSent(std::move(packet));
    }

    EXPECT_EQ(detector.UnackedCount(), 10u);

    // ACK packets 5-10 (leaving 1-4 unacked)
    AckRangeSet ack_ranges;
    ack_ranges.AddRange(5, 10);

    auto now = std::chrono::steady_clock::now();
    auto lost_frames = detector.OnAckReceived(ack_ranges, now, std::chrono::microseconds{0});

    // Packets 1-4 remain unacked, but with largest_acked=10 and threshold=3,
    // loss_threshold = 10 - 3 = 7, so packets ≤7 are lost (which is 1-4)
    EXPECT_FALSE(lost_frames.empty());
    EXPECT_EQ(detector.GetLargestAcked(), 10u);

    // All packets 1-4 should be declared lost since they're all ≤7
    EXPECT_EQ(detector.UnackedCount(), 0u);
}

TEST(LossDetectorTests, TimeThresholdLoss)
{
    LossDetectionConfig config;
    config.initial_rtt = std::chrono::milliseconds{100};
    config.time_threshold = 1.25; // Loss after 125ms
    LossDetector detector(config);

    auto base_time = std::chrono::steady_clock::now();

    // Send packets with delays
    for (std::uint64_t pn = 1; pn <= 5; ++pn)
    {
        SentPacket packet;
        packet.packet_number = pn;
        packet.sent_time = base_time + std::chrono::milliseconds{pn * 10};
        packet.ack_eliciting = true;

        CryptoFrame crypto;
        crypto.offset = 0;
        crypto.data = {0x01};
        packet.frames.push_back(crypto);

        detector.OnPacketSent(std::move(packet));
    }

    // Wait long enough for time threshold
    std::this_thread::sleep_for(std::chrono::milliseconds{150});

    // ACK packet 5 only
    AckRangeSet ack_ranges;
    ack_ranges.AddPacketNumber(5);

    auto now = std::chrono::steady_clock::now();
    auto lost_frames = detector.OnAckReceived(ack_ranges, now, std::chrono::microseconds{0});

    // Packets 1-4 should be declared lost due to time threshold
    EXPECT_FALSE(lost_frames.empty());
}

TEST(LossDetectorTests, RttUpdate)
{
    LossDetector detector;

    auto send_time = std::chrono::steady_clock::now();

    SentPacket packet;
    packet.packet_number = 1;
    packet.sent_time = send_time;
    packet.ack_eliciting = true;
    detector.OnPacketSent(std::move(packet));

    // Simulate 50ms RTT
    std::this_thread::sleep_for(std::chrono::milliseconds{50});

    AckRangeSet ack_ranges;
    ack_ranges.AddPacketNumber(1);

    auto ack_time = std::chrono::steady_clock::now();
    [[maybe_unused]] auto lost_frames = detector.OnAckReceived(ack_ranges, ack_time, std::chrono::microseconds{0});

    // RTT should be updated (approximately 50ms, allowing some variance)
    auto rtt = detector.GetLatestRtt();
    EXPECT_GT(rtt.count(), 40);  // At least 40ms
    EXPECT_LT(rtt.count(), 100); // Less than 100ms
}

TEST(LossDetectorTests, ProbeTimeout)
{
    LossDetectionConfig config;
    config.initial_rtt = std::chrono::milliseconds{50};
    LossDetector detector(config);

    auto base_time = std::chrono::steady_clock::now();

    SentPacket packet;
    packet.packet_number = 1;
    packet.sent_time = base_time;
    packet.ack_eliciting = true;

    CryptoFrame crypto;
    crypto.offset = 0;
    crypto.data = {0x01, 0x02};
    packet.frames.push_back(crypto);

    detector.OnPacketSent(std::move(packet));

    // Wait beyond PTO
    std::this_thread::sleep_for(std::chrono::milliseconds{200});

    auto now = std::chrono::steady_clock::now();
    auto lost_frames = detector.CheckForTimeout(now);

    // Packet should be declared lost due to timeout
    EXPECT_FALSE(lost_frames.empty());
    EXPECT_EQ(detector.UnackedCount(), 0u);
}

TEST(LossDetectorTests, OnlyRetransmittableFramesReturned)
{
    LossDetector detector;

    SentPacket packet;
    packet.packet_number = 1;
    packet.sent_time = std::chrono::steady_clock::now();
    packet.ack_eliciting = true;

    // Add retransmittable frame (CRYPTO)
    CryptoFrame crypto;
    crypto.offset = 0;
    crypto.data = {0x01, 0x02};
    packet.frames.push_back(crypto);

    // Add non-retransmittable frame (PING)
    packet.frames.push_back(PingFrame{});

    detector.OnPacketSent(std::move(packet));

    // Force loss by acking much later packet
    AckRangeSet ack_ranges;
    ack_ranges.AddPacketNumber(10);

    auto now = std::chrono::steady_clock::now();
    auto lost_frames = detector.OnAckReceived(ack_ranges, now, std::chrono::microseconds{0});

    // Should only have the CRYPTO frame, not PING
    EXPECT_EQ(lost_frames.size(), 1u);
    EXPECT_TRUE(std::holds_alternative<CryptoFrame>(lost_frames[0]));
}

TEST(LossDetectorTests, AckDelayHandling)
{
    LossDetector detector;

    auto send_time = std::chrono::steady_clock::now();

    SentPacket packet;
    packet.packet_number = 1;
    packet.sent_time = send_time;
    packet.ack_eliciting = true;
    detector.OnPacketSent(std::move(packet));

    std::this_thread::sleep_for(std::chrono::milliseconds{60});

    AckRangeSet ack_ranges;
    ack_ranges.AddPacketNumber(1);

    auto ack_time = std::chrono::steady_clock::now();

    // Peer reports 10ms ack_delay
    auto lost_frames = detector.OnAckReceived(
        ack_ranges,
        ack_time,
        std::chrono::microseconds{10000});

    // RTT should account for ack_delay
    auto rtt = detector.GetLatestRtt();
    EXPECT_GT(rtt.count(), 40); // At least 40ms
    EXPECT_LT(rtt.count(), 70); // Should be less than measured time
}

TEST(LossDetectorTests, NoLossOnInOrderAcks)
{
    LossDetector detector;

    // Send packets 1-5
    for (std::uint64_t pn = 1; pn <= 5; ++pn)
    {
        SentPacket packet;
        packet.packet_number = pn;
        packet.sent_time = std::chrono::steady_clock::now();
        packet.ack_eliciting = true;

        CryptoFrame crypto;
        crypto.data = {0x01};
        packet.frames.push_back(crypto);

        detector.OnPacketSent(std::move(packet));
    }

    // ACK them in order: 1, then 2, then 3, etc.
    for (std::uint64_t pn = 1; pn <= 5; ++pn)
    {
        AckRangeSet ack_ranges;
        ack_ranges.AddRange(1, pn);

        auto now = std::chrono::steady_clock::now();
        auto lost_frames = detector.OnAckReceived(ack_ranges, now, std::chrono::microseconds{0});

        EXPECT_TRUE(lost_frames.empty()) << "No loss should occur with in-order ACKs";
    }

    EXPECT_EQ(detector.UnackedCount(), 0u);
}
