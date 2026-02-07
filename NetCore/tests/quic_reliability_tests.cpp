#include <gtest/gtest.h>
#include <thread>
#include "quic/quic_reliability.h"

using namespace clv::quic;
using namespace std::chrono_literals;

// ================================================================================================
// PacketTracker Tests
// ================================================================================================

class PacketTrackerTests : public ::testing::Test
{
  protected:
    PacketTracker tracker_;
};

TEST_F(PacketTrackerTests, InitialState)
{
    EXPECT_EQ(tracker_.NextPacketNumber(), 0u);
    EXPECT_EQ(tracker_.LargestAcked(), 0u);
    EXPECT_EQ(tracker_.UnackedCount(), 0u);
}

TEST_F(PacketTrackerTests, NextPacketNumberIncrements)
{
    EXPECT_EQ(tracker_.NextPacketNumber(), 0u);
    EXPECT_EQ(tracker_.NextPacketNumber(), 1u);
    EXPECT_EQ(tracker_.NextPacketNumber(), 2u);
}

TEST_F(PacketTrackerTests, OnPacketSent)
{
    PacketTracker::SentPacket packet;
    packet.packet_number = tracker_.NextPacketNumber();
    packet.frames = {PingFrame{}};
    packet.sent_time = std::chrono::steady_clock::now();
    packet.bytes_sent = 100;
    packet.ack_eliciting = true;

    tracker_.OnPacketSent(packet);

    EXPECT_EQ(tracker_.UnackedCount(), 1u);
}

TEST_F(PacketTrackerTests, OnPacketSent_MultiplePackets)
{
    for (int i = 0; i < 5; ++i)
    {
        PacketTracker::SentPacket packet;
        packet.packet_number = tracker_.NextPacketNumber();
        packet.frames = {PingFrame{}};
        packet.sent_time = std::chrono::steady_clock::now();
        packet.bytes_sent = 100;
        packet.ack_eliciting = true;

        tracker_.OnPacketSent(packet);
    }

    EXPECT_EQ(tracker_.UnackedCount(), 5u);
}

TEST_F(PacketTrackerTests, OnAckReceived_SinglePacket)
{
    // Send packet 0
    PacketTracker::SentPacket packet;
    packet.packet_number = tracker_.NextPacketNumber();
    packet.frames = {PingFrame{}};
    packet.sent_time = std::chrono::steady_clock::now();
    packet.bytes_sent = 100;
    packet.ack_eliciting = true;
    tracker_.OnPacketSent(packet);

    // ACK packet 0
    AckFrame ack;
    ack.largest_acknowledged = 0;
    ack.ack_delay = 0;
    ack.ranges = {{0, 1}}; // Range [0, 0]

    auto lost = tracker_.OnAckReceived(ack);

    EXPECT_TRUE(lost.empty());
    EXPECT_EQ(tracker_.UnackedCount(), 0u);
    EXPECT_EQ(tracker_.LargestAcked(), 0u);
}

TEST_F(PacketTrackerTests, OnAckReceived_MultiplePackets)
{
    // Send packets 0-4
    for (int i = 0; i < 5; ++i)
    {
        PacketTracker::SentPacket packet;
        packet.packet_number = tracker_.NextPacketNumber();
        packet.frames = {PingFrame{}};
        packet.sent_time = std::chrono::steady_clock::now();
        packet.bytes_sent = 100;
        packet.ack_eliciting = true;
        tracker_.OnPacketSent(packet);
    }

    // ACK packets 0-2
    AckFrame ack;
    ack.largest_acknowledged = 2;
    ack.ack_delay = 0;
    ack.ranges = {{0, 3}}; // Range [0, 2]

    auto lost = tracker_.OnAckReceived(ack);

    EXPECT_TRUE(lost.empty());
    EXPECT_EQ(tracker_.UnackedCount(), 2u); // Packets 3, 4 remain
    EXPECT_EQ(tracker_.LargestAcked(), 2u);
}

TEST_F(PacketTrackerTests, OnAckReceived_WithGaps)
{
    // Send packets 0-9
    for (int i = 0; i < 10; ++i)
    {
        PacketTracker::SentPacket packet;
        packet.packet_number = tracker_.NextPacketNumber();
        packet.frames = {PingFrame{}};
        packet.sent_time = std::chrono::steady_clock::now();
        packet.bytes_sent = 100;
        packet.ack_eliciting = true;
        tracker_.OnPacketSent(packet);
    }

    // ACK packets 0-2, 5-7 (gaps at 3-4, 8-9)
    AckFrame ack;
    ack.largest_acknowledged = 7;
    ack.ack_delay = 0;
    ack.ranges = {{5, 3}, {0, 3}}; // Ranges [5,7] and [0,2]

    auto lost = tracker_.OnAckReceived(ack);

    EXPECT_TRUE(lost.empty());
    EXPECT_EQ(tracker_.UnackedCount(), 4u); // Packets 3, 4, 8, 9 remain
    EXPECT_EQ(tracker_.LargestAcked(), 7u);
}

TEST_F(PacketTrackerTests, CheckForLoss_Timeout)
{
    // Send packet 0
    PacketTracker::SentPacket packet;
    packet.packet_number = tracker_.NextPacketNumber();
    packet.frames = {StreamFrame{1, 0, false, std::vector<uint8_t>{1, 2, 3}}};
    packet.sent_time = std::chrono::steady_clock::now() - 200ms; // Old packet
    packet.bytes_sent = 100;
    packet.ack_eliciting = true;
    tracker_.OnPacketSent(packet);

    // Check for loss with 100ms timeout
    auto lost = tracker_.CheckForLoss(100ms);

    EXPECT_EQ(lost.size(), 1u);
    EXPECT_EQ(tracker_.UnackedCount(), 0u); // Packet removed

    // Verify it's a STREAM frame
    ASSERT_TRUE(std::holds_alternative<StreamFrame>(lost[0]));
}

TEST_F(PacketTrackerTests, CheckForLoss_NoTimeout)
{
    // Send recent packet
    PacketTracker::SentPacket packet;
    packet.packet_number = tracker_.NextPacketNumber();
    packet.frames = {StreamFrame{1, 0, false, std::vector<uint8_t>{1, 2, 3}}};
    packet.sent_time = std::chrono::steady_clock::now();
    packet.bytes_sent = 100;
    packet.ack_eliciting = true;
    tracker_.OnPacketSent(packet);

    // Check for loss with 100ms timeout (packet is fresh)
    auto lost = tracker_.CheckForLoss(100ms);

    EXPECT_TRUE(lost.empty());
    EXPECT_EQ(tracker_.UnackedCount(), 1u); // Packet still there
}

TEST_F(PacketTrackerTests, CheckForLoss_OnlyRetransmittableFrames)
{
    // Send packet with PING (not retransmittable)
    PacketTracker::SentPacket packet1;
    packet1.packet_number = tracker_.NextPacketNumber();
    packet1.frames = {PingFrame{}};
    packet1.sent_time = std::chrono::steady_clock::now() - 200ms;
    packet1.bytes_sent = 50;
    packet1.ack_eliciting = true;
    tracker_.OnPacketSent(packet1);

    // Send packet with STREAM (retransmittable)
    PacketTracker::SentPacket packet2;
    packet2.packet_number = tracker_.NextPacketNumber();
    packet2.frames = {StreamFrame{1, 0, false, std::vector<uint8_t>{1, 2, 3}}};
    packet2.sent_time = std::chrono::steady_clock::now() - 200ms;
    packet2.bytes_sent = 100;
    packet2.ack_eliciting = true;
    tracker_.OnPacketSent(packet2);

    // Check for loss
    auto lost = tracker_.CheckForLoss(100ms);

    // Only STREAM frame should be in lost list
    EXPECT_EQ(lost.size(), 1u);
    ASSERT_TRUE(std::holds_alternative<StreamFrame>(lost[0]));
}

TEST_F(PacketTrackerTests, CheckForLoss_CryptoFrameRetransmitted)
{
    // Send packet with CRYPTO frame
    PacketTracker::SentPacket packet;
    packet.packet_number = tracker_.NextPacketNumber();
    packet.frames = {CryptoFrame{0, std::vector<uint8_t>{1, 2, 3, 4}}};
    packet.sent_time = std::chrono::steady_clock::now() - 200ms;
    packet.bytes_sent = 100;
    packet.ack_eliciting = true;
    tracker_.OnPacketSent(packet);

    // Check for loss
    auto lost = tracker_.CheckForLoss(100ms);

    EXPECT_EQ(lost.size(), 1u);
    ASSERT_TRUE(std::holds_alternative<CryptoFrame>(lost[0]));
}

// ================================================================================================
// AckGenerator Tests
// ================================================================================================

class AckGeneratorTests : public ::testing::Test
{
  protected:
    AckGenerator generator_;
};

TEST_F(AckGeneratorTests, InitialState)
{
    EXPECT_EQ(generator_.LargestReceived(), 0u);
    EXPECT_FALSE(generator_.ShouldSendAck()); // No packets received yet
}

TEST_F(AckGeneratorTests, OnPacketReceived_Single)
{
    generator_.OnPacketReceived(5);

    EXPECT_EQ(generator_.LargestReceived(), 5u);
}

TEST_F(AckGeneratorTests, OnPacketReceived_UpdatesLargest)
{
    generator_.OnPacketReceived(3);
    EXPECT_EQ(generator_.LargestReceived(), 3u);

    generator_.OnPacketReceived(7);
    EXPECT_EQ(generator_.LargestReceived(), 7u);

    generator_.OnPacketReceived(5); // Out of order, doesn't change largest
    EXPECT_EQ(generator_.LargestReceived(), 7u);
}

TEST_F(AckGeneratorTests, OnPacketReceived_DuplicateIgnored)
{
    generator_.OnPacketReceived(5);
    generator_.OnPacketReceived(5); // Duplicate

    auto ack = generator_.GenerateAck();

    // Should only have one packet
    EXPECT_EQ(ack.largest_acknowledged, 5u);
    EXPECT_EQ(ack.ranges.size(), 1u);
    EXPECT_EQ(ack.ranges[0].first, 5u);
    EXPECT_EQ(ack.ranges[0].second, 1u);
}

TEST_F(AckGeneratorTests, GenerateAck_SinglePacket)
{
    generator_.OnPacketReceived(10);

    auto ack = generator_.GenerateAck();

    EXPECT_EQ(ack.largest_acknowledged, 10u);
    EXPECT_EQ(ack.ranges.size(), 1u);
    EXPECT_EQ(ack.ranges[0].first, 10u);
    EXPECT_EQ(ack.ranges[0].second, 1u); // One packet
}

TEST_F(AckGeneratorTests, GenerateAck_ContiguousRange)
{
    generator_.OnPacketReceived(5);
    generator_.OnPacketReceived(6);
    generator_.OnPacketReceived(7);
    generator_.OnPacketReceived(8);

    auto ack = generator_.GenerateAck();

    EXPECT_EQ(ack.largest_acknowledged, 8u);
    EXPECT_EQ(ack.ranges.size(), 1u);
    EXPECT_EQ(ack.ranges[0].first, 5u);
    EXPECT_EQ(ack.ranges[0].second, 4u); // 4 packets [5,8]
}

TEST_F(AckGeneratorTests, GenerateAck_WithGaps)
{
    generator_.OnPacketReceived(1);
    generator_.OnPacketReceived(2);
    generator_.OnPacketReceived(5);
    generator_.OnPacketReceived(6);
    generator_.OnPacketReceived(10);

    auto ack = generator_.GenerateAck();

    EXPECT_EQ(ack.largest_acknowledged, 10u);
    EXPECT_EQ(ack.ranges.size(), 3u);

    // Ranges should be in descending order
    EXPECT_EQ(ack.ranges[0].first, 10u);
    EXPECT_EQ(ack.ranges[0].second, 1u);

    EXPECT_EQ(ack.ranges[1].first, 5u);
    EXPECT_EQ(ack.ranges[1].second, 2u); // [5,6]

    EXPECT_EQ(ack.ranges[2].first, 1u);
    EXPECT_EQ(ack.ranges[2].second, 2u); // [1,2]
}

TEST_F(AckGeneratorTests, GenerateAck_OutOfOrderReceive)
{
    generator_.OnPacketReceived(7);
    generator_.OnPacketReceived(3);
    generator_.OnPacketReceived(5);
    generator_.OnPacketReceived(6);
    generator_.OnPacketReceived(4);

    auto ack = generator_.GenerateAck();

    EXPECT_EQ(ack.largest_acknowledged, 7u);
    EXPECT_EQ(ack.ranges.size(), 1u);
    EXPECT_EQ(ack.ranges[0].first, 3u);
    EXPECT_EQ(ack.ranges[0].second, 5u); // [3,7]
}

TEST_F(AckGeneratorTests, ShouldSendAck_AfterThreshold)
{
    generator_.OnPacketReceived(1);
    // After 1 packet, might not trigger yet (threshold is 2)

    generator_.OnPacketReceived(2);
    // After 2 packets, should trigger
    EXPECT_TRUE(generator_.ShouldSendAck());
}

TEST_F(AckGeneratorTests, ShouldSendAck_AfterTimeout)
{
    generator_.OnPacketReceived(1);

    // Wait longer than 25ms
    std::this_thread::sleep_for(30ms);

    EXPECT_TRUE(generator_.ShouldSendAck());
}

TEST_F(AckGeneratorTests, ShouldSendAck_ResetsAfterGenerate)
{
    generator_.OnPacketReceived(1);
    generator_.OnPacketReceived(2);

    EXPECT_TRUE(generator_.ShouldSendAck());

    // Generate ACK (resets counter)
    [[maybe_unused]] auto ack = generator_.GenerateAck();

    EXPECT_FALSE(generator_.ShouldSendAck());
}

// ================================================================================================
// Integration Tests
// ================================================================================================

TEST(ReliabilityIntegrationTests, SendAckRetransmitWorkflow)
{
    PacketTracker sender;
    AckGenerator receiver;

    // Sender sends packets 0-4
    for (int i = 0; i < 5; ++i)
    {
        PacketTracker::SentPacket packet;
        packet.packet_number = sender.NextPacketNumber();
        packet.frames = {StreamFrame{1, static_cast<uint64_t>(i * 100), false, std::vector<uint8_t>(100, static_cast<uint8_t>(i))}};
        packet.sent_time = std::chrono::steady_clock::now();
        packet.bytes_sent = 100;
        packet.ack_eliciting = true;
        sender.OnPacketSent(packet);
    }

    EXPECT_EQ(sender.UnackedCount(), 5u);

    // Receiver gets packets 0, 1, 3, 4 (missing 2)
    receiver.OnPacketReceived(0);
    receiver.OnPacketReceived(1);
    receiver.OnPacketReceived(3);
    receiver.OnPacketReceived(4);

    // Generate ACK
    auto ack = receiver.GenerateAck();

    EXPECT_EQ(ack.largest_acknowledged, 4u);
    EXPECT_EQ(ack.ranges.size(), 2u); // [3,4] and [0,1]

    // Sender processes ACK
    auto lost = sender.OnAckReceived(ack);

    EXPECT_EQ(sender.UnackedCount(), 1u); // Packet 2 remains
    EXPECT_EQ(sender.LargestAcked(), 4u);
}
