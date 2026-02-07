// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <vector>
#include <variant>

#include "quic_frame.h"
#include "quic_types.h"

namespace clv::quic {

/// Tracks sent packets awaiting acknowledgement
struct PacketTracker
{
    /// Backward-compatible alias for the shared SentPacket type
    using SentPacket = ::clv::quic::SentPacket;

    /// Record a sent packet
    void OnPacketSent(SentPacket packet);

    /// Process received ACK frame
    /// Returns frames that were lost and need retransmission
    std::vector<Frame> OnAckReceived(const AckFrame &ack);

    /// Check for timeout-based loss
    /// Returns frames that need retransmission
    std::vector<Frame> CheckForLoss(std::chrono::milliseconds timeout);

    /// Get next packet number
    [[nodiscard]] std::uint64_t NextPacketNumber() noexcept;

    /// Get the largest acknowledged packet number
    [[nodiscard]] std::uint64_t LargestAcked() const noexcept;

    /// Get count of unacked packets
    [[nodiscard]] std::size_t UnackedCount() const noexcept;

  private:
    std::deque<SentPacket> mUnackedPackets{};
    std::uint64_t mNextPacketNumber{0};
    std::uint64_t mLargestAcked{0};
};

/// Tracks received packets for generating ACKs
struct AckGenerator
{
    /// Record a received packet
    void OnPacketReceived(std::uint64_t packet_number);

    /// Generate ACK frame for received packets
    [[nodiscard]] AckFrame GenerateAck() noexcept;

    /// Should we send an ACK now?
    /// Simple heuristic: send after receiving a certain number of packets
    [[nodiscard]] bool ShouldSendAck() const noexcept;

    /// Get the largest received packet number
    [[nodiscard]] std::uint64_t LargestReceived() const noexcept;

  private:
    std::vector<std::uint64_t> mReceivedPackets{}; // Sorted list of received packet numbers
    std::uint64_t mLargestReceived{0};
    std::size_t mUnackedCount{0};
    std::chrono::steady_clock::time_point mLastReceiveTime{std::chrono::steady_clock::now()};
};

// ================================================================================================
// PacketTracker Inline Implementations
// ================================================================================================

inline void PacketTracker::OnPacketSent(SentPacket packet)
{
    mUnackedPackets.push_back(std::move(packet));
}

inline std::vector<Frame> PacketTracker::OnAckReceived(const AckFrame &ack)
{
    std::vector<Frame> lost_frames;

    // Update largest acked
    if (ack.largest_acknowledged > mLargestAcked)
        mLargestAcked = ack.largest_acknowledged;

    // Mark packets as acked
    for (auto it = mUnackedPackets.begin(); it != mUnackedPackets.end();)
    {
        bool is_acked = false;

        // Check if packet number is in any of the ACK ranges
        for (const auto &[start, length] : ack.ranges)
        {
            const std::uint64_t end = start + length - 1;
            if (it->packet_number >= start && it->packet_number <= end)
            {
                is_acked = true;
                break;
            }
        }

        if (is_acked)
        {
            it = mUnackedPackets.erase(it);
        }
        else
        {
            ++it;
        }
    }

    return lost_frames;
}

inline std::vector<Frame> PacketTracker::CheckForLoss(std::chrono::milliseconds timeout)
{
    std::vector<Frame> lost_frames;
    const auto now = std::chrono::steady_clock::now();

    for (auto it = mUnackedPackets.begin(); it != mUnackedPackets.end();)
    {
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->sent_time);

        if (elapsed > timeout)
        {
            // Packet is considered lost
            for (const auto &frame : it->frames)
            {
                // Only retransmit certain frame types (CRYPTO, STREAM with data)
                std::visit(
                    [&lost_frames](auto &&f)
                {
                    using T = std::decay_t<decltype(f)>;
                    if constexpr (std::is_same_v<T, CryptoFrame> || std::is_same_v<T, StreamFrame>)
                    {
                        lost_frames.push_back(f);
                    }
                },
                    frame);
            }
            it = mUnackedPackets.erase(it);
        }
        else
        {
            ++it;
        }
    }

    return lost_frames;
}

[[nodiscard]] inline std::uint64_t PacketTracker::NextPacketNumber() noexcept
{
    return mNextPacketNumber++;
}

[[nodiscard]] inline std::uint64_t PacketTracker::LargestAcked() const noexcept
{
    return mLargestAcked;
}

[[nodiscard]] inline std::size_t PacketTracker::UnackedCount() const noexcept
{
    return mUnackedPackets.size();
}

// ================================================================================================
// AckGenerator Inline Implementations
// ================================================================================================

inline void AckGenerator::OnPacketReceived(std::uint64_t packet_number)
{
    // Update largest received
    if (packet_number > mLargestReceived)
        mLargestReceived = packet_number;

    // Insert into received set (for simplicity, use a sorted vector)
    auto it = std::lower_bound(mReceivedPackets.begin(), mReceivedPackets.end(), packet_number);
    if (it == mReceivedPackets.end() || *it != packet_number)
    {
        mReceivedPackets.insert(it, packet_number);
        ++mUnackedCount;
    }

    mLastReceiveTime = std::chrono::steady_clock::now();
}

/// Generate ACK frame for received packets
[[nodiscard]] inline AckFrame AckGenerator::GenerateAck() noexcept
{
    AckFrame ack;
    if (mReceivedPackets.empty())
        return ack;

    ack.largest_acknowledged = mLargestReceived;

    // Calculate ACK delay (in microseconds)
    const auto now = std::chrono::steady_clock::now();
    const auto delay = std::chrono::duration_cast<std::chrono::microseconds>(
        now - mLastReceiveTime);
    ack.ack_delay = delay.count();

    // Build ACK ranges from received packets
    // Ranges are (start, length) pairs representing contiguous blocks
    std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges;

    if (!mReceivedPackets.empty())
    {
        std::uint64_t range_start = mReceivedPackets.back();
        std::uint64_t range_length = 1;

        for (auto it = mReceivedPackets.rbegin() + 1; it != mReceivedPackets.rend(); ++it)
        {
            if (*it == range_start - 1)
            {
                // Contiguous
                --range_start;
                ++range_length;
            }
            else
            {
                // Gap found, save current range
                ranges.emplace_back(range_start, range_length);
                range_start = *it;
                range_length = 1;
            }
        }

        // Save final range
        ranges.emplace_back(range_start, range_length);
    }

    ack.ranges = std::move(ranges);
    mUnackedCount = 0; // Reset after generating ACK

    return ack;
}

/// Should we send an ACK now?
/// Simple heuristic: send after receiving a certain number of packets
[[nodiscard]] inline bool AckGenerator::ShouldSendAck() const noexcept
{
    // Don't send ACK if we haven't received any packets
    if (mReceivedPackets.empty())
        return false;

    // Send ACK after receiving 2+ packets, or if enough time has passed
    constexpr std::size_t ack_threshold = 2;
    const auto now = std::chrono::steady_clock::now();
    const auto time_since_receive = std::chrono::duration_cast<std::chrono::milliseconds>(now - mLastReceiveTime);

    return mUnackedCount >= ack_threshold || time_since_receive.count() > 25;
}

/// Get the largest received packet number
[[nodiscard]] inline std::uint64_t AckGenerator::LargestReceived() const noexcept
{
    return mLargestReceived;
}

} // namespace clv::quic
