// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
#include <vector>

#include "numeric_util.h"

#include "quic_ack.h"
#include "quic_frame.h"
#include "quic_types.h"

namespace clv::quic {

/// Loss detection configuration (RFC 9002)
struct LossDetectionConfig
{
    /// Maximum reordering in packet numbers before declaring loss
    std::uint64_t packet_threshold{3};

    /// Maximum reordering in time before declaring loss (as fraction of RTT)
    double time_threshold{9.0 / 8.0}; // 9/8 = 1.125

    /// Initial RTT estimate (in milliseconds)
    std::chrono::milliseconds initial_rtt{333};

    /// Granularity for loss detection timers
    std::chrono::milliseconds timer_granularity{1};
};

/// Loss detection engine (RFC 9002)
class LossDetector
{
  public:
    explicit LossDetector(LossDetectionConfig config = {}) noexcept
        : config_(config), smoothed_rtt_(config.initial_rtt), latest_rtt_(config.initial_rtt)
    {
    }

    /// Record a sent packet
    void OnPacketSent(SentPacket packet) noexcept
    {
        if (packet.ack_eliciting)
        {
            time_of_last_ack_eliciting_packet_ = packet.sent_time;
        }
        sent_packets_.push_back(std::move(packet));
    }

    /// Process received ACK frame and detect losses
    /// Returns lost frames that need retransmission
    [[nodiscard]] std::vector<Frame> OnAckReceived(
        const AckRangeSet &ack_ranges,
        std::chrono::steady_clock::time_point ack_receive_time,
        std::chrono::microseconds ack_delay) noexcept
    {
        std::vector<Frame> lost_frames;

        // Update largest acked
        std::uint64_t new_largest = ack_ranges.GetLargest();
        if (new_largest > largest_acked_)
        {
            largest_acked_ = new_largest;
        }

        // Update RTT if this ACK acknowledges a new packet
        UpdateRtt(ack_receive_time, ack_delay);

        // Remove acked packets from sent_packets_
        for (auto it = sent_packets_.begin(); it != sent_packets_.end();)
        {
            if (ack_ranges.Contains(it->packet_number))
            {
                it = sent_packets_.erase(it);
            }
            else
            {
                ++it;
            }
        }

        // Detect losses based on packet threshold and time threshold
        auto detected_losses = DetectLostPackets(ack_receive_time);
        lost_frames.insert(lost_frames.end(), detected_losses.begin(), detected_losses.end());

        return lost_frames;
    }

    /// Check for timeout-based loss (Probe Timeout - PTO)
    /// Returns lost frames that need retransmission
    [[nodiscard]] std::vector<Frame> CheckForTimeout(
        std::chrono::steady_clock::time_point now) noexcept
    {
        std::vector<Frame> lost_frames;

        auto pto_timeout = CalculatePTO();

        for (auto it = sent_packets_.begin(); it != sent_packets_.end();)
        {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - it->sent_time);

            if (elapsed > pto_timeout)
            {
                // Packet has timed out - consider it lost
                ExtractRetransmittableFrames(it->frames, lost_frames);
                it = sent_packets_.erase(it);
            }
            else
            {
                ++it;
            }
        }

        return lost_frames;
    }

    /// Get the smoothed RTT estimate
    [[nodiscard]] std::chrono::milliseconds GetSmoothedRtt() const noexcept
    {
        return smoothed_rtt_;
    }

    /// Get the latest RTT sample
    [[nodiscard]] std::chrono::milliseconds GetLatestRtt() const noexcept
    {
        return latest_rtt_;
    }

    /// Get RTT variance
    [[nodiscard]] std::chrono::milliseconds GetRttVariance() const noexcept
    {
        return rtt_var_;
    }

    /// Get the largest acknowledged packet number
    [[nodiscard]] std::uint64_t GetLargestAcked() const noexcept
    {
        return largest_acked_;
    }

    /// Get count of unacked packets
    [[nodiscard]] std::size_t UnackedCount() const noexcept
    {
        return sent_packets_.size();
    }

  private:
    LossDetectionConfig config_;
    std::deque<SentPacket> sent_packets_;
    std::uint64_t largest_acked_{0};

    // RTT tracking (RFC 9002 §5)
    std::chrono::milliseconds smoothed_rtt_;
    std::chrono::milliseconds latest_rtt_;
    std::chrono::milliseconds rtt_var_{config_.initial_rtt / 2};
    std::chrono::steady_clock::time_point time_of_last_ack_eliciting_packet_;

    /// Detect lost packets based on threshold (RFC 9002 §6.1)
    [[nodiscard]] std::vector<Frame> DetectLostPackets(
        std::chrono::steady_clock::time_point now) noexcept
    {
        std::vector<Frame> lost_frames;

        // Loss threshold: largest_acked - packet_threshold
        std::uint64_t loss_threshold = (largest_acked_ > config_.packet_threshold)
                                           ? (largest_acked_ - config_.packet_threshold)
                                           : 0;

        // Time threshold for loss detection
        auto loss_delay = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::duration<double, std::milli>(
                config_.time_threshold * safe_cast<double>(smoothed_rtt_.count())));
        loss_delay = std::max(loss_delay, config_.timer_granularity);

        for (auto it = sent_packets_.begin(); it != sent_packets_.end();)
        {
            bool is_lost = false;

            // Check packet number threshold
            if (it->packet_number <= loss_threshold)
            {
                is_lost = true;
            }

            // Check time threshold
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - it->sent_time);
            if (elapsed > loss_delay)
            {
                is_lost = true;
            }

            if (is_lost)
            {
                ExtractRetransmittableFrames(it->frames, lost_frames);
                it = sent_packets_.erase(it);
            }
            else
            {
                ++it;
            }
        }

        return lost_frames;
    }

    /// Update RTT estimates (RFC 9002 §5)
    void UpdateRtt(
        std::chrono::steady_clock::time_point ack_receive_time,
        std::chrono::microseconds ack_delay) noexcept
    {
        // Find the oldest unacked packet that was just acked
        // For simplicity, use the time of last ack-eliciting packet
        if (time_of_last_ack_eliciting_packet_ == std::chrono::steady_clock::time_point{})
            return;

        auto latest_rtt = std::chrono::duration_cast<std::chrono::milliseconds>(
            ack_receive_time - time_of_last_ack_eliciting_packet_);

        // Don't let ack_delay exceed latest_rtt
        auto adjusted_ack_delay = std::min(
            std::chrono::duration_cast<std::chrono::milliseconds>(ack_delay),
            latest_rtt);

        latest_rtt_ = latest_rtt - adjusted_ack_delay;

        // Update smoothed_rtt and rtt_var (RFC 9002 §5.3)
        if (smoothed_rtt_ == config_.initial_rtt)
        {
            // First RTT sample
            smoothed_rtt_ = latest_rtt_;
            rtt_var_ = latest_rtt_ / 2;
        }
        else
        {
            // Subsequent samples
            auto rtt_diff = std::chrono::abs(smoothed_rtt_ - latest_rtt_);
            rtt_var_ = (3 * rtt_var_ + rtt_diff) / 4;
            smoothed_rtt_ = (7 * smoothed_rtt_ + latest_rtt_) / 8;
        }
    }

    /// Calculate Probe Timeout (PTO) - RFC 9002 §6.2
    [[nodiscard]] std::chrono::milliseconds CalculatePTO() const noexcept
    {
        return smoothed_rtt_ + std::max(4 * rtt_var_, config_.timer_granularity);
    }

    /// Extract retransmittable frames from a packet
    static void ExtractRetransmittableFrames(
        const std::vector<Frame> &frames,
        std::vector<Frame> &out_frames) noexcept
    {
        for (const auto &frame : frames)
        {
            // Only retransmit certain frame types
            std::visit(
                [&out_frames](auto &&f)
            {
                using T = std::decay_t<decltype(f)>;
                if constexpr (std::is_same_v<T, CryptoFrame> || std::is_same_v<T, StreamFrame> || std::is_same_v<T, MaxDataFrame> || std::is_same_v<T, MaxStreamDataFrame>)
                {
                    out_frames.push_back(f);
                }
            },
                frame);
        }
    }
};

} // namespace clv::quic
