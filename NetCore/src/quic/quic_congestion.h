#pragma once

#include <chrono>
#include <cstdint>
#include <algorithm>

#include "numeric_util.h"

using clv::safe_cast;

namespace clv::quic {

/**
 * @brief Configuration for congestion control (RFC 9002 §7)
 */
struct CongestionConfig
{
    // Initial congestion window in bytes (RFC 9002 §7.2)
    uint64_t initial_window = 10 * 1200; // 10 packets of 1200 bytes

    // Minimum congestion window in bytes
    uint64_t minimum_window = 2 * 1200; // 2 packets

    // Maximum congestion window in bytes
    uint64_t maximum_window = UINT64_MAX;

    // Loss reduction factor (multiplicative decrease)
    double loss_reduction_factor = 0.5;

    // Persistent congestion threshold (RFC 9002 §7.6)
    uint32_t persistent_congestion_threshold = 3;
};

/**
 * @brief Congestion controller implementing NewReno algorithm (RFC 9002 §7)
 *
 * This class manages the congestion window (cwnd) and slow start threshold (ssthresh)
 * to control the sending rate and avoid network congestion.
 *
 * States:
 * - Slow Start: Exponential growth until ssthresh
 * - Congestion Avoidance: Linear growth after ssthresh
 * - Recovery: After packet loss, multiplicative decrease
 */
class CongestionController
{
  public:
    explicit CongestionController(const CongestionConfig &config = {})
        : config_(config), congestion_window_(config.initial_window), ssthresh_(UINT64_MAX), bytes_in_flight_(0), congestion_recovery_start_time_(std::chrono::steady_clock::time_point::min())
    {
    }

    /**
     * @brief Get current congestion window in bytes
     */
    uint64_t GetCongestionWindow() const
    {
        return congestion_window_;
    }

    /**
     * @brief Get bytes currently in flight (sent but not acked)
     */
    uint64_t GetBytesInFlight() const
    {
        return bytes_in_flight_;
    }

    /**
     * @brief Get slow start threshold
     */
    uint64_t GetSlowStartThreshold() const
    {
        return ssthresh_;
    }

    /**
     * @brief Check if sending is allowed
     */
    bool CanSend() const
    {
        return bytes_in_flight_ < congestion_window_;
    }

    /**
     * @brief Get available congestion window space
     */
    uint64_t GetAvailableWindow() const
    {
        if (bytes_in_flight_ >= congestion_window_)
        {
            return 0;
        }
        return congestion_window_ - bytes_in_flight_;
    }

    /**
     * @brief Called when a packet is sent
     * @param bytes Number of bytes in the packet
     */
    void OnPacketSent(uint64_t bytes)
    {
        bytes_in_flight_ += bytes;
    }

    /**
     * @brief Called when packets are acknowledged
     * @param bytes Number of bytes acknowledged
     * @param now Current time
     */
    void OnPacketsAcked(uint64_t bytes, std::chrono::steady_clock::time_point now)
    {
        bytes_in_flight_ = bytes > bytes_in_flight_ ? 0 : bytes_in_flight_ - bytes;

        // Don't increase cwnd if we're in recovery (RFC 9002 §7.3.2)
        if (InRecovery(now))
        {
            return;
        }

        // Slow start: exponential growth (RFC 9002 §7.3.1)
        if (congestion_window_ < ssthresh_)
        {
            congestion_window_ += bytes;
        }
        // Congestion avoidance: linear growth (RFC 9002 §7.3.2)
        else
        {
            // Increase cwnd by (acked_bytes * max_packet_size) / cwnd
            // Simplified: increase by acked_bytes / cwnd per acked byte
            constexpr uint64_t max_packet_size = 1200;
            uint64_t increase = (bytes * max_packet_size) / congestion_window_;
            if (increase == 0 && bytes > 0)
            {
                increase = 1; // Always make some progress
            }
            congestion_window_ += increase;
        }

        // Apply maximum window limit
        if (congestion_window_ > config_.maximum_window)
        {
            congestion_window_ = config_.maximum_window;
        }
    }

    /**
     * @brief Called when packets are declared lost
     * @param bytes Number of bytes lost
     * @param largest_lost_pn Largest packet number that was lost
     * @param now Current time
     */
    void OnPacketsLost(uint64_t bytes, uint64_t largest_lost_pn,
                       std::chrono::steady_clock::time_point now)
    {
        bytes_in_flight_ = bytes > bytes_in_flight_ ? 0 : bytes_in_flight_ - bytes;

        // Don't react to losses from before recovery period (RFC 9002 §7.3.2)
        if (InRecovery(now))
        {
            return;
        }

        // Enter recovery
        congestion_recovery_start_time_ = now;

        // Multiplicative decrease (RFC 9002 §7.3.2)
        ssthresh_ = static_cast<uint64_t>(safe_cast<double>(congestion_window_) * config_.loss_reduction_factor);
        congestion_window_ = std::max(ssthresh_, config_.minimum_window);
    }

    /**
     * @brief Called when persistent congestion is detected (RFC 9002 §7.6)
     *
     * Persistent congestion occurs when all packets in a time period are lost,
     * indicating severe network problems. Reset to initial window.
     */
    void OnPersistentCongestion()
    {
        congestion_window_ = config_.minimum_window;
        congestion_recovery_start_time_ = std::chrono::steady_clock::time_point::min();
    }

    /**
     * @brief Check if in congestion recovery period
     */
    bool InRecovery(std::chrono::steady_clock::time_point now) const
    {
        return now < congestion_recovery_start_time_ + std::chrono::milliseconds(100);
    }

    /**
     * @brief Check if in slow start phase
     */
    bool InSlowStart() const
    {
        return congestion_window_ < ssthresh_;
    }

    /**
     * @brief Reset to initial state
     */
    void Reset()
    {
        congestion_window_ = config_.initial_window;
        ssthresh_ = UINT64_MAX;
        bytes_in_flight_ = 0;
        congestion_recovery_start_time_ = std::chrono::steady_clock::time_point::min();
    }

    /**
     * @brief Update configuration
     */
    void SetConfig(const CongestionConfig &config)
    {
        config_ = config;
        // Re-apply limits
        if (congestion_window_ < config_.minimum_window)
        {
            congestion_window_ = config_.minimum_window;
        }
        if (congestion_window_ > config_.maximum_window)
        {
            congestion_window_ = config_.maximum_window;
        }
    }

  private:
    CongestionConfig config_;

    // Current congestion window (cwnd) in bytes
    uint64_t congestion_window_;

    // Slow start threshold in bytes
    uint64_t ssthresh_;

    // Bytes currently in flight (sent but not acked)
    uint64_t bytes_in_flight_;

    // Time when congestion recovery started
    std::chrono::steady_clock::time_point congestion_recovery_start_time_;
};

} // namespace clv::quic
