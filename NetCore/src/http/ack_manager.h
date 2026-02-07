// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#pragma once

#include "quic/quic_reliability.h"
#include "quic/quic_frame.h"
#include "quic/quic_tls.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

namespace clv::http3 {

using clv::quic::AckFrame;
using clv::quic::AckGenerator;
using clv::quic::QuicEncryptionLevel;

/**
 * @brief Manages ACK generation across all encryption levels
 * @details Encapsulates per-level ACK logic and provides a unified interface
 *          for tracking received packets and generating ACK frames.
 */
class AckManager
{
  public:
    /**
     * @brief Record a received packet at a specific encryption level
     * @param packet_number The packet number that was received
     * @param level The encryption level of the packet
     */
    void OnPacketReceived(std::uint64_t packet_number, QuicEncryptionLevel level) noexcept
    {
        std::size_t idx = LevelToIndex(level);
        generators_[idx].OnPacketReceived(packet_number);
    }

    /**
     * @brief Generate an ACK frame if needed for a specific level
     * @param level The encryption level to check
     * @param force Force ACK generation even if heuristics say not needed
     * @return ACK frame if one should be sent, nullopt otherwise
     */
    [[nodiscard]] std::optional<AckFrame> GenerateAckIfNeeded(
        QuicEncryptionLevel level,
        bool force = false) noexcept
    {
        std::size_t idx = LevelToIndex(level);
        auto &gen = generators_[idx];

        // Check if we should send an ACK
        if (force || gen.ShouldSendAck())
        {
            return gen.GenerateAck();
        }

        return std::nullopt;
    }

    /**
     * @brief Check if we should send an ACK at a specific level
     * @param level The encryption level to check
     * @return true if an ACK should be sent
     */
    [[nodiscard]] bool ShouldSendAck(QuicEncryptionLevel level) const noexcept
    {
        std::size_t idx = LevelToIndex(level);
        return generators_[idx].ShouldSendAck();
    }

    /**
     * @brief Get the largest received packet number at a specific level
     * @param level The encryption level to check
     * @return The largest packet number received, or 0 if none
     */
    [[nodiscard]] std::uint64_t LargestReceived(QuicEncryptionLevel level) const noexcept
    {
        std::size_t idx = LevelToIndex(level);
        return generators_[idx].LargestReceived();
    }

    /**
     * @brief Check if a forced ACK should be sent (for handshake completion)
     * @param level The encryption level to check
     * @param force_handshake_ack Whether to force handshake ACK
     * @return true if a forced ACK should be sent
     */
    [[nodiscard]] bool ShouldForceAck(
        QuicEncryptionLevel level,
        bool force_handshake_ack) const noexcept
    {
        return force_handshake_ack && level == QuicEncryptionLevel::Handshake && LargestReceived(level) > 0;
    }

  private:
    std::array<AckGenerator, 3> generators_; // Initial, Handshake, Application

    /**
     * @brief Convert encryption level to array index
     * @param level The encryption level
     * @return Array index (0=Initial, 1=Handshake, 2=Application)
     */
    static constexpr std::size_t LevelToIndex(QuicEncryptionLevel level) noexcept
    {
        switch (level)
        {
        case QuicEncryptionLevel::Initial:
            return 0;
        case QuicEncryptionLevel::Handshake:
            return 1;
        case QuicEncryptionLevel::Application:
            return 2;
        default:
            return 0;
        }
    }
};

} // namespace clv::http3
