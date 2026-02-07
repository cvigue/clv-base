// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#pragma once

#include <chrono>
#include <cstdint>
#include <vector>

#include "quic_frame.h"

namespace clv::quic {

/// Tracks a sent QUIC packet (used by both LossDetector and PacketTracker)
struct SentPacket
{
    std::uint64_t packet_number{0};
    std::vector<Frame> frames{};
    std::chrono::steady_clock::time_point sent_time{};
    std::size_t bytes_sent{0};
    bool ack_eliciting{false}; ///< Does this packet require an ACK?
};

} // namespace clv::quic
