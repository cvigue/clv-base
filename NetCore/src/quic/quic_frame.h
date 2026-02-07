// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "quic_varint.h"

namespace clv::quic {

// TODO: strongly consider rubbing a lot more OOP on this later

/// QUIC frame types (RFC 9000, Section 12.4)
enum class FrameType : std::uint8_t
{
    Padding = 0x00,
    Ping = 0x01,
    Ack = 0x02,
    AckEcn = 0x03,
    ResetStream = 0x04,
    StopSending = 0x05,
    Crypto = 0x06,
    NewToken = 0x07,
    Stream = 0x08, // 0x08-0x0f (with flags)
    MaxData = 0x10,
    MaxStreamData = 0x11,
    MaxStreams = 0x12,
    DataBlocked = 0x14,
    StreamDataBlocked = 0x15,
    NewConnectionId = 0x18,
    RetireConnectionId = 0x19,
    PathChallenge = 0x1a,
    PathResponse = 0x1b,
    ConnectionClose = 0x1c,
    HandshakeDone = 0x1e
};

/// Padding frame (no data, just type 0x00)
struct PaddingFrame
{
    std::size_t length{1}; // Number of consecutive padding bytes
};

/// Ping frame (no data)
struct PingFrame
{
};

/// ACK frame with ranges
struct AckFrame
{
    std::uint64_t largest_acknowledged{0};
    std::uint64_t ack_delay{0};                                    // In microseconds
    std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges{}; // (start, length) pairs
};

/// Stream data frame
struct StreamFrame
{
    std::uint64_t stream_id{0};
    std::uint64_t offset{0};
    bool fin{false};
    std::vector<std::uint8_t> data{};
};

/// CRYPTO frame (TLS handshake data)
struct CryptoFrame
{
    std::uint64_t offset{0};
    std::vector<std::uint8_t> data{};
};

/// Connection close frame
struct ConnectionCloseFrame
{
    std::uint64_t error_code{0};
    std::uint64_t frame_type{0}; // Which frame type caused the error
    std::string reason{};
};

/// MAX_DATA frame
struct MaxDataFrame
{
    std::uint64_t max_data{0};
};

/// MAX_STREAM_DATA frame
struct MaxStreamDataFrame
{
    std::uint64_t stream_id{0};
    std::uint64_t max_stream_data{0};
};

/// RESET_STREAM frame
struct ResetStreamFrame
{
    std::uint64_t stream_id{0};
    std::uint64_t error_code{0};
    std::uint64_t final_size{0};
};

/// HANDSHAKE_DONE frame
struct HandshakeDoneFrame
{
};

/// NEW_CONNECTION_ID frame
struct NewConnectionIdFrame
{
    std::uint64_t sequence_number{0};
    std::uint64_t retire_prior_to{0};
    std::array<std::uint8_t, 20> connection_id{};
    std::uint8_t connection_id_length{0};
    std::array<std::uint8_t, 16> stateless_reset_token{};
};

/// Generic frame container
using Frame = std::variant<PaddingFrame,
                           PingFrame,
                           AckFrame,
                           StreamFrame,
                           CryptoFrame,
                           ConnectionCloseFrame,
                           MaxDataFrame,
                           MaxStreamDataFrame,
                           ResetStreamFrame,
                           HandshakeDoneFrame,
                           NewConnectionIdFrame>;

/// Parse a single frame from bytes
/// Returns the parsed frame and the number of bytes consumed, or std::nullopt if invalid.
[[nodiscard]] inline std::optional<std::pair<Frame, std::size_t>>
ParseFrame(std::span<const std::uint8_t> data) noexcept
{
    if (data.empty())
        return std::nullopt;

    const std::uint8_t type_byte = data[0];
    std::size_t offset = 1;

    // PADDING frame (0x00) - can be multiple consecutive padding bytes
    if (type_byte == static_cast<std::uint8_t>(FrameType::Padding))
    {
        std::size_t count = 1;
        while (offset < data.size() && data[offset] == 0x00)
        {
            ++count;
            ++offset;
        }
        PaddingFrame frame;
        frame.length = count;
        return std::make_pair(Frame{frame}, offset);
    }

    // PING frame (0x01)
    if (type_byte == static_cast<std::uint8_t>(FrameType::Ping))
    {
        return std::make_pair(Frame{PingFrame{}}, 1);
    }

    // ACK frame (0x02)
    if (type_byte == static_cast<std::uint8_t>(FrameType::Ack))
    {
        AckFrame frame;

        // Largest Acknowledged (varint)
        auto largest = DecodeVarint(data.subspan(offset));
        if (!largest)
            return std::nullopt;
        frame.largest_acknowledged = largest->first;
        offset += largest->second;

        // ACK Delay (varint)
        auto delay = DecodeVarint(data.subspan(offset));
        if (!delay)
            return std::nullopt;
        frame.ack_delay = delay->first;
        offset += delay->second;

        // ACK Range Count (varint)
        auto range_count = DecodeVarint(data.subspan(offset));
        if (!range_count)
            return std::nullopt;
        const auto num_ranges = range_count->first;
        offset += range_count->second;

        // First ACK Range (varint)
        auto first_range = DecodeVarint(data.subspan(offset));
        if (!first_range)
            return std::nullopt;
        offset += first_range->second;

        // First range: [largest - first_range, largest]
        frame.ranges.emplace_back(frame.largest_acknowledged - first_range->first,
                                  first_range->first + 1);

        // Additional ACK Ranges
        std::uint64_t prev_smallest = frame.largest_acknowledged - first_range->first;
        for (std::uint64_t i = 0; i < num_ranges; ++i)
        {
            // Gap (varint)
            auto gap = DecodeVarint(data.subspan(offset));
            if (!gap)
                return std::nullopt;
            offset += gap->second;

            // ACK Range Length (varint)
            auto range_len = DecodeVarint(data.subspan(offset));
            if (!range_len)
                return std::nullopt;
            offset += range_len->second;

            const std::uint64_t range_end = prev_smallest - gap->first - 2;
            const std::uint64_t range_start = range_end - range_len->first;
            frame.ranges.emplace_back(range_start, range_len->first + 1);
            prev_smallest = range_start;
        }

        return std::make_pair(Frame{frame}, offset);
    }

    // CRYPTO frame (0x06)
    if (type_byte == static_cast<std::uint8_t>(FrameType::Crypto))
    {
        CryptoFrame frame;

        // Offset (varint)
        auto crypto_offset = DecodeVarint(data.subspan(offset));
        if (!crypto_offset)
            return std::nullopt;
        frame.offset = crypto_offset->first;
        offset += crypto_offset->second;

        // Length (varint)
        auto length = DecodeVarint(data.subspan(offset));
        if (!length)
            return std::nullopt;
        const auto data_len = length->first;
        offset += length->second;

        // Crypto Data
        if (offset + data_len > data.size())
            return std::nullopt;
        frame.data.resize(data_len);
        std::copy_n(data.begin() + offset, data_len, frame.data.begin());
        offset += data_len;

        return std::make_pair(Frame{frame}, offset);
    }

    // STREAM frame (0x08-0x0f)
    if ((type_byte & 0xF8) == 0x08)
    {
        StreamFrame frame;

        const bool has_offset = (type_byte & 0x04) != 0;
        const bool has_length = (type_byte & 0x02) != 0;
        frame.fin = (type_byte & 0x01) != 0;

        // Stream ID (varint)
        auto stream_id = DecodeVarint(data.subspan(offset));
        if (!stream_id)
            return std::nullopt;
        frame.stream_id = stream_id->first;
        offset += stream_id->second;

        // Offset (varint, if present)
        if (has_offset)
        {
            auto stream_offset = DecodeVarint(data.subspan(offset));
            if (!stream_offset)
                return std::nullopt;
            frame.offset = stream_offset->first;
            offset += stream_offset->second;
        }

        // Length (varint, if present)
        std::uint64_t data_len = 0;
        if (has_length)
        {
            auto length = DecodeVarint(data.subspan(offset));
            if (!length)
                return std::nullopt;
            data_len = length->first;
            offset += length->second;
        }
        else
        {
            // Length extends to end of packet
            data_len = data.size() - offset;
        }

        // Stream Data
        if (offset + data_len > data.size())
            return std::nullopt;
        frame.data.resize(data_len);
        std::copy_n(data.begin() + offset, data_len, frame.data.begin());
        offset += data_len;

        return std::make_pair(Frame{frame}, offset);
    }

    // CONNECTION_CLOSE frame (0x1c)
    if (type_byte == static_cast<std::uint8_t>(FrameType::ConnectionClose))
    {
        ConnectionCloseFrame frame;

        // Error Code (varint)
        auto error_code = DecodeVarint(data.subspan(offset));
        if (!error_code)
            return std::nullopt;
        frame.error_code = error_code->first;
        offset += error_code->second;

        // Frame Type (varint)
        auto frame_type = DecodeVarint(data.subspan(offset));
        if (!frame_type)
            return std::nullopt;
        frame.frame_type = frame_type->first;
        offset += frame_type->second;

        // Reason Phrase Length (varint)
        auto reason_len = DecodeVarint(data.subspan(offset));
        if (!reason_len)
            return std::nullopt;
        const auto len = reason_len->first;
        offset += reason_len->second;

        // Reason Phrase
        if (offset + len > data.size())
            return std::nullopt;
        frame.reason.resize(len);
        std::copy_n(data.begin() + offset, len, frame.reason.begin());
        offset += len;

        return std::make_pair(Frame{frame}, offset);
    }

    // MAX_DATA frame (0x10)
    if (type_byte == static_cast<std::uint8_t>(FrameType::MaxData))
    {
        MaxDataFrame frame;

        auto max_data = DecodeVarint(data.subspan(offset));
        if (!max_data)
            return std::nullopt;
        frame.max_data = max_data->first;
        offset += max_data->second;

        return std::make_pair(Frame{frame}, offset);
    }

    // MAX_STREAM_DATA frame (0x11)
    if (type_byte == static_cast<std::uint8_t>(FrameType::MaxStreamData))
    {
        MaxStreamDataFrame frame;

        auto stream_id = DecodeVarint(data.subspan(offset));
        if (!stream_id)
            return std::nullopt;
        frame.stream_id = stream_id->first;
        offset += stream_id->second;

        auto max_stream_data = DecodeVarint(data.subspan(offset));
        if (!max_stream_data)
            return std::nullopt;
        frame.max_stream_data = max_stream_data->first;
        offset += max_stream_data->second;

        return std::make_pair(Frame{frame}, offset);
    }

    // RESET_STREAM frame (0x04)
    if (type_byte == static_cast<std::uint8_t>(FrameType::ResetStream))
    {
        ResetStreamFrame frame;

        auto stream_id = DecodeVarint(data.subspan(offset));
        if (!stream_id)
            return std::nullopt;
        frame.stream_id = stream_id->first;
        offset += stream_id->second;

        auto error_code = DecodeVarint(data.subspan(offset));
        if (!error_code)
            return std::nullopt;
        frame.error_code = error_code->first;
        offset += error_code->second;

        auto final_size = DecodeVarint(data.subspan(offset));
        if (!final_size)
            return std::nullopt;
        frame.final_size = final_size->first;
        offset += final_size->second;

        return std::make_pair(Frame{frame}, offset);
    }

    // HANDSHAKE_DONE frame (0x1e)
    if (type_byte == static_cast<std::uint8_t>(FrameType::HandshakeDone))
    {
        return std::make_pair(Frame{HandshakeDoneFrame{}}, 1);
    }

    // NEW_CONNECTION_ID frame (0x18)
    if (type_byte == static_cast<std::uint8_t>(FrameType::NewConnectionId))
    {
        NewConnectionIdFrame frame;

        // Sequence Number (varint)
        auto seq_num = DecodeVarint(data.subspan(offset));
        if (!seq_num)
            return std::nullopt;
        frame.sequence_number = seq_num->first;
        offset += seq_num->second;

        // Retire Prior To (varint)
        auto retire_prior = DecodeVarint(data.subspan(offset));
        if (!retire_prior)
            return std::nullopt;
        frame.retire_prior_to = retire_prior->first;
        offset += retire_prior->second;

        // Connection ID Length (1 byte, 1-20)
        if (offset >= data.size())
            return std::nullopt;
        frame.connection_id_length = data[offset++];
        if (frame.connection_id_length < 1 || frame.connection_id_length > 20)
            return std::nullopt;

        // Connection ID
        if (offset + frame.connection_id_length > data.size())
            return std::nullopt;
        std::copy_n(data.begin() + offset, frame.connection_id_length, frame.connection_id.begin());
        offset += frame.connection_id_length;

        // Stateless Reset Token (16 bytes)
        if (offset + 16 > data.size())
            return std::nullopt;
        std::copy_n(data.begin() + offset, 16, frame.stateless_reset_token.begin());
        offset += 16;

        return std::make_pair(Frame{frame}, offset);
    }

    // Unsupported frame type
    return std::nullopt;
}

/// Parse all frames from a decrypted packet payload
[[nodiscard]] inline std::vector<Frame> ParseFrames(std::span<const std::uint8_t> payload) noexcept
{
    std::vector<Frame> frames;
    std::size_t offset = 0;

    while (offset < payload.size())
    {
        auto result = ParseFrame(payload.subspan(offset));
        if (!result)
            break; // Invalid or unsupported frame, stop parsing

        frames.push_back(result->first);
        offset += result->second;
    }

    return frames;
}

/// Serialize a frame to bytes
[[nodiscard]] inline std::vector<std::uint8_t> SerializeFrame(const Frame &frame) noexcept
{
    std::vector<std::uint8_t> out;

    std::visit(
        [&out](auto &&f)
    {
        using T = std::decay_t<decltype(f)>;

        if constexpr (std::is_same_v<T, PaddingFrame>)
        {
            out.resize(f.length, 0x00);
        }
        else if constexpr (std::is_same_v<T, PingFrame>)
        {
            out.push_back(static_cast<std::uint8_t>(FrameType::Ping));
        }
        else if constexpr (std::is_same_v<T, AckFrame>)
        {
            out.push_back(static_cast<std::uint8_t>(FrameType::Ack));

            std::array<std::uint8_t, 8> buf;
            auto bytes = EncodeVarint(f.largest_acknowledged, buf);
            out.insert(out.end(), buf.begin(), buf.begin() + bytes);

            bytes = EncodeVarint(f.ack_delay, buf);
            out.insert(out.end(), buf.begin(), buf.begin() + bytes);

            // ACK Range Count (number of additional ranges)
            const std::uint64_t range_count = f.ranges.empty() ? 0 : (f.ranges.size() - 1);
            bytes = EncodeVarint(range_count, buf);
            out.insert(out.end(), buf.begin(), buf.begin() + bytes);

            // First ACK Range
            if (!f.ranges.empty())
            {
                bytes = EncodeVarint(f.ranges[0].second - 1, buf);
                out.insert(out.end(), buf.begin(), buf.begin() + bytes);

                // Additional ranges (gaps and lengths)
                for (std::size_t i = 1; i < f.ranges.size(); ++i)
                {
                    const auto &prev = f.ranges[i - 1];
                    const auto &curr = f.ranges[i];
                    const std::uint64_t gap = prev.first - curr.first - curr.second - 1;
                    bytes = EncodeVarint(gap, buf);
                    out.insert(out.end(), buf.begin(), buf.begin() + bytes);

                    bytes = EncodeVarint(curr.second - 1, buf);
                    out.insert(out.end(), buf.begin(), buf.begin() + bytes);
                }
            }
        }
        else if constexpr (std::is_same_v<T, CryptoFrame>)
        {
            out.push_back(static_cast<std::uint8_t>(FrameType::Crypto));

            std::array<std::uint8_t, 8> buf;
            auto bytes = EncodeVarint(f.offset, buf);
            out.insert(out.end(), buf.begin(), buf.begin() + bytes);

            bytes = EncodeVarint(f.data.size(), buf);
            out.insert(out.end(), buf.begin(), buf.begin() + bytes);

            out.insert(out.end(), f.data.begin(), f.data.end());
        }
        else if constexpr (std::is_same_v<T, StreamFrame>)
        {
            std::uint8_t type = 0x08;
            if (f.offset != 0)
                type |= 0x04;
            type |= 0x02; // Always include length for simplicity
            if (f.fin)
                type |= 0x01;
            out.push_back(type);

            std::array<std::uint8_t, 8> buf;
            auto bytes = EncodeVarint(f.stream_id, buf);
            out.insert(out.end(), buf.begin(), buf.begin() + bytes);

            if (f.offset != 0)
            {
                bytes = EncodeVarint(f.offset, buf);
                out.insert(out.end(), buf.begin(), buf.begin() + bytes);
            }

            bytes = EncodeVarint(f.data.size(), buf);
            out.insert(out.end(), buf.begin(), buf.begin() + bytes);

            out.insert(out.end(), f.data.begin(), f.data.end());
        }
        else if constexpr (std::is_same_v<T, ConnectionCloseFrame>)
        {
            out.push_back(static_cast<std::uint8_t>(FrameType::ConnectionClose));

            std::array<std::uint8_t, 8> buf;
            auto bytes = EncodeVarint(f.error_code, buf);
            out.insert(out.end(), buf.begin(), buf.begin() + bytes);

            bytes = EncodeVarint(f.frame_type, buf);
            out.insert(out.end(), buf.begin(), buf.begin() + bytes);

            bytes = EncodeVarint(f.reason.size(), buf);
            out.insert(out.end(), buf.begin(), buf.begin() + bytes);

            out.insert(out.end(), f.reason.begin(), f.reason.end());
        }
        else if constexpr (std::is_same_v<T, MaxDataFrame>)
        {
            out.push_back(static_cast<std::uint8_t>(FrameType::MaxData));
            std::array<std::uint8_t, 8> buf;
            auto bytes = EncodeVarint(f.max_data, buf);
            out.insert(out.end(), buf.begin(), buf.begin() + bytes);
        }
        else if constexpr (std::is_same_v<T, MaxStreamDataFrame>)
        {
            out.push_back(static_cast<std::uint8_t>(FrameType::MaxStreamData));
            std::array<std::uint8_t, 8> buf;
            auto bytes = EncodeVarint(f.stream_id, buf);
            out.insert(out.end(), buf.begin(), buf.begin() + bytes);
            bytes = EncodeVarint(f.max_stream_data, buf);
            out.insert(out.end(), buf.begin(), buf.begin() + bytes);
        }
        else if constexpr (std::is_same_v<T, ResetStreamFrame>)
        {
            out.push_back(static_cast<std::uint8_t>(FrameType::ResetStream));
            std::array<std::uint8_t, 8> buf;
            auto bytes = EncodeVarint(f.stream_id, buf);
            out.insert(out.end(), buf.begin(), buf.begin() + bytes);
            bytes = EncodeVarint(f.error_code, buf);
            out.insert(out.end(), buf.begin(), buf.begin() + bytes);
            bytes = EncodeVarint(f.final_size, buf);
            out.insert(out.end(), buf.begin(), buf.begin() + bytes);
        }
        else if constexpr (std::is_same_v<T, HandshakeDoneFrame>)
        {
            out.push_back(static_cast<std::uint8_t>(FrameType::HandshakeDone));
        }
    },
        frame);

    return out;
}

/// Serialize multiple frames to bytes
[[nodiscard]] inline std::vector<std::uint8_t>
SerializeFrames(const std::vector<Frame> &frames) noexcept
{
    std::vector<std::uint8_t> out;
    for (const auto &frame : frames)
    {
        auto serialized = SerializeFrame(frame);
        out.insert(out.end(), serialized.begin(), serialized.end());
    }
    return out;
}

} // namespace clv::quic
