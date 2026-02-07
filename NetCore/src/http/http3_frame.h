// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#pragma once

#include "quic/quic_varint.h"
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

namespace clv::http3 {

using clv::quic::DecodeVarint;
using clv::quic::EncodeVarint;

/**
 * @brief HTTP/3 frame types (RFC 9114, Section 7.2)
 */
enum class FrameType : std::uint64_t
{
    Data = 0x00,
    Headers = 0x01,
    CancelPush = 0x03,
    Settings = 0x04,
    PushPromise = 0x05,
    Goaway = 0x07,
    MaxPushId = 0x0d,
    // Reserved frame types (Section 7.2.8)
    Reserved = 0x21 // Example; 0x1f * N + 0x21 are all reserved
};

/**
 * @brief HTTP/3 DATA frame
 * Carries HTTP message body data
 */
struct DataFrame
{
    std::vector<std::uint8_t> payload;
};

/**
 * @brief HTTP/3 HEADERS frame
 * Carries compressed HTTP header fields (QPACK encoded)
 */
struct HeadersFrame
{
    std::vector<std::uint8_t> header_block; // QPACK-encoded headers
};

/**
 * @brief HTTP/3 SETTINGS frame
 * Conveys configuration parameters (RFC 9114, Section 7.2.4)
 */
struct SettingsFrame
{
    std::unordered_map<std::uint64_t, std::uint64_t> settings;

    // Common settings identifiers (RFC 9114, Section 7.2.4.1)
    static constexpr std::uint64_t QPACK_MAX_TABLE_CAPACITY = 0x01;
    static constexpr std::uint64_t MAX_FIELD_SECTION_SIZE = 0x06;
    static constexpr std::uint64_t QPACK_BLOCKED_STREAMS = 0x07;
};

/**
 * @brief HTTP/3 GOAWAY frame
 * Initiates graceful shutdown
 */
struct GoawayFrame
{
    std::uint64_t stream_id; // Last stream ID processed
};

/**
 * @brief HTTP/3 MAX_PUSH_ID frame
 * Controls server push
 */
struct MaxPushIdFrame
{
    std::uint64_t push_id;
};

/**
 * @brief Variant holding all HTTP/3 frame types
 */
using Frame = std::variant<
    DataFrame,
    HeadersFrame,
    SettingsFrame,
    GoawayFrame,
    MaxPushIdFrame>;

/**
 * @brief Parsed frame with type and payload
 */
struct ParsedFrame
{
    FrameType type;
    Frame frame;
};

/**
 * @brief Helper to encode varint and return as vector
 */
inline std::vector<std::uint8_t> EncodeVarintToVector(std::uint64_t value)
{
    std::vector<std::uint8_t> buffer(8); // Max varint size
    std::size_t len = EncodeVarint(value, buffer);
    buffer.resize(len);
    return buffer;
}

/**
 * @brief Parse HTTP/3 frame from stream data
 *
 * @param data Stream data containing frame(s)
 * @return Parsed frame and number of bytes consumed, or nullopt on error
 */
inline std::optional<std::pair<ParsedFrame, std::size_t>> ParseFrame(std::span<const std::uint8_t> data)
{
    if (data.empty())
    {
        return std::nullopt;
    }

    std::size_t offset = 0;

    // Decode frame type (varint)
    auto type_result = DecodeVarint(data);
    if (!type_result)
    {
        return std::nullopt;
    }
    auto [frame_type_raw, type_len] = *type_result;
    offset += type_len;

    // Decode frame length (varint)
    auto length_result = DecodeVarint(data.subspan(offset));
    if (!length_result)
    {
        return std::nullopt;
    }
    auto [frame_length, length_len] = *length_result;
    offset += length_len;

    // Check if we have the full frame payload
    if (data.size() < offset + frame_length)
    {
        return std::nullopt; // Incomplete frame
    }

    auto payload = data.subspan(offset, frame_length);
    offset += frame_length;

    FrameType frame_type = static_cast<FrameType>(frame_type_raw);

    ParsedFrame parsed;
    parsed.type = frame_type;

    switch (frame_type)
    {
    case FrameType::Data:
        {
            DataFrame df;
            df.payload = std::vector<std::uint8_t>(payload.begin(), payload.end());
            parsed.frame = std::move(df);
            break;
        }
    case FrameType::Headers:
        {
            HeadersFrame hf;
            hf.header_block = std::vector<std::uint8_t>(payload.begin(), payload.end());
            parsed.frame = std::move(hf);
            break;
        }
    case FrameType::Settings:
        {
            SettingsFrame sf;
            std::size_t settings_offset = 0;
            while (settings_offset < payload.size())
            {
                auto id_result = DecodeVarint(payload.subspan(settings_offset));
                if (!id_result)
                    break;
                auto [setting_id, id_len] = *id_result;
                settings_offset += id_len;

                auto value_result = DecodeVarint(payload.subspan(settings_offset));
                if (!value_result)
                    break;
                auto [setting_value, value_len] = *value_result;
                settings_offset += value_len;

                sf.settings[setting_id] = setting_value;
            }
            parsed.frame = std::move(sf);
            break;
        }
    case FrameType::Goaway:
        {
            auto id_result = DecodeVarint(payload);
            if (!id_result)
            {
                return std::nullopt;
            }
            GoawayFrame gf;
            gf.stream_id = id_result->first;
            parsed.frame = std::move(gf);
            break;
        }
    case FrameType::MaxPushId:
        {
            auto id_result = DecodeVarint(payload);
            if (!id_result)
            {
                return std::nullopt;
            }
            MaxPushIdFrame mpf;
            mpf.push_id = id_result->first;
            parsed.frame = std::move(mpf);
            break;
        }
    default:
        // Unknown frame type - skip it per RFC 9114 Section 9
        // Return a DATA frame as placeholder
        DataFrame df;
        parsed.frame = std::move(df);
        break;
    }

    return std::make_pair(std::move(parsed), offset);
}

/**
 * @brief Serialize HTTP/3 frame to bytes
 *
 * @param frame Frame to serialize
 * @return Serialized frame bytes
 */
inline std::vector<std::uint8_t> SerializeFrame(const Frame &frame)
{
    std::vector<std::uint8_t> result;

    std::visit(
        [&result](const auto &f)
    {
        using T = std::decay_t<decltype(f)>;

        if constexpr (std::is_same_v<T, DataFrame>)
        {
            auto type_bytes = EncodeVarintToVector(static_cast<std::uint64_t>(FrameType::Data));
            auto length_bytes = EncodeVarintToVector(f.payload.size());
            result.insert(result.end(), type_bytes.begin(), type_bytes.end());
            result.insert(result.end(), length_bytes.begin(), length_bytes.end());
            result.insert(result.end(), f.payload.begin(), f.payload.end());
        }
        else if constexpr (std::is_same_v<T, HeadersFrame>)
        {
            auto type_bytes = EncodeVarintToVector(static_cast<std::uint64_t>(FrameType::Headers));
            auto length_bytes = EncodeVarintToVector(f.header_block.size());
            result.insert(result.end(), type_bytes.begin(), type_bytes.end());
            result.insert(result.end(), length_bytes.begin(), length_bytes.end());
            result.insert(result.end(), f.header_block.begin(), f.header_block.end());
        }
        else if constexpr (std::is_same_v<T, SettingsFrame>)
        {
            // First, calculate payload size
            std::vector<std::uint8_t> payload;
            for (const auto &[id, value] : f.settings)
            {
                auto id_bytes = EncodeVarintToVector(id);
                auto value_bytes = EncodeVarintToVector(value);
                payload.insert(payload.end(), id_bytes.begin(), id_bytes.end());
                payload.insert(payload.end(), value_bytes.begin(), value_bytes.end());
            }

            auto type_bytes = EncodeVarintToVector(static_cast<std::uint64_t>(FrameType::Settings));
            auto length_bytes = EncodeVarintToVector(payload.size());
            result.insert(result.end(), type_bytes.begin(), type_bytes.end());
            result.insert(result.end(), length_bytes.begin(), length_bytes.end());
            result.insert(result.end(), payload.begin(), payload.end());
        }
        else if constexpr (std::is_same_v<T, GoawayFrame>)
        {
            auto id_bytes = EncodeVarintToVector(f.stream_id);
            auto type_bytes = EncodeVarintToVector(static_cast<std::uint64_t>(FrameType::Goaway));
            auto length_bytes = EncodeVarintToVector(id_bytes.size());
            result.insert(result.end(), type_bytes.begin(), type_bytes.end());
            result.insert(result.end(), length_bytes.begin(), length_bytes.end());
            result.insert(result.end(), id_bytes.begin(), id_bytes.end());
        }
        else if constexpr (std::is_same_v<T, MaxPushIdFrame>)
        {
            auto id_bytes = EncodeVarintToVector(f.push_id);
            auto type_bytes = EncodeVarintToVector(static_cast<std::uint64_t>(FrameType::MaxPushId));
            auto length_bytes = EncodeVarintToVector(id_bytes.size());
            result.insert(result.end(), type_bytes.begin(), type_bytes.end());
            result.insert(result.end(), length_bytes.begin(), length_bytes.end());
            result.insert(result.end(), id_bytes.begin(), id_bytes.end());
        }
    },
        frame);

    return result;
}

} // namespace clv::http3
