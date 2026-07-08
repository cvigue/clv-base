// Copyright (c) 2026- Charlie Vigue. All rights reserved.

#ifndef CLV_PARSE_INTAKE_H
#define CLV_PARSE_INTAKE_H

#include <charconv>
#include <concepts>
#include <cstdint>
#include <expected>
#include <format>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>

#include <nlohmann/json.hpp>

namespace clv {

enum class ParseError
{
    NotInteger,
    OutOfRange,
};

struct ParseContext
{
    std::string_view source;
    std::string_view field;
};

namespace detail {

template <typename T>
[[nodiscard]] constexpr bool parse_fits_range(long long parsed, T min_value, T max_value) noexcept
{
    return parsed >= static_cast<long long>(min_value) && parsed <= static_cast<long long>(max_value);
}

template <typename T>
[[nodiscard]] constexpr bool parse_fits_range(unsigned long long parsed, T min_value, T max_value) noexcept
{
    if constexpr (std::is_signed_v<T>)
    {
        if (parsed > static_cast<unsigned long long>(std::numeric_limits<T>::max()))
            return false;
        return static_cast<T>(parsed) >= min_value && static_cast<T>(parsed) <= max_value;
    }
    else
    {
        if (parsed > static_cast<unsigned long long>(max_value))
            return false;
        return parsed >= static_cast<unsigned long long>(min_value);
    }
}

template <std::signed_integral T>
[[nodiscard]] inline std::expected<T, ParseError> ParseBoundedSigned(std::string_view text,
                                                                     T min_value,
                                                                     T max_value) noexcept
{
    long long parsed = 0;
    const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), parsed);
    if (ec != std::errc{} || ptr != text.data() + text.size())
        return std::unexpected(ParseError::NotInteger);
    if (!parse_fits_range(parsed, min_value, max_value))
        return std::unexpected(ParseError::OutOfRange);
    return static_cast<T>(parsed);
}

template <std::unsigned_integral T>
[[nodiscard]] inline std::expected<T, ParseError> ParseBoundedUnsigned(std::string_view text,
                                                                       T min_value,
                                                                       T max_value) noexcept
{
    unsigned long long parsed = 0;
    const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), parsed);
    if (ec != std::errc{} || ptr != text.data() + text.size())
        return std::unexpected(ParseError::NotInteger);
    if (!parse_fits_range(parsed, min_value, max_value))
        return std::unexpected(ParseError::OutOfRange);
    return static_cast<T>(parsed);
}

} // namespace detail

template <std::integral T>
[[nodiscard]] inline std::expected<T, ParseError> ParseBounded(std::string_view text,
                                                               T min_value,
                                                               T max_value) noexcept
{
    if constexpr (std::is_signed_v<T>)
        return detail::ParseBoundedSigned(text, min_value, max_value);
    else
        return detail::ParseBoundedUnsigned(text, min_value, max_value);
}

[[nodiscard]] inline std::string FormatParseError(ParseContext ctx,
                                                  std::string_view text,
                                                  ParseError err)
{
    const auto where = ctx.field.empty() ? std::string(ctx.source) : std::format("{} '{}'", ctx.source, ctx.field);
    switch (err)
    {
    case ParseError::NotInteger:
        return std::format("{}: invalid integer value '{}'", where, text);
    case ParseError::OutOfRange:
        return std::format("{}: value out of range: '{}'", where, text);
    }
    return std::format("{}: parse error for '{}'", where, text);
}

template <std::integral T, typename ThrowFn>
[[nodiscard]] inline T ParseBoundedOrThrow(std::string_view text,
                                           T min_value,
                                           T max_value,
                                           ParseContext ctx,
                                           ThrowFn throw_fn)
{
    auto result = ParseBounded<T>(text, min_value, max_value);
    if (!result)
        throw throw_fn(FormatParseError(ctx, text, result.error()));
    return *result;
}

template <std::integral T>
[[nodiscard]] inline std::expected<T, ParseError> RequireJsonInt(const nlohmann::json &json,
                                                                 std::string_view key,
                                                                 T min_value,
                                                                 T max_value)
{
    const auto &val = json.at(std::string(key));
    if (!val.is_number_integer())
        return std::unexpected(ParseError::NotInteger);

    if constexpr (std::is_signed_v<T>)
    {
        const auto num = val.get<std::int64_t>();
        if (num < static_cast<std::int64_t>(min_value) || num > static_cast<std::int64_t>(max_value))
            return std::unexpected(ParseError::OutOfRange);
        return static_cast<T>(num);
    }
    else
    {
        const auto num = val.get<std::uint64_t>();
        if (num < static_cast<std::uint64_t>(min_value) || num > static_cast<std::uint64_t>(max_value))
            return std::unexpected(ParseError::OutOfRange);
        return static_cast<T>(num);
    }
}

template <std::integral T, typename ThrowFn>
[[nodiscard]] inline T RequireJsonIntOrThrow(const nlohmann::json &json,
                                             std::string_view key,
                                             T min_value,
                                             T max_value,
                                             ParseContext ctx,
                                             ThrowFn throw_fn)
{
    try
    {
        auto result = RequireJsonInt<T>(json, key, min_value, max_value);
        if (!result)
            throw throw_fn(FormatParseError({.source = ctx.source, .field = key}, key, result.error()));
        return *result;
    }
    catch (const nlohmann::json::exception &e)
    {
        throw throw_fn(std::format("{}: '{}': {}", ctx.source, key, e.what()));
    }
}

/** Parse JSON cpu/thread affinity: "off" → -1, "auto" → -2, or bounded integer. */
inline void ParseAffinityField(const nlohmann::json &json,
                               std::string_view key,
                               int &out,
                               int min_value = std::numeric_limits<int>::min(),
                               int max_value = std::numeric_limits<int>::max())
{
    if (!json.contains(std::string(key)))
        return;

    const auto &val = json.at(std::string(key));
    if (val.is_string())
    {
        const auto s = val.get<std::string>();
        if (s == "off")
            out = -1;
        else if (s == "auto")
            out = -2;
        return;
    }

    if (val.is_number_integer())
    {
        out = RequireJsonIntOrThrow<int>(
            json,
            key,
            min_value,
            max_value,
            {.source = "ConfigParser", .field = key},
            [](const std::string &msg)
            { return std::runtime_error(msg); });
    }
}

} // namespace clv

#endif // CLV_PARSE_INTAKE_H
