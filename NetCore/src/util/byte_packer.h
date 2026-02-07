// Copyright (c) 2023- Charlie Vigue. All rights reserved.

// Small header to provide byte-packing helpers used by things like networking.
// Places the helpers in the netcore namespace.

#ifndef CLV_NETCORE_BYTE_PACKER_HPP
#define CLV_NETCORE_BYTE_PACKER_HPP

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>

namespace clv::netcore {

/**
 * @brief Packs a sequence of bytes into an unsigned integer in big-endian order.
 * @tparam Out The output unsigned integer type.
 * @tparam Bytes A variadic pack of integral byte values.
 * @param bytes The byte values to pack.
 * @return The packed unsigned integer.
 * @details This function takes a sequence of byte values and packs them into
 *          an unsigned integer of type `Out` in big-endian order. The number of
 *          bytes provided must not exceed the size of the output type.
 * @example
 *   auto value = bytes_to_uint<std::uint32_t>(0x12, 0x34, 0x56, 0x78); // value == 0x12345678
 *   auto value2 = bytes_to_uint(0x12, 0x34); // deduces uint16_t, value2 == 0x1234
 */
template <std::unsigned_integral Out, std::integral... Bytes>
[[nodiscard]] constexpr Out bytes_to_uint(Bytes... bytes) noexcept
{
    static_assert(sizeof...(Bytes) > 0, "must provide at least one byte");
    static_assert(sizeof...(Bytes) <= sizeof(Out), "too many bytes for requested output type");

    Out result = 0;
    ((result = (result << 8) | static_cast<Out>(bytes)), ...);
    return result;
}

/**
 * @brief Packs a sequence of bytes into an appropriately sized unsigned integer in big-endian order.
 * @tparam Bytes A variadic pack of integral byte values.
 * @param bytes The byte values to pack.
 * @return The packed unsigned integer.
 * @details This function deduces the smallest unsigned integer type that can hold
 *          the provided number of bytes and packs them into that type in big-endian order.
 * @example
 *   auto value = bytes_to_uint(0x12, 0x34, 0x56, 0x78); // deduces uint32_t, value == 0x12345678
 *   auto value2 = bytes_to_uint(0x12, 0x34); // deduces uint16_t, value2 == 0x1234
 */
template <std::integral... Bytes>
[[nodiscard]] constexpr auto bytes_to_uint(Bytes... bytes) noexcept
{
    constexpr std::size_t N = sizeof...(Bytes);
    static_assert(N > 0, "must provide at least one byte");
    static_assert(N <= 8, "up to 8 bytes are supported for deduction");

    using out_t = std::conditional_t<
        (N <= 1),
        std::uint8_t,
        std::conditional_t<
            (N <= 2),
            std::uint16_t,
            std::conditional_t<
                (N <= 4),
                std::uint32_t,
                std::uint64_t>>>;

    std::uintmax_t acc = 0;
    ((acc = (acc << 8) | static_cast<std::uintmax_t>(bytes)), ...);
    return static_cast<out_t>(acc);
}

/**
 * @brief Unpacks an unsigned integer into a sequence of bytes in big-endian order.
 * @tparam N The number of bytes to produce.
 * @tparam T The unsigned integer type of the input value.
 * @param value The unsigned integer to unpack.
 * @return A std::array of bytes representing the input value in big-endian order.
 * @details This function extracts bytes from the input unsigned integer and stores
 *          them in a std::array in big-endian order (most significant byte first).
 * @example
 *   auto bytes = uint_to_bytes<4>(0x12345678);  // std::array<uint8_t, 4>{0x12, 0x34, 0x56, 0x78}
 *   auto bytes = uint_to_bytes<2>(port);         // 2-byte big-endian
 *   auto bytes = uint_to_bytes<8>(packet_num);   // 8-byte big-endian
 */
template <std::size_t N, std::unsigned_integral T>
[[nodiscard]] constexpr std::array<std::uint8_t, N> uint_to_bytes(T value) noexcept
{
    static_assert(N > 0, "must produce at least one byte");
    static_assert(N <= sizeof(T), "cannot produce more bytes than the input type contains");

    std::array<std::uint8_t, N> result{};
    for (std::size_t i = 0; i < N; ++i)
    {
        result[N - 1 - i] = static_cast<std::uint8_t>(value & 0xFF);
        if constexpr (N > 1 && sizeof(T) > 1)
        {
            value >>= 8;
        }
    }
    return result;
}

/**
 * @brief Unpacks an unsigned integer into a sequence of bytes in big-endian order.
 * @tparam T The unsigned integer type of the input value.
 * @param value The unsigned integer to unpack.
 * @return A std::array of bytes representing the input value in big-endian order.
 * @details This function extracts bytes from the input unsigned integer and stores
 *          them in a std::array in big-endian order (most significant byte first).
 * @example
 *   auto bytes = uint_to_bytes(std::uint32_t{0x12345678});  // std::array<uint8_t, 4>{0x12, 0x34, 0x56, 0x78}
 *   auto bytes = uint_to_bytes(std::uint16_t{port});        // std::array<uint8_t, 2>
 */
template <std::unsigned_integral T>
[[nodiscard]] constexpr std::array<std::uint8_t, sizeof(T)> uint_to_bytes(T value) noexcept
{
    return uint_to_bytes<sizeof(T)>(value);
}

/**
 * @brief Packs multiple unsigned integers into a single byte array in big-endian order.
 * @tparam Ts A variadic pack of unsigned integer types.
 * @param values The unsigned integer values to pack.
 * @return A std::array of bytes representing the packed unsigned integers in big-endian order.
 * @details This function takes multiple unsigned integer values and packs them into
 *          a single std::array in big-endian order. It is more efficient than
 *          calling `uint_to_bytes` separately for each value, as it avoids creating
 *          intermediate arrays.
 * @example
 *   auto bytes = multi_uint_to_bytes(std::uint8_t{0x12}, std::uint32_t{0x34567890});
 *      // Returns std::array<uint8_t, 5>{0x12, 0x34, 0x56, 0x78, 0x90}
 *   auto header = multi_uint_to_bytes(first_byte, version, packet_num);
 *   out.insert(out.end(), header.begin(), header.end());
 */
template <std::unsigned_integral... Ts>
[[nodiscard]] constexpr auto multi_uint_to_bytes(Ts... values) noexcept
{
    constexpr std::size_t total_size = (sizeof(Ts) + ...);
    std::array<std::uint8_t, total_size> result{};

    std::size_t offset = 0;
    // Fold expression to process each value
    ([&]()
    {
        auto bytes = uint_to_bytes(values);
        for (std::size_t i = 0; i < sizeof(values); ++i)
        {
            result[offset++] = bytes[i];
        }
    }(),
     ...);

    return result;
}

// ========== Buffer Reading ==========

/**
 * @brief Read N bytes from a buffer as an unsigned integer in big-endian order.
 * @tparam N The number of bytes to read (1-8).
 * @param data The buffer to read from (must have at least N bytes).
 * @return The unpacked unsigned integer.
 * @details This function reads N bytes from the buffer and interprets them as
 *          a big-endian unsigned integer. The return type is automatically
 *          selected based on N.
 * @example
 *   auto val = read_uint<4>(data);  // reads 4 bytes as uint32_t
 *   auto id = read_uint<8>(data);   // reads 8 bytes as uint64_t
 */
template <std::size_t N>
[[nodiscard]] constexpr auto read_uint(std::span<const std::uint8_t> data) noexcept
{
    static_assert(N > 0 && N <= 8, "N must be 1-8 bytes");

    using out_t = std::conditional_t<
        (N <= 1),
        std::uint8_t,
        std::conditional_t<
            (N <= 2),
            std::uint16_t,
            std::conditional_t<
                (N <= 4),
                std::uint32_t,
                std::uint64_t>>>;

    out_t result = 0;
    for (std::size_t i = 0; i < N && i < data.size(); ++i)
    {
        result = static_cast<out_t>((result << 8) | data[i]);
    }
    return result;
}

/**
 * @brief Read sizeof(T) bytes from a buffer as type T in big-endian order.
 * @tparam T The unsigned integer type to read.
 * @param data The buffer to read from.
 * @return The unpacked unsigned integer.
 * @example
 *   auto val = read_uint<std::uint32_t>(data);  // reads 4 bytes
 */
template <std::unsigned_integral T>
[[nodiscard]] constexpr T read_uint(std::span<const std::uint8_t> data) noexcept
{
    return static_cast<T>(read_uint<sizeof(T)>(data));
}

/**
 * @brief Write an unsigned integer to a buffer in big-endian order.
 * @tparam N The number of bytes to write.
 * @tparam T The unsigned integer type.
 * @param dest The destination buffer (must have at least N bytes).
 * @param value The value to write.
 * @example
 *   write_uint<4>(buffer, packet_id);   // writes 4 bytes
 *   write_uint<8>(buffer, session_id);  // writes 8 bytes
 */
template <std::size_t N, std::unsigned_integral T>
constexpr void write_uint(std::span<std::uint8_t> dest, T value) noexcept
{
    static_assert(N > 0 && N <= sizeof(T), "N must be 1 to sizeof(T)");

    for (std::size_t i = 0; i < N && i < dest.size(); ++i)
    {
        dest[N - 1 - i] = static_cast<std::uint8_t>(value & 0xFF);
        value >>= 8;
    }
}

/**
 * @brief Write an unsigned integer to a buffer in big-endian order (full size).
 * @tparam T The unsigned integer type.
 * @param dest The destination buffer.
 * @param value The value to write.
 */
template <std::unsigned_integral T>
constexpr void write_uint(std::span<std::uint8_t> dest, T value) noexcept
{
    write_uint<sizeof(T)>(dest, value);
}

// ========== Length-Prefixed String Packing ==========

/**
 * @brief Append a length-prefixed, null-terminated string to a byte container.
 * @tparam LenBytes The number of bytes for the length prefix (1, 2, or 4).
 * @tparam Container A container type with push_back and insert (e.g., std::vector<uint8_t>).
 * @param dest The destination container to append to.
 * @param str The string to pack.
 * @details Writes the string length (including null terminator) as a big-endian integer,
 *          followed by the string bytes, followed by a null terminator.
 * @example
 *   std::vector<uint8_t> buffer;
 *   append_length_prefixed_string<2>(buffer, "hello");
 *   // buffer contains: [0x00, 0x06, 'h', 'e', 'l', 'l', 'o', 0x00]
 */
template <std::size_t LenBytes = 2, typename Container>
void append_length_prefixed_string(Container &dest, std::string_view str)
{
    static_assert(LenBytes == 1 || LenBytes == 2 || LenBytes == 4,
                  "LenBytes must be 1, 2, or 4");

    using len_t = std::conditional_t<
        (LenBytes == 1),
        std::uint8_t,
        std::conditional_t<(LenBytes == 2), std::uint16_t, std::uint32_t>>;

    auto len_bytes = uint_to_bytes(static_cast<len_t>(str.length() + 1));
    dest.insert(dest.end(), len_bytes.begin(), len_bytes.end());
    dest.insert(dest.end(), str.begin(), str.end());
    dest.push_back(0x00);
}

/**
 * @brief Read a length-prefixed, null-terminated string from a buffer.
 * @tparam LenBytes The number of bytes for the length prefix (1, 2, or 4).
 * @param data The buffer to read from.
 * @param pos The current position in the buffer (updated on success).
 * @return The extracted string, or std::nullopt if insufficient data.
 * @details Reads the length prefix as a big-endian integer, then extracts
 *          the string (excluding the null terminator).
 * @example
 *   size_t pos = 0;
 *   auto str = read_length_prefixed_string<2>(data, pos);
 *   if (str) { // use *str }
 */
template <std::size_t LenBytes = 2>
[[nodiscard]] std::optional<std::string> read_length_prefixed_string(
    std::span<const std::uint8_t> data,
    std::size_t &pos)
{
    static_assert(LenBytes == 1 || LenBytes == 2 || LenBytes == 4,
                  "LenBytes must be 1, 2, or 4");

    if (pos + LenBytes > data.size())
        return std::nullopt;

    auto len = read_uint<LenBytes>(data.subspan(pos));
    pos += LenBytes;

    if (len == 0)
        return std::string{};

    if (pos + len > data.size())
        return std::nullopt;

    // String includes null terminator, extract len-1 bytes
    std::size_t str_len = len > 1 ? len - 1 : 0;
    std::string result(reinterpret_cast<const char *>(data.data() + pos), str_len);
    pos += len;

    return result;
}

} // namespace clv::netcore

#endif // CLV_NETCORE_BYTE_PACKER_HPP
