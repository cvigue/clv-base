// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <openssl/evp.h>
#include <spdlog/spdlog.h>

#include "connection_id.h"
#include "numeric_util.h"
#include <result_or.h>
#include "quic_packet.h"
#include "util/byte_packer.h"

// Use SslHelp wrappers for QUIC crypto (works with quictls/openssl)
#include "HelpSslEvpPkeyCtx.h"
#include "HelpSslCipher.h"

namespace clv::quic {

using OpenSSL::SslEvpPkeyCtx;
// Use free functions for AEAD/ECB operations
using OpenSSL::AES_128_ECB_TRAITS;
using OpenSSL::AES_128_GCM_TRAITS;
using OpenSSL::DecryptAead;
using OpenSSL::EncryptAead;
using OpenSSL::EncryptEcb;

/// QUIC encryption level / key phase
enum class EncryptionLevel : std::uint8_t
{
    Initial = 0,     // Derived from connection ID (RFC 9001 §5.2)
    Handshake = 1,   // After ClientHello/ServerHello exchange
    Application = 2, // After handshake complete
    EarlyData = 3    // 0-RTT (future support)
}; // "Better make up something quic(k)" - Heart, Barracuda (1980)

/// Convert from QuicEncryptionLevel (OpenSSL/quictls numbering) to EncryptionLevel (QUIC RFC numbering)
/// OpenSSL: Initial=0, EarlyData=1, Handshake=2, Application=3
/// QUIC:    Initial=0, Handshake=1, Application=2, EarlyData=3
inline EncryptionLevel FromQuicTlsLevel(int level) noexcept
{
    switch (level)
    {
    case 0:
        return EncryptionLevel::Initial; // ssl_encryption_initial
    case 1:
        return EncryptionLevel::EarlyData; // ssl_encryption_early_data
    case 2:
        return EncryptionLevel::Handshake; // ssl_encryption_handshake
    case 3:
        return EncryptionLevel::Application; // ssl_encryption_application
    default:
        return EncryptionLevel::Initial;
    }
}

/// Convert from EncryptionLevel (QUIC RFC numbering) to OpenSSL ssl_encryption_level_t integer
/// QUIC:    Initial=0, Handshake=1, Application=2, EarlyData=3
/// OpenSSL: Initial=0, EarlyData=1, Handshake=2, Application=3
inline int ToQuicTlsLevel(EncryptionLevel level) noexcept
{
    switch (level)
    {
    case EncryptionLevel::Initial:
        return 0; // ssl_encryption_initial
    case EncryptionLevel::EarlyData:
        return 1; // ssl_encryption_early_data
    case EncryptionLevel::Handshake:
        return 2; // ssl_encryption_handshake
    case EncryptionLevel::Application:
        return 3; // ssl_encryption_application
    default:
        return 0;
    }
}

/// Packet protection keys for a single encryption level
struct PacketKeys
{
    std::array<std::uint8_t, 32> key{};    // AEAD key (AES-128-GCM uses 16, AES-256-GCM uses 32)
    std::array<std::uint8_t, 12> iv{};     // IV (nonce) base
    std::array<std::uint8_t, 16> hp_key{}; // Header protection key
    std::size_t key_length{16};            // Actual key length used
    std::size_t iv_length{12};             // Actual IV length used
};

// RFC 9001 constants for initial secrets
namespace detail {

// clang-format off
// QUIC version 1 initial salt (RFC 9001 §5.2)
inline constexpr std::array<std::uint8_t, 20> kInitialSalt = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};
// clang-format on

// HKDF labels for initial key derivation
inline constexpr std::string_view kClientInitialLabel = "client in";
inline constexpr std::string_view kServerInitialLabel = "server in";
inline constexpr std::string_view kQuicKeyLabel = "quic key";
inline constexpr std::string_view kQuicIvLabel = "quic iv";
inline constexpr std::string_view kQuicHpLabel = "quic hp";
inline constexpr std::string_view kQuicKuLabel = "quic ku"; // Key update (RFC 9001 §6)

/// HKDF-Expand-Label for QUIC (RFC 9001 §5.1) - runtime size
inline std::vector<std::uint8_t> HkdfExpandLabel(std::span<const std::uint8_t> secret,
                                                 std::string_view label,
                                                 std::size_t length)
{
    // QuicHkdfLabel structure:
    // struct {
    //     uint16 length = Length;
    //     opaque label<7..255> = "tls13 " + Label;
    //     opaque context<0..255> = Context;
    // } QuicHkdfLabel;

    const std::string_view prefix = "tls13 ";

    std::vector<std::uint8_t> hkdf_label;

    // Reserve: length(2) + label_len(1) + "tls13 "(6) + label + context_len(1)
    hkdf_label.reserve(sizeof(uint16_t) + 1 + prefix.size() + label.size() + 1);

    // Length (2 bytes, big-endian)
    auto len_bytes = netcore::uint_to_bytes<2>(length);
    hkdf_label.insert(hkdf_label.end(), len_bytes.begin(), len_bytes.end());

    // Label length + "tls13 " prefix
    const std::size_t label_len = prefix.size() + label.size();
    hkdf_label.push_back(static_cast<std::uint8_t>(label_len));

    // Label content
    hkdf_label.insert(hkdf_label.end(), prefix.begin(), prefix.end());
    hkdf_label.insert(hkdf_label.end(), label.begin(), label.end());

    // Context length (empty for QUIC initial secrets)
    hkdf_label.push_back(0);

    // Perform HKDF-Expand with the constructed label as info
    return SslEvpPkeyCtx::ExpandHkdf(EVP_sha256(),
                                     SslEvpPkeyCtx::Key(secret.data(), secret.size()),
                                     SslEvpPkeyCtx::Info(hkdf_label.data(), hkdf_label.size()),
                                     length);
}

/// HKDF-Expand-Label for QUIC (RFC 9001 §5.1) - fixed size (zero allocation)
template <std::size_t N>
inline std::array<std::uint8_t, N> HkdfExpandLabel(std::span<const std::uint8_t> secret,
                                                   std::string_view label)
{
    const std::string_view prefix = "tls13 ";

    std::vector<std::uint8_t> hkdf_label;
    hkdf_label.reserve(sizeof(uint16_t) + 1 + prefix.size() + label.size() + 1);

    // Length (2 bytes, big-endian)
    auto len_bytes = netcore::uint_to_bytes<2>(N);
    hkdf_label.insert(hkdf_label.end(), len_bytes.begin(), len_bytes.end());

    // Label length + "tls13 " prefix
    const std::size_t label_len = prefix.size() + label.size();
    hkdf_label.push_back(static_cast<std::uint8_t>(label_len));

    // Label content
    hkdf_label.insert(hkdf_label.end(), prefix.begin(), prefix.end());
    hkdf_label.insert(hkdf_label.end(), label.begin(), label.end());

    // Context length (empty for QUIC initial secrets)
    hkdf_label.push_back(0);

    // Perform HKDF-Expand with the constructed label as info
    return SslEvpPkeyCtx::ExpandHkdf<N>(EVP_sha256(),
                                        SslEvpPkeyCtx::Key(secret.data(), secret.size()),
                                        SslEvpPkeyCtx::Info(hkdf_label.data(), hkdf_label.size()));
}

} // namespace detail

/// HKDF-Expand-Label for QUIC (RFC 9001 §5.1) - public API with context support
/// @param secret Input key material
/// @param label QUIC-specific label (e.g., "quic key", "quic iv", "quic hp")
/// @param context Context data (typically empty for QUIC)
/// @param length Output length in bytes
/// @return Derived key material or empty on error
[[nodiscard]] inline std::vector<std::uint8_t> HkdfExpandLabel(std::span<const std::uint8_t> secret,
                                                               std::string_view label,
                                                               std::span<const std::uint8_t> context,
                                                               std::size_t length) noexcept
{
    if (secret.empty() || length == 0)
        return {};

    try
    {
        // QuicHkdfLabel structure:
        // struct {
        //     uint16 length = Length;
        //     opaque label<7..255> = "tls13 " + Label;
        //     opaque context<0..255> = Context;
        // } QuicHkdfLabel;

        const std::string_view prefix = "tls13 ";

        std::vector<std::uint8_t> hkdf_label;

        // Reserve: length(2) + label_len(1) + "tls13 "(6) + label + context_len(1) + context
        hkdf_label.reserve(sizeof(uint16_t) + 1 + prefix.size() + label.size() + 1 + context.size());

        // Length (2 bytes, big-endian)
        auto len_bytes = netcore::uint_to_bytes<2>(length);
        hkdf_label.insert(hkdf_label.end(), len_bytes.begin(), len_bytes.end());

        // Label length + "tls13 " prefix
        const std::size_t label_len = prefix.size() + label.size();
        hkdf_label.push_back(static_cast<std::uint8_t>(label_len));

        // Label content
        hkdf_label.insert(hkdf_label.end(), prefix.begin(), prefix.end());
        hkdf_label.insert(hkdf_label.end(), label.begin(), label.end());

        // Context length and data
        hkdf_label.push_back(static_cast<std::uint8_t>(context.size()));
        if (!context.empty())
        {
            hkdf_label.insert(hkdf_label.end(), context.begin(), context.end());
        }

        // Perform HKDF-Expand with the constructed label as info
        return SslEvpPkeyCtx::ExpandHkdf(EVP_sha256(),
                                         SslEvpPkeyCtx::Key(secret.data(), secret.size()),
                                         SslEvpPkeyCtx::Info(hkdf_label.data(), hkdf_label.size()),
                                         length);
    }
    catch (...)
    {
        return {};
    }
}

/**
 * @brief QUIC-TLS integration for packet protection and handshake
 * @details Manages key derivation, TLS handshake data, and packet protection keys
 *          for different encryption levels. Integrates with OpenSSL for HKDF and TLS operations.
 *
 *   This class manages:
 *  - Initial key derivation from connection ID (RFC 9001 §5.2)
 *  - TLS 1.3 handshake via CRYPTO frames
 *  - Packet encryption/decryption (AEAD with AES-128-GCM)
 *  - Header protection/unprotection
 *  - Key updates during connection lifetime
 *
 * @note Currently supports only AES-128-GCM for packet protection.
 */
class QuicCrypto
{
  public:
    /// Create server-side crypto context
    [[nodiscard]] static clv::result_or<QuicCrypto, std::errc> CreateServer(const ConnectionId &conn_id)
    {
        std::string hex_str;
        for (std::uint8_t i = 0; i < conn_id.length; ++i)
        {
            hex_str += fmt::format("{:02x}", conn_id.data[i]);
        }
        spdlog::debug("QuicCrypto::CreateServer: Deriving keys from connection ID (length={}, data={})",
                      conn_id.length,
                      hex_str);

        QuicCrypto crypto;
        crypto.is_server_ = true;

        auto client_keys = crypto.DeriveInitialKeys(conn_id, true);
        if (!client_keys)
            return client_keys.error();

        auto server_keys = crypto.DeriveInitialKeys(conn_id, false);
        if (!server_keys)
            return server_keys.error();

        crypto.initial_client_keys_ = std::move(*client_keys);
        crypto.initial_server_keys_ = std::move(*server_keys);

        return crypto;
    }

    /// Create client-side crypto context
    [[nodiscard]] static clv::result_or<QuicCrypto, std::errc> CreateClient(const ConnectionId &conn_id)
    {
        std::string hex_str;
        for (std::uint8_t i = 0; i < conn_id.length; ++i)
        {
            hex_str += fmt::format("{:02x}", conn_id.data[i]);
        }
        spdlog::debug("QuicCrypto::CreateClient: Deriving keys from connection ID (length={}, data={})",
                      conn_id.length,
                      hex_str);

        QuicCrypto crypto;
        crypto.is_server_ = false;

        auto client_keys = crypto.DeriveInitialKeys(conn_id, true);
        if (!client_keys)
            return client_keys.error();

        auto server_keys = crypto.DeriveInitialKeys(conn_id, false);
        if (!server_keys)
            return server_keys.error();

        crypto.initial_client_keys_ = std::move(*client_keys);
        crypto.initial_server_keys_ = std::move(*server_keys);

        return crypto;
    }

    QuicCrypto() = default;
    ~QuicCrypto() = default;
    QuicCrypto(const QuicCrypto &) = default;
    QuicCrypto &operator=(const QuicCrypto &) = default;
    QuicCrypto(QuicCrypto &&) noexcept = default;
    QuicCrypto &operator=(QuicCrypto &&) noexcept = default;

    /// Derive initial keys from connection ID (RFC 9001 §5.2)
    [[nodiscard]] clv::result_or<PacketKeys, std::errc> DeriveInitialKeys(
        const ConnectionId &conn_id,
        bool is_client) const
    {
        if (conn_id.length == 0)
            return std::errc::invalid_argument;

        // Step 1: HKDF-Extract with initial salt and connection ID
        auto initial_secret = SslEvpPkeyCtx::ExtractHkdf(
            EVP_sha256(),
            SslEvpPkeyCtx::Key(conn_id.data.data(), conn_id.length),
            SslEvpPkeyCtx::Salt(detail::kInitialSalt.data(), detail::kInitialSalt.size()));

        // Step 2: Derive client or server secret from initial_secret
        const auto &label = is_client ? detail::kClientInitialLabel : detail::kServerInitialLabel;
        auto secret = detail::HkdfExpandLabel<32>(initial_secret, label);

        // Step 3: Derive packet protection keys from the secret (zero allocation)
        PacketKeys keys;
        keys.key_length = 16; // AES-128-GCM
        keys.iv_length = 12;

        auto key = detail::HkdfExpandLabel<16>(secret, detail::kQuicKeyLabel);
        auto iv = detail::HkdfExpandLabel<12>(secret, detail::kQuicIvLabel);
        auto hp = detail::HkdfExpandLabel<16>(secret, detail::kQuicHpLabel);

        std::copy(key.begin(), key.end(), keys.key.begin());
        keys.iv = iv;
        keys.hp_key = hp;

        return keys;
    }

    /// Process incoming CRYPTO frame data (feed to TLS engine)
    [[nodiscard]] std::optional<std::errc> ProvideHandshakeData(
        EncryptionLevel /*level*/,
        std::span<const std::uint8_t> /*data*/) noexcept
    {
        // TODO: Route to TLS engine
        return std::nullopt;
    }

    /// Get outgoing CRYPTO frame data (from TLS engine)
    [[nodiscard]] std::vector<std::uint8_t> ConsumeHandshakeData(EncryptionLevel /*level*/) noexcept
    {
        // TODO: Read from TLS engine
        return {};
    }

    /// Check if TLS handshake is complete
    [[nodiscard]] bool IsHandshakeComplete() const noexcept
    {
        return handshake_complete_;
    }

    /// Simulate handshake completion and set application keys (for testing)
    /// In production, this would be called by the TLS engine after handshake
    void SetHandshakeComplete() noexcept
    {
        handshake_complete_ = true;

        // Derive application keys from initial keys (simplified for testing)
        // In real implementation, these would come from TLS handshake
        if (initial_client_keys_ && initial_server_keys_)
        {
            app_client_keys_ = *initial_client_keys_;
            app_server_keys_ = *initial_server_keys_;
        }
    }

    /// Get packet protection keys for a given encryption level
    [[nodiscard]] std::optional<PacketKeys> GetKeys(EncryptionLevel level, bool is_send) const noexcept
    {
        const bool use_server_keys = (is_server_ == is_send);

        spdlog::debug("GetKeys: level={}, is_send={}, is_server={}, use_server_keys={}",
                      static_cast<int>(level),
                      is_send,
                      is_server_,
                      use_server_keys);

        switch (level)
        {
        case EncryptionLevel::Initial:
            return use_server_keys ? initial_server_keys_ : initial_client_keys_;
        case EncryptionLevel::Handshake:
            spdlog::debug("GetKeys Handshake: handshake_server_keys_={}, handshake_client_keys_={}",
                          handshake_server_keys_.has_value(),
                          handshake_client_keys_.has_value());
            return use_server_keys ? handshake_server_keys_ : handshake_client_keys_;
        case EncryptionLevel::Application:
            return use_server_keys ? app_server_keys_ : app_client_keys_;
        case EncryptionLevel::EarlyData:
            return std::nullopt; // 0-RTT not supported yet
        }
        return std::nullopt;
    }

    /// Encrypt packet payload using AEAD (AES-128-GCM)
    [[nodiscard]] clv::result_or<std::vector<std::uint8_t>, std::errc> EncryptPacket(
        const PacketHeader &header,
        std::span<const std::uint8_t> payload,
        std::uint64_t packet_number,
        EncryptionLevel level) noexcept
    {
        // Serialize header to build AAD
        auto aad = SerializeHeader(header);
        return EncryptPacketWithAad(payload, packet_number, level, aad);
    }

    /// Encrypt packet payload using AEAD with explicit AAD
    /// Use this when you have the actual header bytes you'll put on the wire
    [[nodiscard]] clv::result_or<std::vector<std::uint8_t>, std::errc> EncryptPacketWithAad(
        std::span<const std::uint8_t> payload,
        std::uint64_t packet_number,
        EncryptionLevel level,
        std::span<const std::uint8_t> aad) noexcept
    {
        // Get encryption keys for this level
        auto keys_opt = GetKeys(level, true);
        if (!keys_opt)
        {
            spdlog::error("EncryptPacketWithAad: GetKeys failed for level {} (is_server={})",
                          static_cast<int>(level),
                          is_server_);
            return std::errc::invalid_argument;
        }

        const auto &keys = *keys_opt;

        // Construct nonce: IV ⊕ packet_number
        std::array<std::uint8_t, 12> nonce;
        std::copy(keys.iv.begin(), keys.iv.begin() + 12, nonce.begin());

        // XOR packet number into the last 8 bytes of nonce
        for (std::size_t i = 0; i < 8; ++i)
        {
            nonce[4 + i] ^= static_cast<std::uint8_t>((packet_number >> (56 - i * 8)) & 0xFF);
        }

        try
        {
            // Use first 16 bytes of key (AES-128)
            std::span<const std::uint8_t, 16> key_span(keys.key.data(), 16);
            return EncryptAead(AES_128_GCM_TRAITS, key_span, nonce, payload, aad);
        }
        catch (...)
        {
            return std::errc::io_error;
        }
    }

    /// Decrypt packet payload using AEAD
    [[nodiscard]] clv::result_or<std::vector<std::uint8_t>, std::errc> DecryptPacket(
        const PacketHeader &header,
        std::span<const std::uint8_t> ciphertext,
        std::uint64_t packet_number,
        EncryptionLevel level) noexcept
    {
        // Serialize header to build AAD
        auto aad = SerializeHeader(header);
        return DecryptPacketWithAad(ciphertext, packet_number, level, aad);
    }

    /// Decrypt packet payload using AEAD with explicit AAD
    /// Use this when you have the actual header bytes from the wire
    [[nodiscard]] clv::result_or<std::vector<std::uint8_t>, std::errc> DecryptPacketWithAad(
        std::span<const std::uint8_t> ciphertext,
        std::uint64_t packet_number,
        EncryptionLevel level,
        std::span<const std::uint8_t> aad) noexcept
    {
        // Get decryption keys for this level
        auto keys_opt = GetKeys(level, false);
        if (!keys_opt)
        {
            spdlog::warn("DecryptPacketWithAad: No keys available for level {}", static_cast<int>(level));
            return std::errc::invalid_argument;
        }

        const auto &keys = *keys_opt;

        spdlog::debug("DecryptPacketWithAad: level={}, is_server={}, ciphertext_size={}, aad_size={}, pn={}",
                      static_cast<int>(level),
                      is_server_,
                      ciphertext.size(),
                      aad.size(),
                      packet_number);

        // Construct nonce: IV ⊕ packet_number
        std::array<std::uint8_t, 12> nonce;
        std::copy(keys.iv.begin(), keys.iv.begin() + 12, nonce.begin());

        // XOR packet number into the last 8 bytes of nonce
        for (std::size_t i = 0; i < 8; ++i)
        {
            nonce[4 + i] ^= static_cast<std::uint8_t>((packet_number >> (56 - i * 8)) & 0xFF);
        }

        try
        {
            // Use first 16 bytes of key (AES-128)
            std::span<const std::uint8_t, 16> key_span(keys.key.data(), 16);
            auto decrypted = DecryptAead(AES_128_GCM_TRAITS, key_span, nonce, ciphertext, aad);
            spdlog::debug("DecryptPacketWithAad: SUCCESS - decrypted {} bytes", decrypted.size());
            return decrypted;
        }
        catch (const std::exception &e)
        {
            spdlog::warn("DecryptPacketWithAad: EXCEPTION - {}", e.what());
            return std::errc::io_error;
        }
        catch (...)
        {
            spdlog::warn("DecryptPacketWithAad: UNKNOWN EXCEPTION during decryption");
            return std::errc::io_error;
        }
    }

    /// Apply header protection (mask packet number and first byte) - RFC 9001 §5.4
    [[nodiscard]] std::optional<std::errc> ProtectHeader(
        std::span<std::uint8_t> header_bytes,
        std::size_t pn_offset,
        std::size_t pn_length,
        std::span<const std::uint8_t> sample,
        EncryptionLevel level) noexcept
    {
        if (sample.size() < 16)
            return std::errc::invalid_argument;

        if (pn_offset + pn_length > header_bytes.size())
            return std::errc::invalid_argument;

        // Get header protection key
        auto keys_opt = GetKeys(level, true);
        if (!keys_opt)
            return std::errc::invalid_argument;

        try
        {
            // Generate mask using AES-ECB
            std::span<const std::uint8_t, 16> hp_key_span(keys_opt->hp_key.data(), 16);
            std::span<const std::uint8_t, 16> sample_span(sample.data(), 16);
            auto mask = EncryptEcb(AES_128_ECB_TRAITS, hp_key_span, sample_span);

            // Mask the first byte (flags)
            // RFC 9001 §5.4.1: For long headers, mask lower 4 bits (0x0F)
            // For short headers, mask lower 5 bits (0x1F)
            bool is_long_header = (header_bytes[0] & 0x80) != 0;
            std::uint8_t flags_mask = is_long_header ? 0x0F : 0x1F;
            header_bytes[0] ^= safe_cast<std::uint8_t>(mask[0] & flags_mask);

            // Mask packet number bytes
            for (std::size_t i = 0; i < pn_length; ++i)
            {
                header_bytes[pn_offset + i] ^= mask[1 + i];
            }

            return std::nullopt; // Success
        }
        catch (...)
        {
            return std::errc::io_error;
        }
    }

    /// Remove header protection (unmask packet number and first byte) - RFC 9001 §5.4
    [[nodiscard]] clv::result_or<std::size_t, std::errc> UnprotectHeader(
        std::span<std::uint8_t> header_bytes,
        std::size_t pn_offset,
        std::span<const std::uint8_t> sample,
        EncryptionLevel level) noexcept
    {
        if (sample.size() < 16)
            return std::errc::invalid_argument;

        if (pn_offset >= header_bytes.size())
            return std::errc::invalid_argument;

        // Get header protection key
        auto keys_opt = GetKeys(level, false);
        if (!keys_opt)
            return std::errc::invalid_argument;

        try
        {
            // Generate mask using AES-ECB
            std::span<const std::uint8_t, 16> hp_key_span(keys_opt->hp_key.data(), 16);
            std::span<const std::uint8_t, 16> sample_span(sample.data(), 16);
            auto mask = EncryptEcb(AES_128_ECB_TRAITS, hp_key_span, sample_span);

            // Unmask the first byte to get packet number length
            // RFC 9001 §5.4.1: For long headers, mask lower 4 bits (0x0F)
            // For short headers, mask lower 5 bits (0x1F)
            bool is_long_header = (header_bytes[0] & 0x80) != 0;
            std::uint8_t flags_mask = is_long_header ? 0x0F : 0x1F;
            header_bytes[0] ^= safe_cast<std::uint8_t>(mask[0] & flags_mask);
            const std::size_t pn_length = (header_bytes[0] & 0x03) + 1; // Extract PN length from flags

            // Unmask packet number bytes
            for (std::size_t i = 0; i < pn_length; ++i)
            {
                if (pn_offset + i >= header_bytes.size())
                    return std::errc::invalid_argument;
                header_bytes[pn_offset + i] ^= mask[1 + i];
            }

            return pn_length; // Return the packet number length
        }
        catch (...)
        {
            return std::errc::io_error;
        }
    }

    /// Update to next key phase (for key rotation) - RFC 9001 §6
    /// Derives new application data keys from current keys using HKDF-Expand-Label("quic ku")
    [[nodiscard]] std::optional<std::errc> UpdateKeys() noexcept
    {
        // Can only update application data keys after handshake is complete
        if (!handshake_complete_)
            return std::errc::operation_not_permitted;

        if (!app_client_keys_ || !app_server_keys_)
            return std::errc::invalid_argument;

        try
        {
            // Derive new keys from existing application keys
            // RFC 9001 §6: next_secret = HKDF-Expand-Label(current_secret, "quic ku", "", Hash.length)
            auto new_client_keys = UpdatePacketKeys(*app_client_keys_);
            auto new_server_keys = UpdatePacketKeys(*app_server_keys_);

            app_client_keys_ = new_client_keys;
            app_server_keys_ = new_server_keys;

            // Toggle key phase bit
            key_phase_ ^= 1;

            return std::nullopt;
        }
        catch (...)
        {
            return std::errc::io_error;
        }
    }

    /// Get the currently active application data key phase
    [[nodiscard]] std::uint8_t GetKeyPhase() const noexcept
    {
        return key_phase_;
    }

    /// Check if we have secrets for a given encryption level
    [[nodiscard]] bool HasSecretsForLevel(EncryptionLevel level) const noexcept
    {
        switch (level)
        {
        case EncryptionLevel::Initial:
            return initial_client_keys_.has_value() && initial_server_keys_.has_value();
        case EncryptionLevel::Handshake:
            return handshake_client_keys_.has_value() && handshake_server_keys_.has_value();
        case EncryptionLevel::Application:
            return app_client_keys_.has_value() && app_server_keys_.has_value();
        default:
            return false;
        }
    }

    // ============================================================================================
    // Packet Number Encoding/Decoding (RFC 9000 §17.1)
    // ============================================================================================

    /// Encode packet number using variable-length encoding (1-4 bytes)
    /// Returns the encoded bytes and the number of bytes used (1-4)
    /// RFC 9000 §17.1: Packet numbers are encoded in 1, 2, 3, or 4 bytes based on largest_acked
    [[nodiscard]] static std::pair<std::array<std::uint8_t, 4>, std::size_t> EncodePacketNumber(
        std::uint64_t packet_number,
        std::uint64_t largest_acked) noexcept
    {
        std::array<std::uint8_t, 4> encoded{};

        // Calculate the number of bytes needed
        // We need enough bytes to represent (packet_number - largest_acked) with room for loss
        const std::uint64_t diff = packet_number - largest_acked;

        std::size_t num_bytes = 1;
        if (diff > 0x7F)
            num_bytes = 2; // > 127: need 2 bytes
        if (diff > 0x3FFF)
            num_bytes = 3; // > 16383: need 3 bytes
        if (diff > 0x1FFFFF)
            num_bytes = 4; // > 2097151: need 4 bytes

        // Encode in big-endian
        for (std::size_t i = 0; i < num_bytes; ++i)
        {
            encoded[num_bytes - 1 - i] = static_cast<std::uint8_t>(packet_number & 0xFF);
            packet_number >>= 8;
        }

        return {encoded, num_bytes};
    }

    /// Decode truncated packet number from wire format (RFC 9000 §A.3)
    /// @param truncated_pn The truncated packet number bytes from the wire
    /// @param pn_nbits Number of bits in the truncated packet number (8, 16, 24, or 32)
    /// @param expected_pn The next expected packet number (largest_pn + 1)
    /// @return The full 64-bit packet number
    [[nodiscard]] static std::uint64_t DecodePacketNumber(
        std::uint64_t truncated_pn,
        std::size_t pn_nbits,
        std::uint64_t expected_pn) noexcept
    {
        // RFC 9000 Appendix A.3 - Sample Packet Number Decoding Algorithm
        const std::uint64_t pn_win = 1ULL << pn_nbits;
        const std::uint64_t pn_hwin = pn_win / 2;
        const std::uint64_t pn_mask = pn_win - 1;

        // The incoming packet number should be greater than expected_pn - pn_hwin
        // and less than or equal to expected_pn + pn_hwin
        const std::uint64_t candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;

        // Need to handle underflow carefully for expected_pn - pn_hwin
        if (expected_pn > pn_hwin && candidate_pn <= expected_pn - pn_hwin && candidate_pn < (1ULL << 62) - pn_win)
        {
            return candidate_pn + pn_win;
        }
        else if (candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win)
        {
            return candidate_pn - pn_win;
        }

        return candidate_pn;
    }

    // ============================================================================================
    // Packet Number Space Management
    // ============================================================================================

    /// Get the next packet number to send for a given encryption level
    [[nodiscard]] std::uint64_t GetNextPacketNumber(EncryptionLevel level) const noexcept
    {
        switch (level)
        {
        case EncryptionLevel::Initial:
            return next_pn_initial_;
        case EncryptionLevel::Handshake:
            return next_pn_handshake_;
        case EncryptionLevel::Application:
            return next_pn_application_;
        case EncryptionLevel::EarlyData:
            return 0; // Not supported
        }
        return 0;
    }

    /// Increment packet number for a given encryption level (call after sending)
    void IncrementPacketNumber(EncryptionLevel level) noexcept
    {
        switch (level)
        {
        case EncryptionLevel::Initial:
            ++next_pn_initial_;
            break;
        case EncryptionLevel::Handshake:
            ++next_pn_handshake_;
            break;
        case EncryptionLevel::Application:
            ++next_pn_application_;
            break;
        case EncryptionLevel::EarlyData:
            break; // Not supported
        }
    }

    /// Get the largest acknowledged packet number for a given encryption level
    [[nodiscard]] std::uint64_t GetLargestAcked(EncryptionLevel level) const noexcept
    {
        switch (level)
        {
        case EncryptionLevel::Initial:
            return largest_acked_initial_;
        case EncryptionLevel::Handshake:
            return largest_acked_handshake_;
        case EncryptionLevel::Application:
            return largest_acked_application_;
        case EncryptionLevel::EarlyData:
            return 0;
        }
        return 0;
    }

    /// Update largest acknowledged packet number (called when processing ACK frames)
    void SetLargestAcked(EncryptionLevel level, std::uint64_t pn) noexcept
    {
        switch (level)
        {
        case EncryptionLevel::Initial:
            largest_acked_initial_ = std::max(largest_acked_initial_, pn);
            break;
        case EncryptionLevel::Handshake:
            largest_acked_handshake_ = std::max(largest_acked_handshake_, pn);
            break;
        case EncryptionLevel::Application:
            largest_acked_application_ = std::max(largest_acked_application_, pn);
            break;
        case EncryptionLevel::EarlyData:
            break;
        }
    }

    /// Set Handshake-level keys from TLS-derived secrets
    /// @param client_secret The client handshake traffic secret (32 bytes for SHA-256)
    /// @param server_secret The server handshake traffic secret (32 bytes for SHA-256)
    /// @return true on success, false on error
    bool SetHandshakeSecrets(std::span<const std::uint8_t> client_secret,
                             std::span<const std::uint8_t> server_secret) noexcept
    {
        if (client_secret.size() < 32 || server_secret.size() < 32)
            return false;

        try
        {
            // Derive client handshake keys
            PacketKeys client_keys;
            client_keys.key_length = 16; // AES-128-GCM
            client_keys.iv_length = 12;

            auto c_key = detail::HkdfExpandLabel<16>(client_secret, detail::kQuicKeyLabel);
            auto c_iv = detail::HkdfExpandLabel<12>(client_secret, detail::kQuicIvLabel);
            auto c_hp = detail::HkdfExpandLabel<16>(client_secret, detail::kQuicHpLabel);

            std::copy(c_key.begin(), c_key.end(), client_keys.key.begin());
            client_keys.iv = c_iv;
            client_keys.hp_key = c_hp;

            // Derive server handshake keys
            PacketKeys server_keys;
            server_keys.key_length = 16;
            server_keys.iv_length = 12;

            auto s_key = detail::HkdfExpandLabel<16>(server_secret, detail::kQuicKeyLabel);
            auto s_iv = detail::HkdfExpandLabel<12>(server_secret, detail::kQuicIvLabel);
            auto s_hp = detail::HkdfExpandLabel<16>(server_secret, detail::kQuicHpLabel);

            std::copy(s_key.begin(), s_key.end(), server_keys.key.begin());
            server_keys.iv = s_iv;
            server_keys.hp_key = s_hp;

            handshake_client_keys_ = client_keys;
            handshake_server_keys_ = server_keys;

            spdlog::debug("SetHandshakeSecrets: stored keys (is_server={}, client_has={}, server_has={})",
                          is_server_,
                          handshake_client_keys_.has_value(),
                          handshake_server_keys_.has_value());

            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    /// Set Application-level keys from TLS-derived secrets
    /// @param client_secret The client application traffic secret (32 bytes for SHA-256)
    /// @param server_secret The server application traffic secret (32 bytes for SHA-256)
    /// @return true on success, false on error
    bool SetApplicationSecrets(std::span<const std::uint8_t> client_secret,
                               std::span<const std::uint8_t> server_secret) noexcept
    {
        if (client_secret.size() < 32 || server_secret.size() < 32)
            return false;

        try
        {
            // Derive client application keys
            PacketKeys client_keys;
            client_keys.key_length = 16;
            client_keys.iv_length = 12;

            auto c_key = detail::HkdfExpandLabel<16>(client_secret, detail::kQuicKeyLabel);
            auto c_iv = detail::HkdfExpandLabel<12>(client_secret, detail::kQuicIvLabel);
            auto c_hp = detail::HkdfExpandLabel<16>(client_secret, detail::kQuicHpLabel);

            std::copy(c_key.begin(), c_key.end(), client_keys.key.begin());
            client_keys.iv = c_iv;
            client_keys.hp_key = c_hp;

            // Derive server application keys
            PacketKeys server_keys;
            server_keys.key_length = 16;
            server_keys.iv_length = 12;

            auto s_key = detail::HkdfExpandLabel<16>(server_secret, detail::kQuicKeyLabel);
            auto s_iv = detail::HkdfExpandLabel<12>(server_secret, detail::kQuicIvLabel);
            auto s_hp = detail::HkdfExpandLabel<16>(server_secret, detail::kQuicHpLabel);

            std::copy(s_key.begin(), s_key.end(), server_keys.key.begin());
            server_keys.iv = s_iv;
            server_keys.hp_key = s_hp;

            app_client_keys_ = client_keys;
            app_server_keys_ = server_keys;
            handshake_complete_ = true;

            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    /// Check if Handshake keys are available
    [[nodiscard]] bool HasHandshakeKeys() const noexcept
    {
        return handshake_client_keys_.has_value() && handshake_server_keys_.has_value();
    }

    /// Check if Application keys are available
    [[nodiscard]] bool HasApplicationKeys() const noexcept
    {
        return app_client_keys_.has_value() && app_server_keys_.has_value();
    }

  private:
    bool is_server_{false};
    bool handshake_complete_{false};
    std::uint8_t key_phase_{0};

    // Packet number tracking per encryption level
    std::uint64_t next_pn_initial_{0};
    std::uint64_t next_pn_handshake_{0};
    std::uint64_t next_pn_application_{0};
    std::uint64_t largest_acked_initial_{0};
    std::uint64_t largest_acked_handshake_{0};
    std::uint64_t largest_acked_application_{0};

    // Initial encryption keys (derived from connection ID)
    std::optional<PacketKeys> initial_client_keys_;
    std::optional<PacketKeys> initial_server_keys_;

    // Handshake keys (derived after ClientHello/ServerHello)
    std::optional<PacketKeys> handshake_client_keys_;
    std::optional<PacketKeys> handshake_server_keys_;

    // Application data keys (derived after handshake complete)
    std::optional<PacketKeys> app_client_keys_;
    std::optional<PacketKeys> app_server_keys_;

    /// Derive updated packet keys for key rotation (RFC 9001 §6)
    /// Uses current secret to derive: next_secret = HKDF-Expand-Label(secret, "quic ku", "", 32)
    [[nodiscard]] PacketKeys UpdatePacketKeys(const PacketKeys &current) const
    {
        // For key updates, we use the current key as the secret
        // RFC 9001 §6: next_secret = HKDF-Expand-Label(current_secret, "quic ku", "", Hash.length)
        std::span<const std::uint8_t> current_secret(current.key.data(), 32);

        // Derive new secret (32 bytes for SHA-256)
        auto new_secret = detail::HkdfExpandLabel<32>(current_secret, detail::kQuicKuLabel);

        // Derive new packet protection keys from the new secret
        PacketKeys new_keys;
        new_keys.key_length = 16; // AES-128-GCM
        new_keys.iv_length = 12;

        auto key = detail::HkdfExpandLabel<16>(new_secret, detail::kQuicKeyLabel);
        auto iv = detail::HkdfExpandLabel<12>(new_secret, detail::kQuicIvLabel);
        auto hp = detail::HkdfExpandLabel<16>(new_secret, detail::kQuicHpLabel);

        std::copy(key.begin(), key.end(), new_keys.key.begin());
        new_keys.iv = iv;
        new_keys.hp_key = hp;

        return new_keys;
    }
};

} // namespace clv::quic
