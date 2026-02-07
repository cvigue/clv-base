// Copyright (c) 2025- Charlie Vigue. All rights reserved.

#include "quic/quic_crypto.h"
#include "quic/connection_id.h"
#include "HelpSslException.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>

using namespace clv::quic;

// RFC 9001 Appendix A test vectors for initial key derivation
// https://www.rfc-editor.org/rfc/rfc9001.html#name-client-initial

namespace {

// Test connection ID from RFC 9001 Appendix A
// client_dst_connection_id = 0x8394c8f03e515708
constexpr std::array<std::uint8_t, 8> kTestConnIdBytes = {
    0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};

// Expected client initial secret (RFC 9001 A.1)
// constexpr std::array<std::uint8_t, 32> kExpectedClientInitialSecret = {
//     0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4, 0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea};

// Expected server initial secret (RFC 9001 A.2)
// constexpr std::array<std::uint8_t, 32> kExpectedServerInitialSecret = {
//     0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd, 0x21, 0x6c, 0x15, 0x5a, 0xd8, 0x44, 0xcc, 0x81, 0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46, 0xfa, 0x7d, 0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b};

// Expected client packet protection key (RFC 9001 A.1)
constexpr std::array<std::uint8_t, 16> kExpectedClientKey = {
    0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d};

// Expected client packet protection IV (RFC 9001 A.1)
constexpr std::array<std::uint8_t, 12> kExpectedClientIv = {
    0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c};

// Expected client header protection key (RFC 9001 A.1)
constexpr std::array<std::uint8_t, 16> kExpectedClientHp = {
    0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2};

// Expected server packet protection key (RFC 9001 A.2)
constexpr std::array<std::uint8_t, 16> kExpectedServerKey = {
    0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c, 0x88, 0xf0, 0xf3, 0x79, 0xb6, 0x06, 0x7e, 0x37};

// Expected server packet protection IV (RFC 9001 A.2)
constexpr std::array<std::uint8_t, 12> kExpectedServerIv = {
    0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53, 0xb0, 0xbb, 0xa0, 0x3e};

// Expected server header protection key (RFC 9001 A.2)
constexpr std::array<std::uint8_t, 16> kExpectedServerHp = {
    0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76, 0x44, 0x43, 0x0b, 0x49, 0x0e, 0xea, 0xa3, 0x14};

ConnectionId MakeTestConnectionId()
{
    ConnectionId cid;
    cid.length = static_cast<std::uint8_t>(kTestConnIdBytes.size());
    std::copy(kTestConnIdBytes.begin(), kTestConnIdBytes.end(), cid.data.begin());
    return cid;
}

template <std::size_t N>
bool BytesEqual(std::span<const std::uint8_t> actual, const std::array<std::uint8_t, N> &expected)
{
    if (actual.size() != N)
        return false;
    return std::equal(actual.begin(), actual.end(), expected.begin());
}

} // anonymous namespace

// Test initial key derivation for client
TEST(QuicCryptoTests, DeriveInitialKeys_Client_RFC9001_TestVectors)
{
    // Create a crypto context (client-side)
    auto conn_id = MakeTestConnectionId();
    auto crypto_result = QuicCrypto::CreateClient(conn_id);
    ASSERT_TRUE(crypto_result.has_value()) << "Failed to create client crypto context";

    auto &crypto = *crypto_result;

    // Derive client initial keys
    auto keys_result = crypto.DeriveInitialKeys(conn_id, true);
    ASSERT_TRUE(keys_result.has_value()) << "Failed to derive client initial keys";

    const auto &keys = *keys_result;

    // Verify key length
    EXPECT_EQ(keys.key_length, 16u) << "Client key length should be 16 bytes (AES-128)";
    EXPECT_EQ(keys.iv_length, 12u) << "Client IV length should be 12 bytes";

    // Verify key material matches RFC 9001 Appendix A.1
    EXPECT_TRUE(BytesEqual(std::span(keys.key.data(), keys.key_length), kExpectedClientKey))
        << "Client key does not match RFC 9001 test vector";

    EXPECT_TRUE(BytesEqual(std::span(keys.iv.data(), keys.iv_length), kExpectedClientIv))
        << "Client IV does not match RFC 9001 test vector";

    EXPECT_TRUE(BytesEqual(std::span(keys.hp_key.data(), 16), kExpectedClientHp))
        << "Client HP key does not match RFC 9001 test vector";
}

// Test initial key derivation for server
TEST(QuicCryptoTests, DeriveInitialKeys_Server_RFC9001_TestVectors)
{
    // Create a crypto context (server-side, needs cert/key paths which we'll skip for key derivation test)
    auto conn_id = MakeTestConnectionId();

    // For this test, we'll use the client creation which also derives keys correctly
    auto crypto_result = QuicCrypto::CreateClient(conn_id);
    ASSERT_TRUE(crypto_result.has_value()) << "Failed to create crypto context";

    auto &crypto = *crypto_result;

    // Derive server initial keys
    auto keys_result = crypto.DeriveInitialKeys(conn_id, false);
    ASSERT_TRUE(keys_result.has_value()) << "Failed to derive server initial keys";

    const auto &keys = *keys_result;

    // Verify key length
    EXPECT_EQ(keys.key_length, 16u) << "Server key length should be 16 bytes (AES-128)";
    EXPECT_EQ(keys.iv_length, 12u) << "Server IV length should be 12 bytes";

    // Verify key material matches RFC 9001 Appendix A.2
    EXPECT_TRUE(BytesEqual(std::span(keys.key.data(), keys.key_length), kExpectedServerKey))
        << "Server key does not match RFC 9001 test vector";

    EXPECT_TRUE(BytesEqual(std::span(keys.iv.data(), keys.iv_length), kExpectedServerIv))
        << "Server IV does not match RFC 9001 test vector";

    EXPECT_TRUE(BytesEqual(std::span(keys.hp_key.data(), 16), kExpectedServerHp))
        << "Server HP key does not match RFC 9001 test vector";
}

// Test that keys are properly stored in crypto context
TEST(QuicCryptoTests, GetKeys_InitialLevel)
{
    auto conn_id = MakeTestConnectionId();
    auto crypto_result = QuicCrypto::CreateClient(conn_id);
    ASSERT_TRUE(crypto_result.has_value());

    auto &crypto = *crypto_result;

    // Get client send keys (client perspective, so is_send=true uses client keys)
    auto send_keys = crypto.GetKeys(EncryptionLevel::Initial, true);
    ASSERT_TRUE(send_keys.has_value()) << "Client send keys should be available";

    // Get client receive keys (client perspective, so is_send=false uses server keys)
    auto recv_keys = crypto.GetKeys(EncryptionLevel::Initial, false);
    ASSERT_TRUE(recv_keys.has_value()) << "Client receive keys should be available";

    // Verify they're different (keys should not be the same)
    bool keys_different = !std::equal(
        send_keys->key.begin(),
        send_keys->key.begin() + send_keys->key_length,
        recv_keys->key.begin());
    EXPECT_TRUE(keys_different) << "Send and receive keys should be different";
}

// Test empty connection ID handling
TEST(QuicCryptoTests, DeriveInitialKeys_EmptyConnectionId)
{
    auto crypto_result = QuicCrypto::CreateClient(ConnectionId{});
    EXPECT_FALSE(crypto_result.has_value()) << "Should fail with empty connection ID";
}

// Test handshake state
TEST(QuicCryptoTests, HandshakeComplete_InitiallyFalse)
{
    auto conn_id = MakeTestConnectionId();
    auto crypto_result = QuicCrypto::CreateClient(conn_id);
    ASSERT_TRUE(crypto_result.has_value());

    auto &crypto = *crypto_result;
    EXPECT_FALSE(crypto.IsHandshakeComplete()) << "Handshake should not be complete initially";
}

// Test key phase tracking
TEST(QuicCryptoTests, KeyPhase_InitiallyZero)
{
    auto conn_id = MakeTestConnectionId();
    auto crypto_result = QuicCrypto::CreateClient(conn_id);
    ASSERT_TRUE(crypto_result.has_value());

    auto &crypto = *crypto_result;
    EXPECT_EQ(crypto.GetKeyPhase(), 0u) << "Key phase should be 0 initially";
}

// Test that handshake and application keys are not available initially
TEST(QuicCryptoTests, GetKeys_HandshakeAndAppNotAvailableInitially)
{
    auto conn_id = MakeTestConnectionId();
    auto crypto_result = QuicCrypto::CreateClient(conn_id);
    ASSERT_TRUE(crypto_result.has_value());

    auto &crypto = *crypto_result;

    // Handshake keys should not be available yet
    auto hs_keys = crypto.GetKeys(EncryptionLevel::Handshake, true);
    EXPECT_FALSE(hs_keys.has_value()) << "Handshake keys should not be available initially";

    // Application keys should not be available yet
    auto app_keys = crypto.GetKeys(EncryptionLevel::Application, true);
    EXPECT_FALSE(app_keys.has_value()) << "Application keys should not be available initially";

    // Early data keys should not be available (not supported)
    auto early_keys = crypto.GetKeys(EncryptionLevel::EarlyData, true);
    EXPECT_FALSE(early_keys.has_value()) << "Early data keys should not be available";
}

// Test HkdfExpandLabel with empty secret
// OpenSSL/quictls throws on null/empty secret unlike BoringSSL
TEST(QuicCryptoTests, HkdfExpandLabel_EmptySecret_Throws)
{
    using namespace clv::quic::detail;

    std::span<const std::uint8_t> empty_secret;

    // quictls throws on empty secret (different from BoringSSL which may accept it)
    EXPECT_THROW(HkdfExpandLabel(empty_secret, "test label", 16), clv::OpenSSL::SslException);
}

// Test HkdfExpandLabel with zero length output
// OpenSSL/quictls throws on zero-length output unlike BoringSSL
TEST(QuicCryptoTests, HkdfExpandLabel_ZeroLength_Throws)
{
    using namespace clv::quic::detail;

    std::array<std::uint8_t, 32> secret{};
    std::fill(secret.begin(), secret.end(), 0x42);

    // quictls throws on zero-length output
    EXPECT_THROW(HkdfExpandLabel(secret, "test label", 0), clv::OpenSSL::SslException);
}

// Test HkdfExpandLabel with excessive length (should throw)
TEST(QuicCryptoTests, HkdfExpandLabel_ExcessiveLength_Throws)
{
    using namespace clv::quic::detail;

    std::array<std::uint8_t, 32> secret{};
    std::fill(secret.begin(), secret.end(), 0x42);

    // HKDF-Expand with SHA-256 can output up to 255 * 32 = 8160 bytes
    // Requesting more should fail
    EXPECT_THROW(HkdfExpandLabel(secret, "test label", 10000), clv::OpenSSL::SslException);
}

// Test that HkdfExpandLabel produces consistent output
TEST(QuicCryptoTests, HkdfExpandLabel_ConsistentOutput)
{
    using namespace clv::quic::detail;

    std::array<std::uint8_t, 32> secret{};
    std::fill(secret.begin(), secret.end(), 0x42);

    auto output1 = HkdfExpandLabel(secret, "test", 16);
    auto output2 = HkdfExpandLabel(secret, "test", 16);

    ASSERT_EQ(output1.size(), 16u);
    ASSERT_EQ(output2.size(), 16u);
    EXPECT_EQ(output1, output2) << "Same inputs should produce same output";
}

// Test that different labels produce different output
TEST(QuicCryptoTests, HkdfExpandLabel_DifferentLabels_DifferentOutput)
{
    using namespace clv::quic::detail;

    std::array<std::uint8_t, 32> secret{};
    std::fill(secret.begin(), secret.end(), 0x42);

    auto output1 = HkdfExpandLabel(secret, "label1", 16);
    auto output2 = HkdfExpandLabel(secret, "label2", 16);

    ASSERT_EQ(output1.size(), 16u);
    ASSERT_EQ(output2.size(), 16u);
    EXPECT_NE(output1, output2) << "Different labels should produce different output";
}

// ================================================================================================
// Packet Encryption/Decryption Tests
// ================================================================================================

TEST(QuicCryptoTests, EncryptDecryptPacket_BasicRoundTrip)
{
    ConnectionId conn_id;
    std::copy(kTestConnIdBytes.begin(), kTestConnIdBytes.end(), conn_id.data.begin());
    conn_id.length = 8;

    auto client_result = QuicCrypto::CreateClient(conn_id);
    auto server_result = QuicCrypto::CreateServer(conn_id);
    ASSERT_TRUE(client_result.has_value());
    ASSERT_TRUE(server_result.has_value());
    auto &client = client_result.value();
    auto &server = server_result.value();

    // Client encrypts a packet
    PacketHeader header;
    std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::uint64_t packet_number = 1;

    // Client encrypts (uses client keys)
    auto ciphertext = client.EncryptPacket(header, payload, packet_number, EncryptionLevel::Initial);
    ASSERT_TRUE(ciphertext.has_value());
    EXPECT_EQ(ciphertext.value().size(), payload.size() + 16) << "Should have 16-byte authentication tag";

    // Server decrypts (uses client keys for receiving)
    auto plaintext = server.DecryptPacket(header, ciphertext.value(), packet_number, EncryptionLevel::Initial);
    ASSERT_TRUE(plaintext.has_value());
    EXPECT_EQ(plaintext.value(), payload) << "Decrypted payload should match original";
}

TEST(QuicCryptoTests, EncryptPacket_DifferentPacketNumbers)
{
    ConnectionId conn_id;
    std::copy(kTestConnIdBytes.begin(), kTestConnIdBytes.end(), conn_id.data.begin());
    conn_id.length = 8;

    auto crypto_result = QuicCrypto::CreateClient(conn_id);
    ASSERT_TRUE(crypto_result.has_value());
    auto &crypto = crypto_result.value();

    PacketHeader header;
    std::vector<std::uint8_t> payload = {0xAA, 0xBB, 0xCC};

    auto ct1 = crypto.EncryptPacket(header, payload, 1, EncryptionLevel::Initial);
    auto ct2 = crypto.EncryptPacket(header, payload, 2, EncryptionLevel::Initial);

    ASSERT_TRUE(ct1.has_value());
    ASSERT_TRUE(ct2.has_value());
    EXPECT_NE(ct1.value(), ct2.value()) << "Different packet numbers should produce different ciphertexts";
}

TEST(QuicCryptoTests, DecryptPacket_WrongPacketNumber_Fails)
{
    ConnectionId conn_id;
    std::copy(kTestConnIdBytes.begin(), kTestConnIdBytes.end(), conn_id.data.begin());
    conn_id.length = 8;

    auto crypto_result = QuicCrypto::CreateClient(conn_id);
    ASSERT_TRUE(crypto_result.has_value());
    auto &crypto = crypto_result.value();

    PacketHeader header;
    std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03};

    auto ciphertext = crypto.EncryptPacket(header, payload, 42, EncryptionLevel::Initial);
    ASSERT_TRUE(ciphertext.has_value());

    // Try to decrypt with wrong packet number
    auto plaintext = crypto.DecryptPacket(header, ciphertext.value(), 99, EncryptionLevel::Initial);
    EXPECT_FALSE(plaintext.has_value()) << "Decryption with wrong packet number should fail";
}

TEST(QuicCryptoTests, DecryptPacket_CorruptedCiphertext_Fails)
{
    ConnectionId conn_id;
    std::copy(kTestConnIdBytes.begin(), kTestConnIdBytes.end(), conn_id.data.begin());
    conn_id.length = 8;

    auto crypto_result = QuicCrypto::CreateClient(conn_id);
    ASSERT_TRUE(crypto_result.has_value());
    auto &crypto = crypto_result.value();

    PacketHeader header;
    std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03};

    auto ciphertext = crypto.EncryptPacket(header, payload, 1, EncryptionLevel::Initial);
    ASSERT_TRUE(ciphertext.has_value());

    // Corrupt a byte
    ciphertext.value()[0] ^= 0xFF;

    auto plaintext = crypto.DecryptPacket(header, ciphertext.value(), 1, EncryptionLevel::Initial);
    EXPECT_FALSE(plaintext.has_value()) << "Decryption of corrupted ciphertext should fail";
}

TEST(QuicCryptoTests, DecryptPacket_ModifiedHeader_Fails)
{
    ConnectionId conn_id;
    std::copy(kTestConnIdBytes.begin(), kTestConnIdBytes.end(), conn_id.data.begin());
    conn_id.length = 8;

    auto client_result = QuicCrypto::CreateClient(conn_id);
    auto server_result = QuicCrypto::CreateServer(conn_id);
    ASSERT_TRUE(client_result.has_value());
    ASSERT_TRUE(server_result.has_value());
    auto &client = client_result.value();
    auto &server = server_result.value();

    // Create a proper long header (Initial packet)
    LongHeader header{};
    header.type = PacketType::Initial;
    header.version = 1;
    header.dest_conn_id = conn_id;
    header.src_conn_id = conn_id;
    header.packet_number = 1;

    PacketHeader pkt_header = header;
    std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03};

    // Client encrypts
    auto ciphertext = client.EncryptPacket(pkt_header, payload, 1, EncryptionLevel::Initial);
    ASSERT_TRUE(ciphertext.has_value());

    // Tamper with header (change version)
    std::get<LongHeader>(pkt_header).version = 999;

    // Server tries to decrypt with modified header - should fail authentication
    auto plaintext = server.DecryptPacket(pkt_header, ciphertext.value(), 1, EncryptionLevel::Initial);
    EXPECT_FALSE(plaintext.has_value()) << "Decryption with modified header should fail AAD authentication";
}

// ================================================================================================
// Header Protection Tests
// ================================================================================================

TEST(QuicCryptoTests, ProtectUnprotectHeader_BasicRoundTrip)
{
    ConnectionId conn_id;
    std::copy(kTestConnIdBytes.begin(), kTestConnIdBytes.end(), conn_id.data.begin());
    conn_id.length = 8;

    auto client_result = QuicCrypto::CreateClient(conn_id);
    auto server_result = QuicCrypto::CreateServer(conn_id);
    ASSERT_TRUE(client_result.has_value());
    ASSERT_TRUE(server_result.has_value());
    auto &client = client_result.value();
    auto &server = server_result.value();

    // Mock header bytes (first byte + packet number)
    // First byte: 0xC2 = 0b11000010 -> PN length bits = 10 = 3-byte PN
    std::vector<std::uint8_t> header_bytes = {0xC2, 0x00, 0x00, 0x01}; // Flags + 3-byte PN
    auto original_header = header_bytes;

    // Sample from ciphertext (16 bytes)
    std::array<std::uint8_t, 16> sample{};
    std::fill(sample.begin(), sample.end(), 0xAA);

    // Client protects header
    auto protect_err = client.ProtectHeader(header_bytes, 1, 3, sample, EncryptionLevel::Initial);
    EXPECT_FALSE(protect_err.has_value()) << "ProtectHeader should succeed";
    EXPECT_NE(header_bytes, original_header) << "Header should be modified";

    // Server unprotects header
    auto pn_length = server.UnprotectHeader(header_bytes, 1, sample, EncryptionLevel::Initial);
    ASSERT_TRUE(pn_length.has_value());
    EXPECT_EQ(pn_length.value(), 3u) << "Should recover packet number length";
    EXPECT_EQ(header_bytes, original_header) << "Header should be restored to original";
}

TEST(QuicCryptoTests, ProtectHeader_ModifiesFirstByte)
{
    ConnectionId conn_id;
    std::copy(kTestConnIdBytes.begin(), kTestConnIdBytes.end(), conn_id.data.begin());
    conn_id.length = 8;

    auto crypto_result = QuicCrypto::CreateClient(conn_id);
    ASSERT_TRUE(crypto_result.has_value());
    auto &crypto = crypto_result.value();

    std::vector<std::uint8_t> header_bytes = {0xC0, 0x00, 0x00, 0x01};
    std::uint8_t original_first_byte = header_bytes[0];

    std::array<std::uint8_t, 16> sample{};
    std::fill(sample.begin(), sample.end(), 0x55);

    auto err = crypto.ProtectHeader(header_bytes, 1, 3, sample, EncryptionLevel::Initial);
    EXPECT_FALSE(err.has_value());
    EXPECT_NE(header_bytes[0], original_first_byte) << "First byte should be masked";
}

TEST(QuicCryptoTests, ProtectHeader_InvalidSample_Fails)
{
    ConnectionId conn_id;
    std::copy(kTestConnIdBytes.begin(), kTestConnIdBytes.end(), conn_id.data.begin());
    conn_id.length = 8;

    auto crypto_result = QuicCrypto::CreateClient(conn_id);
    ASSERT_TRUE(crypto_result.has_value());
    auto &crypto = crypto_result.value();

    std::vector<std::uint8_t> header_bytes = {0xC0, 0x00, 0x01};
    std::array<std::uint8_t, 10> short_sample{}; // Too short

    auto err = crypto.ProtectHeader(header_bytes, 1, 2, short_sample, EncryptionLevel::Initial);
    EXPECT_TRUE(err.has_value()) << "Should fail with invalid sample";
}
// ================================================================================================
// Key Update Tests
// ================================================================================================

TEST(QuicCryptoTests, UpdateKeys_BeforeHandshake_Fails)
{
    ConnectionId conn_id;
    std::copy(kTestConnIdBytes.begin(), kTestConnIdBytes.end(), conn_id.data.begin());
    conn_id.length = 8;

    auto crypto_result = QuicCrypto::CreateClient(conn_id);
    ASSERT_TRUE(crypto_result.has_value());
    auto &crypto = crypto_result.value();

    // Try to update keys before handshake complete
    auto err = crypto.UpdateKeys();
    EXPECT_TRUE(err.has_value()) << "Should not allow key update before handshake";
    EXPECT_EQ(err.value(), std::errc::operation_not_permitted);
}

TEST(QuicCryptoTests, UpdateKeys_AfterHandshake_Success)
{
    ConnectionId conn_id;
    std::copy(kTestConnIdBytes.begin(), kTestConnIdBytes.end(), conn_id.data.begin());
    conn_id.length = 8;

    auto crypto_result = QuicCrypto::CreateClient(conn_id);
    ASSERT_TRUE(crypto_result.has_value());
    auto &crypto = crypto_result.value();

    // Simulate handshake completion
    crypto.SetHandshakeComplete();
    EXPECT_TRUE(crypto.IsHandshakeComplete());

    // Initial key phase
    EXPECT_EQ(crypto.GetKeyPhase(), 0);

    // Update keys
    auto err = crypto.UpdateKeys();
    EXPECT_FALSE(err.has_value()) << "Key update should succeed after handshake";

    // Key phase should toggle
    EXPECT_EQ(crypto.GetKeyPhase(), 1);

    // Update again
    err = crypto.UpdateKeys();
    EXPECT_FALSE(err.has_value());
    EXPECT_EQ(crypto.GetKeyPhase(), 0) << "Key phase should toggle back";
}

TEST(QuicCryptoTests, UpdateKeys_ChangesCiphertext)
{
    ConnectionId conn_id;
    std::copy(kTestConnIdBytes.begin(), kTestConnIdBytes.end(), conn_id.data.begin());
    conn_id.length = 8;

    auto client_result = QuicCrypto::CreateClient(conn_id);
    auto server_result = QuicCrypto::CreateServer(conn_id);
    ASSERT_TRUE(client_result.has_value());
    ASSERT_TRUE(server_result.has_value());
    auto &client = client_result.value();
    auto &server = server_result.value();

    // Simulate handshake
    client.SetHandshakeComplete();
    server.SetHandshakeComplete();

    PacketHeader header;
    std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03};

    // Encrypt before key update
    auto ciphertext1 = client.EncryptPacket(header, payload, 1, EncryptionLevel::Application);
    ASSERT_TRUE(ciphertext1.has_value());

    // Update keys on both sides
    EXPECT_FALSE(client.UpdateKeys().has_value());
    EXPECT_FALSE(server.UpdateKeys().has_value());

    // Encrypt same payload with updated keys
    auto ciphertext2 = client.EncryptPacket(header, payload, 1, EncryptionLevel::Application);
    ASSERT_TRUE(ciphertext2.has_value());

    // Ciphertexts should be different (different keys)
    EXPECT_NE(ciphertext1.value(), ciphertext2.value()) << "Key update should produce different ciphertext";

    // Server should be able to decrypt with updated keys
    auto plaintext = server.DecryptPacket(header, ciphertext2.value(), 1, EncryptionLevel::Application);
    ASSERT_TRUE(plaintext.has_value());
    EXPECT_EQ(plaintext.value(), payload);
}

// ================================================================================================
// Packet Number Encoding/Decoding Tests
// ================================================================================================

TEST(QuicCryptoTests, EncodePacketNumber_OneByte)
{
    // Small difference: 1 byte encoding
    auto [encoded, num_bytes] = QuicCrypto::EncodePacketNumber(10, 5);
    EXPECT_EQ(num_bytes, 1u);
    EXPECT_EQ(encoded[0], 10);
}

TEST(QuicCryptoTests, EncodePacketNumber_TwoBytes)
{
    // Difference > 127: needs 2 bytes
    auto [encoded, num_bytes] = QuicCrypto::EncodePacketNumber(500, 0);
    EXPECT_EQ(num_bytes, 2u);
    EXPECT_EQ(encoded[0], 0x01); // 500 = 0x01F4
    EXPECT_EQ(encoded[1], 0xF4);
}

TEST(QuicCryptoTests, EncodePacketNumber_ThreeBytes)
{
    // Difference > 16383: needs 3 bytes
    auto [encoded, num_bytes] = QuicCrypto::EncodePacketNumber(20000, 0);
    EXPECT_EQ(num_bytes, 3u);
    EXPECT_EQ(encoded[0], 0x00); // 20000 = 0x004E20
    EXPECT_EQ(encoded[1], 0x4E);
    EXPECT_EQ(encoded[2], 0x20);
}

TEST(QuicCryptoTests, EncodePacketNumber_FourBytes)
{
    // Difference > 2097151: needs 4 bytes
    auto [encoded, num_bytes] = QuicCrypto::EncodePacketNumber(3000000, 0);
    EXPECT_EQ(num_bytes, 4u);
    EXPECT_EQ(encoded[0], 0x00); // 3000000 = 0x002DC6C0
    EXPECT_EQ(encoded[1], 0x2D);
    EXPECT_EQ(encoded[2], 0xC6);
    EXPECT_EQ(encoded[3], 0xC0);
}

TEST(QuicCryptoTests, EncodePacketNumber_WithLargestAcked)
{
    // PN=1000, largest_acked=995, diff=5 -> 1 byte
    auto [encoded1, num_bytes1] = QuicCrypto::EncodePacketNumber(1000, 995);
    EXPECT_EQ(num_bytes1, 1u);

    // PN=1000, largest_acked=800, diff=200 -> 2 bytes
    auto [encoded2, num_bytes2] = QuicCrypto::EncodePacketNumber(1000, 800);
    EXPECT_EQ(num_bytes2, 2u);
}

TEST(QuicCryptoTests, DecodePacketNumber_ExactMatch)
{
    // Truncated PN matches expected exactly
    std::uint64_t truncated = 0x0A;
    std::uint64_t expected = 0x0A;
    std::uint64_t decoded = QuicCrypto::DecodePacketNumber(truncated, 8, expected);
    EXPECT_EQ(decoded, 0x0A);
}

TEST(QuicCryptoTests, DecodePacketNumber_WithinWindow)
{
    // RFC 9000 Appendix A.3 example
    // Expected PN = 0x9B32, truncated = 0x9B (8 bits)
    // Should decode to 0x9B32 (not 0x9B00 or 0x9C00)
    std::uint64_t expected = 0x9B32;
    std::uint64_t truncated = 0x32; // Low byte
    std::uint64_t decoded = QuicCrypto::DecodePacketNumber(truncated, 8, expected);
    EXPECT_EQ(decoded, 0x9B32);
}

TEST(QuicCryptoTests, DecodePacketNumber_Wrap)
{
    // Test wrapping behavior
    // Expected = 0x100, truncated = 0x02 (8-bit), should decode to 0x102
    std::uint64_t expected = 0x100;
    std::uint64_t truncated = 0x02;
    std::uint64_t decoded = QuicCrypto::DecodePacketNumber(truncated, 8, expected);
    EXPECT_EQ(decoded, 0x102);
}

TEST(QuicCryptoTests, DecodePacketNumber_16Bit)
{
    // 16-bit encoding
    std::uint64_t expected = 0x10000;
    std::uint64_t truncated = 0x1234;
    std::uint64_t decoded = QuicCrypto::DecodePacketNumber(truncated, 16, expected);
    EXPECT_EQ(decoded, 0x11234);
}

TEST(QuicCryptoTests, DecodePacketNumber_24Bit)
{
    // 24-bit encoding
    std::uint64_t expected = 0x1000000;
    std::uint64_t truncated = 0x123456;
    std::uint64_t decoded = QuicCrypto::DecodePacketNumber(truncated, 24, expected);
    EXPECT_EQ(decoded, 0x1123456);
}

TEST(QuicCryptoTests, DecodePacketNumber_32Bit)
{
    // 32-bit encoding
    std::uint64_t expected = 0x100000000ULL;
    std::uint64_t truncated = 0x12345678;
    std::uint64_t decoded = QuicCrypto::DecodePacketNumber(truncated, 32, expected);
    EXPECT_EQ(decoded, 0x112345678ULL);
}

TEST(QuicCryptoTests, EncodeDecodePacketNumber_RoundTrip)
{
    // Test that encode/decode work together
    std::uint64_t original_pn = 12345;
    std::uint64_t largest_acked = 12300;

    // Encode
    auto [encoded, num_bytes] = QuicCrypto::EncodePacketNumber(original_pn, largest_acked);

    // Convert encoded bytes to truncated PN
    std::uint64_t truncated = 0;
    for (std::size_t i = 0; i < num_bytes; ++i)
    {
        truncated = (truncated << 8) | encoded[i];
    }

    // Decode (expected = largest_acked + 1)
    std::uint64_t decoded = QuicCrypto::DecodePacketNumber(truncated, num_bytes * 8, largest_acked + 1);
    EXPECT_EQ(decoded, original_pn);
}

TEST(QuicCryptoTests, DecodePacketNumber_BackwardsCompatibility)
{
    // Test decoding a packet that arrived out of order (older PN)
    std::uint64_t expected = 1000;  // We expect PN 1000
    std::uint64_t truncated = 0xE8; // 232 in hex (should decode to 1000 - 24 = 976 or thereabouts)

    // With 8-bit encoding, window is 128
    std::uint64_t decoded = QuicCrypto::DecodePacketNumber(truncated, 8, expected);

    // Should decode to something close to expected
    // The algorithm should handle this correctly
    EXPECT_LT(decoded, expected + 128); // Within forward window
    EXPECT_GT(decoded, expected - 128); // Within backward window
}

// ================================================================================================
// Packet Number Space Management Tests
// ================================================================================================

TEST(QuicCryptoTests, PacketNumberSpace_InitiallyZero)
{
    ConnectionId conn_id;
    std::copy(kTestConnIdBytes.begin(), kTestConnIdBytes.end(), conn_id.data.begin());
    conn_id.length = 8;

    auto crypto_result = QuicCrypto::CreateClient(conn_id);
    ASSERT_TRUE(crypto_result.has_value());
    auto &crypto = crypto_result.value();

    // All packet numbers should start at 0
    EXPECT_EQ(crypto.GetNextPacketNumber(EncryptionLevel::Initial), 0u);
    EXPECT_EQ(crypto.GetNextPacketNumber(EncryptionLevel::Handshake), 0u);
    EXPECT_EQ(crypto.GetNextPacketNumber(EncryptionLevel::Application), 0u);

    // Largest acked should start at 0
    EXPECT_EQ(crypto.GetLargestAcked(EncryptionLevel::Initial), 0u);
    EXPECT_EQ(crypto.GetLargestAcked(EncryptionLevel::Handshake), 0u);
    EXPECT_EQ(crypto.GetLargestAcked(EncryptionLevel::Application), 0u);
}

TEST(QuicCryptoTests, PacketNumberSpace_Increment)
{
    ConnectionId conn_id;
    std::copy(kTestConnIdBytes.begin(), kTestConnIdBytes.end(), conn_id.data.begin());
    conn_id.length = 8;

    auto crypto_result = QuicCrypto::CreateClient(conn_id);
    ASSERT_TRUE(crypto_result.has_value());
    auto &crypto = crypto_result.value();

    // Increment Initial packet number
    EXPECT_EQ(crypto.GetNextPacketNumber(EncryptionLevel::Initial), 0u);
    crypto.IncrementPacketNumber(EncryptionLevel::Initial);
    EXPECT_EQ(crypto.GetNextPacketNumber(EncryptionLevel::Initial), 1u);
    crypto.IncrementPacketNumber(EncryptionLevel::Initial);
    EXPECT_EQ(crypto.GetNextPacketNumber(EncryptionLevel::Initial), 2u);

    // Other levels should be unaffected
    EXPECT_EQ(crypto.GetNextPacketNumber(EncryptionLevel::Handshake), 0u);
    EXPECT_EQ(crypto.GetNextPacketNumber(EncryptionLevel::Application), 0u);
}

TEST(QuicCryptoTests, PacketNumberSpace_IndependentSpaces)
{
    ConnectionId conn_id;
    std::copy(kTestConnIdBytes.begin(), kTestConnIdBytes.end(), conn_id.data.begin());
    conn_id.length = 8;

    auto crypto_result = QuicCrypto::CreateClient(conn_id);
    ASSERT_TRUE(crypto_result.has_value());
    auto &crypto = crypto_result.value();

    // Increment each level independently
    crypto.IncrementPacketNumber(EncryptionLevel::Initial);
    crypto.IncrementPacketNumber(EncryptionLevel::Initial);
    crypto.IncrementPacketNumber(EncryptionLevel::Handshake);
    crypto.IncrementPacketNumber(EncryptionLevel::Application);
    crypto.IncrementPacketNumber(EncryptionLevel::Application);
    crypto.IncrementPacketNumber(EncryptionLevel::Application);

    EXPECT_EQ(crypto.GetNextPacketNumber(EncryptionLevel::Initial), 2u);
    EXPECT_EQ(crypto.GetNextPacketNumber(EncryptionLevel::Handshake), 1u);
    EXPECT_EQ(crypto.GetNextPacketNumber(EncryptionLevel::Application), 3u);
}

TEST(QuicCryptoTests, PacketNumberSpace_SetLargestAcked)
{
    ConnectionId conn_id;
    std::copy(kTestConnIdBytes.begin(), kTestConnIdBytes.end(), conn_id.data.begin());
    conn_id.length = 8;

    auto crypto_result = QuicCrypto::CreateClient(conn_id);
    ASSERT_TRUE(crypto_result.has_value());
    auto &crypto = crypto_result.value();

    // Set largest acked for Initial level
    crypto.SetLargestAcked(EncryptionLevel::Initial, 5);
    EXPECT_EQ(crypto.GetLargestAcked(EncryptionLevel::Initial), 5u);

    // Setting a smaller value should not decrease it
    crypto.SetLargestAcked(EncryptionLevel::Initial, 3);
    EXPECT_EQ(crypto.GetLargestAcked(EncryptionLevel::Initial), 5u) << "Largest acked should not decrease";

    // Setting a larger value should update it
    crypto.SetLargestAcked(EncryptionLevel::Initial, 10);
    EXPECT_EQ(crypto.GetLargestAcked(EncryptionLevel::Initial), 10u);
}

TEST(QuicCryptoTests, PacketNumberSpace_WorkflowIntegration)
{
    ConnectionId conn_id;
    std::copy(kTestConnIdBytes.begin(), kTestConnIdBytes.end(), conn_id.data.begin());
    conn_id.length = 8;

    auto client_result = QuicCrypto::CreateClient(conn_id);
    auto server_result = QuicCrypto::CreateServer(conn_id);
    ASSERT_TRUE(client_result.has_value());
    ASSERT_TRUE(server_result.has_value());
    auto &client = client_result.value();
    auto &server = server_result.value();

    // Client sends packets and increments PN
    for (int i = 0; i < 5; ++i)
    {
        std::uint64_t pn = client.GetNextPacketNumber(EncryptionLevel::Initial);
        EXPECT_EQ(pn, static_cast<std::uint64_t>(i));

        // Simulate sending
        client.IncrementPacketNumber(EncryptionLevel::Initial);
    }

    // Server processes ACKs
    server.SetLargestAcked(EncryptionLevel::Initial, 3);

    // Server can use this for encoding
    auto largest_acked = server.GetLargestAcked(EncryptionLevel::Initial);
    auto [encoded, num_bytes] = QuicCrypto::EncodePacketNumber(100, largest_acked);
    EXPECT_LE(num_bytes, 4u);

    // Decode with expected = largest_acked + 1
    std::uint64_t truncated = 0;
    for (std::size_t i = 0; i < num_bytes; ++i)
    {
        truncated = (truncated << 8) | encoded[i];
    }

    std::uint64_t decoded = QuicCrypto::DecodePacketNumber(truncated, num_bytes * 8, largest_acked + 1);
    EXPECT_EQ(decoded, 100u);
}
