// Copyright (c) 2023- Charlie Vigue. All rights reserved.

#include "gtest/gtest.h"
#include "stun/stun_utils.h"

#include <array>
#include <asio/ip/address_v4.hpp>
#include <cstddef>
#include <cstdint>
#include <numeric>
#include <vector>

using namespace clv::netcore;

class StunUtilsTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        // Any setup needed for tests
    }
};

TEST_F(StunUtilsTest, GenerateTransactionIdLength)
{
    auto id = stun_utils::generate_transaction_id();
    EXPECT_EQ(id.size(), stun_constants::transaction_id_size); // Should be 12 bytes (96 bits)
}

TEST_F(StunUtilsTest, GenerateTransactionIdUniqueness)
{
    auto id1 = stun_utils::generate_transaction_id();
    auto id2 = stun_utils::generate_transaction_id();

    // The probability of generating the same 96-bit ID twice is extremely low
    EXPECT_NE(id1, id2);
}

TEST_F(StunUtilsTest, CreateBindingRequestFormat)
{
    auto transaction_id = stun_utils::generate_transaction_id();
    auto packet = stun_utils::create_binding_request(transaction_id);

    EXPECT_EQ(packet.size(), stun_constants::header_size); // STUN header is 20 bytes

    // Check message type (Binding Request = 0x0001)
    EXPECT_EQ(packet[0], 0x00);
    EXPECT_EQ(packet[1], 0x01);

    // Check message length (should be 0 for basic request)
    EXPECT_EQ(packet[2], 0x00);
    EXPECT_EQ(packet[3], 0x00);

    // Check transaction ID is properly embedded
    for (size_t i = 0; i < transaction_id.size(); ++i)
    {
        EXPECT_EQ(packet[8 + i], transaction_id[i]);
    }
}

TEST_F(StunUtilsTest, CreateBindingRequestWithKnownTransactionId)
{
    // Use a known transaction ID for predictable testing
    transaction_id known_id;
    std::iota(known_id.begin(), known_id.end(), 1); // {1, 2, 3, ..., 12}

    auto packet = stun_utils::create_binding_request(known_id);

    // Verify the transaction ID is correctly placed
    for (size_t i = 0; i < known_id.size(); ++i)
    {
        EXPECT_EQ(packet[8 + i], known_id[i]);
    }
}

TEST_F(StunUtilsTest, ParseBindingResponseInvalidSize)
{
    std::array<std::uint8_t, 2> too_small = {0x01, 0x01}; // Only 2 bytes

    auto result = stun_utils::parse_binding_response(too_small);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), stun_error_code::parse_error);
}

TEST_F(StunUtilsTest, ParseBindingResponseInvalidMessageType)
{
    // Create a packet with wrong message type
    std::array<std::uint8_t, 20> wrong_type = {
        0x00, 0x02, // Wrong message type (not binding response)
        0x00,
        0x00, // Message length
        0x21,
        0x12,
        0xA4,
        0x42, // Magic cookie
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06, // Transaction ID
        0x07,
        0x08,
        0x09,
        0x0A,
        0x0B,
        0x0C};

    auto result = stun_utils::parse_binding_response(wrong_type);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), stun_error_code::invalid_response);
}

TEST_F(StunUtilsTest, IsValidStunPacket)
{
    // Valid packet
    std::array<std::uint8_t, 20> valid_packet = {
        0x01, 0x01, // Message type
        0x00,
        0x00, // Message length
        0x21,
        0x12,
        0xA4,
        0x42, // Magic cookie
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06, // Transaction ID
        0x07,
        0x08,
        0x09,
        0x0A,
        0x0B,
        0x0C};

    EXPECT_TRUE(stun_utils::is_valid_stun_packet(valid_packet));

    // Invalid magic cookie
    std::array<std::uint8_t, 20> invalid_packet = valid_packet;
    invalid_packet[4] = 0xFF;

    EXPECT_FALSE(stun_utils::is_valid_stun_packet(invalid_packet));
}

TEST_F(StunUtilsTest, GetMessageType)
{
    std::array<std::uint8_t, 20> binding_request = {
        0x00,
        0x01, // Binding request
        0x00,
        0x00, // Rest doesn't matter for this test
    };

    auto type = stun_utils::get_message_type(binding_request);
    EXPECT_TRUE(type.has_value());
    EXPECT_EQ(*type, message_type::binding_request);

    // Invalid packet
    std::array<std::uint8_t, 1> too_small = {0x00};
    auto invalid_type = stun_utils::get_message_type(too_small);
    EXPECT_FALSE(invalid_type.has_value());
}

// Keep some of the original parsing tests but simplified
TEST_F(StunUtilsTest, ParseBindingResponseWithMappedAddress)
{
    // Create a valid STUN binding response with MAPPED-ADDRESS attribute
    std::vector<std::uint8_t> valid_response = {
        // STUN Header
        0x01,
        0x01, // Message type: Binding Success Response
        0x00,
        0x0C, // Message length: 12 bytes (attribute)
        0x21,
        0x12,
        0xA4,
        0x42, // Magic cookie
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06, // Transaction ID
        0x07,
        0x08,
        0x09,
        0x0A,
        0x0B,
        0x0C,

        // MAPPED-ADDRESS Attribute
        0x00,
        0x01, // Attribute type: MAPPED-ADDRESS
        0x00,
        0x08, // Attribute length: 8 bytes
        0x00,
        0x01, // Reserved + Address family (IPv4)
        0x1F,
        0x90, // Port: 8080
        0xC0,
        0xA8,
        0x01,
        0x64 // IP: 192.168.1.100
    };

    auto result = stun_utils::parse_binding_response(valid_response);
    EXPECT_TRUE(result.has_value());

    const auto &addr = *result;
    EXPECT_TRUE(addr.is_valid());
    EXPECT_EQ(addr.address, asio::ip::make_address_v4("192.168.1.100"));
    EXPECT_EQ(addr.port, 8080);
}