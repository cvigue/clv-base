// Copyright (c) 2025- Charlie Vigue. All rights reserved.

/**
 * @file quic_test_client.cpp
 * @brief Simple QUIC test client that sends an Initial packet
 *
 * This is a minimal test client to validate the QUIC echo server.
 * It sends a QUIC Initial packet to the server.
 */

#include "quic/quic_packet.h"
#include "quic/connection_id.h"

#include <asio.hpp>
#include <iostream>
#include <random>
#include <vector>

using namespace clv::quic;

// Generate a random connection ID
ConnectionId GenerateConnectionId()
{
    ConnectionId cid;
    cid.length = 8;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (std::size_t i = 0; i < cid.length; ++i)
    {
        cid.data[i] = static_cast<std::uint8_t>(dis(gen));
    }

    return cid;
}

int main(int argc, char *argv[])
{
    std::string host = "127.0.0.1";
    unsigned short port = 9002;

    if (argc > 1)
    {
        host = argv[1];
    }
    if (argc > 2)
    {
        port = static_cast<unsigned short>(std::stoi(argv[2]));
    }

    try
    {
        std::cout << std::format("Connecting to QUIC server at {}:{}\n", host, port);

        asio::io_context io_context;
        asio::ip::udp::socket socket(io_context, asio::ip::udp::endpoint(asio::ip::udp::v4(), 0));
        asio::ip::udp::resolver resolver(io_context);
        asio::ip::udp::endpoint remote = *resolver.resolve(asio::ip::udp::v4(), host, std::to_string(port)).begin();

        // Create an Initial packet
        LongHeader header;
        header.type = PacketType::Initial;
        header.version = 1; // QUIC version 1
        header.dest_conn_id = GenerateConnectionId();
        header.src_conn_id = GenerateConnectionId();
        header.packet_number = 0;
        header.token = {};          // No token
        header.payload_length = 20; // Dummy payload

        std::cout << std::format("Generated dest CID: length={}\n", header.dest_conn_id.length);
        std::cout << std::format("Generated src CID: length={}\n", header.src_conn_id.length);

        // Serialize the packet header
        auto serialized = SerializeHeader(header);

        std::cout << std::format("Serialized {} bytes for Initial packet\n", serialized.size());

        // Send it
        socket.send_to(asio::buffer(serialized), remote);

        std::cout << "Sent Initial packet to server\n";
        std::cout << "Waiting for response...\n";

        // Try to receive a response (with timeout)
        std::vector<std::uint8_t> recv_buffer(2000);
        asio::ip::udp::endpoint sender_endpoint;

        // Set a receive timeout of 2 seconds
        socket.non_blocking(true);
        bool received = false;

        for (int i = 0; i < 20 && !received; ++i)
        {
            try
            {
                auto len = socket.receive_from(asio::buffer(recv_buffer), sender_endpoint);
                if (len > 0)
                {
                    std::cout << std::format("Received {} bytes from server\n", len);
                    received = true;
                }
            }
            catch (const std::system_error &)
            {
                // Expected - no data yet
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }

        if (!received)
        {
            std::cout << "No response received (expected - server is still basic)\n";
        }

        std::cout << "Test complete\n";
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
