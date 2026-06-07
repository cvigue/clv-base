# UDP Echo Demo

A simple UDP echo server demonstrating the `MicroUdpServer` template - the foundation for QUIC implementation.

## Overview

This demo shows the basic usage of `MicroUdpServer` with a simple echo handler that returns any received datagram back to the sender.

## Building

From the repository root:

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build --target udp_echo_demo
```

## Usage

```bash
# Start the echo server (default port 9001)
./udp_echo_demo

# Start on a specific port
./udp_echo_demo --port 8888

# Show help
./udp_echo_demo --help
```

## Testing

### Using netcat

```bash
# Send a single message
echo "hello" | nc -u localhost 9001

# Interactive mode (type messages, see echoes)
nc -u localhost 9001
```

### Using Python

```python
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(b"Hello QUIC!", ("localhost", 9001))
data, addr = sock.recvfrom(1500)
print(f"Received: {data.decode()}")
```

## Handler Interface

The `MicroUdpServer` accepts any handler type that implements this interface:

```cpp
struct DatagramHandler
{
    asio::awaitable<bool> HandleDatagram(
        std::span<const std::uint8_t> data,
        asio::ip::udp::endpoint remote,
        UdpServerDefs::SendDatagramFnT send_fn,
        asio::io_context& io_ctx);
};
```

- **data**: The received datagram bytes
- **remote**: The sender's endpoint (IP:port)
- **send_fn**: Async function to send a response
- **io_ctx**: Reference to the ASIO io_context

Return `true` if handled, `false` to indicate the packet was not processed (for handler chaining).

## Architecture

```
┌─────────────────────┐
│   MicroUdpServer    │
│  (UDP socket mgmt)  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│   DatagramHandler   │
│ (protocol-specific) │
└─────────────────────┘
```

This is the same pattern as `MicroTlsServer` - the transport layer handles socket I/O while the handler implements protocol logic.

## QUIC Foundation

This UDP server is the first building block for QUIC:

1. ✅ **Phase 1**: `MicroUdpServer` (this demo)
2. ⬜ **Phase 2**: Connection state management
3. ⬜ **Phase 3**: QUIC packet format & reliability
4. ⬜ **Phase 4**: TLS integration for crypto
5. ⬜ **Phase 5**: HTTP/3 over QUIC streams

## See Also

- [QUIC Implementation Plan](../docs/quic_plan.md)
- [micro_udp_server.h](../src/micro_udp_server.h)
