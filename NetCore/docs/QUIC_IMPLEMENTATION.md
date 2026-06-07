# QUIC Implementation

## Status

**Phase 3 Complete** (December 18, 2025)

- ✅ UDP transport layer (`MicroUdpServer`)
- ✅ Connection multiplexing (`UdpConnectionMultiplexer`)
- ✅ QUIC packet format and frame parsing
- ✅ Reliability layer with ACK tracking
- ✅ 61+ tests passing

**Next:** Phase 4 (TLS integration for crypto/packet protection)

## Architecture

```
┌─────────────────────────────────────────┐
│      MicroUdpServer<MultiplexerT>       │  ← Generic UDP I/O layer
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│  UdpConnectionMultiplexer               │  ← Stateful connection routing
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│      SessionT (Protocol Logic)          │  ← QUIC/HTTP/3
└─────────────────────────────────────────┘
```

## Components

### Core Headers

| File | Description |
|------|-------------|
| `quic/quic_varint.h` | Variable-length integer encoding (RFC 9000 §16) |
| `quic/quic_packet.h` | Packet header parsing/serialization |
| `quic/quic_frame.h` | Frame parsing for 10+ frame types |
| `quic/quic_reliability.h` | ACK tracking, loss detection, congestion control |

### Variable-Length Integers

QUIC uses compact variable-length encoding:
- 1 byte: 0-63
- 2 bytes: 0-16,383
- 4 bytes: 0-1,073,741,823
- 8 bytes: 0-2^62-1

### Packet Headers

**Long Headers** (Initial, Handshake, 0-RTT, Retry):
- Version, connection IDs, token, payload length

**Short Headers** (Application data, post-handshake):
- Spin bit, key phase, connection ID, packet number

### Frame Types

| Frame | Purpose |
|-------|---------|
| PADDING, PING | Connection probing |
| ACK | Acknowledge received packets |
| CRYPTO | TLS handshake data |
| STREAM | Application data with offset, length, FIN |
| MAX_DATA, MAX_STREAM_DATA | Flow control |
| RESET_STREAM | Abort stream |
| CONNECTION_CLOSE | Terminate connection |
| HANDSHAKE_DONE | Signal handshake completion |

### Reliability Layer

- **PacketTracker**: Tracks sent packets awaiting ACKs
- **AckGenerator**: Tracks received packets, generates ACK frames
- **CongestionController**: NewReno congestion control (RFC 9002 §7) in `quic_congestion.h`
- Loss detection based on timeouts
- Frame retransmission for CRYPTO, STREAM

## Remaining Phases

### Phase 4: TLS Integration
- BoringSSL QUIC API integration
- Initial packet protection
- Handshake packet protection
- Application data protection

### Phase 5: HTTP/3
- QPACK header compression
- Request/response streams
- Server push (optional)

## Testing

```bash
# Run QUIC tests
cd build
ctest -R quic --output-on-failure
```

## References

- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html) - QUIC Transport
- [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html) - QUIC TLS
- [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114.html) - HTTP/3
