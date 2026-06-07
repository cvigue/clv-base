# HTTP/3 QUIC Server

An experimental HTTP/3 server built on QUIC protocol with full TLS 1.3 support, API routing, and static file serving.

## Features

- **HTTP/3 over QUIC**: Native QUIC transport with UDP
- **TLS 1.3**: Secure connections using BoringSSL
- **QPACK Compression**: Efficient header compression
- **API Routing**: Built-in API endpoints with JSON responses
- **Static File Serving**: Serve files from configured directory
- **Config-Driven**: JSON configuration for all settings
- **Multi-Threaded**: Thread pool for concurrent connections

## Architecture

Based on the `simple_server` pattern but adapted for HTTP/3:
- **ApiRouter**: Handles `/api/*` endpoints
- **HttpStaticRouter**: Serves static files with MIME type detection
- **QuicConnection**: Manages QUIC connection state
- **QuicTls**: Handles TLS 1.3 handshake via BoringSSL
- **HTTP/3 Frame Parsing**: HEADERS and DATA frames
- **QPACK**: Header compression/decompression

## Configuration

Uses `server_config.json`:

```json
{
    "api": {
        "enable": true
    },
    "server": {
        "host": "0.0.0.0",
        "port": 8443,
        "threads": 4
    },
    "ssl": {
        "cert_path": "./cert.pem",
        "key_path": "./pvtkey.pem",
        "dh_path": "./dh2048.pem"
    },
    "static": {
        "root_dir": "./www",
        "default_file": "index.html"
    }
}
```

## Building

```bash
cd build
cmake ..
ninja quic_simple_server
```

## Running

```bash
cd NetCore/demos
../../build/NetCore/quic_simple_server [config_file]
```

## API Endpoints

- `GET /api/hello` - Returns greeting message
- `GET /api/config` - Returns server configuration as JSON

## Testing with Browsers

### Chrome
```bash
chrome --enable-quic --origin-to-force-quic-on=localhost:8443 https://localhost:8443/
```

### Firefox
1. Open `about:config`
2. Set `network.http.http3.enabled` to `true`
3. Navigate to `https://localhost:8443/`

### cURL (with HTTP/3 support)
```bash
curl --http3 https://localhost:8443/api/hello
```

## Implementation Details

### Request Flow

1. **UDP Packet Reception**: Server receives QUIC packet
2. **QUIC Parsing**: Extract connection IDs from Initial packet
3. **TLS Handshake**: QuicTls performs TLS 1.3 handshake with ALPN "h3"
4. **Stream Creation**: Client opens bidirectional stream for HTTP/3
5. **HTTP/3 Parsing**: Parse HEADERS and DATA frames from stream
6. **QPACK Decoding**: Decompress request headers
7. **Routing**: Try API router, then static file router
8. **Response Generation**: Build QPACK-encoded HEADERS + DATA frames
9. **Stream Transmission**: Send response frames on same stream

### Key Components

- **QuicConnection**: State machine (Initial → Handshake → Active → Closed)
- **QuicTls**: TLS callbacks for secrets and handshake data
- **HTTP/3 Frames**: FrameType enum (Headers, Data, Settings, etc.)
- **QPACK**: QpackEncoder/QpackDecoder for header compression

## Security

- TLS 1.3 with certificate validation
- Path traversal protection for static files
- Certificate and key file verification on startup

## Performance

- Multi-threaded I/O with ASIO coroutines
- UDP transport (lower latency than TCP)
- Connection pooling via QUIC connection IDs
- Zero-copy buffer operations where possible

## Future Enhancements

- [ ] Complete QuicCrypto key installation from TLS callbacks
- [ ] CRYPTO frame queuing and transmission
- [ ] Flow control and congestion control integration
- [ ] Connection migration support
- [ ] 0-RTT support
- [ ] Server push (PUSH_PROMISE frames)
- [ ] Rate limiting
- [ ] Access logging

## Comparison with simple_server

| Feature | simple_server | quic_simple_server |
|---------|--------------|-------------------|
| Protocol | HTTP/1.1 | HTTP/3 |
| Transport | TCP | QUIC (UDP) |
| TLS Library | OpenSSL | BoringSSL |
| Header Compression | None | QPACK |
| Multiplexing | Connection-based | Stream-based |
| Handshake | TCP + TLS | Integrated QUIC handshake |

## References

- [RFC 9114: HTTP/3](https://datatracker.ietf.org/doc/html/rfc9114)
- [RFC 9000: QUIC](https://datatracker.ietf.org/doc/html/rfc9000)
- [RFC 9204: QPACK](https://datatracker.ietf.org/doc/html/rfc9204)
- [BoringSSL QUIC API](https://boringssl.googlesource.com/boringssl/+/HEAD/include/openssl/ssl.h)
