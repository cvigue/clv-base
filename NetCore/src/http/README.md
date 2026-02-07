# HTTP Implementation Architecture

This directory contains HTTP/1.x and HTTP/3 server implementations with a focus on protocol-agnostic content routing and async I/O.

## Design Philosophy

The HTTP implementation follows these principles:

1. **Protocol-agnostic content generation** — Content routers are decoupled from HTTP protocol framing
2. **Zero-cost abstractions** — All polymorphism resolved at compile time, no virtual functions
3. **Async I/O throughout** — Non-blocking file operations prevent event loop stalling
4. **Chunked streaming** — Large files streamed in chunks to avoid memory bloat
5. **Type safety** — Leverage C++23 features (concepts, strong types) where appropriate

## Core Components

### Protocol-Agnostic Content Router

**`async_static_file_router.h`** — The foundation of the content routing pattern.

```cpp
class AsyncStaticFileRouter {
public:
    // Callback types define the protocol interface
    using HeaderSenderFn = std::function<asio::awaitable<void>(
        std::string_view mime_type, size_t content_length)>;
    using ChunkSenderFn = std::function<asio::awaitable<void>(
        std::span<const uint8_t>)>;

    // Protocol-agnostic async file serving
    asio::awaitable<bool> RouteRequest(
        const std::string& requestPath,
        HeaderSenderFn send_headers,
        ChunkSenderFn send_chunk,
        asio::io_context& io_ctx);
};
```

**Key features:**
- Uses ASIO `stream_descriptor` (POSIX) or `stream_file` (Windows) for async file I/O
- Streams files in 64KB chunks using `async_read_some()`
- Delegates protocol framing to callbacks provided by adapters
- Single implementation serves HTTP/1.x, HTTP/2 (future), and HTTP/3

**Benefits:**
- ~220 lines of async file I/O logic written once
- Protocol adapters are thin (~35-105 lines)
- Easy to extend to other content types (APIs, proxies, dynamic content)
- No blocking I/O in the event loop

### HTTP/1.x Implementation

**`HttpStaticRouter.h`** — Thin wrapper around `AsyncStaticFileRouter` for HTTP/1.x protocols.

```cpp
class HttpStaticRouter {
    AsyncStaticFileRouter core_;
public:
    asio::awaitable<bool> Route(HttpRequest msg, SendingFuncT rfn,
                                 asio::io_context& io_ctx) {
        return core_.RouteHttp1(msg, rfn, io_ctx);
    }
};
```

The `RouteHttp1()` convenience method creates callbacks that:
1. Build HTTP/1.1 response headers (`200 OK`, `Content-Type`, `Content-Length`)
2. Write raw chunk data directly to the socket

**Total lines:** ~35 (was ~310 before refactoring)

### HTTP/3 Implementation

**`http3_async_static_router.h`** — HTTP/3 adapter wrapping `AsyncStaticFileRouter`.

```cpp
class Http3AsyncStaticRouter {
    http::AsyncStaticFileRouter core_;
public:
    template<typename StreamWriterFn>
    asio::awaitable<bool> RouteMsg(
        const std::string& path,
        StreamWriterFn stream_writer,
        asio::io_context& io_ctx);
};
```

The adapter creates callbacks that:
1. **Headers:** Build QPACK-encoded HEADERS frame with `:status: 200`, `content-type`, `content-length`
2. **Chunks:** Build HTTP/3 DATA frames with varint length encoding

The `stream_writer` callback accumulates all frame data, which is then passed to the connection handler's `SendStreamData()` API.

**Total lines:** ~105

**HTTP/3 frame structure produced:**
```
HEADERS frame: [type=0x01] [QPACK-encoded headers]
DATA frame:    [type=0x00] [varint length] [payload]
DATA frame:    [type=0x00] [varint length] [payload]
...
```

### Shared Utilities

**`util/static_file_resolver.h`** — Path resolution and security validation shared by all routers.

Key functions:
- `Resolve()` — Maps URL paths to filesystem paths with security checks:
  - Null byte injection prevention
  - Directory traversal prevention (canonical path validation)
  - Default file handling (e.g., `/` → `index.html`)
- `NormalizeUrlPrefix()` — Ensures consistent URL prefix format

**`util/MimeType.h`** — MIME type detection based on file extensions.

Supports common types: `text/html`, `text/css`, `application/javascript`, `image/*`, etc.

## Architecture Pattern: Strategy with Zero-Cost Abstractions

The callback-based design is an implementation of the **Strategy pattern** that maintains zero-cost abstractions:

```
┌──────────────────────────────────────────┐
│   AsyncStaticFileRouter (Core)           │
│   - Async file I/O (ASIO descriptors)    │
│   - Chunked streaming (64KB)             │
│   - Protocol-agnostic interface          │
└────────────┬─────────────────────────────┘
             │ callbacks
             │ (HeaderSenderFn, ChunkSenderFn)
             │
     ┌───────┴────────┐
     │                │
┌────▼─────┐    ┌────▼──────────┐
│ HTTP/1.x │    │ HTTP/3        │
│ Adapter  │    │ Adapter       │
│ (~35 LOC)│    │ (~105 LOC)    │
│          │    │               │
│ Builds:  │    │ Builds:       │
│ - HTTP   │    │ - QPACK       │
│   headers│    │   HEADERS     │
│ - Raw    │    │ - HTTP/3      │
│   chunks │    │   DATA frames │
└──────────┘    └───────────────┘
```

**Why callbacks instead of inheritance?**
- No virtual function overhead
- Callbacks inlined at compile time
- Protocol adapters are simple lambdas
- Easy to test each layer independently

## Code Reduction Summary

Through consolidation and the protocol-agnostic pattern:

| Component | Before | After | Reduction |
|-----------|--------|-------|-----------|
| HTTP/1.x router | ~310 lines | ~35 lines | **89%** |
| HTTP/3 router | ~148 lines (sync) | ~105 lines (async) | More features, less code |
| **Total eliminated** | | | **~440 lines** |

Additionally:
- Shared path resolution logic (`StaticFileResolver`) eliminated ~150 lines of duplication
- MIME type detection reuses existing `MimeType` utility
- Both protocols now use async I/O (HTTP/3 was previously blocking with `std::ifstream`)

## Usage Examples

### HTTP/1.x Static File Serving

```cpp
#include "http/HttpStaticRouter.h"

// Create router
HttpStaticRouter router("/", "./www", "index.html");

// In request handler:
co_await router.Route(request, send_fn, io_ctx);
```

### HTTP/3 Static File Serving

```cpp
#include "http/http3_async_static_router.h"

// Create router
Http3AsyncStaticRouter router("/", "./www", "index.html");

// In connection handler:
std::vector<uint8_t> response_data;
auto stream_writer = [&](std::vector<uint8_t> data) {
    response_data.insert(response_data.end(), data.begin(), data.end());
};

bool handled = co_await router.RouteMsg(path, stream_writer, io_ctx);
if (handled) {
    connection.SendStreamData(stream_id, response_data);
}
```

### Custom Content Router (Future Extension)

The same pattern can be applied to API endpoints, proxies, or dynamic content:

```cpp
class AsyncApiRouter {
    using HeaderSenderFn = /* same as AsyncStaticFileRouter */;
    using ChunkSenderFn = /* same as AsyncStaticFileRouter */;

    asio::awaitable<bool> RouteRequest(
        const std::string& path,
        HeaderSenderFn send_headers,
        ChunkSenderFn send_chunk,
        asio::io_context& io_ctx)
    {
        if (path == "/api/hello") {
            co_await send_headers("application/json", response.size());
            co_await send_chunk(std::span(response));
            co_return true;
        }
        co_return false;
    }
};
```

Then wrap with protocol-specific adapters just like `AsyncStaticFileRouter`.

## File Organization

```
http/
├── async_static_file_router.h      # Protocol-agnostic async core
├── HttpStaticRouter.h              # HTTP/1.x adapter (thin wrapper)
├── http3_async_static_router.h     # HTTP/3 adapter
├── http3_connection_handler.h      # HTTP/3 connection state machine
├── http3_session_adapter.h         # Adapts connection handler to multiplexer
├── HttpDefs.h                      # Common HTTP types and constants
├── HttpRequest.h                   # HTTP/1.x request parser
├── HttpResponse.h                  # HTTP/1.x response builder
└── README.md                       # This file
```

Related utilities:
```
util/
├── static_file_resolver.h          # Path resolution and security
├── MimeType.h                      # MIME type detection
└── ...
```

## Testing

Static file routers are tested through:
1. Unit tests for path resolution (`static_file_resolver` tests)
2. Integration tests with actual HTTP clients
3. Server demos (`simple_server` for HTTP/1.x, `quic_simple_server` for HTTP/3)

Example test with gtlsclient:
```bash
cd build/NetCore
./quic_simple_server server_config.json &
gtlsclient localhost 8443 https://localhost:8443/
```

## Performance Characteristics

**Async I/O benefits:**
- Non-blocking file reads prevent event loop stalling
- Multiple concurrent file transfers without thread-per-connection
- Graceful handling of slow disk I/O

**Chunked streaming:**
- 64KB chunk size balances memory usage with I/O efficiency
- Large files (GBs) served with constant memory footprint
- Single `std::vector<uint8_t>` buffer reused across chunks

**Zero-cost abstractions:**
- Callbacks inlined by compiler (with optimization)
- No virtual function overhead
- Protocol adapters optimized away when used with known types

## Future Enhancements

### HTTP/2 Support
Add HTTP/2 adapter following the same pattern:
```cpp
class Http2AsyncStaticRouter {
    http::AsyncStaticFileRouter core_;
    // Build HTTP/2 HEADERS and DATA frames
};
```

### Compression Support
Add compression layer between core and protocol adapters:
```cpp
auto compressed_chunk = [original_send_chunk](span<const uint8_t> data) {
    auto compressed = gzip_compress(data);
    co_await original_send_chunk(compressed);
};
co_await core_.RouteRequest(path, send_headers, compressed_chunk, io_ctx);
```

### Range Request Support
Extend `AsyncStaticFileRouter` to handle `Range` headers for partial content delivery.

### Caching Layer
Add optional in-memory cache for frequently accessed small files.

## Related Documentation

- Main README: `/README.md` — Project overview and build instructions
- NetCore README: `/NetCore/README.md` — Network components overview
- QUIC implementation: `/NetCore/src/quic/` — QUIC transport layer used by HTTP/3
