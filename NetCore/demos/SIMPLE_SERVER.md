# Simple Config-Driven Server

A lightweight HTTPS server demonstrating clv components working together.

## Features

- ✅ JSON-based configuration
- ✅ SSL/TLS support
- ✅ Static file serving
- ✅ API endpoint routing with fallback
- ✅ Multi-threaded async I/O (C++20 coroutines)

## Components Used

- **Config + JsonConfigParser**: Type-safe JSON configuration loading
- **HttpServerProto**: HTTP protocol handler with multi-router support
- **MicroTlsServer**: Async TLS server with ASIO
- **HttpStaticRouter**: Static file serving with MIME type detection
- **Custom ApiRouter**: Example API endpoint handler

## Building

From the repository root:

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build --target simple_server
```

This produces the `simple_server` binary in `build/NetCore/` and copies
`server_config.json`, TLS certs/keys, and the `www/` directory into the same
directory for you.

## Running

From the NetCore build directory:

```bash
cd build/NetCore
./simple_server [config_file]
```

If no argument is given, the server uses `server_config.json` in the current
directory.

## Configuration

Edit `server_config.json` (copied next to the binary):

```json
{
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

## Testing

The server provides:

- **Static Files**: Place files in `www/` directory
  - https://localhost:8443/ → serves `www/index.html`
  - https://localhost:8443/any.html → serves `www/any.html`

- **API Endpoints**:
  - https://localhost:8443/api/hello → "Hello from Simple Server!"
  - https://localhost:8443/api/config → Server configuration info

Use curl with `-k` to bypass self-signed certificate validation:

```bash
curl -k https://localhost:8443/
curl -k https://localhost:8443/api/hello
curl -k https://localhost:8443/api/config
```

## Architecture

The server uses a router priority system:

1. **ApiRouter** checks `/api/*` routes first
2. **HttpStaticRouter** serves files from `www/` if API didn't handle it
3. **Automatic 404** if no router handles the request

Each router returns `true` if it handled the request, `false` to try next router.

## Shutdown

Press `Ctrl+C` for graceful shutdown. The server will:
1. Stop accepting new connections
2. Wait for active requests to complete
3. Clean up resources
4. Exit cleanly
