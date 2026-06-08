This directory contains NetCore demos and sample utilities.

| Executable | Source | Description |
|------------|--------|-------------|
| `quic_simple_server` | `quic_simple_server.cpp` | HTTP/3 over QUIC (ngtcp2 + nghttp3) |
| `simple_server` | `simple_server.cpp` | Config-driven HTTPS server |
| `stun_test_client` | `stun_test_client.cpp` | STUN connectivity / NAT type |
| `hole_punch_demo` | `hole_punch_demo.cpp` | UDP hole punching |

Built via NetCore `CMakeLists.txt` when `USING_QUIC_TLS` is enabled (`quic_simple_server` requires QUIC).

## Build and run

From the repository root:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --target simple_server stun_test_client hole_punch_demo quic_simple_server
```

Run from the build tree (paths vary by CMake layout):

```bash
./build/clv-base/NetCore/simple_server
./build/clv-base/NetCore/stun_test_client
./build/clv-base/NetCore/hole_punch_demo
./build/clv-base/NetCore/quic_simple_server   # see demos/QUIC_SIMPLE_SERVER.md
```

Per-demo detail:

- [QUIC_SIMPLE_SERVER.md](QUIC_SIMPLE_SERVER.md)
- [SIMPLE_SERVER.md](SIMPLE_SERVER.md)
- [STUN_TEST_CLIENT.md](STUN_TEST_CLIENT.md)
- [HOLE_PUNCH_DEMO.md](HOLE_PUNCH_DEMO.md)
