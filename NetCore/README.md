# NetCore

NetCore contains the C++20 networking components and related demos for `clvlib`.

At a high level it provides:

- A coroutine-based STUN client (`stun_client.hpp`)
- STUN protocol helpers (`stun_utils.hpp`)
- TUN device abstraction (`tun/tun_device.h`)
- IPv4 utilities (`util/ipv4_utils.h`)
- Netlink helpers (`util/netlink_helper.h`)
- Demos and sample utilities under `demos/`

This README is a high-level overview; for in-depth usage details, see the code and tests under `src/` and `tests/`.

## Layout

- `src/` – library headers and implementation (STUN client, helpers, result type)
- `tests/` – unit tests and the HTTP integration test script
- `demos/` – sample programs (simple HTTPS server, STUN test client, hole punch demo)
- `docs/` - A few minimal high level documents.

## Key components

### STUN client (`stun_client.hpp`)

An RFC 5389 STUN client built on standalone Asio and C++20 coroutines. It can:

- Discover the public IP/port of a local UDP endpoint
- Probe and classify common NAT types
- Talk to one or more STUN servers with fallback

The implementation favors RAII, strong types, and exception-free error handling using `net_result`.

### STUN utilities (`stun_utils.hpp`)

Low-level helpers for building and parsing STUN packets:

- Generate transaction IDs and binding requests
- Parse binding responses and extract address attributes
- Work with typed enums for message and NAT types

## Building and testing NetCore

From the repository root (recommended):

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build --target test_netcore
```

Then run the tests via CTest:

```bash
ctest --test-dir build --output-on-failure
```

This will build the NetCore unit tests including the HTTP-related tests that exercise the HTTP pieces living in this module.

## Demos

The NetCore demos live under `demos/` and are built as separate executables:

- `simple_server` – config-driven HTTPS server demo
- `stun_test_client` – STUN server connectivity and NAT detection tool
- `hole_punch_demo` – UDP hole punching demonstration

See `demos/README.md` for quick build/run examples.

## Appendix: Errata

### GCC 15.2

In query_server_impl, the structured binding auto [resolve_ec, endpoints] = co_await resolver.async_resolve(...) creates a hidden tuple local in the coroutine frame (because its lifetime spans the subsequent co_await socket_.async_send_to(...)). GCC 15 has a regression where the destructor of such coroutine-frame-local structured binding variables is not called when the coroutine completes — so the basic_resolver_results<udp> (which holds the shared_ptr<vector<entry>>) is never freed. 3 objects = 3 STUN servers in the fixture.

This causes ASAN builds with GCC 15.2 to correctly report the leaks.

GCC 14 and Clang destroy them correctly.