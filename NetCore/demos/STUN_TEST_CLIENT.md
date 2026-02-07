# STUN Test Client Demo

A small command-line tool that exercises the STUN client and utilities in `NetCore`.
It discovers your public address and can perform basic NAT-type probing using
one or more public STUN servers.

## Build

From the repository root:

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build --target stun_test_client
```

This builds the `stun_test_client` executable into `build/NetCore/`.

## Run

From the NetCore build directory:

```bash
cd build/NetCore
./stun_test_client [options]
```

Typical options (check `--help` for the exact set if available):

- `--server <host:port>` – override default STUN server
- `--timeout <ms>` – per-operation timeout

### Example: default STUN servers

```bash
cd build/NetCore
./stun_test_client
```

Example output:

```text
STUN Test Client
----------------
Using server: stun.l.google.com:19302
Public address: 203.0.113.45:54321
NAT type: Port-Restricted Cone
```

### Example: custom STUN server

```bash
./stun_test_client --server stun.example.com:3478
```

## What this demo shows

- How `stun_client` uses C++20 coroutines and Asio to talk to STUN servers
- How `stun_utils` builds/parses STUN packets
- How the generic `result_or` style error handling is used instead of exceptions

For lower-level usage details, see `NetCore/src/stun_client.hpp` and
`NetCore/src/stun_utils.hpp`, as well as the unit tests under `NetCore/tests/`.
