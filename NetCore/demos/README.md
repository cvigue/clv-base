This directory contains NetCore demos and sample utilities.

- `simple_server.cpp` – config-driven HTTPS server demo
- `stun_test_client.cpp` – STUN test client
- `hole_punch_demo.cpp` – UDP hole punching demo

These sources are built as standalone executables via the NetCore `CMakeLists.txt`.

## Build and run

From the repository root:

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build --target simple_server stun_test_client hole_punch_demo
```

Then run the demos from the NetCore build directory:

```bash
cd build/NetCore
./simple_server        # HTTPS server using demos/server_config.json and demos/www
./stun_test_client     # Query public address / NAT type
./hole_punch_demo      # UDP hole punching demo
```
