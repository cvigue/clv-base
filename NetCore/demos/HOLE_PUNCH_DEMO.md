# NAT Hole Punching Demo

A practical demonstration of NAT hole punching using STUN address discovery and a TCP control channel for coordination.

## Overview

This demo shows how two peers behind different NATs can establish direct UDP connectivity without requiring a rendezvous server in the steady state. The key innovation here is using a **VPN as a control channel** for metadata exchange while testing actual **internet connectivity** via STUN-discovered public addresses.

### Network Topology

```
Peer A (10.10.1.0 LAN)          VPN Tunnel           Peer B (10.40.1.0 LAN)
    ├─ Local: 10.10.1.50:9999  ←────TCP───→        ├─ Local: 10.40.1.75:9999
    ├─ Public: 203.0.113.45:54321          198.51.100.30:55555
    └─ NAT Gateway A                               └─ NAT Gateway B
       │                                              │
       └───────────────── Internet ───────────────────┘
             (UDP hole punch packets travel here)
```

### Key Features

1. **Dual Address Discovery**
   - Local LAN address (via socket inspection)
   - Public address (via STUN protocol)

2. **TCP Control Channel** (over VPN)
   - Peers exchange their LAN and public addresses
   - Clean separation between control and data paths
   - Designed for easy extension to external rendezvous servers

3. **UDP Hole Punching** (over Internet)
   - Client sends hole punch packets to server's public address
   - Server receives and responds, confirming connectivity
   - Test message exchange to verify end-to-end data transfer

## Usage

### Server Mode (Listener)

Start the server on one machine and it will listen for peer connections:

```bash
./hole_punch_demo -s
# or with custom port:
./hole_punch_demo -s --port 8888
```

Output example:
```
==========================================
    NAT Hole Punching Demo
    Using STUN + TCP Control Channel
==========================================

[Server Mode]
Local LAN Address: 10.10.1.50:9999
Public Address:   203.0.113.45:54321

✓ Listening for peer connection...

[Peer Connected]
Peer LAN Address: 10.40.1.75:9999

[Control Channel Exchange]
Sending local address info via TCP...
Receiving peer address info via TCP...
  Remote: LAN: 10.40.1.75:9999, PUBLIC: 198.51.100.30:55555

[Hole Punch Phase]
  Creating UDP socket on port 9999
  Waiting for peer response...
  ✓ Received response from 198.51.100.30:55555 (4 bytes)
  ✓ Sent acknowledgment

[Data Exchange Phase]
  ✓ Sent test message: "Hello from hole punch demo!"
  ✓ Received test message: "Hello from hole punch demo!"

✅ Hole punching successful!
```

### Client Mode (Initiator)

Connect to the server's LAN address (via VPN):

```bash
./hole_punch_demo 10.10.1.50:9999
```

Output example:
```
==========================================
    NAT Hole Punching Demo
    Using STUN + TCP Control Channel
==========================================

[Client Mode]
Peer Endpoint: 10.10.1.50:9999 (via VPN)
Local LAN Address: 10.40.1.75 (using ephemeral UDP port)
Public Address:   198.51.100.30:55555

[Control Channel Connection]
Connecting to peer...
✓ Connected to peer

[Control Channel Exchange]
Sending local address info via TCP...
Receiving peer address info via TCP...
  Peer: LAN: 10.10.1.50:9999, PUBLIC: 203.0.113.45:54321

[Hole Punch Phase]
  Creating UDP socket on port [ephemeral]
  Sending hole punch packets to 203.0.113.45:54321
  ✓ Sent hole punch packet 1
  ✓ Sent hole punch packet 2
  ✓ Sent hole punch packet 3
  Waiting for peer response...
  ✓ Received response from 203.0.113.45:54321 (4 bytes)
  ✓ Sent acknowledgment

[Data Exchange Phase]
  ✓ Sent test message: "Hello from hole punch demo!"
  ✓ Received test message: "Hello from hole punch demo!"

✅ Hole punching successful!
```

## How It Works

### Phase 1: Address Discovery

1. **Local Address**: Get the IP address of the interface used to reach the internet
   - Uses a UDP "route probe" to 8.8.8.8 to determine the default route

2. **Public Address**: Use STUN to discover the public IP:port seen by external servers
   - Sends STUN binding requests to public STUN servers
   - Receives the NAT's view of the client's address

### Phase 2: Control Channel Exchange (TCP over VPN)

1. **Server** listens on TCP port (default: 9999)
2. **Client** connects to server's LAN address
3. Both peers serialize their addresses (12 bytes each):
   ```
   [LAN IP (4 bytes)][LAN Port (2 bytes)][Public IP (4 bytes)][Public Port (2 bytes)]
   ```
4. Exchange completes, TCP connection closes

### Phase 3: Hole Punching (UDP over Internet)

1. **Client** sends 3 hole punch packets to server's **public** address
   - These packets punch through both NAT gateways
   - Creates a pinhole in the client-side NAT
   - Server-side NAT sees traffic from this specific address+port combination

2. **Server** receives from client's public address
   - Sends acknowledgment back, punching its side
   - Both NATs now have bidirectional pinholes open

3. **Data Exchange**: Send test messages to verify connectivity

## Design for Future Extension

The control channel is abstracted as `tcp_control_channel` class:
- Serialize/deserialize peer info (12 bytes)
- Send/receive operations are decoupled
- Easy to replace with:
  - External rendezvous server
  - TURN protocol
  - VPN Server control channel extension

## Testing on Your VMs

### Terminal 1 (10.10.1.0 - Build VM, Server):
```bash
./hole_punch_demo -s
```

### Terminal 2 (10.40.1.0 - Test VM, Client):
```bash
# First find build VM's LAN address
ping 10.10.1.50  # adjust if needed

# Then run client
./hole_punch_demo 10.10.1.50:9999
```

## Observations

### What You'll See

1. **Before hole punch**: UDP packets from client to server's public address would be dropped (NAT doesn't know the flow)
2. **After hole punch**: Direct UDP connectivity works despite NATs
3. **VPN vs Internet**: Control channel shows "via VPN", but data travels via actual internet routes

### Hairpinning Note

This demo explicitly avoids hairpinning by having peers on different NATs. If you need to test hairpinning, add both peers to the same LAN but use their public addresses—your NAT doesn't support this, so you'd need two different NATs or a router with hairpinning support.

## Troubleshooting

- **STUN discovery fails**: Check internet connectivity, STUN servers may be blocked
- **Control channel times out**: Verify VPN is connected and peer LAN address is reachable
- **Hole punch fails**: NAT may block unsolicited inbound traffic on random ports
- **Messages don't exchange**: Firewall rules or advanced stateful inspection may block the UDP flow

## References

- RFC 3489: STUN Classic
- RFC 5389: STUN Modern
- RFC 5780: NAT Behavior Detection
- Ford, Srisuresh, and Holdrege (2005): "Peer-to-Peer Communication Across Network Address Translators"
