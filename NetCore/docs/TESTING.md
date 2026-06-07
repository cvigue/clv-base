# NetCore Testing

Testing guide for NetCore. For shared infrastructure details (VMs, networks, CI runners), see [docs/TEST_INFRASTRUCTURE.md](../../docs/TEST_INFRASTRUCTURE.md).

## Current State

As of February 2026:
- ✅ Unit tests for QUIC, UDP multiplexer, and other components
- ⬚ Integration tests (TODO)

---

## Test Infrastructure

NetCore can use the shared test VMs on Emerald for network integration testing:

| VM | Management (eth0) | Isolated (eth1) | Potential Role |
|----|-------------------|-----------------|----------------|
| vpn-test-0 | 10.10.1.x | 192.168.50.10 | QUIC server |
| vpn-test-1 | 10.10.1.x | 192.168.50.11 | QUIC client |
| vpn-test-2 | 10.10.1.x | 192.168.50.12 | Additional client / relay |

The isolated 192.168.50.0/24 network has no external routing, ideal for testing network code without interference.

---

## Test Scenarios (Proposed)

| Scenario | Tier 1 (netns) | Tier 2 (VM) | Notes |
|----------|---------------|-------------|-------|
| QUIC handshake | ✓ | ✓ | Connection establishment |
| QUIC streams | ✓ | ✓ | Bidirectional data |
| UDP multiplexer | ✓ | ✓ | Multiple endpoints |
| Congestion control | ✓ | ✓ | Under load |
| Packet loss handling | ✓ | ✓ | tc netem |
| NAT traversal | ✗ | ✓ | Requires router config |

---

## Next Steps

1. [ ] Define NetCore-specific integration test scenarios
2. [ ] Create `NetCore/integration/` directory structure
3. [ ] Write network namespace test harness
4. [ ] Document VM roles for NetCore testing
