# Siren - Man-in-the-Middle Testing Proxy

Siren is a configurable man-in-the-middle (MITM) proxy for testing client implementations. It sits between clients and servers to intercept, inspect, modify, delay, or drop traffic, enabling comprehensive client resilience testing.

## Overview

Siren acts as a transparent proxy that can be positioned between clients and servers using ARP/DNS spoofing or explicit proxy configuration. It uses **Trident** as its transport layer for connecting to real servers, providing support for TCP, TLS, UDP, DTLS, and lower-layer protocols.

### Key Features

- **Multi-Protocol Support** - TCP, TLS, UDP, DTLS via Trident conduits
- **Traffic Manipulation** - Intercept, modify, delay, drop, or inject packets
- **Rule-Based Testing** - YAML configuration for complex test scenarios
- **Network Positioning** - ARP/DNS spoofing helpers for transparent proxying
- **Traffic Recording** - Capture and analyze all proxied traffic
- **Fault Injection** - Simulate network failures, corrupted data, protocol violations
- **TLS Interception** - Man-in-the-middle TLS connections with custom certificates

## Architecture

```
┌─────────┐         ┌───────────────────────────┐         ┌─────────┐
│ Client  │────────▶│   Siren MITM Proxy        │────────▶│ Server  │
└─────────┘         │                           │         └─────────┘
                    │  ┌─────────────────────┐  │
                    │  │  Intercept Engine   │  │
                    │  │  - Log traffic      │  │
                    │  │  - Modify payloads  │  │
                    │  │  - Delay packets    │  │
                    │  │  - Drop packets     │  │
                    │  │  - Inject faults    │  │
                    │  └─────────────────────┘  │
                    │                           │
                    │  Uses Trident Conduits    │
                    └───────────────────────────┘
```

### Components

- **proxy/** - Core proxy implementations
    - `stream_proxy.go` - TCP/TLS stream proxy
    - `datagram_proxy.go` - UDP/DTLS datagram proxy
    - `proxy.go` - Common proxy interfaces

- **intercept/** - Traffic interception and manipulation
    - `engine.go` - Rule evaluation engine
    - `rules.go` - Rule definitions and matchers
    - `actions.go` - Actions (drop, delay, modify, corrupt, etc.)

- **spoof/** - Network positioning utilities
    - `arp.go` - ARP spoofing for L2 positioning
    - `dns.go` - DNS spoofing for transparent redirection

- **recorder/** - Traffic capture and analysis
    - `recorder.go` - Traffic recording to disk
    - `pcap.go` - PCAP export support

- **config/** - Configuration management
    - `config.go` - YAML configuration parser
    - `scenarios.go` - Pre-defined test scenarios

- **cmd/siren/** - Main application entry point

## Installation

```bash
cd siren
go build -o siren ./cmd/siren
```

## Usage

### Basic TCP Proxy

```bash
# Proxy TCP traffic from :8080 to example.com:80
./siren -listen :8080 -target example.com:80 -proto tcp
```

### TLS Interception

```bash
# Intercept TLS traffic with custom certificate
./siren -listen :8443 -target example.com:443 -proto tls \
    -cert server.crt -key server.key
```

### UDP Proxy

```bash
# Proxy UDP traffic
./siren -listen :5353 -target 8.8.8.8:53 -proto udp
```

### Configuration File

```bash
# Run with configuration file
./siren -config scenarios/delay_test.yaml
```

## Configuration

Siren uses YAML configuration files to define complex test scenarios:

### Example: Packet Loss Simulation

```yaml
name: "Packet Loss Test"
description: "Drop 10% of packets randomly"

proxy:
    listen: ":8080"
    target: "server.example.com:80"
    protocol: tcp

rules:
    - name: "Random Packet Loss"
      match:
          direction: both
      action:
          type: drop
          probability: 0.1 # 10% drop rate
```

### Example: Latency Injection

```yaml
name: "High Latency Test"
description: "Add 500ms delay to all packets"

proxy:
    listen: ":8080"
    target: "server.example.com:80"
    protocol: tcp

rules:
    - name: "Add Latency"
      match:
          direction: both
      action:
          type: delay
          duration: 500ms
```

### Example: Payload Modification

```yaml
name: "Corrupt Response Test"
description: "Corrupt specific server responses"

proxy:
    listen: ":8080"
    target: "server.example.com:80"
    protocol: tcp

rules:
    - name: "Corrupt JSON Responses"
      match:
          direction: server_to_client
          content_contains: "application/json"
      action:
          type: modify
          operation: corrupt_bytes
          positions: [10, 50, 100] # Corrupt bytes at these positions
```

### Example: Connection Termination

```yaml
name: "Sudden Disconnect Test"
description: "Drop connection after 5 seconds"

proxy:
    listen: ":8080"
    target: "server.example.com:80"
    protocol: tcp

rules:
    - name: "Disconnect After Delay"
      match:
          connection_age: ">5s"
      action:
          type: disconnect
          close_type: abrupt # or "graceful"
```

### Example: Protocol Violation

```yaml
name: "HTTP Protocol Violation"
description: "Send malformed HTTP responses"

proxy:
    listen: ":8080"
    target: "server.example.com:80"
    protocol: tcp

rules:
    - name: "Malformed Status Line"
      match:
          direction: server_to_client
          content_starts_with: "HTTP/"
      action:
          type: modify
          operation: replace
          pattern: "HTTP/1.1 200 OK"
          replacement: "HTTP/9.9 999 INVALID"
```

## Rule Matching

Rules can match traffic based on various criteria:

### Match Conditions

```yaml
match:
    # Direction
    direction: client_to_server | server_to_client | both

    # Content matching
    content_contains: "string"
    content_starts_with: "string"
    content_ends_with: "string"
    content_regex: "regex pattern"

    # Size matching
    size_gt: 1024 # Greater than
    size_lt: 100 # Less than
    size_eq: 512 # Equal to

    # Connection state
    connection_age: ">10s"
    packet_count: ">100"
    bytes_transferred: ">1MB"

    # Probability
    probability: 0.1 # 10% chance to match

    # Protocol-specific
    http_method: GET | POST | ...
    http_path: "/api/endpoint"
    http_header: "Authorization: Bearer *"
    tls_sni: "example.com"
```

## Actions

Available actions for matched traffic:

### Drop

```yaml
action:
    type: drop
    probability: 0.5 # Optional: drop only 50% of matches
```

### Delay

```yaml
action:
    type: delay
    duration: 100ms
    jitter: 50ms # Optional: add random jitter ±50ms
```

### Modify

```yaml
action:
    type: modify
    operation: replace | corrupt_bytes | truncate | append
    # Operation-specific parameters
    pattern: "search string"
    replacement: "new string"
    positions: [10, 20, 30] # For corrupt_bytes
    bytes: [0xFF, 0xAA] # For append
```

### Duplicate

```yaml
action:
    type: duplicate
    count: 2 # Send packet twice
    delay: 10ms # Delay between duplicates
```

### Throttle

```yaml
action:
    type: throttle
    rate: 10KB/s # Limit bandwidth
    burst: 1KB # Burst size
```

### Disconnect

```yaml
action:
    type: disconnect
    close_type: abrupt | graceful
    delay: 1s # Optional: disconnect after delay
```

### Log

```yaml
action:
    type: log
    level: info | debug | trace
    message: "Custom log message"
    dump_payload: true
```

### Chain (Multiple Actions)

```yaml
action:
    type: chain
    actions:
        - type: log
          message: "Before delay"
        - type: delay
          duration: 100ms
        - type: log
          message: "After delay"
```

## ARP Spoofing

Position Siren as a gateway using ARP spoofing:

```bash
# Spoof ARP to redirect traffic from victim to attacker
./siren spoof arp \
    -interface eth0 \
    -target 192.168.1.100 \
    -gateway 192.168.1.1 \
    -listen :8080
```

**Requirements:**

- Root/admin privileges
- IP forwarding enabled: `sysctl -w net.ipv4.ip_forward=1`

## DNS Spoofing

Redirect clients using DNS responses:

```bash
# Run DNS proxy that redirects specific domains
./siren spoof dns \
    -listen :53 \
    -upstream 8.8.8.8:53 \
    -spoof "example.com=192.168.1.50"
```

## Traffic Recording

Record all proxied traffic for analysis:

```yaml
proxy:
    listen: ":8080"
    target: "server.example.com:80"
    protocol: tcp

recording:
    enabled: true
    output: "captures/session.pcap"
    format: pcap | json | raw
    include_payload: true
```

Or via CLI:

```bash
./siren -listen :8080 -target server:80 \
    -record captures/session.pcap
```

## Integration with Trident

Siren uses Trident conduits for server-side connections:

```go
// Example: Creating a TLS proxy with Trident
import (
    "bytemomo/trident/conduit"
    "bytemomo/trident/conduit/transport"
    "bytemomo/siren/proxy"
)

// Client-facing listener (standard Go)
listener, _ := tls.Listen("tcp", ":8443", tlsConfig)

// Server-facing conduit (Trident)
serverConduit := transport.TCP("server.example.com:443")
tlsConduit := tls.NewTlsClient(serverConduit, &tls.Config{
    ServerName: "server.example.com",
})

// Create proxy
p := proxy.NewStreamProxy(listener, tlsConduit, rules)
p.Start()
```

### Conduit Stack Examples

**TCP Proxy:**

```yaml
proxy:
    target: "server.com:80"
    conduit:
        kind: stream
        stack:
            - name: tcp
```

**TLS over TCP:**

```yaml
proxy:
    target: "server.com:443"
    conduit:
        kind: stream
        stack:
            - name: tcp
            - name: tls
              params:
                  server_name: "server.com"
                  skip_verify: false
```

**DTLS over UDP:**

```yaml
proxy:
    target: "server.com:5684"
    conduit:
        kind: datagram
        stack:
            - name: udp
            - name: dtls
              params:
                  server_name: "server.com"
```

## Test Scenarios

Siren includes pre-defined test scenarios in `scenarios/`:

- `packet_loss.yaml` - Random packet loss (1%, 5%, 10%, 25%)
- `high_latency.yaml` - High latency injection (100ms, 500ms, 1s)
- `jitter.yaml` - Variable latency (±100ms jitter)
- `bandwidth_limit.yaml` - Bandwidth throttling
- `connection_instability.yaml` - Random disconnects
- `protocol_violations.yaml` - Malformed protocol messages
- `corruption.yaml` - Random byte corruption
- `reordering.yaml` - Packet reordering
- `duplicate.yaml` - Duplicate packets

Run a scenario:

```bash
./siren -config scenarios/packet_loss.yaml
```

## API

Siren can be controlled via a REST API:

```bash
# Start with API enabled
./siren -listen :8080 -target server:80 -api :9090
```

### Endpoints

**GET /status** - Proxy status

```json
{
    "active_connections": 5,
    "bytes_proxied": 1048576,
    "packets_dropped": 10,
    "uptime": "1h30m"
}
```

**POST /rules** - Add rule dynamically

```json
{
    "name": "Emergency Drop",
    "match": { "direction": "both" },
    "action": { "type": "drop" }
}
```

**DELETE /rules/:name** - Remove rule

**GET /connections** - List active connections

**POST /record/start** - Start recording

**POST /record/stop** - Stop recording

## Security Considerations

⚠️ **Warning:** Siren is a testing tool that can:

- Intercept sensitive traffic
- Perform ARP/DNS spoofing attacks
- Violate network policies

**Use only in controlled test environments with proper authorization.**

### TLS Interception

When intercepting TLS:

1. Generate a CA certificate
2. Install CA cert in client trust stores
3. Siren generates per-connection certificates signed by the CA

```bash
# Generate CA
openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt \
    -days 365 -nodes -subj "/CN=Siren Test CA"

# Run with CA
./siren -listen :8443 -target server:443 -proto tls \
    -ca-cert ca.crt -ca-key ca.key
```

## Performance

Siren is designed for testing, not production performance:

- Uses Go's standard library for server-side (accept)
- Uses Trident for client-side (dial) with optimized I/O
- Supports connection pooling
- Buffer pooling for zero-copy where possible
- Batched operations for datagram protocols

Typical overhead: 0.1-1ms per packet (without delays/modifications)

## Troubleshooting

### Permission Denied (ARP/DNS Spoofing)

```bash
# Run with sudo/root
sudo ./siren spoof arp ...

# Or set capabilities
sudo setcap cap_net_raw,cap_net_admin=eip ./siren
```

### TLS Certificate Errors

```bash
# Verify CA installation
openssl verify -CAfile ca.crt server.crt

# Check SNI matching
openssl s_client -connect localhost:8443 -servername example.com
```

### High Memory Usage

Adjust buffer sizes and connection limits:

```yaml
proxy:
    max_connections: 100
    buffer_size: 4096
    connection_timeout: 30s
```

## Examples

See `examples/` directory for complete examples:

- `examples/http_proxy/` - HTTP proxy with request/response logging
- `examples/iot_protocol/` - IoT protocol testing (MQTT, CoAP)
- `examples/game_server/` - Game server latency simulation
- `examples/api_testing/` - API fault injection

## Roadmap

- [ ] WebSocket proxy support
- [ ] HTTP/2 and HTTP/3 interception
- [ ] GUI for real-time traffic visualization
- [ ] Module system for custom protocols
- [ ] Distributed proxy support (multiple Siren instances)
- [ ] Machine learning-based anomaly detection
- [ ] Performance testing mode (high throughput)
- [ ] Integration with Kraken for automated testing campaigns

## Contributing

Contributions welcome! Please see `CONTRIBUTING.md`.

## License

See `LICENSE` file in the root of the Nautilus project.

## See Also

- [Trident README](../trident/README.md) - Transport abstraction layer
- [Kraken README](../kraken/README.md) - Campaign orchestration
