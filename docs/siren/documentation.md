# Siren

Siren is a configurable MITM proxy that transparently sits between clients and
servers. It accepts client connections (stdlib listeners) and dials upstream
servers using **Trident** conduits (TCP/TLS/UDP/DTLS/L2/L3).

A rule-driven **Intercept Engine** can log, delay, drop, duplicate, throttle,
modify, or corrupt traffic; **Spoof** helpers position the proxy on-path
(ARP/DNS); a **Recorder** captures traffic.

## Key Features

- **Multi-Protocol Support**: TCP, TLS, UDP, DTLS via Trident conduits
- **Traffic Manipulation**: Intercept, modify, delay, drop, or inject packets
- **Rule-Based Testing**: YAML configuration for test scenarios
- **Network Positioning**: ARP/DNS spoofing helpers for transparent proxying
- **Traffic Recording**: Capture and analyze all proxied traffic
- **Fault Injection**: Simulate network failures, corrupted data, protocol violations
- **TLS Interception**: Man-in-the-middle TLS connections with custom certificates

Future:

- **eBPF Support**: Instead of relying on trident conduits use eBPF to make it faster
  and really transparent, it will use XDP and eBP to enhance the Intercept engine.

    > [!WARNING]
    > In the case this approach is taken the siren agent will be able to be installed
    > only on Linux (kernel version >= 3.18) machines.

    > [!NOTE]
    > On the future will be compatible also on windows
    > when [ebpf for windows](github.com/microsoft/ebpf-for-windows) comes out of
    > alpha stage.

## Architecture

```text
┌─────────┐         ┌───────────────────────────┐         ┌─────────┐
│ Client  │────────▶│   Siren                   │────────▶│ Server  │
└─────────┘         │  ┌─────────────────────┐  │         └─────────┘
                    │  │  Intercept Engine   │  │
                    │  │  - Log traffic      │  │
                    │  │  - Modify payloads  │  │
                    │  │  - Delay packets    │  │
                    │  │  - Drop packets     │  │
                    │  │  - Inject faults    │  │
                    │  └─────────────────────┘  │
                    └───────────────────────────┘
```

### Components

1. **proxy**: Core proxy implementations
    - `stream_proxy.go`: TCP/TLS stream proxy
    - `datagram_proxy.go`: UDP/DTLS datagram proxy
    - `proxy.go`: Common proxy interfaces
2. **intercept**: Traffic interception and manipulation
    - `engine.go`: Rule evaluation engine
    - `rules.go`: Rule definitions and matchers
    - `actions.go`: Actions (drop, delay, modify, corrupt, etc.)
3. **spoof**: Network positioning utilities
    - `arp.go`: ARP spoofing for L2 positioning
    - `dns.go`: DNS spoofing for transparent redirection
    - `in_line.go`: Classical proxy that is legitemaly inline
4. **recorder**: Traffic capture and analysis
    - `recorder.go`: Traffic recording to disk
    - `pcap.go`: PCAP export support
5. **config**: Configuration management
    - `config.go`: YAML configuration parser
    - `scenarios.go`: Pre-defined test scenarios
