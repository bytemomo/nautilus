# Siren

Siren is a transparent MITM agent that now runs fully in the Linux kernel using
eBPF + XDP for packet interception. Packets are copied into a userspace ring
buffer where the Go intercept engine evaluates rules, logging, recording or
injecting actions. Decisions such as “drop this flow” are pushed back into the
kernel via BPF maps which allows Siren to stay invisible to the clients.

## Key Features

- **Kernel-level interception**: eBPF/XDP program copies packet metadata/payload
  with < 1 µs overhead and can drop flows directly in the kernel.
- **Rule-based engine**: YAML rules feed the classic intercept engine (regex,
  payload matching, throttling metadata, etc.).
- **Manipulators**: Optional user-defined processors (implemented in Go) can
  augment or replace rule results.
- **Recorder**: Structured JSON output of every intercepted packet/decision.
- **Simple deployment**: Only needs the interface name and root privileges to
  attach the XDP program; no iptables or LD_PRELOAD tricks.

> [!WARNING]
> Only Linux hosts with kernel ≥ 5.4 are supported right now. The code relies on
> XDP and the eBPF ring-buffer helpers which are unavailable on older kernels.

> [!NOTE]
> The previous user-space proxy (Trident-based) has been removed to keep the
> scope small. Reintroducing it would require re-adding the old proxy package.

## Architecture

<!--
```text
┌──────────┐       ┌─────────────────────────────┐        ┌──────────┐
│ Client   │──────▶│    NIC + XDP (siren_xdp)    │───────▶│ Server   │
└──────────┘       └─────────────────────────────┘        └──────────┘
                        │                  ▲
                        │  ring buffer     │ flow actions
                        ▼                  │
                 ┌─────────────────────────────────┐
                 │    Userspace Siren runtime      │
                 │  - Intercept engine             │
                 │  - Manipulators                 │
                 │  - Recorder                     │
                 └─────────────────────────────────┘
```-->

![architecture](./architecture.svg)

### Components

1. **ebpf/program**: `xdp_proxy.c` compiled into `xdp_proxy.bpf.o`. Exports a ring
   buffer (`events`) and an LRU map (`flow_actions`) used to enforce drops.
2. **ebpf.Manager**: Loads the embedded object, attaches it to the requested NIC,
   manages the ring buffer reader, and exposes helpers to install flow actions.
3. **ebpf.Runtime**: Drains packets, translates them into `core.TrafficContext`,
   passes everything through the rule engine + manipulators and pushes the result
   back to the Manager (e.g., program a drop).
4. **intercept**: Unchanged rule evaluation engine and action primitives.
5. **proxy/recorder/pkg**: Shared infrastructure for stats, manipulators, logging
   and structured recordings.

## Building the eBPF object

The repository ships with a pre-built object (`siren/ebpf/program/xdp_proxy.bpf.o`)
so `go build ./siren` works out-of-the-box. When you change `xdp_proxy.c` you must
recompile manually:

```sh
go generate ./siren/ebpf
```

Requirements:

- Clang/LLVM ≥ 11
- Kernel headers (`linux/types.h`, etc.)
- Root or capabilities to attach XDP (run Siren with sudo)

## Configuration

```yaml
name: demo
description: Demo rule-set
ebpf:
    interface: eth0
    drop_action_duration: 5s
    targets:
        - "ip:192.0.2.10"
        - "ip_port:192.0.2.10:1883"
        - "mac:aa:bb:cc:dd:ee:ff"
        - "ethercat:0x1234"
recording:
    enabled: true
    output: /tmp/siren.pcap
    format: pcap
rules:
    - name: drop-telnet
      match:
          payload_regex: "USER root"
      action:
          type: drop
```

`drop_action_duration` controls how long the kernel will keep dropping packets for
a matching 5‑tuple. Rules still have access to delay/duplicate/modify actions; at
the moment only `drop` is enforced inside XDP, other actions are logged.

`targets` accepts the following selectors (all strings):

- `ip:<address>` — capture IPv4 traffic to/from that address.
- `ip_port:<address>:<port>` — restrict to a single TCP/UDP port.
- `mac:<mac>` — match Ethernet address irrespective of IP.
- `ethercat:<slave_id>` — match EtherCAT frames by slave ID.

If the list is omitted or empty, Siren captures every frame on the interface.

## Running Siren

```sh
sudo ./siren -config siren/config/example-ebpf.yaml
```

Use `ethtool -K <iface> rxvlan off gro off` if the NIC refuses to attach XDP.
Siren writes captured frames into the configured PCAP file, so you can open them
directly in Wireshark, while logging rule matches to stdout.
