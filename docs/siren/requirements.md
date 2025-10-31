# 🎺 Siren — System Requisites (MITM Testing Proxy)

## Architecture Overview

Siren is a configurable MITM proxy that transparently sits between clients and servers. It accepts client connections (stdlib listeners) and dials upstream servers using **Trident** conduits (TCP/TLS/UDP/DTLS/L2/L3). A rule-driven **Intercept Engine** can log, delay, drop, duplicate, throttle, modify, or corrupt traffic; **Spoof** helpers position the proxy on-path (ARP/DNS); a **Recorder** captures traffic; a REST **API** enables live control.

---

## 1) Architectural Requirements

- **SRN-A1** — Siren shall implement a **transparent MITM proxy** architecture for L2–L4 traffic testing.
- **SRN-A2** — Siren shall be implemented in **Go** and built as a CLI app (`cmd/siren`) plus internal packages.
- **SRN-A3** — Siren shall use **Trident** conduits for upstream/server-side connectivity and stacking (e.g., TCP→TLS, UDP→DTLS).
- **SRN-A4** — The **Intercept Engine** shall be a pluggable pipeline that evaluates rules and applies actions to flows/packets.
- **SRN-A5** — The proxy core shall expose **Stream** and **Datagram** proxy implementations with a common interface.
- **SRN-A6** — **Spoof** utilities (ARP/DNS) shall be isolated from the proxy core and invoked explicitly.
- **SRN-A7** — The **Recorder** shall integrate passively with the proxy pipeline to capture traffic without changing semantics.
- **SRN-A8** — Configuration shall be **YAML-first**, with CLI flags as overrides and a stable schema.
- **SRN-A9** — A **REST API** (optional) shall control runtime operations (rules, recording, status) without process restart.
- **SRN-A10** — Siren shall support **rule evaluation order** and deterministic action chaining.

---

## 2) Functional Requirements

### 2.1 Proxy Core

- **SRN-F1** — Provide **stream proxy** for TCP/TLS and **datagram proxy** for UDP/DTLS.
- **SRN-F2** — Support **transparent** operation via ARP/DNS spoofing and **explicit** proxy via listen/target flags.
- **SRN-F3** — Permit **bidirectional interception**: client→server and server→client.
- **SRN-F4** — Expose **conduit stacks** in config (e.g., `stack: [tcp, tls]` with per-layer params).
- **SRN-F5** — Support **TLS interception**: dynamic per-connection leaf certs signed by a configured CA.
- **SRN-F6** — Provide **connection lifecycle controls**: abrupt/graceful close, timed disconnects, resets (where applicable).
- **SRN-F7** — Support **connection limits**, timeouts, and buffer sizes (configurable).

### 2.2 Intercept Engine (Rules & Actions)

- **SRN-F8** — Load rules from YAML; allow **live updates** via REST API (`POST /rules`, `DELETE /rules/:name`).
- **SRN-F9** — Rule matching shall support **direction**, **content** (contains/starts/ends/regex), **size**, **probability**, and **state** (age, packet/byte counters).
- **SRN-F10** — Provide protocol-aware matchers (HTTP method/path/header, TLS SNI).
- **SRN-F11** — Actions shall include **drop**, **delay (+jitter)**, **modify** (replace/corrupt/truncate/append), **duplicate**, **throttle**, **disconnect**, **log**, and **chain** (sequences).
- **SRN-F12** — Ensure **message boundary preservation** for datagrams; safe mutation for streams with buffer-aware ops.
- **SRN-F13** — Support **fault injection** (protocol violations, corrupted bytes, malformed responses).

### 2.3 Spoofing (Positioning)

- **SRN-F14** — Provide **ARP spoofing** helper to place Siren on-path (requires privileges).
- **SRN-F15** — Provide **DNS spoofing** helper to redirect domains to Siren while proxying upstream with real DNS.

### 2.4 Recording

- **SRN-F16** — Record proxied traffic to **pcap/json/raw** with optional payload inclusion and per-flow indexing.
- **SRN-F17** — Allow **start/stop recording** via CLI or REST (`/record/start`, `/record/stop`).

### 2.5 Configuration & Scenarios

- **SRN-F18** — Support a YAML schema for proxy settings, rule sets, recording, and pre-defined **scenarios**.
- **SRN-F19** — Include bundled scenarios (packet loss, latency, jitter, throttle, disconnects, corruption, reordering, duplicates, protocol violations).
- **SRN-F20** — CLI flags (`-listen`, `-target`, `-proto`, `-config`, `-api`, `-cert/key`, `-ca-cert/ca-key`, `-record`) shall override config.

### 2.6 REST API

- **SRN-F21** — Expose **/status** (connections, bytes, drops, uptime) and **/connections** (active list).
- **SRN-F22** — Support **dynamic rules** management and **recording controls**.

---

## 3) Non-Functional Requirements

### 3.1 Security

- **SRN-N1** — TLS/DTLS interception shall be **opt-in**; require explicit CA material; never intercept by default.
- **SRN-N2** — **Sensitive keys** (CA, leaf, PSKs) shall never be logged and shall be redacted from errors.
- **SRN-N3** — Provide clear **warnings** and documentation; intended for **authorized test environments only**.
- **SRN-N4** — Honor Trident’s **secure defaults**; insecure modes (e.g., skip verify) must be explicit and clearly labeled.

### 3.2 Observability

- **SRN-N5** — Structured logging with **per-connection IDs**; levels: debug/info/warn/error.
- **SRN-N6** — Optional **payload dump** with redaction and size caps; disabled by default.
- **SRN-N7** — Expose metrics counters (bytes, packets, drops, duplicates, delays); tracing hooks compatible with OpenTelemetry.

### 3.3 Performance & Concurrency

- **SRN-N8** — Stream and datagram proxies shall be **goroutine-safe** where documented; handle ≥ **1k concurrent** connections on commodity hosts.
- **SRN-N9** — Use **buffer pooling** and zero-copy paths when possible; provide **batched I/O** via Trident for datagrams.
- **SRN-N10** — Typical baseline overhead target: **0.1–1 ms/packet** (without user-injected delays/modifications).

### 3.4 Platform & Permissions

- **SRN-N11** — Support **Linux** and **macOS**; document OS-specific behavior (e.g., raw sockets, pf).
- **SRN-N12** — Spoofing features may require **root/capabilities**; emit actionable error messages.

### 3.5 Reliability & Error Model

- **SRN-N13** — All operations shall be **context-aware** (timeouts/cancel); return typed errors.
- **SRN-N14** — Partial I/O shall report accurate byte counts; no silent drops outside explicit actions.
- **SRN-N15** — Provide **graceful degradation** when spoofing privileges are missing (proxy still usable in explicit mode).

### 3.6 Testing & Tooling

- **SRN-N16** — ≥ **80%** unit test coverage for core packages (proxy, intercept engine, recorder, config).
- **SRN-N17** — Integration tests for TCP/TLS and UDP/DTLS paths; scenario smoke tests.
- **SRN-N18** — Provide **mocks/fakes** for deterministic rule/action testing.

### 3.7 Documentation

- **SRN-N19** — GoDoc for public types; examples for TCP, TLS MITM, UDP/DTLS, spoofing, recording, and rule chains.
- **SRN-N20** — Document **security implications**, required privileges, and configuration defaults.

### 3.8 Dependencies

- **SRN-N21** — Pin and audit external dependencies (e.g., Trident, DTLS lib); keep transitive set minimal.
- **SRN-N22** — Maintain compatibility with **Trident** public interfaces within a major version.

### 3.9 Roadmap (Non-Blocking)

- **SRN-N23** — WebSocket proxy; HTTP/2/3 interception.
- **SRN-N24** — GUI for real-time traffic visualization.
- **SRN-N25** — Plugin system for custom protocols and matchers.
- **SRN-N26** — Distributed multi-node proxying and performance mode.
- **SRN-N27** — ML-based anomaly detection; Prometheus exporters.

---

## 4) Subsystem Breakout (Traceability Map)

> (Maps repo layout to requirement clusters)

- **proxy/** → SRN-A5, SRN-F1–F7, SRN-N8–N10
- **intercept/** → SRN-A4, SRN-F8–F13, SRN-N5–N7, SRN-N16–N18
- **spoof/** → SRN-A6, SRN-F14–F15, SRN-N11–N12
- **recorder/** → SRN-A7, SRN-F16–F17, SRN-N5–N7
- **config/** → SRN-A8, SRN-F18–F20, SRN-N19–N20
- **cmd/siren/** → SRN-A2, SRN-F20–F22
- **api/** (if separated) → SRN-A9, SRN-F21–F22
