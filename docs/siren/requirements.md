# 🧜 Siren — System Requisites

## 1) Architectural Requirements

- **SRN-A1** — Siren shall implement a **transparent MITM proxy** architecture
  for L2–L4 traffic testing.
- **SRN-A2** — Siren shall be implemented in **Go** and built as a CLI app
  (`cmd/siren`) plus internal packages.
- **SRN-A3** — Siren shall use **Trident** conduits for upstream/server-side
  connectivity and stacking (e.g., TCP→TLS, UDP→DTLS).
- **SRN-A4** — The **Intercept Engine** shall be a pluggable pipeline that
  evaluates rules and applies actions to flows/packets.
- **SRN-A5** — The proxy core shall expose **Stream** and **Datagram** proxy
  implementations with a common interface.
- **SRN-A6** — **Spoof** utilities (ARP/DNS) shall be isolated from the proxy
  core and invoked explicitly.
- **SRN-A7** — The **Recorder** shall integrate passively with the proxy pipeline
  to capture traffic without changing semantics.
- **SRN-A8** — Configuration shall be **YAML-first**, with CLI flags as overrides
  and a stable schema.
- **SRN-A9** — A **REST API** (optional) shall control runtime operations
  (rules, recording, status) without process restart.
- **SRN-A10** — Siren shall support **rule evaluation order** and deterministic
  action chaining.

---

## 2) Functional Requirements

### 2.1 Proxy Core

- **SRN-F1** — Provide **stream proxy** for TCP/TLS and **datagram proxy** for UDP/DTLS.
- **SRN-F2** — Support **transparent** operation via ARP/DNS spoofing and
  **explicit** proxy via listen/target flags.
- **SRN-F3** — Permit **bidirectional interception**: client→server and server→client.
- **SRN-F4** — Expose **conduit stacks** in config (e.g., `stack: [tcp, tls]`
  with per-layer params).
- **SRN-F5** — Support **TLS interception**: dynamic per-connection leaf certs
  signed by a configured CA.
- **SRN-F6** — Provide **connection lifecycle controls**: abrupt/graceful close,
  timed disconnects, resets (where applicable).
- **SRN-F7** — Support **connection limits**, timeouts, and buffer sizes (configurable).

### 2.2 Intercept Engine (Rules & Actions)

- **SRN-F8** — Load rules from YAML; allow **live updates** via REST API
  (`POST /rules`, `DELETE /rules/:name`).
- **SRN-F9** — Rule matching shall support **direction**, **content**
  (contains/starts/ends/regex), **size**, **probability**, and **state**
  (age, packet/byte counters).
- **SRN-F10** — Provide protocol-aware matchers (HTTP method/path/header, TLS SNI).
- **SRN-F11** — Actions shall include **drop**, **delay (+jitter)**, **modify**
  (replace/corrupt/truncate/append), **duplicate**, **throttle**,
  **disconnect**, **log**, and **chain** (sequences).
- **SRN-F12** — Ensure **message boundary preservation** for datagrams;
  safe mutation for streams with buffer-aware ops.
- **SRN-F13** — Support **fault injection** (protocol violations, corrupted
  bytes, malformed responses).

### 2.3 Spoofing (Positioning)

- **SRN-F14** — Provide **ARP spoofing** helper to place Siren on-path
  (requires privileges).
- **SRN-F15** — Provide **DNS spoofing** helper to redirect domains to Siren
  while proxying upstream with real DNS.

### 2.4 Recording

- **SRN-F16** — Record proxied traffic to **pcap/json/raw** with optional payload
  inclusion and per-flow indexing.
- **SRN-F17** — Allow **start/stop recording** via CLI or REST (`/record/start`,
  `/record/stop`).

### 2.5 Configuration & Scenarios

- **SRN-F18** — Support a YAML schema for proxy settings, rule sets, recording,
  and pre-defined **scenarios**.
- **SRN-F19** — Include bundled scenarios (packet loss, latency, jitter, throttle,
  disconnects, corruption, reordering, duplicates, protocol violations).
- **SRN-F20** — CLI flags (`-listen`, `-target`, `-proto`, `-config`, `-api`,
  `-cert/key`, `-ca-cert/ca-key`, `-record`) shall override config.

### 2.6 REST API

- **SRN-F21** — Expose **/status** (connections, bytes, drops, uptime) and
  **/connections** (active list).
- **SRN-F22** — Support **dynamic rules** management and **recording controls**.

---

## 3) Non-Functional Requirements

### 3.1 Security

- **SRN-N1** — TLS/DTLS interception shall be **opt-in**; require explicit CA
  material; never intercept by default.
- **SRN-N2** — **Sensitive keys** (CA, leaf, PSKs) shall never be logged and
  shall be redacted from errors.
- **SRN-N3** — Provide clear **warnings** and documentation; intended for
  **authorized test environments only**.
- **SRN-N4** — Honor Trident’s **secure defaults**; insecure modes (e.g., skip
  verify) must be explicit and clearly labeled.

### 3.6 Testing & Tooling

- **SRN-N16** — unit test coverage for core packages (proxy, intercept
  engine, recorder, config).
- **SRN-N17** — Integration tests for TCP/TLS and UDP/DTLS paths
- **SRN-N18** — Provide **mocks/fakes** for deterministic rule/action testing.

### 3.7 Documentation

- **SRN-N19** — GoDoc for public types; examples for TCP, TLS MITM, UDP/DTLS,
  spoofing, recording, and rule chains.
- **SRN-N20** — Document **security implications**, required privileges, and
  configuration defaults.

### 3.8 Dependencies

- **SRN-N21** — Pin and audit external dependencies (e.g., Trident, DTLS lib);
  keep transitive set minimal.
- **SRN-N22** — Maintain compatibility with **Trident** public interfaces within
  a major version.

### 3.9 Roadmap (Non-Blocking)

- **SRN-N23** — WebSocket proxy; HTTP/2/3 interception.
- **SRN-N24** — GUI for real-time traffic visualization.
- **SRN-N25** — Module system for custom protocols and matchers.
- **SRN-N26** — Distributed multi-node proxying and performance mode.
- **SRN-N27** — ML-based anomaly detection; Prometheus exporters.
