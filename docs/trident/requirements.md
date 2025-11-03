# ⚙️ **Trident --- System Requisites**

## **Architecture Overview**

Trident is a Go-based transport framework that provides a unified, layered
**conduit abstraction** across OSI layers L2–L4.
It enables consistent, composable network interactions for tools like **Kraken**
and for standalone modules.

---

## **1. Architectural Requirements**

- **TRD-A1** --- Trident shall provide a unified, layered **conduit** abstraction
  usable across OSI L2–L4.
- **TRD-A2** --- Trident shall be implemented in **Go** and exposed as a stable
  **library/package API**.
- **TRD-A3** --- Trident shall support **composition** of conduits to
  form layered protocols (e.g., TCP→TLS).
- **TRD-A4** --- Trident shall remain **protocol-agnostic** and usable
  independently from Kraken.

<!---
**TRD-A5** --- The core API shall define a generic type-safe interface `Conduit[V any]` with:
    - `Dial(context.Context) error`, `Close() error`
    - `Kind() Kind` (Stream/Datagram/Network/Frame)
    - `Stack() []string`
    - `Underlying() V`
-->

- **TRD-A6** --- Each conduit shall correctly record its **stack**.
- **TRD-A7** --- Conduits shall expose **capabilities via type** at compile time.
- **TRD-A8** --- `Dial(ctx)` shall be **idempotent**, and `Close()` shall safely
  release resources and be re-callable.
- **TRD-A9** --- Conduits shall be **context-aware**, with all operations
  respecting cancellation and deadlines.
- **TRD-A10** --- The library shall include **built-in conduits** for baseline protocols:
  TCP, UDP, TLS, DTLS, Raw IP, and Ethernet Frame.
- **TRD-A11** --- Allow **custom conduits** to be defined externally by implementing
  the `Conduit` interface.

---

## **2. Functional Requirements**

### **2.1 Layer Interfaces**

#### **Stream (L4 --- connection-oriented)**

- **TRD-F1** --- Provide APIs `Recv(ctx, *RecvOptions) (*StreamChunk, error)` and
  `Send(ctx, p []byte, buf Buffer, *SendOptions) (int, Metadata, error)`.
- **TRD-F2** --- Implement `Close()`, `CloseWrite()`, `SetDeadline(time.Time)`,
  `LocalAddr()`, and `RemoteAddr()`.
- **TRD-F3** --- Support **half-close semantics** if underlying transport allows.

#### **Datagram (L4 --- connectionless)**

- **TRD-F4** --- Provide `Recv` / `RecvBatch` and `Send` / `SendBatch` APIs.
- **TRD-F5** --- Implement `SetDeadline`, `LocalAddr()`, `RemoteAddr()`.
- **TRD-F6** --- Preserve message boundaries (no implicit aggregation or fragmentation).

#### **Network (L3 --- Raw IP)**

- **TRD-F7** --- Provide `Recv/RecvBatch`, `Send/SendBatch`, and `SetDeadline`.
- **TRD-F8** --- Expose `LocalAddr() netip.Addr`, `Proto() int`, and `IsIPv6() bool`.

#### **Frame (L2 --- Ethernet)**

- **TRD-F9** --- Provide `Recv/RecvBatch`, `Send/SendBatch`, `SetDeadline`.
- **TRD-F10** --- Expose `Interface() *net.Interface`.

---

### **2.2 Metadata & Telemetry**

- **TRD-F11** --- Each send/recv operation shall produce `Metadata` with
  timestamps, interface index, protocol, and flags.
- **TRD-F12** --- Expose per-conduit **statistics** (bytes, packets, retries,
  handshake time, errors).

---

### **2.3 Configuration & Options**

- **TRD-F13** --- All conduits shall support **timeouts**
  (connect/read/write/handshake) and **retry/backoff** options.
- **TRD-F14** --- TLS/DTLS conduits shall expose configurable options:
  protocol versions, cipher suites, SNI, certificates, PSKs.
- **TRD-F15** --- Datagram conduits shall allow **tunable batch size**, socket
  buffer, and MTU limits.

---

### **2.4 Reliability & Flow Control**

- **TRD-F16** --- Implement **exponential backoff with jitter** for reconnects.
- **TRD-F17** --- All I/O operations shall honor **deadlines**, producing typed
  timeout errors.
- **TRD-F18** --- Support optional **connection pooling** hooks.

---

### **2.5 Security**

- **TRD-F19** --- Default TLS/DTLS settings shall enforce **secure defaults**
  (no weak ciphers).
- **TRD-F20** --- Support **mTLS** and **DTLS client authentication** with
  negotiated parameters exposed via metadata.
- **TRD-F21** --- Sensitive keys or PSKs shall never be logged; redact from logs
  and error strings.
- **TRD-F22** --- Provide an **opt-in insecure mode** (`InsecureSkipVerify`)
  that is **disabled by default** and clearly labeled.

---

## **3. Non-Functional Requirements**

### **3.1 Platform & Permissions**

- **TRD-N1** --- Support **Linux** and **macOS** as primary platforms.
- **TRD-N2** --- L2/L3 conduits may require elevated privileges; failures must
  produce clear guidance.
- **TRD-N3** --- IPv6 behavior (zones, extension headers) shall remain
  consistent across platforms.

---

### **3.2 Performance & Concurrency**

- **TRD-N4** --- Conduits shall be **goroutine-safe** where documented, or
  provide safe wrappers.
- **TRD-N5** --- Minimize allocations in hot paths; reuse
  buffers for **zero-copy** efficiency.

---

### **3.3 API Stability & Extensibility**

- **TRD-N6** --- Public interfaces shall be **versioned and stable**
  within a major release.
- **TRD-N7** --- Enable **Decorator pattern** for protocol layering.
- **TRD-N8** --- Document and validate behavior for third-party conduit implementations.

---

### **3.4 Testing & Tooling**

- **TRD-N9** --- Provide unit tests for all conduits and interfaces (`go test ./...`).
- **TRD-N10** --- Include integration tests for TCP/TLS, UDP/DTLS, raw IP, and
  Ethernet.
- **TRD-N11** --- Provide mock/fake conduits for deterministic tests.

---

### **3.5 Documentation**

- **TRD-N12** --- All public types and methods shall include GoDoc comments.
- **TRD-N13** --- Provide examples for all conduit types: TCP, TLS, UDP, DTLS,
  Raw IP, and Ethernet.
- **TRD-N14** --- Document option defaults, security trade-offs, and
  privilege requirements.

---

### **3.6 Dependencies**

- **TRD-N15** --- Avoid unnecessary dependencies; keep the library lightweight.

---

### **3.7 Future Enhancements (Non-blocking)**

- **TRD-N16** --- Add support for QUIC, SCTP, WebSocket, HTTP/2/3 conduits.
- **TRD-N17** --- Explore asynchronous/non-blocking backends (e.g., `io_uring`).
