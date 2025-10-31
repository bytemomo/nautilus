# ⚙️ **Trident — System Requisites**

## **Architecture Overview**

Trident is a Go-based transport framework that provides a unified, layered **conduit abstraction** across OSI layers L2–L4.
It enables consistent, composable network interactions for tools like **Kraken** and for standalone modules.

---

## **1. Architectural Requirements**

- **TRD-A1** — Trident shall provide a unified, layered **conduit** abstraction usable across OSI L2–L4.
- **TRD-A2** — Trident shall be implemented in **Go** and exposed as a stable **library/package API**.
- **TRD-A3** — Trident shall support **composition (stacking)** of conduits to form layered protocols (e.g., TCP→TLS).
- **TRD-A4** — Trident shall remain **protocol-agnostic** and usable independently from Kraken.
- **TRD-A5** — The core API shall define a generic type-safe interface `Conduit[V any]` with:
    - `Dial(context.Context) error`, `Close() error`
    - `Kind() Kind` (Stream/Datagram/Network/Frame)
    - `Stack() []string`
    - `Underlying() V`

- **TRD-A6** — Each conduit shall correctly record its **stack** (e.g., `["tls","tcp"]`).
- **TRD-A7** — Conduits shall expose **capabilities via type** at compile time (no runtime type assertions).
- **TRD-A8** — `Dial(ctx)` shall be **idempotent**, and `Close()` shall safely release resources and be re-callable.
- **TRD-A9** — Conduits shall be **context-aware**, with all operations respecting cancellation and deadlines.
- **TRD-A10** — The library shall include **built-in conduits** for baseline protocols:
  TCP, UDP, TLS, DTLS, Raw IP, and Ethernet Frame.
- **TRD-A11** — The constructor pattern shall follow the **Factory approach**, e.g. `transport.TCP(addr)` or `tlscond.NewTlsClient(inner, cfg)`.
- **TRD-A12** — Allow **custom conduits** to be defined externally by implementing the `Conduit` interface.

---

## **2. Functional Requirements**

### **2.1 Layer Interfaces**

#### **Stream (L4 — connection-oriented)**

- **TRD-F1** — Provide APIs `Recv(ctx, *RecvOptions) (*StreamChunk, error)` and
  `Send(ctx, p []byte, buf Buffer, *SendOptions) (int, Metadata, error)`.
- **TRD-F2** — Implement `Close()`, `CloseWrite()`, `SetDeadline(time.Time)`, `LocalAddr()`, and `RemoteAddr()`.
- **TRD-F3** — Support **half-close semantics** if underlying transport allows.

#### **Datagram (L4 — connectionless)**

- **TRD-F4** — Provide `Recv` / `RecvBatch` and `Send` / `SendBatch` APIs.
- **TRD-F5** — Implement `SetDeadline`, `LocalAddr()`, `RemoteAddr()`.
- **TRD-F6** — Preserve message boundaries (no implicit aggregation or fragmentation).

#### **Network (L3 — Raw IP)**

- **TRD-F7** — Provide `Recv/RecvBatch`, `Send/SendBatch`, and `SetDeadline`.
- **TRD-F8** — Expose `LocalAddr() netip.Addr`, `Proto() int`, and `IsIPv6() bool`.

#### **Frame (L2 — Ethernet)**

- **TRD-F9** — Provide `Recv/RecvBatch`, `Send/SendBatch`, `SetDeadline`.
- **TRD-F10** — Expose `Interface() *net.Interface`.

---

### **2.2 Buffering & Zero-Copy**

- **TRD-F11** — Provide a pooled `Buffer` type with `Bytes()`, `Grow(n)`, `Release()`.
- **TRD-F12** — Receive paths shall return buffers that **must be released** by callers; misuse detectable in debug mode.
- **TRD-F13** — Send paths shall accept both caller-owned slices and pooled buffers for **zero-copy I/O**.
- **TRD-F14** — Buffer pools shall minimize allocations and remain **concurrency-safe**.

---

### **2.3 Metadata & Telemetry**

- **TRD-F15** — Each send/recv operation shall produce `Metadata` with timestamps, interface index, protocol, and flags.
- **TRD-F16** — When available, include **hardware/software timestamps** and IPv6 zone data.
- **TRD-F17** — Expose per-conduit **statistics** (bytes, packets, retries, handshake time, errors).

---

### **2.4 Configuration & Options**

- **TRD-F18** — All conduits shall support **timeouts** (connect/read/write/handshake) and **retry/backoff** options.
- **TRD-F19** — TLS/DTLS conduits shall expose configurable options:
    - protocol versions, cipher suites, SNI, certificates, PSKs.

- **TRD-F20** — Datagram conduits shall allow **tunable batch size**, socket buffer, and MTU limits.
- **TRD-F21** — Configuration shall use typed option functions or structured configs.

---

### **2.5 Reliability & Flow Control**

- **TRD-F22** — Implement **exponential backoff with jitter** for reconnects.
- **TRD-F23** — All I/O operations shall honor **deadlines**, producing typed timeout errors.
- **TRD-F24** — Support optional **connection pooling** hooks (future enhancement).

---

### **2.6 Security**

- **TRD-F25** — Default TLS/DTLS settings shall enforce **secure defaults** (no weak ciphers).
- **TRD-F26** — Support **mTLS** and **DTLS client authentication** with negotiated parameters exposed via metadata.
- **TRD-F27** — Sensitive keys or PSKs shall never be logged; redact from logs and error strings.
- **TRD-F28** — Provide an **opt-in insecure mode** (`InsecureSkipVerify`) that is **disabled by default** and clearly labeled.

---

### **2.7 Observability & Diagnostics**

- **TRD-F29** — Provide structured logging with **per-connection IDs** and standard levels (debug/info/warn/error).
- **TRD-F30** — Offer **logging decorators** to wrap conduits and measure durations, byte counts, and operations.
- **TRD-F31** — Provide **OpenTelemetry hooks** for tracing without hard dependency.
- **TRD-F32** — Support **optional payload capture** (disabled by default; redacted and size-bounded).

---

### **2.8 Error Model**

- **TRD-F33** — Standardize error categories: `ErrTimeout`, `ErrClosed`, `ErrHandshake`, `ErrAuth`, `ErrConfig`, `ErrUnsupported`.
- **TRD-F34** — Wrap OS/library errors with context (operation, endpoint, layer).
- **TRD-F35** — Guarantee **partial I/O** returns correct byte counts; never silently drop data.

---

## **3. Non-Functional Requirements**

### **3.1 Platform & Permissions**

- **TRD-N1** — Support **Linux** and **macOS** as primary platforms.
- **TRD-N2** — L2/L3 conduits may require elevated privileges; failures must produce clear guidance.
- **TRD-N3** — IPv6 behavior (zones, extension headers) shall remain consistent across platforms.

---

### **3.2 Performance & Concurrency**

- **TRD-N4** — Conduits shall be **goroutine-safe** where documented, or provide safe wrappers.
- **TRD-N5** — Batch APIs shall deliver measurable throughput improvement vs. single I/O.
- **TRD-N6** — Minimize allocations in hot paths; reuse buffers for **zero-copy** efficiency.

---

### **3.3 API Stability & Extensibility**

- **TRD-N7** — Public interfaces shall be **versioned and stable** within a major release.
- **TRD-N8** — Enable **Decorator pattern** for protocol layering (e.g., TLS over TCP).
- **TRD-N9** — Document and validate behavior for third-party conduit implementations.

---

### **3.4 Testing & Tooling**

- **TRD-N10** — Provide unit tests for all conduits and interfaces (`go test ./...`).
- **TRD-N11** — Include integration tests for TCP/TLS, UDP/DTLS, raw IP, and Ethernet (with permission checks).
- **TRD-N12** — Provide mock/fake conduits for deterministic tests.
- **TRD-N13** — Maintain ≥80% code coverage across core packages.

---

### **3.5 Documentation**

- **TRD-N14** — All public types and methods shall include GoDoc comments.
- **TRD-N15** — Provide examples for all conduit types: TCP, TLS, UDP, DTLS, Raw IP, and Ethernet.
- **TRD-N16** — Document option defaults, security trade-offs, and privilege requirements.

---

### **3.6 Dependencies**

- **TRD-N17** — Pin and audit all external dependencies (`pion/dtls`, `x/net`, `mdlayher/raw`, etc.).
- **TRD-N18** — Avoid unnecessary transitive dependencies; keep the core lightweight.

---

### **3.7 Future Enhancements (Non-blocking)**

- **TRD-N19** — Add support for QUIC, SCTP, WebSocket, HTTP/2/3 conduits.
- **TRD-N20** — Introduce connection pooling and load-balancing strategies.
- **TRD-N21** — Explore asynchronous/non-blocking backends (e.g., `io_uring`).
- **TRD-N22** — Expand observability with Prometheus exporters and richer metadata.
