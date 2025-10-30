# Trident — System Requisites

## 1. General

- **T1.1** — Trident shall provide a unified, layered **conduit** abstraction usable across OSI L2–L4.
- **T1.2** — Trident shall be implemented in Go and exposed as a stable library/package API.
- **T1.3** — Trident shall support **composition (stacking)** of conduits to form layered protocols (e.g., TCP→TLS).
- **T1.4** — Trident shall be **protocol-agnostic** and usable by Kraken and standalone modules.
- **T1.5** — `Dial(ctx)` shall be **idempotent**; repeated calls succeed without side effects when already connected.
- **T1.6** — `Close()` shall release all resources (sockets, buffers, timers) and be safe to call multiple times.

---

## 2. Conduit Model & Base API

- **T2.1** — Trident shall define `Conduit[V any]` with:
    - `Dial(context.Context) error`, `Close() error`
    - `Kind() Kind` (Stream/Datagram/Network/Frame)
    - `Stack() []string` (top→bottom layer names)
    - `Underlying() V` (layer-specific interface)

- **T2.2** — Trident shall implement **generic, type-safe** conduits (`Conduit[Stream]`, `Conduit[Datagram]`, etc.).
- **T2.3** — Each conduit shall expose **capability via type** (compile-time), not runtime casting.
- **T2.4** — Conduits shall be **context-aware**: all I/O honors cancellation and deadlines.
- **T2.5** — Conduits shall record their **stack** accurately (e.g., `["tls","tcp"]`).

---

## 3. Layer Interfaces (Functional)

### 3.1 Stream (L4 – connection-oriented)

- **T3.1.1** — Provide `Recv(ctx, *RecvOptions) (*StreamChunk, error)` and `Send(ctx, p []byte, buf Buffer, *SendOptions) (int, Metadata, error)`.
- **T3.1.2** — Provide `Close()`, `CloseWrite()`, `SetDeadline(time.Time)`, `LocalAddr()`, `RemoteAddr()`.
- **T3.1.3** — Support **half-close** semantics where the transport supports it.

### 3.2 Datagram (L4 – connectionless)

- **T3.2.1** — Provide `Recv` and **`RecvBatch`** APIs; `Send` and **`SendBatch`** for efficient batched I/O.
- **T3.2.2** — Provide `SetDeadline`, `LocalAddr() netip.AddrPort`, `RemoteAddr() netip.AddrPort`.

### 3.3 Network (L3 – raw IP)

- **T3.3.1** — Provide `Recv/RecvBatch`, `Send/SendBatch`, `SetDeadline`.
- **T3.3.2** — Expose `LocalAddr() netip.Addr`, `Proto() int`, `IsIPv6() bool`.

### 3.4 Frame (L2 – Ethernet)

- **T3.4.1** — Provide `Recv/RecvBatch`, `Send/SendBatch`, `SetDeadline`.
- **T3.4.2** — Expose `Interface() *net.Interface`.

---

## 4. Buffering & Zero-Copy

- **T4.1** — Trident shall provide a **pooled `Buffer`** with `Bytes()`, `Grow(n)`, `Release()`.
- **T4.2** — Receive paths shall return buffers that **must be released** by callers; misuse should be detectable in debug builds.
- **T4.3** — Send paths shall accept either caller-owned `[]byte` or pooled `Buffer` to enable **zero-copy** fast paths where possible.
- **T4.4** — Buffer pools shall minimize allocations and be safe under concurrency.

---

## 5. Metadata & Telemetry

- **T5.1** — Each send/recv operation shall return **`Metadata`** including timestamps, interface index, protocol, flags, and extensible fields.
- **T5.2** — When available from the OS, capture **hardware/software timestamps** and **IPv6 zone**.
- **T5.3** — Trident shall expose per-conduit **stats** (bytes in/out, packets, retries, handshake time, error counts).

---

## 6. Built-In Conduits (Baseline)

- **T6.1** — **TCP** (Stream) with IPv4/IPv6 support and deadlines.
- **T6.2** — **TLS over TCP** (Stream) with configurable `tls.Config`, ALPN, SNI; stack reports `["tls","tcp"]`.
- **T6.3** — **UDP** (Datagram) with batch send/recv and MTU-aware options.
- **T6.4** — **DTLS over UDP** (Datagram) using `github.com/pion/dtls/v3`; stack `["dtls","udp"]`.
- **T6.5** — **Raw IP** (Network) for protocol numbers (e.g., ICMP = 1), IPv4/IPv6.
- **T6.6** — **Ethernet Frame** (Data Link) for raw frame I/O with EtherType selection.
- **T6.7** — Constructors shall follow the **Factory pattern** (e.g., `transport.TCP(addr)`, `transport.UDP(addr)`, `tlscond.NewTlsClient(inner, cfg)`).

---

## 7. Configuration & Options

- **T7.1** — All conduits shall support **timeouts** (connect/read/write/handshake) and **retry/backoff** policies.
- **T7.2** — TLS/DTLS shall expose options for **min/max version**, **cipher suites**, **server name/SNI**, **custom CA**, **client certs**, and **PSK** (if supported).
- **T7.3** — Datagram batch sizes, socket buffers, and maximum payload sizes shall be **tunable**.
- **T7.4** — Expose **per-conduit options** through typed option functions or config structs.

---

## 8. Reliability & Flow Control

- **T8.1** — Implement **exponential backoff with jitter** for reconnects where applicable.
- **T8.2** — All I/O shall honor **deadlines**; timeouts yield typed timeout errors.
- **T8.3** — Datagram APIs shall preserve **message boundaries** (no silent fragmentation/aggregation by the library).
- **T8.4** — Provide optional **connection pooling** hooks for short-lived, repeated connections (future-flagged if not in v1).

---

## 9. Security

- **T9.1** — Default TLS/DTLS configs shall be **secure by default** (modern protocol versions, weak ciphers disabled).
- **T9.2** — Support **mTLS** and **DTLS client auth**; surface negotiated parameters (version, cipher) via metadata or debug hooks.
- **T9.3** — **Sensitive material** (keys/PSKs) shall never be logged; redact in errors and logs.
- **T9.4** — Provide an opt-in **insecure** mode (e.g., `InsecureSkipVerify`) that is **off by default** and clearly labeled.

---

## 10. Observability & Diagnostics

- **T10.1** — Provide structured logging with **per-connection IDs**; levels: debug/info/warn/error.
- **T10.2** — Offer a **logging decorator** that can wrap any conduit and log Dial/Send/Recv with durations and sizes.
- **T10.3** — Provide **OpenTelemetry hooks** (spans for Dial, handshake, Send/Recv) without forcing a dependency (use interfaces).
- **T10.4** — Support optional **payload capture** hooks (off by default; bounded size; redaction options).

---

## 11. Error Model

- **T11.1** — Standardize error categories (e.g., `ErrTimeout`, `ErrClosed`, `ErrHandshake`, `ErrAuth`, `ErrConfig`, `ErrUnsupported`).
- **T11.2** — Wrap underlying OS/library errors with context (operation, endpoint, layer).
- **T11.3** — Ensure **partial I/O** returns accurate byte counts and metadata, never silent drops.

---

## 12. Platform & Permissions

- **T12.1** — Support Linux and macOS; document any OS-specific limitations.
- **T12.2** — L2/L3 conduits may require **elevated privileges** or capabilities; fail with clear errors and guidance.
- **T12.3** — IPv6 features (zones, extension headers) shall behave consistently where supported.

---

## 13. Performance & Concurrency

- **T13.1** — Conduits shall be **goroutine-safe** where documented or provide safe wrappers.
- **T13.2** — Batch APIs (`RecvBatch`, `SendBatch`) shall provide measurable throughput gains for datagram, network, and frame layers.
- **T13.3** — Minimize allocations on hot paths; reuse buffers and avoid copying where possible.

---

## 14. API Stability & Extensibility

- **T14.1** — Public interfaces (`Conduit`, `Stream`, `Datagram`, `Network`, `Frame`, `Buffer`, options) shall be **versioned** and stable within a major version.
- **T14.2** — Provide a **Decorator** pattern for layering (e.g., TLS over TCP) without exposing internals.
- **T14.3** — Allow **custom conduits** by third parties by implementing the interfaces; document required behaviors (Dial/Close/Stack/Underlying).

---

## 15. Testing & Tooling

- **T15.1** — Provide unit tests for each conduit and layer (`go test ./...`).
- **T15.2** — Include **integration tests** for TCP/TLS, UDP/DTLS, raw IP, and Ethernet where feasible (with skips if perms missing).
- **T15.3** — Provide **mock/fake conduits** for deterministic tests.
- **T15.4** — Achieve ≥80% coverage on core packages (interfaces, buffer pool, batch paths).

---

## 16. Documentation

- **T16.1** — Document all public types and methods with GoDoc.
- **T16.2** — Provide **usage examples** for TCP, TLS, UDP, DTLS, raw IP, and Ethernet (as in your description).
- **T16.3** — Document **option defaults**, security trade-offs, and required privileges per layer.

---

## 17. Dependencies

- **T17.1** — External deps (e.g., `pion/dtls`, `x/net`, `x/sys`, `mdlayher/raw`, `mdlayher/packet`) shall be pinned and audited.
- **T17.2** — Avoid unnecessary transitive deps; keep the core small and composable.

---

## 18. Future (Non-blocking) Enhancements

- **T18.1** — QUIC (datagram+stream hybrid), SCTP, WebSocket, HTTP/2/3 conduits.
- **T18.2** — Connection pooling and load-balancing strategies.
- **T18.3** — Async/non-blocking mode and `io_uring` backend (Linux).
- **T18.4** — Extended metrics/observability (prometheus exporters, richer metadata).
