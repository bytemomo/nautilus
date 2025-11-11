# 🔱 Trident System Requisites

## Architecture Overview

Trident is a Go-based transport framework that provides a unified, layered **conduit abstraction** across OSI layers L2–L4. It enables consistent, composable network interactions for tools like Kraken and for standalone modules.

---

## 1. High-Level Requirements

These requirements define Trident's overall purpose, and quality attributes as
a developer library.

### 1.1 Core Functionality

- **HL-F1** --- Trident shall provide a unified `Conduit` interface to abstract network communications across L2 (Ethernet), L3 (IP), and L4 (TCP/UDP).
- **HL-F2** --- Trident shall enable the composition of conduits to form layered protocol stacks (e.g., TLS over TCP).
- **HL-F3** --- Trident shall include built-in, production-ready conduits for common protocols: TCP, UDP, TLS, and DTLS.
- **HL-F4** --- Trident shall allow developers to implement and integrate custom conduits.

### 1.2 User Interaction

- **HL-U1** --- Trident shall be exposed as a Go library with a stable, versioned, and clearly documented public API.
- **HL-U2** --- The API design shall be idiomatic Go, leveraging interfaces, `context`, and compile-time type safety.

### 1.3 System Qualities (Non-Functional)

- **HL-Q1** --- Trident shall be lightweight, with minimal external dependencies to ensure easy integration.
- **HL-Q2** --- The library shall be high-performance, with an emphasis on low-allocation and zero-copy patterns in hot paths.
- **HL-Q3** --- All conduits shall be safe for concurrent use by multiple goroutines
  (even at the expense of speed).
- **HL-Q4** --- Trident shall enforce secure defaults for all cryptographic conduits (e.g., TLS/DTLS).
  NOTE: Don't really know if this is ok as it simply has to be used in kraken and the
  options can be insecure.
- **HL-Q5** --- The library shall be self-contained and independent.
  NOTE: This is difficult for now it depends on standard lib and famous packages
  for go.

---

## 2. Low-Level Requirements

### 2.1 Core Conduit API (TRD-API)

#### 2.1.1 Architectural Requirements

- **TRD-API-A1** --- The core interface `Conduit[V any]` shall define the primary methods: `Dial`, `Close`, `Kind`, `Stack`, and `Underlying`.
- **TRD-API-A2** --- `Dial(ctx)` shall be idempotent, and `Close()` shall be safe to call multiple times.
- **TRD-API-A3** --- All potentially blocking operations shall accept a `context.Context` for cancellation and deadlines.

#### 2.1.2 Functional Requirements

- **TRD-API-F1** --- `Stack()` shall return a slice of strings representing the protocol layers (e.g., `["tls", "tcp"]`).
- **TRD-API-F2** --- `Underlying() V` shall return the layer-specific interface, enabling compile-time type assertions for capabilities.

### 2.2 Built-in Conduits (TRD-IMPL)

#### 2.2.1 Functional Requirements

- **TRD-IMPL-F1** --- Provide a **Stream** interface for connection-oriented conduits (TCP/TLS) with `Recv`, `Send`, and `CloseWrite` methods.
- **TRD-IMPL-F2** --- Provide a **Datagram** interface for connectionless conduits (UDP/DTLS) with `RecvBatch` and `SendBatch` methods that preserve message boundaries.
- **TRD-IMPL-F3** --- Provide **Network** (L3) and **Frame** (L2) conduits for raw socket operations, requiring elevated privileges.
- **TRD-IMPL-F4** --- All send/receive operations shall return structured `Metadata` including timestamps and protocol details.
- **TRD-IMPL-F5** --- All conduits shall support configurable timeouts (connect, read, write).

#### 2.2.2 Non-Functional Requirements

- **TRD-IMPL-N1** --- L2/L3 conduits that fail due to insufficient privileges must return clear, actionable errors.
- **TRD-IMPL-N2** --- The library shall support both Linux and macOS as primary target platforms.

### 2.3 Security (TRD-SEC)

#### 2.3.1 Functional Requirements

- **TRD-SEC-F1** --- TLS/DTLS conduits shall support configuration of certificates, SNI, and PSKs.
- **TRD-SEC-F2** --- Support for mutual authentication (mTLS/mDTLS) shall be provided.

#### 2.3.2 Non-Functional Requirements

- **TRD-SEC-N1** --- Sensitive materials like private keys and PSKs must be included
  in logs if a specified flag is provided (being used for testing in kraken and
  other modules this is usefull to save keys and use them later with Wireshark).

### 2.4 Testing and Documentation (TRD-DOC)

#### 2.4.1 Non-Functional Requirements

- **TRD-DOC-N1** --- All public APIs must have comprehensive GoDoc comments.
- **TRD-DOC-N2** --- The `docs` directory shall include runnable examples for each built-in conduit type.
- **TRD-DOC-N3** --- The project shall have high unit test coverage for all conduits.
- **TRD-DOC-N4** --- The project shall include integration tests for layered conduits (TCP/TLS, UDP/DTLS).
- **TRD-DOC-N5** --- The library shall provide mock/fake conduits to facilitate deterministic testing for consumers of Trident.
