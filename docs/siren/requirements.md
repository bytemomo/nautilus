# 🧜 Siren System Requisites

## Architecture Overview

![architecture](./architecture.svg)

---

## 1. High-Level Requirements

### 1.1 Core Functionality

- **HL-F1** --- Siren shall transparently intercept and analyze L2-L4 network
  traffic on a designated Linux network interface.
- **HL-F2** --- Siren shall use eBPF/XDP/TC for high-performance packet
  interception at the kernel level.
- **HL-F3** --- Siren shall provide a rule-based engine to match packet
  characteristics and apply actions such as **drop**, **modify**, **delay**,
  **log**, or **duplicate**.
- **HL-F4** --- Siren shall support custom, user-defined traffic processors written in Go.
- **HL-F5** --- Siren shall record intercepted traffic and rule engine decisions to a structured format for offline analysis.
- **HL-F6** --- Siren shall hook SSL/TLS functions to intercept master keys and
  be able to decode traffic in user-space without the need of passing certificates
  around. NOTE: Not important as this si quite advanced.

### 1.2 User Interaction

- **HL-U1** --- Siren shall be configured via a single, comprehensive YAML file.
- **HL-U2** --- Siren shall be operated as a standalone CLI application, requiring
  `sudo` to attach its eBPF programs.
- **HL-U3** --- Siren shall expose an optional REST API for runtime control over
  rules and recording without requiring a restart.

### 1.3 System Qualities (Non-Functional)

- **HL-Q1** --- Siren shall operate with minimal performance overhead (e.g., <
  10µs per-packet processing latency in userspace).
- **HL-Q2** --- Siren shall be delivered as a single, self-contained binary with
  no runtime dependencies other than a compatible Linux kernel (≥ 5.4).
- **HL-Q3** --- The system shall be secure by default, requiring explicit configuration
  for any features that might weaken security (e.g., TLS interception).
- **HL-Q4** --- The system shall be easily deployable, avoiding complex setup
  like `iptables` rules or `LD_PRELOAD`.

---

## 2. Low-Level Requirements

### 2.1 General

- **LL-G1** --- The Siren CLI shall accept a `-config` flag to specify the path
  to the YAML configuration file.
- **LL-G2** --- The YAML configuration schema shall be versioned and documented,
  covering eBPF settings, targets, rules, and recording.

### 2.2 eBPF Engine (SRN-EBPF)

#### 2.2.1 Architectural Requirements

- **SRN-EBPF-A1** --- The eBPF component shall use an XDP program to gain read-only
  access to all incoming packets on an interface.
- **SRN-EBPF-A2** --- A BPF ring buffer (`ringbuf`) shall be used to pass packet
  metadata and payloads efficiently to userspace.
- **SRN-EBPF-A3** --- A BPF map (e.g., `LRU_HASH`) shall be used to receive
  "drop" decisions from userspace and enforce them in-kernel for specific flows.

#### 2.2.2 Functional Requirements

- **SRN-EBPF-F1** --- The XDP program shall filter packets based on a target
  list (IP, MAC, IP:Port, EtherCAT ID) defined in a BPF map.
- **SRN-EBPF-F2** --- If the target list is empty, the XDP program shall capture
  all traffic on the interface.
- **SRN-EBPF-F3** --- The userspace component shall load, attach, and manage the
  lifecycle of the eBPF program.

#### 2.2.3 Non-Functional Requirements

- **SRN-EBPF-N1** --- The eBPF program must be compatible with Linux kernels
  version 5.4 and newer.
- **SRN-EBPF-N2** --- The pre-compiled eBPF object file shall be embedded in
  the Siren Go binary.
- **SRN-EBPF-N3** --- A `go generate` command shall be provided to recompile
  the eBPF C code using `clang`.

### 2.3 Intercept Engine (SRN-INT)

#### 2.3.1 Architectural Requirements

- **SRN-INT-A1** --- The Intercept Engine shall be a pluggable pipeline that
  processes traffic contexts received from the eBPF engine.
- **SRN-INT-A2** --- The engine shall first evaluate a list of rules and then pass
  the traffic and result to any configured manipulators.

#### 2.3.2 Functional Requirements

- **SRN-INT-F1** --- Rule matching shall support packet direction (ingress/egress),
  content (regex, contains, etc.), and size.
- **SRN-INT-F2** --- Actions shall include `drop`, `delay`, `modify`, `duplicate`,
  `throttle`, and `log`.
- **SRN-INT-F3** --- Only the `drop` action shall be enforced in-kernel via (XDP)
  the eBPF map; all other actions that are compatible should be done via TC the
  remaining done in userspace.
- **SRN-INT-F4** --- Rules shall be loaded from the YAML config and be updatable
  at runtime via the REST API.

### 2.4 Recorder (SRN-REC)

#### 2.4.1 Functional Requirements

- **SRN-REC-F1** --- The Recorder shall capture all intercepted traffic to a file.
- **SRN-REC-F2** --- Supported output formats shall include PCAP and a structured
  JSON format.
- **SRN-REC-F3** --- Recording shall be enabled, disabled, and configured via the
  YAML file and controllable via the REST API.

#### 2.4.2 Non-Functional Requirements

- **SRN-REC-N1** --- Recording shall have minimal performance impact on the core
  interception loop.
