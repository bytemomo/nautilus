# ORCA — Network Assessment Orchestrator

ORCA is a **protocol-agnostic, attack-agnostic** engine to assess networks and their machines.
It runs **campaigns** made of checks / attacks / compliance steps, either:

- against a **real network** (live mode), or
- inside a **reproduced virtual topology** (Docker blueprint) for safe, repeatable testing.

Core loop: **Scan → Classify → Assess → Report**.

---

## High-Level Components

- **Config**
  Loads/validates Campaigns, Extension Manifests, and optional Docker Blueprints.

- **Scanner (Scan)**
  Discovers **Hosts** and **Services** in scope (e.g., `192.168.1.0/24`).
  Uses port/banners to build canonical `Targets`.

- **Classifier (Plan/Map)**
  Maps discovered services to **candidate steps** (checks/attacks/compliance) via selectors (ports, protocol hints, tags).

- **Provisioner (Optional)**
  If a Docker blueprint is provided (or steps require it), stands up an **isolated virtual lab** (networks + containers).
  Otherwise, returns **live network** targets unchanged.

- **Planner**
  Expands campaign steps + targets into **AssessmentJobs**, applies safety modes and scheduling policy.

- **Assessor (Execute)**
  Executes jobs via **Extensions** (dynamic components) with concurrency, timeouts, retries.
  Captures PCAP, logs, artifacts, and normalizes findings.

- **Extensions (Dynamic)**
  Implement one of the stable interfaces and are loaded at runtime via **gRPC** (out-of-process) or **C shared libraries** (in-process):
    - **Protocol** (encode/decode/handshake; e.g., MQTT, CoAP, Modbus)
    - **Mutator** (input transformation; grammar, havoc, sequence)
    - **Executor** (transport; TCP/UDP/Serial/MITM)
    - **Inspector** (checks/compliance; e.g., TLS policy)
      ORCA only depends on their **interfaces**—backend (gRPC/C) is hidden by a registry.

- **Collector & Reporter (Results)**
  Stores artifacts per job (pcaps, crash inputs, logs) and produces **protocol-agnostic findings** (JSON) and optional HTML.

- **Platform**
  Infra utilities: Docker client, networks/containers, FS paths, structured logging, readiness probes.

---

## Project Structure

```
orca/
├─ cmd/
│  └─ orca/
│     └─ main.go                      # CLI: loads campaign, runs orchestrator
│
├─ internal/
│  ├─ config/                         # Parsing & validation
│  │  ├─ campaign.go                  # Campaign, Step, Selector, RuntimeOpts
│  │  ├─ blueprint.go                 # Docker blueprint schema
│  │  ├─ manifest.go                  # Extension manifest schema
│  │  └─ loader.go                    # Load+validate files
│  │
│  ├─ entity/                         # Core domain types
│  │  ├─ target.go                    # Host/Service targets
│  │  ├─ result.go                    # Finding, Artifact, Report
│  │  └─ job.go                       # AssessmentJob, JobStatus
│  │
│  ├─ pipeline/                       # Scan → Classify → Assess → Report
│  │  ├─ scanner/
│  │  │  ├─ scanner.go                # Interface + coordinator
│  │  │  ├─ nmap.go                   # Host+service discovery
│  │  │  └─ masscan.go                # Fast discovery (optional)
│  │  ├─ classifier/
│  │  │  ├─ classifier.go             # Map services → campaign steps
│  │  │  └─ rules.yaml                # Port/banner → protocol hints
│  │  ├─ planner/
│  │  │  └─ planner.go                # Build job queue from steps+targets
│  │  ├─ assessor/
│  │  │  ├─ assessor.go               # Job executor (concurrency, timeouts)
│  │  │  ├─ scheduler.go              # Safety modes, retries, limits
│  │  │  └─ collector.go              # PCAP/log/artifact capture
│  │  └─ reporter/
│  │     ├─ reporter.go               # Aggregate findings, write reports
│  │     └─ templates/                # Optional HTML templates
│  │
│  ├─ usecase/
│  │  ├─ orchestrator.go              # Wires phases per campaign
│  │  └─ provisioner.go               # Provisioner interface, ResolvedTarget
│  │
│  ├─ platform/                       # Infra: FS, logging, docker, net
│  │  ├─ fs/                          # Results layout, run-id dirs
│  │  │  └─ paths.go
│  │  ├─ log/
│  │  │  └─ logger.go
│  │  ├─ net/
│  │  │  └─ tcp_probe.go              # TCP readiness checks
│  │  └─ docker/
│  │     ├─ client.go                 # Docker SDK wrapper
│  │     ├─ containers.go             # Start/Stop/Remove
│  │     ├─ networks.go               # Create/Remove/Attach
│  │     └─ health.go                 # Wait for service readiness
│  │
│  └─ extensions/                     # Interfaces + dynamic loaders
│     ├─ ports.go                     # Protocol/Mutator/Executor/Inspector
│     ├─ registry.go                  # Open/Close by manifest
│     ├─ backends/
│     │  ├─ grpc/
│     │  │  ├─ client_protocol.go
│     │  │  ├─ client_mutator.go
│     │  │  ├─ client_executor.go
│     │  │  └─ client_inspector.go
│     │  └─ cshared/
│     │     ├─ loader_protocol.go     # dlopen+dlsym
│     │     ├─ loader_mutator.go
│     │     ├─ loader_executor.go
│     │     └─ loader_inspector.go
│     └─ types.go                     # Common types/metadata
│
├─ extensions/                        # Reference implementations (optional)
│  ├─ grpc/
│  │  ├─ tls_checker/
│  │  │  ├─ manifest.yaml
│  │  │  └─ server.go
│  │  └─ mqtt_fuzzer/
│  │     ├─ manifest.yaml
│  │     └─ server.go
│  └─ c/
│     ├─ protocol_mqtt/
│     │  ├─ manifest.yaml
│     │  ├─ orca_protocol.h
│     │  └─ libmqttcodec.c
│     └─ executor_tcp/
│        ├─ manifest.yaml
│        └─ libtcpexec.c
│
├─ blueprints/                        # Optional Docker topologies
│  └─ iot_lab.yaml
│
├─ campaigns/                         # Campaign definitions (YAML)
│  └─ subnet_assessment.yaml
│
├─ seeds/                             # Seed corpora (by protocol)
│  └─ mqtt/
│     └─ seed1.bin
│
├─ results/                           # Outputs (per run-id)
│  └─ .gitkeep
│
├─ go.mod
└─ README.md
```

**Results layout (per run-id):**

```
results/<run-id>/
├─ logs/ orchestrator.log
├─ scan/ hosts.json services.json
├─ jobs/<job-id>/ { stdout.txt, stderr.txt, pcap.pcap, artifacts/... }
└─ report/ { findings.json, report.html }
```

---

## Two Example Campaigns

### 1) Mixed mode: Subnet assessment with TLS check + MQTT fuzz

Runs live scans against `192.168.100.0/24`, checks TLS services for policy, fuzzes MQTT brokers, and (optionally) spins a small Docker lab for additional tests.

```yaml
name: full_subnet_assessment
scope:
    type: subnet
    value: 192.168.100.0/24

mode: mixed # live + optional docker blueprint
docker_blueprint: blueprints/iot_lab.yaml

runtime:
    out_dir: results/run_001
    concurrency: 12
    duration_seconds: 7200
    safety:
        read_only: false # allow attacks (fuzzing)
        non_destructive: false
        dry_run: false

steps:
    - id: tls_check
      kind: check
      name: tls_protocol_baseline
      selector:
          ports: [443, 8443, 9443, 8883]
          proto_guesses: ["tls", "https", "mqtt-tls"]
      implementation:
          manifest: extensions/grpc/tls_checker/manifest.yaml
          backend: grpc
      params:
          min_version: "1.2"
          reject_self_signed: true
      policy:
          severity_if_fail: high

    - id: mqtt_fuzz
      kind: attack
      name: mqtt_basic_publish_fuzz
      selector:
          ports: [1883, 8883]
          proto_guesses: ["mqtt"]
      implementation:
          manifest: extensions/grpc/mqtt_fuzzer/manifest.yaml
          backend: grpc
      params:
          seeds_dir: seeds/mqtt
          duration_seconds: 900
          mutator_manifest: extensions/grpc/mutator_grammar/manifest.yaml
```

**What happens**

- **Scan** finds hosts/services; classifier tags TLS/MQTT candidates.
- **TLS check** inspects certs/ciphers and records findings.
- **MQTT fuzz** runs with grammar mutator; artifacts (pcap, crash inputs) saved per job.
- **Report** aggregates per host/service with severities and evidence.

---

### 2) Live mode (read-only): TLS & HTTP compliance sweep

Safe sweep across a production subnet—no attacks or fuzzing; only checks.

```yaml
name: prod_readonly_sweep
scope:
    type: subnet
    value: 10.20.0.0/16

mode: live

runtime:
    out_dir: results/run_prod_2025_10_01
    concurrency: 30
    duration_seconds: 3600
    safety:
        read_only: true # enforce checks-only
        non_destructive: true
        dry_run: false

steps:
    - id: tls_policy
      kind: compliance
      name: tls_nist_sp800_52r2
      selector:
          ports: [443, 8443]
          proto_guesses: ["tls", "https"]
      implementation:
          manifest: extensions/grpc/tls_policy_checker/manifest.yaml
          backend: grpc
      params:
          policy: "nist_sp800-52r2"

    - id: http_headers
      kind: check
      name: http_security_headers
      selector:
          ports: [80, 8080, 443, 8443]
          proto_guesses: ["http", "https"]
      implementation:
          manifest: extensions/grpc/http_header_checker/manifest.yaml
          backend: grpc
      params:
          required_headers: ["Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options"]
```

**What happens**

- **Scan** + **Classify** identify TLS/HTTP services.
- **Assess** runs only non-destructive checks (enforced by `safety.read_only`).
- **Report** highlights missing headers, outdated TLS, self-signed certs, etc., with remediation hints.

---

## Summary

- ORCA treats networks as **assets** (hosts/services), not just single endpoints.
- Campaigns describe **what** to run (checks/attacks/compliance) and **where** to run it (live vs docker).
- Extensions are dynamic (gRPC/C) and **protocol-agnostic** behind stable interfaces.
- Output is normalized, making cross-protocol results **comparable** and **actionable**.

If you want, I can generate starter files for the **campaign schema structs**, a **scanner stub**, and the **provisioner** so you can run a minimal end-to-end dry run right away.
