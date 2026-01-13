# Nautilus

Nautilus is a security assessment suite for ICS/IoT environments, built around three core principles:

1. **Orchestration first** - Core handles config parsing, discovery, scheduling, and reporting
2. **Safety by default** - Conservative defaults, bounded concurrency, timeouts
3. **Evidence as first-class output** - Structured findings, attack tree evaluation

## Components

| Component   | Description                                                                                                                                        |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Kraken**  | Server-side security testing orchestrator. Executes modules for fuzzing, CVE checks, misconfiguration detection, and protocol conformance testing. |
| **Trident** | Transport abstraction library introducing the `Conduit` concept for protocol-agnostic I/O.                                                         |

## Features

### Multi-Protocol Support

Nautilus supports security testing across multiple ICS/IoT protocols:

- **MQTT** - Authentication testing, ACL probing, conformance validation, CVE replay
- **RTSP** - Service discovery, path enumeration, credential testing
- **Telnet** - Dictionary-based credential testing
- **TLS** - Version detection, certificate inspection

### Flexible Module System

Kraken supports six module adapter types for maximum flexibility:

- **Native (Go)** - Compiled directly into the binary for performance
- **ABI v1/v2** - C/Rust shared libraries for low-level protocol access
- **CLI** - External executables for tool integration
- **Docker** - Container-based modules for fuzzing campaigns
- **gRPC** - Remote service modules for distributed testing

### Attack Tree Evaluation

Define complex attack scenarios using YAML-based attack trees with:

- AND/OR/LEAF node logic
- Configurable finding modes (any/all/threshold)
- Automatic Mermaid graph generation
- Per-target and aggregated reporting

### Transport Abstraction

Trident provides composable protocol stacks through the `Conduit` interface:

```go
type Conduit[V any] interface {
    Dial(ctx context.Context) error
    Close() error
    Kind() Kind
    Stack() []string
    Underlying() V
}
```

Supported transports: TCP, TLS, UDP, DTLS, Raw IP

## Project Structure

```text
.
├── campaigns/              # Campaign definitions for kraken
│   ├── iot-standard.yaml   # Production campaign
│   ├── iot-black-fuzz.yaml # Black-box fuzzing (Boofuzz)
│   ├── iot-grey-fuzz.yaml  # Grey-box fuzzing (AFL++)
│   └── trees/
│       └── iot.yaml        # Attack tree definitions
├── docs/
│   ├── kraken/
│   ├── trident/
│   └── status.md           # Implementation status
├── kraken/                 # Kraken orchestrator
│   ├── internal/
│   │   ├── adapter/        # Report writers (JSON, attack tree markdown)
│   │   ├── domain/         # Core types (Campaign, Finding, AttackNode)
│   │   ├── loader/         # Dynamic library loader
│   │   ├── modules/        # Native modules (mqtt, rtsp, telnet)
│   │   ├── native/         # Module registry
│   │   ├── runner/         # Parallel execution engine
│   │   ├── scanner/        # nmap-based discovery
│   │   └── transport/      # Conduit management
│   ├── pkg/
│   │   ├── moduleabi/      # ABI headers (v1, v2)
│   │   └── modulepb/       # gRPC protobuf definitions
│   └── main.go
├── modules/                # External modules
│   └── kraken/
│       └── abi/            # C/Rust ABI modules
├── resources/
│   └── scenario-a/         # MQTT evaluation scenario
├── trident/                # Transport abstraction library
│   └── conduit/
├── fuzz/                   # Fuzzing infrastructure
│   ├── harnesses/          # AFL++ harnesses
│   └── seeds/              # Seed corpus
└── deploy/                 # Docker deployment scripts
```

## Quick Start

### Building Kraken

```sh
cd kraken
go build -o kraken .
```

### Running a Campaign

```sh
./kraken -campaign ../campaigns/iot-standard.yaml \
         -cidrs "192.168.1.0/24" \
         -out ../kraken-results
```

### Results

Results are written to `{out}/{campaign_id}/{timestamp}/`:

- `assessment.json` - All findings
- `assessment.success.json` - Successful findings only
- `runs/{host}_{port}.json` - Per-target results
- `attack-trees/summary.md` - Attack tree evaluation summary
- `attack-trees/{host}_{port}.md` - Per-target attack tree details with Mermaid graphs

## Documentation

- [Kraken docs](docs/kraken/documentation.md) - Campaign orchestration, module APIs, attack trees
- [Trident docs](docs/trident/documentation.md) - Transport abstraction and conduit system
- [Implementation status](docs/status.md) - Current implementation status
- [Kraken progress](KRAKEN_PROGRESS.md) - Detailed progress tracking

## Testing

```sh
# Trident tests
go test ./trident/...

# Kraken tests
go test ./kraken/...
```
