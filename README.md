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
├── campaigns
│   ├── iot-black-fuzz.yaml
│   ├── iot-grey-fuzz.yaml
│   ├── iot-standard.yaml
│   ├── README.md
│   └── trees
│       └── iot.yaml
├── deploy
│   ├── build
│   │   └── Dockerfile.alpine.kraken
│   └── fuzzing
│       └── aflpp
├── dist
│   └── kraken
├── docs
│   ├── kraken
│   │   ├── architecture.svg
│   │   ├── component.puml
│   │   ├── documentation.md
│   │   └── requirements.md
│   └── trident
│       ├── documentation.md
│       └── requirements.md
├── go.work
├── go.work.sum
├── Justfile
├── kraken
│   ├── go.mod
│   ├── go.sum
│   ├── internal
│   │   ├── adapter
│   │   ├── domain
│   │   ├── loader
│   │   ├── modules
│   │   ├── native
│   │   ├── protocol
│   │   ├── runner
│   │   ├── scanner
│   │   ├── testutil
│   │   └── transport
│   ├── main.go
│   ├── pkg
│   │   ├── moduleabi
│   │   └── modulepb
│   └── testdata
│       ├── campaigns
│       └── modules
├── modules
│   └── kraken
│       ├── abi
│       ├── fuzz
│       └── README.md
├── README.md
├── resources
│   └── scenario-a
│       ├── attack-tree.yaml
│       ├── campaign.yaml
│       ├── captures
│       ├── certs
│       ├── docker-compose.yaml
│       ├── profiles
│       ├── README.md
│       ├── results
│       └── scripts
├── thesis_extracted.txt
└── trident
    ├── conduit
    │   ├── adapters
    │   ├── conduit.go
    │   ├── datalink
    │   ├── logging
    │   ├── network
    │   ├── transport
    │   └── utils
    ├── go.mod
    └── go.sum
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

## Testing

```sh
# Trident tests
go test ./trident/...

# Kraken tests
go test ./kraken/...
```
