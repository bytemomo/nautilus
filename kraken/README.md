# Kraken - Modular IoT Security Testing Orchestrator

Kraken is a flexible campaign-based security assessment orchestrator designed for IoT and embedded systems. It automates the process of network scanning, target classification, and executing protocol-specific security tests across diverse IoT protocols (MQTT, CoAP, Modbus, HTTP, etc.).

## Overview

Kraken operates in three main phases:

1. **Scanning** - Discovers targets using nmap and classifies them based on services and protocols
2. **Execution** - Runs security test modules against classified targets in parallel
3. **Reporting** - Aggregates findings and evaluates attack trees

## Architecture

Kraken follows Clean Architecture principles with clear separation of concerns:

```
kraken/
├── main.go                    # CLI entry point
├── internal/
│   ├── domain/               # Core business logic and entities
│   │   ├── entities.go       # Core types (Finding, Target, Campaign, etc.)
│   │   ├── config.go         # Configuration structures
│   │   ├── ports.go          # Interface definitions
│   │   └── attack_tree.go    # Attack tree evaluation logic
│   ├── usecase/              # Business logic orchestration
│   │   ├── scanner.go        # Phase 1: Network scanning
│   │   ├── runner.go         # Phase 2: Module execution
│   │   └── reporter.go       # Phase 3: Result aggregation
│   ├── adapter/              # External integrations
│   │   ├── yamlconfig/       # YAML campaign loader
│   │   ├── jsonreport/       # JSON report writer
│   │   ├── abiplugin/        # ABI-based plugin executor (V1/V2)
│   │   ├── cliplugin/        # CLI-based plugin executor (V1 only)
│   │   └── grpcplugin/       # gRPC plugin executor (V2 only)
│   └── module/               # Module system
│       ├── module.go         # Module definition
│       └── registry.go       # Module registry and loader
└── pkg/
    ├── plugabi/              # Plugin ABI headers (C/C++)
    │   ├── orca_plugin_abi.h     # V1 API
    │   └── orca_plugin_abi_v2.h  # V2 API with conduit support
    └── plugpb/               # Plugin protocol buffers (gRPC)
        └── plugin.proto      # V2 gRPC service definition
```

## Key Concepts

### Campaigns

A **campaign** is a YAML-defined security assessment workflow that specifies:

- Target scanning parameters
- Execution configuration (timeouts, parallelism)
- Security test modules to run
- Attack tree definitions for post-analysis

### Modules

**Modules** are security test implementations that can be executed via three different interfaces:

1. **ABI (Application Binary Interface)** - Native/shared libraries (.so, .dylib, .dll)
    - Supports both V1 and V2 APIs
    - High performance, low overhead
    - Direct function calls via dlopen/dlsym

2. **CLI (Command Line Interface)** - External executables
    - V1 API only
    - Easy to develop in any language
    - Returns JSON results via stdout

3. **gRPC (Remote Procedure Call)** - Network services
    - V2 API only
    - Supports bidirectional streaming for I/O
    - Language-agnostic plugin development

### Module Versions

#### V1 API (Legacy)

- Module receives target host:port
- Module creates its own connection
- Module handles all transport logic
- Supported execution types: ABI, CLI

#### V2 API (Modern)

- Module receives a **connected conduit** handle
- Runner manages connection lifecycle
- Module focuses on protocol logic only
- Transport abstraction via conduit system
- Supported execution types: ABI (with conduit), gRPC

### Conduits

A **conduit** is a transport abstraction layer that provides:

- Protocol-agnostic communication (TCP, TLS, UDP, DTLS)
- Layered architecture (e.g., TCP → TLS)
- Unified I/O interface for modules

Conduits are configured in module definitions and built by the runner before module execution.

### Target Classification

Targets are automatically **tagged** during scanning based on:

- Detected services (nmap service detection)
- Port numbers (standard port heuristics)
- Protocol indicators (MQTT, CoAP, Modbus, HTTP, etc.)
- Transport security (TLS/DTLS support)

Example tags:

- `protocol:mqtt`, `protocol:coap`, `protocol:http`
- `transport:tcp`, `transport:udp`
- `supports:tls`

Modules specify **required tags** to filter which targets they should run against.

### Attack Trees

**Attack trees** define logical conditions for successful attacks using:

- **LEAF nodes** - Check for specific findings
- **AND nodes** - All children must succeed
- **OR nodes** - At least one child must succeed

Finding modes for LEAF nodes:

- `any` - At least one finding must succeed
- `all` - All findings must succeed
- `threshold` - Minimum number of findings must succeed

## Usage

### Basic Execution

```bash
./kraken \
  -campaign campaign.yaml \
  -cidrs "192.168.1.0/24,10.0.0.0/24" \
  -out ./results
```

### Campaign YAML Structure

```yaml
id: "iot-mqtt-assessment"
name: "IoT MQTT Security Assessment"
version: "1.0"

# Scanner configuration
scanner:
    iface: "eth0"
    skip_host_discovery: false
    enable_udp: false
    ports: ["1883", "8883", "80", "443", "5683", "502"]
    open_only: true
    service_detect:
        enabled: true
        version: "LIGHT"
    timing: "T4"
    min_rate: 1000
    timeout: 10m

# Runner configuration
runner:
    global_timeout: 5m
    max_parallel_targets: 10

# Path to module definitions directory
modules_path: "./modules"

# Security test modules
steps:
    - id: "mqtt-anon-pub"
      required_tags: ["protocol:mqtt"]
      max_duration: 30s
      type: "lib"
      api: 1 # V2 API
      exec:
          abi:
              library_path: "./modules/mqtt_anon_pub"
              symbol: "ORCA_Run_V2"
          conduit:
              kind: 1 # Stream
              stack:
                  - name: "tcp"
                  - name: "tls"
                    params:
                        skip_verify: true
          params:
              topic: "test/kraken"
              payload: "test"

    - id: "http-banner-grab"
      required_tags: ["protocol:http"]
      max_duration: 15s
      type: "grpc"
      api: 1 # V2 API
      exec:
          grpc:
              server_addr: "localhost:50051"
              dial_timeout: 5s
          conduit:
              kind: 1 # Stream
              stack:
                  - name: "tcp"
                  - name: "tls"
                    params:
                        skip_verify: true
          params:
              path: "/"

# Attack tree definition file
attack_trees_def_path: "./attack_trees.yaml"
```

### Attack Tree Definition

```yaml
- name: "Full MQTT Compromise"
  type: "AND"
  children:
      - name: "Authentication Bypass"
        type: "OR"
        children:
            - name: "Anonymous Access"
              type: "LEAF"
              finding_ids: ["mqtt-anon-pub", "mqtt-anon-sub"]
              finding_mode: "any"

            - name: "Weak Credentials"
              type: "LEAF"
              finding_ids: ["mqtt-weak-auth"]
              finding_mode: "any"

      - name: "Unauthorized Operations"
        type: "AND"
        children:
            - name: "Topic Injection"
              type: "LEAF"
              finding_ids: ["mqtt-topic-inject"]
              finding_mode: "all"

            - name: "Data Manipulation"
              type: "LEAF"
              finding_ids: ["mqtt-data-tamper"]
              finding_mode: "any"
```

## Writing Plugins

### V1 ABI Plugin (C)

```c
#include "orca_plugin_abi.h"
#include <stdlib.h>
#include <string.h>

ORCA_API int ORCA_Run(const char *host, uint32_t port,
                      uint32_t timeout_ms, const char *params_json,
                      ORCA_RunResult **out_result) {
    // Create connection yourself
    int sock = connect_to_target(host, port);

    // Perform security test
    bool vulnerable = test_security_issue(sock);

    // Build result
    ORCA_RunResult *result = malloc(sizeof(ORCA_RunResult));
    result->target.host = strdup(host);
    result->target.port = port;

    // Add findings...
    *out_result = result;
    return 0;
}

ORCA_API void ORCA_Free(void *p) {
    free(p);
}
```

### V2 ABI Plugin (C)

```c
#include "orca_plugin_abi_v2.h"
#include <stdlib.h>
#include <string.h>

ORCA_API int ORCA_Run_V2(ORCA_ConnectionHandle conn,
                         const ORCA_ConnectionOps *ops,
                         const ORCA_HostPort *target,
                         uint32_t timeout_ms,
                         const char *params_json,
                         ORCA_RunResult **out_result) {
    // Connection is already established by runner!
    const ORCA_ConnectionInfo *info = ops->get_info(conn);

    // Send request over provided connection
    const char *request = "GET / HTTP/1.0\r\n\r\n";
    int64_t sent = ops->send(conn, (uint8_t*)request,
                             strlen(request), timeout_ms);

    // Receive response
    uint8_t buffer[4096];
    int64_t received = ops->recv(conn, buffer, sizeof(buffer), timeout_ms);

    // Analyze and build result
    ORCA_RunResult *result = malloc(sizeof(ORCA_RunResult));
    // ... populate findings ...

    *out_result = result;
    return 0;
}

ORCA_API void ORCA_Free_V2(void *p) {
    free(p);
}
```

### V2 gRPC Plugin (Go)

```go
package main

import (
    "context"
    "io"
    plugpb "bytemomo/kraken/pkg/plugpb"
)

type MyPlugin struct {
    plugpb.UnimplementedOrcaPluginV2Server
}

func (p *MyPlugin) RunWithConnection(
    stream plugpb.OrcaPluginV2_RunWithConnectionServer) error {

    // 1. Receive StartExecution
    msg, _ := stream.Recv()
    start := msg.GetStart()

    // 2. Send Ready
    stream.Send(&plugpb.PluginToRunner{
        Message: &plugpb.PluginToRunner_Ready{
            Ready: &plugpb.Ready{
                PluginId: "my-plugin",
                Version:  "1.0.0",
            },
        },
    })

    // 3. Write data to connection
    stream.Send(&plugpb.PluginToRunner{
        Message: &plugpb.PluginToRunner_Write{
            Write: &plugpb.WriteRequest{
                RequestId: 1,
                Data:      []byte("HELLO"),
                TimeoutMs: 5000,
            },
        },
    })

    // 4. Read data from connection
    stream.Send(&plugpb.PluginToRunner{
        Message: &plugpb.PluginToRunner_Read{
            Read: &plugpb.ReadRequest{
                RequestId: 2,
                MaxBytes:  4096,
                TimeoutMs: 5000,
            },
        },
    })

    // 5. Receive data response
    msg, _ = stream.Recv()
    data := msg.GetData()

    // 6. Analyze and return results
    findings := analyzeResponse(data.Data)

    stream.Send(&plugpb.PluginToRunner{
        Message: &plugpb.PluginToRunner_Complete{
            Complete: &plugpb.ExecutionComplete{
                Result: &plugpb.RunResult{
                    Findings: findings,
                },
            },
        },
    })

    return nil
}
```

### V1 CLI Plugin (Python)

```python
#!/usr/bin/env python3
import sys
import json
import socket

def main():
    if len(sys.argv) != 5:
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    timeout_ms = int(sys.argv[3])
    params_json = sys.argv[4]

    # Create connection and test
    sock = socket.create_connection((host, port), timeout=timeout_ms/1000)
    vulnerable = test_vulnerability(sock)
    sock.close()

    # Return JSON result
    result = {
        "target": {"host": host, "port": port},
        "findings": [
            {
                "id": "my-test-1",
                "plugin_id": "my-plugin",
                "success": true | false,
                "title": "Security Issue Found",
                "severity": "high",
                "description": "Detailed description...",
                "evidence": {"key": "value"},
                "tags": ["auth", "bypass"],
                "timestamp": int(time.time()),
                "target": {"host": host, "port": port}
            }
        ],
        "logs": ["Test started", "Test completed"]
    }

    print(json.dumps(result))

if __name__ == "__main__":
    main()
```

## Output

Kraken generates JSON reports in the output directory:

```
./results/
└── iot-mqtt-assessment/
    └── 1704067200/
        ├── 192.168.1.10_1883.json
        ├── 192.168.1.15_8883.json
        ├── 10.0.0.5_80.json
        └── report.json
```

Each target's results include:

- Target information (host:port)
- Findings from all executed modules
- Execution logs
- Timestamps

The final `report.json` aggregates all results.

## Scanner Configuration

| Option                   | Description                    | Example                 |
| ------------------------ | ------------------------------ | ----------------------- |
| `iface`                  | Network interface              | `"eth0"`                |
| `skip_host_discovery`    | Disable ping scan (-Pn)        | `true`                  |
| `enable_udp`             | Enable UDP scanning (-sU)      | `true`                  |
| `ports`                  | Port list to scan              | `["80", "443", "1883"]` |
| `open_only`              | Only report open ports         | `true`                  |
| `service_detect.enabled` | Enable service detection (-sV) | `true`                  |
| `service_detect.version` | Detection intensity            | `"LIGHT"` or `"ALL"`    |
| `timing`                 | Nmap timing template           | `"T0"` to `"T5"`        |
| `min_rate`               | Minimum packet rate            | `1000`                  |
| `timeout`                | Overall scan timeout           | `"10m"`                 |

## Runner Configuration

| Option                 | Description              | Default |
| ---------------------- | ------------------------ | ------- |
| `global_timeout`       | Maximum time per target  | None    |
| `max_parallel_targets` | Parallel execution limit | 1       |

## Module Types

| Type     | Description               | API Support |
| -------- | ------------------------- | ----------- |
| `native` | Native ABI plugin         | V1, V2      |
| `lib`    | Shared library ABI plugin | V1, V2      |
| `grpc`   | gRPC remote plugin        | V2 only     |
| `cli`    | External process          | V1 only     |

## Conduit Configuration

### Stream-based (TCP, TLS)

```yaml
conduit:
    kind: 1 # Stream
    stack:
        - name: "tcp"
        - name: "tls"
          params:
              server_name: "example.com"
              skip_verify: false
              min_version: "TLS1.2"
```

### Datagram-based (UDP, DTLS)

```yaml
conduit:
    kind: 2 # Datagram
    stack:
        - name: "dtls"
          params:
              skip_verify: true
```

## Attack Tree Evaluation

After module execution, Kraken evaluates attack trees against collected findings:

```
For target [192.168.1.10:1883] attack tree is evaluated as true: Full MQTT Compromise
Target: 192.168.1.10:1883
 - Full MQTT Compromise [AND]
   - Authentication Bypass [OR]
     - Anonymous Access [LEAF] Success: true
     - Weak Credentials [LEAF] Success: false
   - Unauthorized Operations [AND]
     - Topic Injection [LEAF] Success: true
     - Data Manipulation [LEAF] Success: true
```

## Development

### Building

```bash
cd kraken
go build -o kraken main.go
```

### Generating Protocol Buffers

```bash
cd pkg/plugpb
go generate
```

## Dependencies

- `github.com/Ullaakut/nmap/v3` - Nmap wrapper
- `github.com/sirupsen/logrus` - Structured logging
- `google.golang.org/grpc` - gRPC support
- `google.golang.org/protobuf` - Protocol buffers
- `gopkg.in/yaml.v3` - YAML parsing
- `bytemomo/trident/conduit` - Transport abstraction layer

## Integration with Trident

Kraken uses the **Trident conduit system** for transport abstraction. Trident provides:

- Unified API for stream and datagram protocols
- Layered architecture (e.g., TCP → TLS → MQTT)
- Connection lifecycle management
- Buffer pooling and memory efficiency

## Roadmap

- [ ] Support for more protocols (BACnet, KNX, Zigbee)
- [ ] Plugin hot-reloading
- [ ] Distributed execution across multiple runners
- [ ] Interactive mode with live results
- [ ] HTML report generation
- [ ] CVE correlation and scoring
- [ ] Plugin marketplace/registry
