# ORCA — Network Assessment Orchestrator (Implementation)

This README documents the current implementation of ORCA, a protocol-agnostic, attack-agnostic engine to assess networks and their machines.

## Implementation Status

✅ **Implemented Components:**
- Core configuration system (campaigns, blueprints, manifests)
- Scanner interface with mock implementation
- Rule-based target classifier
- Assessment job planner with dependency management
- Orchestrator coordinating the full pipeline
- Reporter interface for generating assessment reports
- CLI interface with campaign execution
- Clean architecture following the design specification

⚠️ **Partially Implemented:**
- Assessor (mock job execution)
- Reporter (basic reporting)
- File system utilities

❌ **Not Implemented (as requested):**
- Docker runtime and provisioner
- Extension loading (gRPC/C shared libraries)
- Real network scanning (nmap/masscan integration)
- PCAP capture
- Artifact collection

## Architecture

The implementation follows clean architecture principles with clear separation of concerns:

```
cmd/orca/               # CLI entry point
internal/
├── config/             # Configuration loading & validation
├── entity/             # Core domain entities
├── pipeline/           # Core pipeline components
│   ├── scanner/        # Network discovery
│   ├── classifier/     # Target-to-step mapping
│   ├── planner/        # Job scheduling & planning
│   ├── assessor/       # Job execution
│   └── reporter/       # Report generation
├── usecase/           # Orchestration & provisioning
└── platform/          # Infrastructure utilities (placeholder)
```

## Quick Start

### Build the System

```bash
cd orca
go mod tidy
go build -o orca.exe ./cmd/orca
```

### Run a Campaign

```bash
# Show version
./orca.exe --version

# Run a simple TLS check campaign
./orca.exe --campaign campaigns/simple_tls_check.yaml

# Run in dry-run mode
./orca.exe --campaign campaigns/simple_tls_check.yaml --dry-run

# Run with verbose output
./orca.exe --campaign campaigns/simple_tls_check.yaml --verbose
```

### Example Output

```
============================================================
CAMPAIGN EXECUTION SUMMARY
============================================================
Campaign: simple_tls_check
Run ID: 20251001_192802
Mode: live
Status: completed
Duration: 100.9252ms

SCAN RESULTS:
  Hosts discovered: 2
  Services discovered: 3
  Targets identified: 3

CLASSIFICATION RESULTS:
  Target-step mappings: 1
  Unmatched targets: 2
  Unused steps: 0

PLANNING RESULTS:
  Jobs planned: 1
  Job groups: 1
  Estimated runtime: 5m0s

ASSESSMENT RESULTS:
  Jobs executed: 1
  Jobs completed: 1
  Jobs failed: 0

REPORT SUMMARY:
  Total findings: 0
  Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0
============================================================
```

## Campaign Configuration

Campaigns are defined in YAML format. Here's a simple example:

```yaml
name: simple_tls_check
description: Simple TLS/SSL security check campaign
scope:
    type: subnet
    value: 192.168.1.0/24

mode: live

runtime:
    out_dir: results/simple_tls_check
    concurrency: 4
    duration_seconds: 1800
    safety:
        read_only: true
        non_destructive: true
        dry_run: false

steps:
    - id: tls_check
      kind: check
      name: TLS Configuration Check
      selector:
          ports: [443, 8443]
          proto_guesses: ["tls", "https"]
      implementation:
          manifest: ../extensions/grpc/tls_checker/manifest.yaml
          backend: grpc
      params:
          min_version: "1.2"
          reject_self_signed: true
          check_expiration: true
      policy:
          severity_if_fail: high
```

## Extension Manifests

Extensions are described by manifest files. Example:

```yaml
name: tls_checker
version: 1.0.0
description: TLS/SSL configuration and security checker

interface:
  type: inspector
  version: 1.0

backend:
  type: grpc
  config:
    grpc:
      port: 50051
      timeout: 30s

parameters:
  - name: min_version
    type: string
    description: Minimum required TLS version
    default: "1.2"
    valid_values: ["1.0", "1.1", "1.2", "1.3"]

  - name: reject_self_signed
    type: bool
    description: Reject self-signed certificates
    default: true
```

## Core Pipeline Flow

The system implements the core **Scan → Classify → Assess → Report** flow:

1. **Scan Phase**: Discovers hosts and services in the target scope
   - Currently uses mock data (2 hosts, 3 services)
   - Real implementation would integrate nmap/masscan

2. **Classify Phase**: Maps discovered targets to campaign steps
   - Rule-based classification using ports, protocols, services
   - Supports exclusion rules and custom expressions

3. **Plan Phase**: Creates execution plan with job scheduling
   - Handles dependencies between jobs
   - Groups similar jobs for concurrent execution
   - Applies safety policies and constraints

4. **Assess Phase**: Executes assessment jobs
   - Currently mock execution returning sample results
   - Real implementation would load and execute extensions

5. **Report Phase**: Aggregates results into comprehensive reports
   - JSON and HTML output formats
   - Findings grouped by severity and target
   - Statistics and coverage analysis

## Result Structure

Results are organized in timestamped directories:

```
results/
└── simple_tls_check/
    └── 20251001_192802/
        ├── jobs/           # Individual job results
        ├── logs/           # Execution logs
        ├── report/         # Final reports
        ├── scan/           # Discovery results
        └── summary.txt     # Campaign summary
```

## Configuration Validation

The system includes comprehensive configuration validation:

- **Campaign Validation**: Scope, steps, runtime settings
- **Manifest Validation**: Interface compliance, parameter types
- **Blueprint Validation**: Docker service definitions
- **Cross-Validation**: Manifest references, dependencies

## Safety Features

Multiple safety mechanisms are implemented:

- **Read-Only Mode**: Prevents destructive operations
- **Dry-Run Mode**: Plan execution without running jobs
- **Port Restrictions**: Allowed/forbidden port lists
- **Rate Limiting**: Connection and request rate limits
- **Timeout Controls**: Job and campaign timeouts
- **Retry Policies**: Configurable retry mechanisms

## Mock Data for Testing

The current implementation includes realistic mock data:

- **Hosts**:
  - 192.168.1.10 (web-server.local, Linux)
  - 192.168.1.20 (db-server.local, Linux)

- **Services**:
  - HTTP on port 80 (Apache/2.4.41)
  - HTTPS on port 443 (Apache/2.4.41 TLS)
  - MySQL on port 3306 (MySQL 8.0.25)

This allows full pipeline testing without external dependencies.

## Known Limitations

1. **Extension Loading**: Extensions are not actually loaded or executed
2. **Network Scanning**: Uses mock data instead of real network discovery
3. **Docker Provisioning**: Infrastructure provisioning is stubbed
4. **Artifact Collection**: No real artifact capture or PCAP generation
5. **List Command**: Campaign file discovery has path resolution issues

## Next Implementation Steps

To complete the system, the following components need implementation:

1. **Extension Runtime**:
   - gRPC client implementation
   - C shared library loader
   - Extension process management

2. **Real Network Scanning**:
   - Nmap integration for host discovery
   - Masscan integration for fast port scanning
   - Banner grabbing and service fingerprinting

3. **Docker Provisioning**:
   - Docker SDK integration
   - Container lifecycle management
   - Network creation and management
   - Health checks and readiness probes

4. **Artifact System**:
   - PCAP capture during assessments
   - Log aggregation
   - File-based artifact storage
   - Artifact metadata tracking

## Testing the Implementation

The system can be tested with the provided example campaigns:

```bash
# Basic TLS check
./orca.exe --campaign campaigns/simple_tls_check.yaml

# Complex subnet assessment (will fail on missing manifests)
./orca.exe --campaign campaigns/example_subnet_scan.yaml --dry-run
```

The mock implementation provides realistic execution flows and demonstrates the complete architecture working together.

## Code Quality

The implementation follows Go best practices:

- **Interfaces**: All major components use interfaces for testability
- **Error Handling**: Comprehensive error handling with context
- **Configuration**: Struct-based configuration with validation
- **Logging**: Structured logging throughout
- **Testing**: Mock implementations for all external dependencies
- **Documentation**: Comprehensive inline documentation

This implementation provides a solid foundation for building the complete ORCA system while demonstrating clean architecture principles and comprehensive security assessment workflows.
