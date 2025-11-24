# Kraken

Kraken is a security testing tool that orchestrates scanners and execution
modules against network targets (host:port pairs). The core binary focuses on
target discovery, orchestration, and reporting. Modules receive the target and
user-supplied parameters and own the actual testing logic, which makes Kraken
flexible enough to run anything.

## Architecture

A Kraken run follows four stages:

1. `internal/adapter/yamlconfig` loads `campaign.yaml` plus the optional attack
   trees definition.
2. `internal/scanner` classifies targets (for `network` campaigns) using nmap
   and annotates each host/port with protocol tags.
3. `internal/runner` executes all tasks against every classified target. It
   routes work to the appropriate executor adapter: native Go modules,
   dynamically loaded ABI plugins, CLI binaries, Docker containers, or gRPC
   stubs.
4. `internal/adapter/jsonreport` writes `report.json` and the attack tree
   evaluator checks whether any attacker objective is satisfied.

The high-level component diagram for these stages is defined in
`component.puml` and rendered inside this document using PlantUML.

![Architecture](./architecture.svg)

## Campaign

Kraken is configured with a YAML campaign file. A campaign describes how Kraken
should behave (network discovery vs. fuzzing), which modules to run, and how to
report the results.

### General options

```yaml
id: "iot-standard"
version: "2.0.0"
type: "network" # network (default) or fuzz

name: "IoT Network Assessment"
description: |
    General description of the campaign, what it does, etc...

attack_trees_def_path: "./trees/iot.yaml"
```

`type: fuzz` skips the network scanner entirely and runs the tasks as
stand-alone fuzzers. This mode exists so teams can keep long-running fuzzing
jobs (AFL++, libFuzzer harnesses, etc.) under the same
campaign format and reporting stack, even when the targets are binaries or
protocol parsers instead of reachable services. Network campaigns require CIDRs
through the `--cidrs` flag, whereas fuzzing campaigns do not.

### Runner configuration

Runner options control parallelism during the execution phase:

```yaml
runner:
    max_parallel_targets: 16
```

Kraken enforces this limit when running modules against multiple targets and
always serializes the steps for the same host/port.

### Scanner configuration

Scanner options are only used for `network` campaigns. Kraken wraps
`github.com/Ullaakut/nmap` and exposes a subset of its knobs:

```yaml
scanner:
    open_only: true
    skip_host_discovery: false
    enable_udp: false
    service_detect:
        enabled: true
        version: "ALL" # or "LIGHT"
    min_rate: 100
    timeout: 30m
    timing: T3
    ports:
        - "1883,8883,8083,8084,80,443,8000,8080,8443,8888,502,4840,554,8554"
```

The scanner tags each open service (e.g. `protocol:mqtt`, `supports:tls`), and
these tags are later matched against the modules’ `required_tags`.

### Tasks configuration

Tasks describe which modules Kraken should run. Each task defines:

- `id`: unique name.
- `type`: one of `native`, `lib`, `cli`, `grpc`, or `fuzz`.
- `required_tags`: optional list of tags that must be present on a target.
- `max_duration`: optional timeout enforced by the runner.
- `exec`: execution-specific block (ABI, CLI, Docker, gRPC, parameters, etc.).

```yaml
tasks:
    - id: "mqtt-dict-native"
      type: native
      required_tags: ["protocol:mqtt"]
      max_duration: 30s
      exec:
          params:
              credentials_file: "./wordlists/mqtt.txt"

    - id: "lib-module-v1"
      type: lib
      required_tags: ["supports:tls", "protocol:tcp"]
      exec:
          abi:
              api: v1
              library_path: "/path/to/lib.so"
              symbol: kraken_run
          params:
              tls_insecure: true

    - id: "lib-module-v2"
      type: lib
      required_tags: ["supports:tls", "protocol:tcp"]
      exec:
          abi:
              api: v2
              library_path: "/path/to/lib.so"
              symbol: kraken_run_v2
          conduit:
              kind: 1
              stack:
                  - name: tcp
                  - name: tls
                    params:
                        skip_verify: true

    - id: "cli-module"
      type: cli
      required_tags: ["protocol:mqtt"]
      exec:
          cli:
              exec: "/path/to/exec"
              command: "scan"
          params:
              --test-case-index: "10-20"

    - id: "docker-fuzzer"
      type: fuzz
      exec:
          docker:
              runtime: "podman"
              image: "example/fuzzer:latest"
              mounts:
                  - host_path: "./seeds"
                    container_path: "/work/seeds"
                    read_only: true

    - id: "grpc-module"
      type: grpc
      required_tags: ["protocol:mqtt"]
      exec:
          grpc:
              server_addr: 127.0.0.1:5053
              dial_timeout: 30s
          params:
              key1: value1
```

Modules can be arbitrarily combined in a campaign. Kraken filters the list for
each target based on tag requirements and then executes the filtered plan.

## Modules

### Native modules

Native modules are implemented in Go and compiled into the Kraken binary (see
`internal/modules`). They expose their capabilities through `type: native` tasks
and can be listed with `kraken --native-modules`. Native modules accept per-run
configuration from `exec.params` and automatically receive the conduit stack
defined in their native descriptor.

### Library (ABI) modules

Library modules are shared libraries loaded via the Kraken Module ABI. Two ABI
versions are supported:

- **v1**: the module establishes its own transport (TCP, TLS, etc.) and manages
  all I/O.
- **v2**: Kraken owns the transport stack and injects a conduit handle into the
  module. The `conduit` block specifies the stack (e.g. TCP+TLS) and the kind
  (`kind: 1` for stream, `kind: 2` for datagram). V2 greatly simplifies modules
  but currently only supports a single connection per execution.

Transports available today are `tcp`/`tls` for stream conduits and
`udp`/`dtls` for datagram conduits.

### CLI modules

CLI modules run an external executable on the same machine as Kraken. The CLI
adapter automatically appends `--host`, `--port`, and `--output-dir` (when
available) plus any key/value pairs found in `exec.params`. Module output must
be a `domain.RunResult` JSON document printed to stdout. CLI modules are
available for both `type: cli` and `type: fuzz` tasks (the runner omits the
target information for fuzzers).

### Docker modules

CLI/fuzz tasks can also specify a `docker` execution block. Kraken runs the
container using the configured runtime (defaults to `podman`) and expects the
container to emit a `domain.RunResult` JSON payload on stdout. Bind mounts can
be declared under `mounts` to pass seeds, wordlists, or output directories into
the container.

### gRPC modules

gRPC modules allow offloading execution to a remote host. The adapter dials
`exec.grpc.server_addr` with an optional `dial_timeout` and streams the target
information together with module parameters.

### Fuzz modules

Fuzz campaigns (`type: fuzz`) still use the CLI and Docker adapters but skip
the scanning phase entirely. The runner injects a placeholder target
(`host: <campaign id>`, `port: 0`), so fuzzers should rely solely on the params
and their mounted assets. This specialized campaign type keeps fuzz orchestration
alongside the rest of Kraken (results are still saved in the same format, attack
trees can still reason about findings) while decoupling the work from network
discovery. It is ideal for AFL++ harnesses, coverage-guided
fuzzer, or any other long-running fuzzing workflow.
