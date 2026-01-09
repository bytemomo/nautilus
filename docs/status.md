# Implementation Status

This document tracks the current implementation status of Nautilus components.

## Kraken

| Component                   | Status | Notes                                               |
| --------------------------- | ------ | --------------------------------------------------- |
| Campaign YAML parsing       | Done   | Network and fuzz campaign types                     |
| Scanner (nmap-based)        | Done   | Host discovery, service detection, protocol tagging |
| Runner (parallel execution) | Done   | max_parallel_targets, timeouts, tag-based filtering |
| Attack Tree Evaluation      | Done   | AND/OR/LEAF logic, finding_mode (any/all/threshold) |
| Attack Tree Reporting       | Done   | Markdown output with tables and Mermaid graphs      |
| JSON Reporting              | Done   | Per-target + aggregated assessment files            |
| Logging (structured)        | Done   | logrus-based, file output                           |

### Module Adapters

| Adapter     | Status | Description                                       |
| ----------- | ------ | ------------------------------------------------- |
| Native (Go) | Done   | Compiled into binary                              |
| ABI v1      | Done   | C/Rust shared libraries, single connection model  |
| ABI v2      | Done   | Conduit-based with open/close primitives          |
| CLI         | Done   | External executables (framework only, no modules) |
| Docker      | Done   | Podman/Docker for fuzz campaigns                  |
| gRPC        | Done   | Remote services (framework only, no modules)      |

### Protocol Modules

| Module                | Type   | Protocol | Description                                        |
| --------------------- | ------ | -------- | -------------------------------------------------- |
| mqtt-dict-attack      | Native | MQTT     | Dictionary-based credential brute-force            |
| mqtt-conformance-test | Native | MQTT     | MQTT v5.0 specification compliance (10 assertions) |
| mqtt-auth-check       | ABI v2 | MQTT     | Anonymous auth and pub/sub permission testing      |
| mqtt-acl-probe        | ABI v2 | MQTT     | ACL probing (CONNECT/SUBSCRIBE/PUBLISH)            |
| mqtt-sys-disclosure   | ABI v1 | MQTT     | $SYS topic leakage detection                       |
| mqtt-replay           | ABI v1 | MQTT     | CVE reproduction via packet replay                 |
| rtsp-dict-attack      | Native | RTSP     | Dictionary-based credential testing                |
| rtsp-surface-scan     | Native | RTSP     | Service discovery, path enumeration                |
| telnet-dict-attack    | Native | Telnet   | Dictionary-based credential testing                |
| telnet-default-creds  | ABI v2 | Telnet   | Service presence detection                         |
| tls-version-check     | ABI v1 | TLS      | TLS 1.0-1.3 support testing                        |
| cert-inspect          | ABI v1 | TLS      | Certificate posture inspection (Rust)              |

### Transport Layer

| Feature               | Status  |
| --------------------- | ------- |
| TCP Stream conduits   | Done    |
| TLS transport         | Done    |
| DTLS transport        | Done    |
| UDP Datagram conduits | Partial |

## Trident

| Feature           | Status |
| ----------------- | ------ |
| TCP Conduit       | Done   |
| TLS Conduit       | Done   |
| UDP Conduit       | Done   |
| DTLS Conduit      | Done   |
| Raw IP Conduit    | Done   |
| Composable stacks | Done   |

## Fuzzing Infrastructure

| Component                 | Status  | Notes                                   |
| ------------------------- | ------- | --------------------------------------- |
| Boofuzz MQTT integration  | Partial | Python PoC exists, CLI module type      |
| AFL++ MQTT harnesses      | Done    | nanomq, mosquitto, wolfmqtt             |
| AFL++ EtherCAT harnesses  | Partial | etherlab, soem harnesses exist          |
| Seed corpus (MQTT)        | Partial | Minimal seeds in fuzz/seeds/mqtt        |
| Seed corpus (EtherCAT)    | Partial | Some seeds present                      |
| Fuzz campaign integration | Done    | iot-grey-fuzz.yaml, iot-black-fuzz.yaml |

## What is Missing

### Protocol Modules

| Module                      | Protocol | Description                                       |
| --------------------------- | -------- | ------------------------------------------------- |
| EtherCAT network assessment | EtherCAT | Attack tree defines findings but no modules exist |
| Modbus modules              | Modbus   | Referenced in attack trees but not implemented    |
| MQTT session hijack         | MQTT     | Session riding and clientID collision detection   |
| MQTT retained message abuse | MQTT     | Retained message attack detection                 |
| MQTT topic leak detection   | MQTT     | Device information leakage via topics             |
| RTSP session exhaustion     | RTSP     | Resource exhaustion testing                       |
| RTSP parser overflow        | RTSP     | Parser vulnerability testing                      |

### Module Adapters

| Adapter | Status                                  |
| ------- | --------------------------------------- |
| CLI     | Framework complete, no modules exist    |
| gRPC    | Framework complete, no modules deployed |

### Transport Layer

| Feature               | Status                                        |
| --------------------- | --------------------------------------------- |
| UDP Datagram conduits | Skeleton exists, native modules not supported |

### Fuzzing

| Component              | Status             |
| ---------------------- | ------------------ |
| Seed corpus (MQTT)     | Minimal seeds      |
| Seed corpus (EtherCAT) | Some seeds present |

## Priority Roadmap

### High Priority

1. Implement EtherCAT network discovery module
2. Add MQTT session/clientID collision detection
3. Expand fuzzing seed corpus
4. Run evaluations and collect findings data

### Medium Priority

1. Implement CLI module examples
2. Deploy gRPC module examples
3. Add Modbus protocol support
4. Complete UDP datagram conduit support
