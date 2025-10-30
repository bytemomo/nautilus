# **Kraken — System Requisites**

---

## **1. General Requirements**

- **R1.1** — Kraken shall serve as the main orchestrator for security assessment campaigns.
- **R1.2** — Kraken shall coordinate the interaction between campaigns, modules, and transport layers (via Trident).
- **R1.3** — Kraken shall be implemented in Go and packaged as a standalone executable.
- **R1.4** — Kraken shall support both local and distributed execution modes (future extension).

---

## **2. Campaign Management**

- **R2.1** — Kraken shall load campaign definitions from YAML files.
- **R2.2** — Kraken shall validate campaign files against a defined schema (required keys, formats, data types).
- **R2.3** — Kraken shall allow campaigns to specify:
    - Target network ranges (CIDRs or IPs)
    - Module list and execution order
    - Output directory for results
    - Transport and protocol configurations

- **R2.4** — Kraken shall support command-line overrides for YAML-defined parameters.
- **R2.5** — Kraken shall maintain a campaign state machine (e.g., _Pending_, _Running_, _Completed_, _Failed_).
- **R2.6** — Kraken shall allow pausing, resuming, or stopping campaigns gracefully.
- **R2.7** — Kraken shall support running multiple campaigns sequentially or concurrently.
- **R2.8** — Kraken shall log campaign progress and status.

---

## **3. Target Discovery and Classification**

- **R3.1** — Kraken shall perform target discovery within specified CIDR ranges.
- **R3.2** — Kraken shall detect open ports and available network services.
- **R3.3** — Kraken shall identify protocols used by each discovered target (e.g., TCP, UDP, MQTT, CoAP).
- **R3.4** — Kraken shall classify devices by protocol fingerprint, vendor, or known IoT profile.
- **R3.5** — Kraken shall store discovery results in a structured format for module consumption.

---

## **4. Module Management and Execution**

- **R4.1** — Kraken shall load test modules from a designated `modules/` directory.
- **R4.2** — Kraken shall support three module formats:
    - **ABI:** compiled Go plugins
    - **CLI:** external executables
    - **gRPC:** remote service modules

- **R4.3** — Kraken shall validate module metadata (name, version, author, supported protocols).
- **R4.4** — Kraken shall provide a unified execution interface for all module types.
- **R4.5** — Kraken shall execute modules in isolation, preventing one failure from affecting others.
- **R4.6** — Kraken shall handle module dependencies (e.g., module B depends on module A’s results).
- **R4.7** — Kraken shall collect and standardize module outputs (e.g., JSON records).
- **R4.8** — Kraken shall support concurrent module execution when possible.

---

## **5. Transport Integration (Trident)**

- **R5.1** — Kraken shall use the Trident framework for all network communications.
- **R5.2** — Kraken shall automatically select the appropriate Trident conduit based on the module or campaign definition.
- **R5.3** — Kraken shall handle connection retries, timeouts, and transport-level errors.
- **R5.4** — Kraken shall allow campaigns to specify custom transport parameters (e.g., TLS certificates, timeout values).

---

## **6. Reporting and Results**

- **R6.1** — Kraken shall collect all outputs generated during a campaign.
- **R6.2** — Kraken shall aggregate results per module, per target, and per campaign.
- **R6.3** — Kraken shall generate reports in the following formats:
    - JSON (machine-readable)
    - Markdown (human-readable)

- **R6.4** — Kraken shall store reports under a specified `results/` directory.
- **R6.5** — Kraken shall include in each report:
    - Campaign metadata (date, parameters, duration)
    - Module results (success/failure, findings, severity)
    - Target summary

- **R6.6** — Kraken shall provide a summary report after campaign completion.

---

## **7. Command-Line Interface (CLI)**

- **R7.1** — Kraken shall provide a CLI with the following parameters:
    - `--campaign` (YAML file path)
    - `--cidrs` (target range)
    - `--out` (output path)
    - `--report-format` (e.g., json, md)
    - `--verbose` (logging level)

- **R7.2** — Kraken shall display usage information when invoked with `--help`.
- **R7.3** — Kraken shall validate all CLI inputs and handle missing or conflicting parameters gracefully.
- **R7.4** — Kraken shall display progress information (e.g., number of completed targets, elapsed time).

---

## **8. Logging and Error Handling**

- **R8.1** — Kraken shall provide structured logging using a configurable logging library.
- **R8.2** — Kraken shall support multiple log levels: _debug_, _info_, _warn_, _error_.
- **R8.3** — Logs shall include campaign ID, target, and module context.
- **R8.4** — Kraken shall continue executing remaining tasks even when non-critical errors occur.
- **R8.5** — Kraken shall write both console and file-based logs to the campaign’s output directory.

---

## **9. Configuration and Extensibility**

- **R9.1** — Kraken shall allow configuration through both YAML and environment variables.
- **R9.2** — Kraken shall expose a well-defined internal API for integrating new module types.
- **R9.3** — Kraken shall allow future addition of REST/gRPC APIs for remote orchestration.
- **R9.4** — Kraken shall maintain backward compatibility with existing module and campaign formats.

---

## **10. Non-Functional Requirements**

- **R10.1** — Kraken shall run on Linux and macOS operating systems.
- **R10.2** — Kraken shall handle concurrent executions efficiently without data corruption.
- **R10.3** — Kraken shall be able to scale linearly with available CPU cores.
- **R10.4** — Kraken shall isolate module processes to prevent system compromise.
- **R10.5** — Kraken shall include comprehensive developer and user documentation.
- **R10.6** — Kraken shall achieve ≥80% code coverage in unit tests.
- **R10.7** — Kraken’s average campaign run time shall scale proportionally with target count and module complexity.
