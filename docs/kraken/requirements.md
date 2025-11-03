# 🦑 **Kraken System Requisites**

## **Architecture Overview**

![architecture](./architecture.svg)

---

## **0. General Requirements**

- **G1** --- Kraken shall implement a `cli`interface, it is composed
  of 4 commands:
    1. `--campaign`: specify campaign path to load the campaign from
    2. `--cidrs` (optional): specify cidr/host to target in the campaign, can be
       specified inside the campaign.
    3. `--out`(default: `./results`): specify where to output campaign's output
    4. `--help`: print the help to use the cli interface of the program.
- **G2** --- Kraken shall be a binary executable.
- **G3** --- Kraken binary shall be light and fast in execution.
- **G4** --- Kraken binary shall be modular and designed to make each subsystem
  handle a specific tasks, no duplication of duties.
- **G5** --- Kraken shall take modules as input to make it usable on different
  transport and protocols.
- **G6** --- Kraken shall have a recovery system in case of a module crash.
- **G7** --- Kraken shall have an interface (Web/Native) to see the results in
  real time and to have a direct control on the campaign.
- **G8** --- Kraken shall take as input campaigns which define the security modules
  to test on certain network(s).

## **1. Runner Component (KRK-RUN)**

### **1.1 Architectural Requirements**

- **KRK-RUN-A1** --- The Runner shall be a core subsystem of Kraken responsible
  for executing modules defined in campaigns.
- **KRK-RUN-A2** --- The Runner shall communicate via the Trident conduits
  (transport abstraction).
- **KRK-RUN-A3** --- The Runner shall provide an internal interface for module
  scheduling, execution, and lifecycle management.
- **KRK-RUN-A4** --- The Runner shall isolate each module execution to prevent cross-failure.

### **1.2 Functional Requirements**

- **KRK-RUN-F1** --- The Runner shall not crash if a module crashes.
- **KRK-RUN-F2** --- The Runner shall execute modules in parallel.
- **KRK-RUN-F3** --- The Runner shall support a configurable maximum number of
  parallel module executions.
- **KRK-RUN-F4** --- The Runner shall execute modules targeting different targets
  in parallel.
- **KRK-RUN-F5** --- The Runner shall be configurable from the campaign YAML file.
- **KRK-RUN-F6** --- The Runner shall collect module outputs for the Reporter.
- **KRK-RUN-F7** --- The Runner shall handle retry and timeout logic during execution.

### **1.3 Non-Functional Requirements**

- **KRK-RUN-N1** --- The Runner shall efficiently use system resources during
  concurrent execution.
- **KRK-RUN-N2** --- The Runner shall ensure stability under high concurrency.
- **KRK-RUN-N3** --- The Runner shall produce structured logs for every module execution.
- **KRK-RUN-N4** --- The Runner shall recover gracefully from transient system
  or network errors.

---

## **2. Scanner Component (KRK-SCN)**

### **2.1 Architectural Requirements**

- **KRK-SCN-A1** --- The Scanner shall serve as Kraken's discovery subsystem.
- **KRK-SCN-A2** --- The Scanner shall integrate with Nmap for IP-layer discovery
  and scanning.
- **KRK-SCN-A3** --- The Scanner shall expose its results to the Runner and Reporter
  through a standardized data schema.
- **KRK-SCN-A4** --- The Scanner shall support modular extensions for future
  discovery engines.

### **2.2 Functional Requirements**

- **KRK-SCN-F1** --- The Scanner shall perform network reconnaissance as the
  first step of a campaign.
- **KRK-SCN-F2** --- The Scanner shall use Nmap for IP-layer scanning (TCP/UDP ports).
- **KRK-SCN-F3** --- The Scanner shall identify targets at the L2 layer.
- **KRK-SCN-F4** --- The Scanner shall assign classification tags to identified
  targets.
- **KRK-SCN-F5** --- The Scanner shall be configurable via YAML parameters.
- **KRK-SCN-F6** --- The Scanner shall provide non-invasive and non-aggressive
  options by default.
- **KRK-SCN-F7** --- The Scanner shall output structured data consumable by
  the Runner.
- **KRK-SCN-F8** --- The Scanner shall support both IPv4 and IPv6 scanning.

### **2.3 Non-Functional Requirements**

- **KRK-SCN-N1** --- The Scanner shall minimize network footprint during reconnaissance.
- **KRK-SCN-N2** --- The Scanner shall ensure accuracy of service and protocol identification.
- **KRK-SCN-N3** --- The Scanner shall be extensible for integration with
  other discovery tools.
- **KRK-SCN-N4** --- The Scanner shall complete discovery within a configurable
  timeout per target.

---

## **3. Reporter Component (KRK-REP)**

### **3.1 Architectural Requirements**

- **KRK-REP-A1** --- The Reporter shall serve as the result aggregation and
  reporting subsystem.
- **KRK-REP-A2** --- The Reporter shall consume outputs from the Runner and
  Scanner through defined interfaces.
- **KRK-REP-A3** --- The Reporter shall support multiple pluggable output formats.
- **KRK-REP-A4** --- The Reporter shall write all reports under the campaign's
  `result` directory.

### **3.2 Functional Requirements**

- **KRK-REP-F1** --- The Reporter shall aggregate findings from all modules and scanners.
- **KRK-REP-F2** --- The Reporter shall generate campaign-level summaries
  (metadata, duration, target counts).
- **KRK-REP-F3** --- The Reporter shall produce reports in two formats:
    1. **Markdown/PDF** --- for human readability
    2. **JSON** --- for machine readability
    3. **WebSite** --- for interactive view
- **KRK-REP-F4** --- The Reporter shall support per-module and per-target report
  breakdowns.
- **KRK-REP-F5** --- The Reporter shall include severity levels and result
  statuses (success/failure).

### **3.3 Non-Functional Requirements**

- **KRK-REP-N1** --- The Reporter shall produce reports asap.
- **KRK-REP-N2** --- The Reporter shall ensure report files are deterministic
  and reproducible.
- **KRK-REP-N3** --- The Reporter shall maintain consistent schema across versions
  for backward compatibility.
