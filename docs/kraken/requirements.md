# 🦑 **Kraken System Requisites**

## **Architecture Overview**

![architecture](./architecture.svg)

---

## **1. Runner Component (KRK-RUN)**

### **1.1 Architectural Requirements**

- **KRK-RUN-A1** — The Runner shall be a core subsystem of Kraken responsible for executing modules defined in campaigns.
- **KRK-RUN-A2** — The Runner shall communicate with the Trident transport layer for network I/O.
- **KRK-RUN-A3** — The Runner shall provide an internal interface for module scheduling, execution, and lifecycle management.
- **KRK-RUN-A4** — The Runner shall isolate each module execution to prevent cross-failure.

### **1.2 Functional Requirements**

- **KRK-RUN-F1** — The Runner shall not crash if a module crashes.
- **KRK-RUN-F2** — The Runner shall execute modules in parallel.
- **KRK-RUN-F3** — The Runner shall support a configurable maximum number of parallel module executions.
- **KRK-RUN-F4** — The Runner shall execute modules targeting different targets in parallel.
- **KRK-RUN-F5** — The Runner shall be configurable from the campaign YAML file.
- **KRK-RUN-F6** — The Runner shall collect and standardize module outputs for the Reporter.
- **KRK-RUN-F7** — The Runner shall manage module dependencies (e.g., run module B only after A).
- **KRK-RUN-F8** — The Runner shall handle retry and timeout logic during execution.

### **1.3 Non-Functional Requirements**

- **KRK-RUN-N1** — The Runner shall efficiently use system resources during concurrent execution.
- **KRK-RUN-N2** — The Runner shall ensure stability under high concurrency (≥100 parallel modules).
- **KRK-RUN-N3** — The Runner shall produce structured logs for every module execution (success/failure).
- **KRK-RUN-N4** — The Runner shall recover gracefully from transient system or network errors.

---

## **2. Scanner Component (KRK-SCN)**

### **2.1 Architectural Requirements**

- **KRK-SCN-A1** — The Scanner shall serve as Kraken’s reconnaissance subsystem.
- **KRK-SCN-A2** — The Scanner shall integrate with Nmap for IP-layer discovery and scanning.
- **KRK-SCN-A3** — The Scanner shall expose its results to the Runner and Reporter through a standardized data schema.
- **KRK-SCN-A4** — The Scanner shall support modular extensions for future discovery engines.

### **2.2 Functional Requirements**

- **KRK-SCN-F1** — The Scanner shall perform network reconnaissance as the first step of a campaign.
- **KRK-SCN-F2** — The Scanner shall use Nmap for IP-layer scanning (TCP/UDP ports).
- **KRK-SCN-F3** — The Scanner shall identify targets at the L2 layer (e.g., MAC addresses, vendor).
- **KRK-SCN-F4** — The Scanner shall assign classification tags to identified targets (e.g., protocol, vendor, type).
- **KRK-SCN-F5** — The Scanner shall be configurable via YAML parameters.
- **KRK-SCN-F6** — The Scanner shall provide non-invasive and non-aggressive options by default.
- **KRK-SCN-F7** — The Scanner shall output structured data consumable by the Runner (e.g., JSON).
- **KRK-SCN-F8** — The Scanner shall support both IPv4 and IPv6 scanning.

### **2.3 Non-Functional Requirements**

- **KRK-SCN-N1** — The Scanner shall minimize network footprint during reconnaissance.
- **KRK-SCN-N2** — The Scanner shall ensure accuracy of service and protocol identification.
- **KRK-SCN-N3** — The Scanner shall be extensible for integration with third-party discovery tools.
- **KRK-SCN-N4** — The Scanner shall complete discovery within a configurable timeout per target.

---

## **3. Reporter Component (KRK-REP)**

### **3.1 Architectural Requirements**

- **KRK-REP-A1** — The Reporter shall serve as the result aggregation and reporting subsystem.
- **KRK-REP-A2** — The Reporter shall consume outputs from the Runner and Scanner through defined interfaces.
- **KRK-REP-A3** — The Reporter shall support pluggable output formats (e.g., Markdown, JSON).
- **KRK-REP-A4** — The Reporter shall write all reports under the campaign’s result directory.

### **3.2 Functional Requirements**

- **KRK-REP-F1** — The Reporter shall aggregate findings from all modules and scanners.
- **KRK-REP-F2** — The Reporter shall generate campaign-level summaries (metadata, duration, target counts).
- **KRK-REP-F3** — The Reporter shall produce reports in two formats:
    1. **Markdown** — for human readability
    2. **JSON** — for machine readability

- **KRK-REP-F4** — The Reporter shall support per-module and per-target report breakdowns.
- **KRK-REP-F5** — The Reporter shall include severity levels and result statuses (success/failure).
- **KRK-REP-F6** — The Reporter shall summarize results after campaign completion.

### **3.3 Non-Functional Requirements**

- **KRK-REP-N1** — The Reporter shall produce reports in <10 seconds for campaigns with ≤1,000 targets.
- **KRK-REP-N2** — The Reporter shall ensure report files are deterministic and reproducible.
- **KRK-REP-N3** — The Reporter shall maintain consistent schema across versions for backward compatibility.
- **KRK-REP-N4** — The Reporter shall handle partial or missing module data gracefully.
