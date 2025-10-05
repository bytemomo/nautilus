## 🐋 ORCA — Offensive Reconnaissance & Cybersecurity Automation

**ORCA** is a modular, extensible orchestration framework for automated security assessment and IoT device analysis.
It integrates **network scanning**, **service classification**, and **plugin-driven vulnerability testing** under a unified campaign model.

---

### ⚙️ Features

- **🧭 Automated Scanning (Nmap-based)**
    - Discovers live hosts and open ports via `github.com/Ullaakut/nmap`.
    - Supports TCP, UDP, and version/service detection.
    - Configurable via YAML campaign file (per-scan tuning).
    - IoT-optimized default behavior for constrained environments.

- **🧩 Plugin Architecture**
    - Supports **ABI plugins** (`.dll`, `.so`) for native C/C++/Rust modules.
    - Supports **gRPC plugins** for remote or distributed checks.
    - Parameters and transport definitions are per-test in YAML.
    - Plugins receive structured JSON parameters and return structured findings.

- **📑 Structured Reporting**
    - Aggregates results into `JSON` reports (per-target and global).
    - Compatible with external dashboards or pipelines.
    - Rich evidence storage and tagging.

- **🔐 Supported Plugin Types (examples)**
    - TLS Certificate Inspection (expiry, weak keys, insecure algorithms).
    - MQTT Anonymous Authentication & Default Credentials.
    - Default Password Audit (Telnet/HTTP/SSH).
    - Future: CoAP fuzzing, Modbus security checks, etc.

---

### 🗂️ Project Structure

```
orca/
├── cmd/orca/main.go             # CLI orchestrator entrypoint
├── internal/
│   ├── adapter/
│   │   ├── abiplugin/           # ABI plugin loader (.dll/.so)
│   │   ├── grpcplugin/          # gRPC plugin client
│   │   ├── jsonreport/          # JSON report writer
│   │   └── yamlconfig/          # Campaign YAML loader
│   ├── domain/                  # Core entities (Campaign, Finding, RunResult, etc.)
│   └── usecase/
│       ├── scanner.go           # Nmap-based scanner (IoT-focused)
│       ├── runner.go            # Plugin orchestrator
│       └── reporter.go          # Final report aggregator
├── pkg/
│   └── plugpb/                  # Protobuf definitions (for gRPC plugins)
├── plugins/
│   ├── tls_version_check/       # Example ABI plugin (C)
│   ├── cert_inspect/            # Example ABI plugin (Rust)
│   └── mqtt_audit/              # Example ABI plugin (C with libmosquitto)
└── proto/
    └── plugin.proto             # Plugin interface definition
```

---

### 🚀 Getting Started

#### **1. Build ORCA**

```bash
go build -o orca ./cmd/orca
```

#### **2. Compile Plugins**

Each plugin (C, Rust, etc.) builds as a shared library (`.so`, `.dll`):

```bash
# Example (Linux)
cd plugins/tls_version_check
cmake -B build -S .
cmake --build build --config Release

# Example (Rust)
cd plugins/cert_inspect
cargo build --release
```

The resulting `.so` / `.dll` will be loaded dynamically by ORCA.

---

### 🧰 Usage

#### **1. Prepare a campaign YAML**

Example `campaign.yaml`:

```yaml
scanner:
    enable_udp: false
    service_detect: true
    version_light: true
    skip_host_discovery: true
    open_only: true
    min_rate: 1500
    mqtt_probe_unknown: true
    probe_per_port_timeout: 3s

steps:
    - plugin_id: "tls_version_check"
      required_tags: ["supports:tls", "protocol:tcp"]
      max_duration_s: 20
      exec:
          abi:
              library: "./plugins/tls_version_check/tls_version_check"
              symbol: "ORCA_Run"
          params:
              min_version: "TLS1.2"
              max_version: "TLS1.3"

    - plugin_id: "mqtt_audit"
      required_tags: ["protocol:mqtt"]
      exec:
          abi:
              library: "./plugins/mqtt_audit/mqtt_audit"
              symbol: "ORCA_Run"
          params:
              creds_file: "./creds/mqtt_creds.txt"
```

---

#### **2. Run ORCA**

```bash
./orca --campaign ./campaign.yaml --cidrs 192.168.1.0/24 --out ./results
```

Example output:

```
[scanner] 2025/10/05 22:17:41 [INFO] starting scan: targets=1, ports=default, udp=false, sV=true (light=true, all=false)
[scanner] 2025/10/05 22:17:44 [INFO] scanning... elapsed=3s
[scanner] 2025/10/05 22:18:12 [INFO] scan finished in 31s — hosts=4, open_ports=22
Report written to: results/assessment.json
```

---

### 🧪 Writing Plugins

All ABI plugins must export:

```c
int ORCA_Run(const char *host, uint32_t port, uint32_t timeout_ms,
             const char *params_json, char **out_json, size_t *out_len);

void ORCA_Free(void *p);
```

- `params_json`: UTF-8 JSON string with plugin-specific parameters.
- `out_json`: must contain a valid **RunResponse** JSON object:

```json
{
    "findings": [
        {
            "id": "TLS-WEAK",
            "plugin_id": "cert_inspect",
            "title": "Weak certificate key length",
            "severity": "medium",
            "description": "RSA key < 2048 bits",
            "evidence": { "key_bits": "1024" },
            "tags": ["crypto", "weak-key"],
            "timestamp": 1728457812
        }
    ],
    "logs": [{ "ts": 1728457812, "line": "Checked 192.168.1.157:443" }]
}
```

---

### ⚙️ Configurable Parameters

| Field                 | Description              | Example |
| :-------------------- | :----------------------- | :------ |
| `enable_udp`          | Enable UDP scanning      | `false` |
| `skip_host_discovery` | Use `-Pn`                | `true`  |
| `service_detect`      | Enable version detection | `true`  |
| `open_only`           | Report only open ports   | `true`  |
| `min_rate`            | Nmap packet rate         | `2000`  |

---

### 📦 Example Outputs

Per-host:

```
results/runs/192.168.1.108_1883.json
```

Aggregated:

```
results/assessment.json
```

---

### 🧱 Future Improvements

- [ ] MQTT protocol behavioral fuzzing
- [ ] CoAP and Modbus stateful plugins
- [ ] Remote distributed scanning via gRPC plugins
- [ ] Web dashboard for real-time monitoring

---
