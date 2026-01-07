# Kraken Modules

## Directory Structure

```
modules/kraken/
├── abi/              # ABI-based modules (C/C++/Rust shared libraries)
│   ├── tls_version_check/     # TLS version detection (v1)
│   ├── mqtt_auth_check/       # MQTT authentication testing (v2)
│   ├── mqtt_acl_probe/        # MQTT ACL probe (v2)
│   ├── telnel_default_creds/  # Telnet default credentials (v2 sample)
│   ├── cert_inspect/          # TLS certificate inspection (Rust, v1)
│   ├── mqtt_sys_disclosure/   # $SYS topic leakage (v1)
│   └── mqtt_replay/           # MQTT packet replay (v1)
├── cli/              # CLI-based modules (external executables) [currently empty]
└── fuzz/             # Seeds and fuzz harness inputs
```

## Module API Versions

### V1 API (api: 0)

- Module receives `host` and `port` parameters
- Module creates its own connections
- Module handles all transport layer logic (TCP, TLS, etc.)
- Entry point: `kraken_run(host, port, timeout, params, result)`
- Use case: Modules that need full connection control (e.g., credential brute-forcing)

### V2 API (api: 1)

- Module receives a **connected conduit handle**
- Runner establishes connection based on `conduit` configuration
- Module focuses on protocol logic only
- Entry point: `kraken_run_v2(conn, ops, target, timeout, params, result)`
- Callbacks: `ops->send()`, `ops->recv()`, `ops->get_info()`
- Use case: Simpler modules, better separation of concerns

## Building Modules

### Prerequisites

- CMake 3.20+
- Ninja (or other build system)
- OpenSSL (for TLS modules)
- Rust toolchain (for Rust modules)

### Build All Modules

```bash
cd modules/kraken/abi

# Build all C/C++ modules
for dir in */; do
  if [ -f "$dir/CMakeLists.txt" ]; then
    cd "$dir"
    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build build --config Release
    cd ..
  fi
done

# Build Rust modules
cd cert_inspect
cargo build --release
```

### Build Individual Module

```bash
cd modules/kraken/abi/tls_version_check
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

## Module Status

| Module               | Type          | Language | Description                                       |
| -------------------- | ------------- | -------- | ------------------------------------------------- |
| tls_version_check    | ABI v1        | C        | Summarizes accepted TLS protocol versions         |
| mqtt_auth_check      | ABI v2        | C        | Tests anonymous MQTT auth and pub/sub on conduit  |
| mqtt_acl_probe       | ABI v2        | C        | Tests MQTT ACLs (connect/sub/pub per credential)  |
| telnet_default_creds | ABI v2        | C        | Telnet banner/probe; brute-force not in v2        |
| cert_inspect         | ABI v1 (Rust) | Rust     | Certificate posture checks (expiry, key, SAN)     |
| mqtt_sys_disclosure  | ABI v1        | C        | Detects `$SYS` topic leakage via `#` subscription |
| mqtt_replay          | ABI v1        | C        | Replays MQTT packet sequences (e.g., CVE repros)  |

## Usage in Campaigns

### V1 Module Example

```yaml
steps:
    - id: "tls-version-check"
      type: lib
      api: 0 # V1
      required_tags: ["supports:tls"]
      exec:
          abi:
              library_path: "./modules/kraken/abi/tls_version_check/build/tls_version_check.so"
              symbol: "kraken_run"
```

### V2 Module Example

```yaml
steps:
    - id: "mqtt-auth-check-v2"
      type: lib
      api: 1 # V2
      exec:
          abi:
              library_path: "./modules/kraken/abi/mqtt_auth_check/build/mqtt_auth_check_v2"
              symbol: "kraken_run_v2"
          conduit: # Runner establishes this connection
              kind: 1 # Stream
              stack:
                  - name: tcp
                  - name: tls
                    params:
                        skip_verify: true
      params:
          creds_file: "./wordlists/mqtt.txt" # logged only; v2 lacks multi-conn brute-force
```

## Creating New Modules

### V2 Module Template (Recommended)

```c
#define KRAKEN_MODULE_BUILD
#include <kraken_module_abi_v2.h>

KRAKEN_API const uint32_t KRAKEN_MODULE_ABI_VERSION_V2 = KRAKEN_ABI_VERSION_V2;

KRAKEN_API int kraken_run_v2(
    KrakenConnectionHandle conn,
    const KrakenConnectionOps *ops,
    const KrakenHostPort *target,
    uint32_t timeout_ms,
    const char *params_json,
    KrakenRunResult **out_result
) {
    // 1. Allocate result
    KrakenRunResult *result = calloc(1, sizeof(KrakenRunResult));
    result->target.host = strdup(target->host);
    result->target.port = target->port;

    // 2. Use conduit I/O operations
    const char *probe = "HELLO\n";
    int64_t sent = ops->send(conn, (const uint8_t*)probe, strlen(probe), timeout_ms);

    uint8_t buffer[4096];
    int64_t received = ops->recv(conn, buffer, sizeof(buffer), timeout_ms);

    // 3. Create findings based on response
    // ... (see existing modules for examples)

    // 4. Return result
    *out_result = result;
    return 0;
}

KRAKEN_API void kraken_free_v2(void *p) {
    // Free allocated result memory
}
```
