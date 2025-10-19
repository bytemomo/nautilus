# Kraken Modules

This directory contains Kraken security assessment modules (formerly "plugins").

## Directory Structure

```
modules/kraken/
├── abi/              # ABI-based modules (C/C++/Rust shared libraries)
│   ├── tls_version_check/     # TLS version detection
│   ├── mqtt_auth_check/       # MQTT authentication testing  
│   ├── telnel_default_creds/  # Telnet default credentials
│   └── cert_inspect/          # TLS certificate inspection (Rust)
└── cli/              # CLI-based modules (external executables)
```

## Module API Versions

### V1 API (api: 0)
- Module receives `host` and `port` parameters
- Module creates its own connections
- Module handles all transport layer logic (TCP, TLS, etc.)
- Entry point: `ORCA_Run(host, port, timeout, params, result)`
- Use case: Modules that need full connection control (e.g., credential brute-forcing)

### V2 API (api: 1)
- Module receives a **connected conduit handle**
- Runner establishes connection based on `conduit` configuration
- Module focuses on protocol logic only
- Entry point: `ORCA_Run_V2(conn, ops, target, timeout, params, result)`
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

| Module | V1 | V2 | Language | Description |
|--------|----|----|----------|-------------|
| tls_version_check | ❌ | ✅ | C | Detects TLS version and analyzes connection |
| mqtt_auth_check | ✅ | ✅ | C | Tests MQTT authentication (anon, weak creds) |
| telnet_default_creds | ✅ | ✅ | C | Tests default telnet credentials |
| cert_inspect | ✅ | ❌ | Rust | Inspects TLS certificates |

## Usage in Campaigns

### V1 Module Example

```yaml
steps:
  - id: "mqtt-auth-check"
    type: lib
    api: 0  # V1
    exec:
      abi:
        library_path: "./modules/kraken/abi/mqtt_auth_check/build/mqtt_auth_check"
        symbol: "ORCA_Run"
      params:
        creds_file: "./credentialdbs/creds.txt"
```

### V2 Module Example

```yaml
steps:
  - id: "tls-version-check-v2"
    type: lib
    api: 1  # V2
    exec:
      abi:
        library_path: "./modules/kraken/abi/tls_version_check/build/tls_version_check_v2"
        symbol: "ORCA_Run_V2"
      conduit:  # Runner establishes this connection
        kind: 1  # Stream
        stack:
          - name: tcp
          - name: tls
            params:
              skip_verify: false
              min_version: TLS1.2
```

## Creating New Modules

### V2 Module Template (Recommended)

```c
#define ORCA_PLUGIN_BUILD
#include <orca_plugin_abi_v2.h>

ORCA_API const uint32_t ORCA_PLUGIN_ABI_VERSION_V2 = ORCA_ABI_VERSION_V2;

ORCA_API int ORCA_Run_V2(
    ORCA_ConnectionHandle conn,
    const ORCA_ConnectionOps *ops,
    const ORCA_HostPort *target,
    uint32_t timeout_ms,
    const char *params_json,
    ORCA_RunResult **out_result
) {
    // 1. Allocate result
    ORCA_RunResult *result = calloc(1, sizeof(ORCA_RunResult));
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

ORCA_API void ORCA_Free_V2(void *p) {
    // Free allocated result memory
}
```

## Known Issues

### V2 Conduit Callbacks Not Fully Wired
The V2 API callbacks (`go_conduit_send`, `go_conduit_recv`, `go_conduit_get_info`) are currently commented out in `kraken/internal/adapter/abiplugin/client_unix.go`. This causes segfaults when running V2 modules.

**Workaround**: Use V1 modules for now, or help implement the missing callbacks!

**What's needed**:
1. Implement Go-side conduit bridge functions
2. Wire up CGo exports for send/recv/get_info
3. Pass actual conduit handles to V2 modules
4. Test with real V2 modules

See the thread summary document for more details on the V2 implementation plan.

## Migration Path

1. **Keep V1 modules working** - They still work and are useful
2. **Create V2 variants** - Simpler, cleaner code
3. **Test both** - Campaigns can mix V1 and V2 modules
4. **Transition gradually** - No rush to deprecate V1

## Contributing

When adding new modules:
1. Use descriptive names (e.g., `mqtt_auth_check` not `plugin3`)
2. Provide both V1 and V2 implementations if possible
3. Document parameters in module YAML
4. Include example campaign usage
5. Add tests

