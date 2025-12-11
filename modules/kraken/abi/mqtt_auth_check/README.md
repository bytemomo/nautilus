# mqtt_auth_check (ABI v2)

Checks MQTT authentication posture using the ABI v2 conduit (runner provides the connection). It verifies anonymous CONNECT acceptance and, when possible, basic pub/sub permissions on that single connection.

## Parameters
- `creds_file` (optional): path to a username:password list. Logged only; full iteration needs runner-side multiple connections.

## Usage (campaign snippet)
```yaml
steps:
  - id: mqtt-auth-check-v2
    type: lib
    api: 1
    required_tags: ["protocol:mqtt"]
    exec:
      abi:
        library_path: "./modules/kraken/abi/mqtt_auth_check/build/mqtt_auth_check_v2"
        symbol: "kraken_run_v2"
      conduit:
        kind: 1
        stack:
          - name: tcp
          - name: tls   # optional, remove if plaintext
            params:
              skip_verify: true
    params:
      creds_file: "./wordlists/mqtt.txt"  # logged only; no per-cred reconnects
```

## Notes
- ABI v2 provides only one conduit per run; credential bruteforce would require runner-driven reconnections (not implemented here).
- Findings include anonymous CONNECT and publish/subscribe acceptance when the broker allows it.
