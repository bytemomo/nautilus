# telnet_default_creds (ABI v2 sample)

Telnet default-credential probe using ABI v2. Because v2 supplies a single connected conduit, this module only verifies service presence and logs banners; full brute-force needs a v1-style reconnect-per-credential module.

## Usage (campaign snippet)

```yaml
steps:
    - id: telnet-default-creds-v2
      type: lib
      api: 1
      required_tags: ["protocol:telnet"]
      exec:
          abi:
              library_path: "./modules/kraken/abi/telnel_default_creds/build/telnet_default_creds_v2"
              symbol: "kraken_run_v2"
          conduit:
              kind: 1
              stack:
                  - name: tcp
```

## Notes

- Single-connection limitation: no iterative credential testing is performed here.
- Finding reports Telnet service detection and a hex-encoded banner snippet (up to 64 bytes) when present; use a v1 module for full dictionary testing.
