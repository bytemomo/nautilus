# Security Configuration Profiles

This directory contains three security configuration profiles for testing
Kraken's detection capabilities. Each profile represents a different
security posture with varying levels of vulnerabilities.

## Profile Overview

| Profile  | Security Level | Expected Kraken Findings    |
| -------- | -------------- | --------------------------- |
| insecure | None           | All checks fail (default)   |
| partial  | Medium         | Some checks pass, some fail |
| hardened | High           | No findings (clean scan)    |

## Directory Structure

```
profiles/
├── common/             # Shared configuration files
│   ├── passwd          # User credentials (hashed at runtime)
│   ├── bridge.conf     # MQTT bridge configuration
│   └── test-credentials.txt
├── insecure/           # Maximum vulnerability profile
│   ├── mosquitto.conf
│   ├── acl.conf
│   └── campaign-cve-replay.yaml
├── partial/            # Partial security profile
│   ├── mosquitto.conf
│   └── acl.conf
└── hardened/           # Full security profile
    ├── mosquitto.conf
    └── acl.conf
```

## Usage

Profiles are selected via the `SECURITY_PROFILE` environment variable.
Docker Compose mounts the appropriate configuration files directly.

```bash
# Use insecure profile (default)
docker compose up -d

# Use partial security profile
SECURITY_PROFILE=partial docker compose up -d

# Use hardened profile
SECURITY_PROFILE=hardened docker compose up -d

# Switch profile on running environment
SECURITY_PROFILE=hardened docker compose up -d --force-recreate broker
```

## Profile Details

### Insecure Profile

**Purpose**: Maximum vulnerability exposure for comprehensive testing

**Vulnerabilities Present**:

- MQTT-ANON: Anonymous access on all ports
- MQTT-PUBSUB-ANON: No authentication for publish/subscribe
- MQTT-ACL-\*: No ACL enforcement
- mqtt-sys-disclosure: $SYS topics accessible to everyone
- TLS-SUPPORT-OVERVIEW: Weak TLS (old versions allowed)
- No client certificate verification

**Ports**:

- 1883: Plaintext, anonymous
- 8883: TLS, anonymous (weak TLS)
- 8884: mTLS port but certificates not required

### Partial Security Profile

**Purpose**: Realistic "legacy" configuration with some security measures

**Security Measures**:

- Password authentication on TLS ports
- TLS 1.2 on secure ports
- ACL file enabled
- mTLS available on port 8884

**Remaining Vulnerabilities**:

- Anonymous access on port 1883 ("for legacy devices")
- Weak ACLs (users can access more than needed)
- $SYS topics accessible to authenticated users
- No TLS 1.3

### Hardened Profile

**Purpose**: Best-practice configuration, should produce zero findings

**Security Measures**:

- No plaintext listener (port 1883 disabled)
- TLS 1.3 enforced
- mTLS required on primary port
- Strict ACLs with least-privilege
- $SYS topics restricted to admin only
- sys_interval=0 (disables $SYS updates)
- Connection limits for DoS protection

## CVE Replay Testing

The `insecure` profile includes a special campaign file for CVE replay testing:

```yaml
profiles/insecure/campaign-cve-replay.yaml
```

**WARNING**: This campaign will crash the MQTT broker by replaying
CVE-2024-8376 exploit packets. Only use in isolated test environments.

This demonstrates:

1. Kraken's capability to reproduce known vulnerabilities
2. The dual-use nature of security testing tools
3. Why such capabilities require strict access controls

## Expected Test Results

### Insecure Profile Scan

```
[FAIL] MQTT-ANON: Anonymous authentication allowed
[FAIL] MQTT-PUBSUB-ANON: Anonymous publish/subscribe allowed
[FAIL] MQTT-ACL-SUB: No ACL restrictions on subscribe
[FAIL] MQTT-ACL-PUB: No ACL restrictions on publish
[FAIL] mqtt-sys-disclosure: $SYS topics exposed
[FAIL] TLS-SUPPORT-OVERVIEW: Weak TLS configuration
[WARN] No mTLS enforcement
Total: 0 passed, 7 failed
```

### Partial Profile Scan

```
[PASS] TLS-SUPPORT-OVERVIEW: TLS 1.2 configured
[PASS] mTLS available on port 8884
[FAIL] MQTT-ANON: Anonymous on port 1883
[FAIL] MQTT-ACL-*: Overly permissive ACLs
[FAIL] mqtt-sys-disclosure: $SYS accessible
Total: 2 passed, 3 failed
```

### Hardened Profile Scan

```
[PASS] No anonymous access
[PASS] TLS 1.3 enforced
[PASS] mTLS required
[PASS] Strict ACL enforcement
[PASS] $SYS topics restricted
[PASS] Connection limits configured
Total: 6 passed, 0 failed
```
