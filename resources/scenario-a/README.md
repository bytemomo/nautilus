# Scenario A: MQTT Threat Model for Remote Telemetry & Control

This directory contains the evaluation environment for **Thesis Section 9.3**,
which models an industrial control system using MQTT for telemetry and command transmission.

## Overview

The scenario simulates a typical ICS/OT architecture:

- **Field Devices (Level 0/1)**: PLCs and RTUs publishing telemetry
- **Control Systems (Level 2)**: SCADA/HMI subscribing to data and issuing commands
- **Industrial DMZ (Level 3.5)**: MQTT broker mediating all communication
- **Optional Bridge**: For testing lateral movement to enterprise networks

## Architecture

```
                    ┌─────────────────────────────────────────────────────────┐
                    │                    IT Network (172.22.0.0/24)           │
                    │                         (Level 4/5)                     │
                    └─────────────────────────┬───────────────────────────────┘
                                              │
                    ┌─────────────────────────┴───────────────────────────────┐
                    │                    DMZ Network (172.20.0.0/24)          │
                    │                        (Level 3.5)                      │
                    │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
                    │  │   Broker     │  │    SCADA     │  │   Bridge     │   │
                    │  │ 172.20.0.10  │  │ 172.20.0.20  │  │ 172.20.0.30  │   │
                    │  │ :1883/:8883  │  │              │  │  (optional)  │   │
                    │  └──────────────┘  └──────────────┘  └──────────────┘   │
                    └─────────────────────────┬───────────────────────────────┘
                                              │
                    ┌─────────────────────────┴───────────────────────────────┐
                    │                    OT Network (172.21.0.0/24)           │
                    │                        (Level 0/1/2)                    │
                    │  ┌──────────────┐  ┌──────────────┐                     │
                    │  │     PLC      │  │     RTU      │                     │
                    │  │ 172.21.0.20  │  │ 172.21.0.21  │                     │
                    │  └──────────────┘  └──────────────┘                     │
                    └─────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Start the Environment

```bash
cd resources/scenario-a

# Start core services (broker, publishers, subscriber, seeder)
docker compose up -d

# Wait for certificates to generate and services to start
docker compose logs -f certs

# Verify broker is running
docker compose ps
```

### 2. Verify MQTT Communication

```bash
# Subscribe to all OT topics (from host)
mosquitto_sub -h localhost -p 1883 -t "ot/#" -v

# Check retained messages
mosquitto_sub -h localhost -p 1883 -t "#" -v -C 10
```

### 3. Run Kraken Assessment

```bash
# Build Kraken (if not already built)
cd ../../kraken
go build -o kraken .

# Run the Scenario A campaign
./kraken -c ../resources/scenario-a/campaign.yaml -t 172.20.0.10

# Results will be in ./kraken-results/scenario-a-mqtt/<timestamp>/
```

### 4. Enable Bridge (for L-1 Testing)

```bash
# Start with bridge profile
docker compose --profile bridge up -d
```

### 5. Stop Environment

```bash
docker compose down -v
```

## Services

| Service          | Container         | IP Address                | Ports            | Description                                |
| ---------------- | ----------------- | ------------------------- | ---------------- | ------------------------------------------ |
| broker           | scenario-a-broker | 172.20.0.10 / 172.21.0.10 | 1883, 8883, 8884 | Eclipse Mosquitto MQTT broker              |
| plc-publisher    | scenario-a-plc    | 172.21.0.20               | -                | Simulated PLC publishing telemetry         |
| rtu-publisher    | scenario-a-rtu    | 172.21.0.21               | -                | Simulated RTU publishing sensor data       |
| scada-subscriber | scenario-a-scada  | 172.20.0.20               | -                | Simulated SCADA/HMI system                 |
| seeder           | scenario-a-seeder | 172.20.0.99               | -                | Seeds initial topics and retained messages |
| bridge           | scenario-a-bridge | 172.20.0.30 / 172.22.0.30 | 1883             | Optional DMZ-to-IT bridge                  |

## Broker Ports

| Port | Protocol         | Authentication     | Description                          |
| ---- | ---------------- | ------------------ | ------------------------------------ |
| 1883 | MQTT (plaintext) | Anonymous allowed  | Insecure - for testing I-1, I-2, S-1 |
| 8883 | MQTTS (TLS)      | Username/Password  | Standard secure MQTT                 |
| 8884 | MQTTS (mTLS)     | Client Certificate | Mutual TLS authentication            |

## Test Credentials

| Username | Password | Role          | ACL Permissions                        |
| -------- | -------- | ------------- | -------------------------------------- |
| admin    | admin123 | Administrator | Full access to all topics              |
| scada    | scada123 | SCADA/HMI     | Read telemetry, write commands         |
| plc      | plc123   | PLC Device    | Write own telemetry, read own commands |
| rtu      | rtu123   | RTU Device    | Write own telemetry, read own commands |
| operator | operator | Operator      | Read-only access                       |
| guest    | guest    | Guest         | Read all, write test/# only            |

## Topic Namespace

```
ot/
├── plc/
│   ├── telemetry/
│   │   ├── temperature
│   │   └── pressure
│   ├── status/
│   │   ├── online
│   │   └── config
│   ├── command/
│   │   └── ...
│   └── alarm/
│       ├── warning
│       ├── critical
│       └── history/
├── rtu/
│   ├── telemetry/
│   │   ├── flow
│   │   └── level
│   ├── status/
│   ├── command/
│   └── alarm/
├── config/
│   └── credentials  (intentionally insecure for testing)
system/
├── health/
│   ├── broker
│   └── network
test/
├── public/
└── sensitive/
$SYS/
└── ...  (broker statistics - for I-2 testing)
```

## Threat Coverage

This environment is designed to test the following threats from Section 9.3:

| ID  | Threat                           | Kraken Module                                     | Finding IDs                               |
| --- | -------------------------------- | ------------------------------------------------- | ----------------------------------------- |
| S-1 | Unauthorized command publication | mqtt-dict-attack, mqtt-auth-check, mqtt-acl-probe | MQTT-ANON, MQTT-VALID-CREDS, MQTT-ACL-PUB |
| T-1 | Telemetry tampering/replay       | mqtt-auth-check, mqtt-acl-probe                   | MQTT-PUBSUB-ANON, MQTT-ACL-PUB            |
| T-2 | Abuse of retained messages       | mqtt-conformance-test                             | mqtt-conformance-test-mqtt-3.3.1-6        |
| I-1 | Unauthorized subscription        | mqtt-auth-check, mqtt-acl-probe                   | MQTT-ANON, MQTT-ACL-SUB                   |
| I-2 | Metadata leakage via $SYS        | mqtt-sys-disclosure                               | mqtt-sys-disclosure                       |
| D-1 | Denial-of-Service on broker      | mqtt-conformance-test                             | mqtt-conformance-test-\*                  |
| E-1 | Session hijack via weak TLS      | tls-version-check, cert-inspect                   | TLS-SUPPORT-OVERVIEW, CERT-\*             |
| R-1 | Non-repudiable actions           | mqtt-dict-attack                                  | DEFAULT-CREDENTIALS                       |
| L-1 | Lateral movement via bridge      | mqtt-dict-attack, mqtt-acl-probe                  | MQTT-VALID-CREDS, MQTT-ACL-\*             |

## Files

```
scenario-a/
├── docker-compose.yaml     # Docker Compose orchestration
├── campaign.yaml           # Kraken campaign configuration
├── attack-tree.yaml        # Attack tree with actual finding IDs
├── README.md               # This file
├── config/
│   ├── mosquitto.conf      # Broker configuration
│   ├── acl.conf            # Access control lists
│   ├── passwd              # User credentials (hashed)
│   ├── bridge.conf         # Bridge configuration
│   └── test-credentials.txt # Credentials for ACL probing
├── scripts/
│   ├── generate-certs.sh   # TLS certificate generation
│   ├── plc-publisher.sh    # PLC telemetry simulator
│   ├── rtu-publisher.sh    # RTU telemetry simulator
│   ├── scada-subscriber.sh # SCADA/HMI simulator
│   └── seed-topics.sh      # Initial topic seeding
└── certs/                  # Generated certificates (created at runtime)
    ├── ca.crt / ca.key
    ├── server.crt / server.key
    ├── plc-01.crt / plc-01.key
    ├── rtu-01.crt / rtu-01.key
    ├── scada-01.crt / scada-01.key
    └── kraken.crt / kraken.key
```

## Manual Testing

### Test Anonymous Access (I-1, S-1)

```bash
# Should succeed on port 1883
mosquitto_sub -h localhost -p 1883 -t "#" -v -C 5

# Should fail on port 8883 (requires auth)
mosquitto_sub -h localhost -p 8883 -t "#" --cafile certs/ca.crt
```

### Test $SYS Disclosure (I-2)

```bash
mosquitto_sub -h localhost -p 1883 -t '$SYS/#' -v -C 10
```

### Test Weak Credentials (S-1)

```bash
mosquitto_sub -h localhost -p 8883 -t "ot/#" -v \
  --cafile certs/ca.crt \
  -u guest -P guest
```

### Test ACL Bypass

```bash
# Guest trying to write to protected topic (should fail with proper ACL)
mosquitto_pub -h localhost -p 8883 \
  --cafile certs/ca.crt \
  -u guest -P guest \
  -t "ot/plc/command/test" -m "unauthorized"
```

### Test TLS Versions

```bash
# Check TLS 1.2 support
openssl s_client -connect localhost:8883 -tls1_2 < /dev/null

# Check if TLS 1.0 is rejected (should be)
openssl s_client -connect localhost:8883 -tls1 < /dev/null
```

## Troubleshooting

### Certificates not generated

```bash
# Manually run certificate generation
docker compose run --rm certs

# Check certificate files
ls -la certs/
```

### Broker not starting

```bash
# Check broker logs
docker compose logs broker

# Verify config file
docker compose exec broker cat /mosquitto/config/mosquitto.conf
```

### Publishers not connecting

```bash
# Check TLS connectivity
docker compose exec plc-publisher mosquitto_pub -h mqtt-broker -p 8883 \
  --cafile /certs/ca.crt -u plc -P plc123 -t test -m hello

# Check DNS resolution
docker compose exec plc-publisher ping mqtt-broker
```
