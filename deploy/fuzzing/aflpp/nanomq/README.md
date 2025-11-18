# NanoMQ AFL++ MQTT Seeds

Binary inputs under `my_seeds/` cover every MQTT v3.1.1 control packet so the `fuzz_nanomq` harness always starts from syntactically valid frames. Hex dumps below come directly from the binary seeds followed by the interpreted field values.

## `connect.bin`

Hex view:

```
00000000: 10 13 00 04 4d 51 54 54 04 02 00 3c 00 04 66 75  ....MQTT...<..fu
00000010: 7a 7a                                            zz
```

Field values:

- Fixed header `0x10` → CONNECT
- Remaining Length `0x13` (19 bytes)
- Protocol Name length `0x0004` + value "MQTT"
- Protocol Level `0x04`
- Connect Flags `0x02` (Clean Session)
- Keep Alive `0x003c` (60 seconds)
- Client Identifier length `0x0004` + value "fuzz"

## `connack.bin`

Hex view:

```
00000000: 20 02 01 00                                       ...
```

Field values:

- Fixed header `0x20` → CONNACK
- Remaining Length `0x02`
- Acknowledge Flags `0x01` (Session Present)
- Connect Return Code `0x00` (Connection Accepted)

## `publish.bin`

Hex view:

```
00000000: 32 15 00 0c 73 65 6e 73 6f 72 73 2f 74 65 6d 70  2...sensors/temp
00000010: 00 01 32 31 2e 35 43                             ..21.5C
```

Field values:

- Fixed header `0x32` → PUBLISH, QoS 1, no DUP/retain
- Remaining Length `0x15` (21 bytes)
- Topic Name length `0x000c` + value "sensors/temp"
- Packet Identifier `0x0001`
- Payload ASCII "21.5C"

## `puback.bin`

Hex view:

```
00000000: 40 02 00 01                                      @...
```

Field values:

- Fixed header `0x40` → PUBACK
- Remaining Length `0x02`
- Packet Identifier `0x0001`

## `pubrec.bin`

Hex view:

```
00000000: 50 02 00 01                                      P...
```

Field values:

- Fixed header `0x50` → PUBREC
- Remaining Length `0x02`
- Packet Identifier `0x0001`

## `pubrel.bin`

Hex view:

```
00000000: 62 02 00 01                                      b...
```

Field values:

- Fixed header `0x62` → PUBREL (QoS level bits set to 1 as required)
- Remaining Length `0x02`
- Packet Identifier `0x0001`

## `pubcomp.bin`

Hex view:

```
00000000: 70 02 00 01                                      p...
```

Field values:

- Fixed header `0x70` → PUBCOMP
- Remaining Length `0x02`
- Packet Identifier `0x0001`

## `subscribe.bin`

Hex view:

```
00000000: 82 0b 00 0a 00 06 61 6c 65 72 74 73 01           ......alerts.
```

Field values:

- Fixed header `0x82` → SUBSCRIBE with QoS 1 command
- Remaining Length `0x0b` (11 bytes)
- Packet Identifier `0x000a`
- Topic Filter length `0x0006` + value "alerts"
- Requested maximum QoS `0x01`

## `suback.bin`

Hex view:

```
00000000: 90 03 00 0a 01                                   .....
```

Field values:

- Fixed header `0x90` → SUBACK
- Remaining Length `0x03`
- Packet Identifier `0x000a`
- Return Code `0x01` (Granted QoS 1)

## `unsubscribe.bin`

Hex view:

```
00000000: a2 0a 00 0b 00 06 61 6c 65 72 74 73              ......alerts
```

Field values:

- Fixed header `0xa2` → UNSUBSCRIBE with QoS 1 command
- Remaining Length `0x0a` (10 bytes)
- Packet Identifier `0x000b`
- Topic Filter length `0x0006` + value "alerts"

## `unsuback.bin`

Hex view:

```
00000000: b0 02 00 0b                                      ....
```

Field values:

- Fixed header `0xb0` → UNSUBACK
- Remaining Length `0x02`
- Packet Identifier `0x000b`

## `pingreq.bin`

Hex view:

```
00000000: c0 00                                            ..
```

Field values:

- Fixed header `0xc0` → PINGREQ
- Remaining Length `0x00` (no variable header or payload)

## `pingresp.bin`

Hex view:

```
00000000: d0 00                                            ..
```

Field values:

- Fixed header `0xd0` → PINGRESP
- Remaining Length `0x00`

## `disconnect.bin`

Hex view:

```
00000000: e0 00                                            ..
```

Field values:

- Fixed header `0xe0` → DISCONNECT
- Remaining Length `0x00`
