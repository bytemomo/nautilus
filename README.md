# Leviathan

## Kraken - Further Improvement

### Better plugin system

The idea is to have three types of plugins:

1. Application plugin: read/write from an interface that implement the transport (whatever it is)
2. Transport plugin: they directly test the transport layer (don't know exacly what)
3. God plugins: they are passed host:port and they have to handle everything, from connection to parsing, to test implementation etc...

With this implementation i can do the following:

1. Define TCP transport
2. Implement MQTT testing plugin (MQTT pub/sub anon etc..)
3. Leverage the TCP transport.

If i need to utilize TLS then i can simply plug it in between TLS transport and MQTT testing plugin
(MQTT plugin will use the TLS transport, that will use the TCP transport).

But also i can do a TLS checker plugin that tests:

1. TLS version supported
2. Certificates and all their properties (if self signed, common name == hostname, key size etc..)
3. mTLS

If you think something is wrong or with a bad architecture tell me.

## ✅ Architecture Overview — What You're Proposing

You're essentially building:

```
              ┌────────────────────┐
              │   God Plugin       │
              │  (full control)    │
              └────────-───────────┘

              ┌────────-─────────┐
              │ Application Layer│
              │ Plugin (e.g MQTT)│
              └────────┬─────────┘
                       │
              ┌────────▼─────────┐
              │ Transport Plugin │
              │ (e.g. TLS)       │
              └────────┬─────────┘
                       │
              ┌────────▼────────┐
              │ Transport Plugin│
              │ (e.g. TCP)      │
              └─────────────────┘
```

This is excellent — you’re implementing a **protocol stack abstraction**, where plugins can be layered and composed.

---

## 🧩 Plugin Types — In More Detail

### 1. **Transport Plugins**

- Purpose: Create or test a **connection**, optionally wrap another transport.
- Examples:
    - TCP (raw)
    - TLS (wraps TCP, does handshake)
    - WebSocket (wraps HTTP/TCP)

- Responsibilities:
    - Establish connections
    - Optionally expose metadata (e.g. TLS cert)
    - Provide a uniform `Read/Write/Close` interface

✅ **Good idea**. These form the backbone of composability.

---

### 2. **Application Plugins**

- Purpose: Use an established transport to speak **protocol-specific logic**.
- Examples:
    - MQTT (connect, publish, subscribe)
    - HTTP (send request, parse headers)
    - SSH (auth attempt)

- They depend on a working transport chain beneath them.

✅ **Also great**. These plugins focus on domain logic.

---

### 3. **God Plugins**

- Purpose: Handle everything themselves: connection, protocol, testing logic.
- Used when:
    - The protocol is tightly coupled
    - Composability isn't worth the indirection
    - Performance or flexibility demands total control

✅ Makes sense as an **escape hatch**, but **limit their use** to edge cases — they are the least reusable and hardest to test.

---

## ⚠️ Things to Watch Out For

### 1. **Transport Stack Initialization Order**

Ensure a **clear, deterministic way to compose transports**, e.g.:

```go
tcp := NewTCPTransport(host, port)
tls := NewTLSTransport(tcp, tlsOptions)
mqtt := NewMQTTPlugin(tls)
```

You can abstract this into a **transport graph** or **chain-of-responsibility**.

#### Suggestion:

Define a `Transport` interface like:

```go
type Transport interface {
    Connect() error
    Read([]byte) (int, error)
    Write([]byte) (int, error)
    Close() error
    Metadata() map[string]interface{}
}
```

And have each transport **wrap another**, like decorators:

```go
type TLSWrapper struct {
    Inner Transport
    // TLS config etc.
}
```

This lets you layer transports without spaghetti.

---

### 2. **Plugin Capabilities / Declarations**

As you grow plugin support, you'll want a standard **plugin manifest or descriptor** for each plugin, indicating:

- Type (`application`, `transport`, `god`)
- Supported protocols (`mqtt`, `tls`, etc.)
- Requires transport? (`true`/`false`)
- Output types / test capabilities

This helps:

- Dynamically load only relevant plugins
- Compose plugin stacks
- Prevent misconfiguration

#### Example:

```json
{
    "name": "mqtt-anon-test",
    "type": "application",
    "protocol": "mqtt",
    "requires_transport": true
}
```

---

### 3. **Connection Proxying for Remote Plugins**

When using remote (gRPC) plugins, you **can’t pass connections**, so transport chaining becomes more complicated.

#### Suggestion:

Implement a **proxy transport adapter**:

- Orchestrator handles actual socket
- Plugin requests `read/write` over the transport API
- You abstract the transport like an API object, not a socket

Plugins "think" they're reading from a socket, but really they're RPC-ing back to the orchestrator.

This lets you still compose layers **remotely**.

---

### 4. **Testing and Observability**

When layering multiple transports and plugins, debugging can get gnarly.

#### Suggestion:

Add structured **logging/tracing** across transport and application plugins:

- Timestamped logs per layer
- Include which plugin did what
- Expose via orchestration UI or logs

Maybe even something like:

```json
[
    { "plugin": "TLS", "action": "connect", "status": "success" },
    { "plugin": "MQTT", "action": "connect", "status": "failed", "error": "Conn refused" }
]
```

---

## 🚀 Example Use Cases (With Your Architecture)

### ✅ TLS-secured MQTT test

1. TCP plugin connects to `host:port`
2. TLS plugin performs handshake, extracts cert
3. MQTT plugin connects, sends PING, tests anon access

### ✅ TLS cert linter

1. TCP plugin connects
2. TLS plugin performs handshake
3. TLS **application** plugin inspects cert details

### ✅ Legacy God plugin: Telnet bruteforce

- God plugin takes `host:port`
- Opens TCP manually, does auth fuzzing
- Doesn’t reuse transport stack (OK for edge case)

Also the orchestrator is written in go, but it would be nice if the transports
and plugins could be written in different languages (with a common API) for
example in RUST, C/C++ or lua.

---

---

---

# ✅ What’s good

- **Clear separation of concerns**: transport vs application vs “god”. That’s exactly what makes the stack composable and reusable.
- **Decorator-style transports** (TLS wraps TCP, WebSocket wraps HTTP/TCP) fits real-world protocols.
- **God plugin as escape hatch** is smart — keep it for cases where you need full control.
- **Support for remote/multi-language plugins** is possible if you define a small, stable RPC surface.

# ⚠️ Main risks & pitfalls

1. **Passing real OS sockets across process/machine boundaries** — impossible in many IPC/RPC systems. You’ll need a proxy abstraction (see below).
2. **Backpressure & blocking I/O** — stacking transports can cause deadlocks or unintended blocking if read/write semantics aren’t carefully defined.
3. **Mixed sync/async expectations** — some plugins will want streaming callbacks; others will be request/response. Standardize this early.
4. **Security surface** — plugins that open sockets or run arbitrary code are risky. You’ll need capability restrictions, sandboxing, and strong validation.
5. **Versioning & capability negotiation** — plugins evolve; you need a manifest and negotiation layer so orchestrator and plugin agree on features.

---

# 📐 Suggested core abstraction (Go-style)

```go
// Minimal transport interface (sync/streaming hybrid)
type Transport interface {
    // Connect establishes a transport-level connection (if applicable)
    Connect(ctx context.Context) error

    // Read/Write are stream-oriented. They should support deadlines via ctx or SetDeadline.
    Read(ctx context.Context, buf []byte) (int, error)
    Write(ctx context.Context, data []byte) (int, error)

    // Close gracefully closes
    Close() error

    // Metadata returns transport-specific info (certs, negotiated protocol, SNI, cipher, etc)
    Metadata() map[string]interface{}
}
```

Notes:

- Use `context.Context` for timeouts/cancellation.
- Keep `Metadata()` typed (or return a structured type) — map[string]interface{} is okay initially but becomes brittle.

---

# 🧾 Plugin manifest / capability descriptor

Every plugin should publish a small JSON/YAML descriptor the orchestrator reads:

```json
{
    "name": "mqtt-client",
    "type": "application", // application | transport | god
    "protocols": ["mqtt"],
    "requires_transport": true,
    "transport_types": ["tcp", "tls"],
    "api_version": "1.2.0",
    "capabilities": {
        "mqtt_versions": ["3.1.1", "5.0"],
        "client_auth": ["anonymous", "username_password"]
    }
}
```

Use this for:

- Dependency checking (prevent an MQTT app plugin from being used without a transport that supports TLS when it needs it).
- Feature negotiation (is mTLS supported?).

---

# 🔁 Remote plugin architecture (cross-language)

You’ll likely use gRPC or a small TCP/RPC protocol for cross-language plugins. Important points:

- **Don’t try to pass sockets**. Instead implement a _proxy transport adapter_:
    - Orchestrator owns the socket and exposes a framed API (read/write/close/metadata) over RPC.
    - Remote plugin uses that API as if it had the socket locally.

Example proto sketch:

```proto
syntax = "proto3";

service TransportService {
  rpc Connect(ConnectReq) returns (ConnectResp);
  rpc Read(ReadReq) returns (stream ReadResp);     // streaming for efficiency
  rpc Write(WriteReq) returns (WriteResp);
  rpc Close(CloseReq) returns (CloseResp);
  rpc Metadata(MetaReq) returns (MetaResp);
}

message ConnectReq {
  string id = 1; // connection id
  map<string,string> options = 2;
}

message ReadReq { string id = 1; }
message ReadResp { bytes data = 1; bool eof = 2; string error = 3; }

message WriteReq { string id = 1; bytes data = 2; }
message WriteResp { int32 written = 1; string error = 2; }

message CloseReq { string id = 1; }
message MetaResp { map<string,string> meta = 1; }
```

- This keeps the orchestrator in control of the actual sockets (important for firewalling, monitoring, and multi-tenant isolation).

---

# 🔒 Security & sandboxing

- **Least privilege**: restrict plugin capabilities in manifest. Don’t let a plugin request unrestricted network access by default.
- **Resource limits**: CPU/memory/time quotas per plugin (use OS cgroups or container boundaries).
- **Seccomp / AppArmor** for native plugins; run untrusted plugins in containers.
- **Plugin signing** and policy: require signed plugins or run in a reviewed repository.
- **Audit logs** for all network operations.

---

# 🔍 Observability & debugging

- Standardize events/logs across layers. Example event model:

```json
{
    "ts": "2025-10-17T12:34:56Z",
    "plugin": "tls-1.0",
    "level": "info",
    "action": "handshake",
    "status": "success",
    "details": { "cipher": "TLS_AES_128_GCM_SHA256", "peer": "example.com" }
}
```

- Trace ID propagated top-to-bottom for a test run; correlate logs across plugin processes.
- Export metrics: connection latencies, handshake times, bytes transferred, errors per plugin.

---

# ⚙️ TLS plugin concerns

- Support for probing: TLS versions, ciphers, cert chain, SNI, renegotiation, client cert request, ALPN.
- Return parsed certificate objects (not just PEM) so higher plugins can validate CN/SAN, expiry, key size, signature algorithm.
- For mTLS: support injecting client certs; orchestrator should secure storage of private keys.

---

# 🧪 Testing strategy

- Unit tests for each plugin (mock the `Transport` interface).
- Integration tests for composition chains: e.g., TCP -> TLS -> MQTT.
- Fuzzing for application plugins that parse bytes (MQTT parsing, HTTP headers).
- Chaos tests: drop packets, delay, corrupt a byte in the stream, abrupt close — ensure plugins fail gracefully and provide actionable errors.

---

# 🧭 Runtime composition / config

- Provide a **declarative DSL** / JSON for stacking:

```yaml
pipeline:
    - type: transport
      name: tcp
      options: { host: "example.com", port: 8883 }
    - type: transport
      name: tls
      options: { sni: "example.com", ca_bundle: "..." }
    - type: application
      name: mqtt-test
      options: { client_id: "tester", qos: 0 }
```

- Or provide a programmatic builder API for dynamic composition.

---

# 📦 Cross-language plugin tips

- Keep RPC surface minimal and stable.
- Use codegen (proto -> Go/Rust/C/Python) for the transport API.
- Provide a **reference SDK** in Go and Rust that implements the common wiring for plugin lifecycle, logging, and manifest publishing.
- Consider embedding a small shim binary for languages that are hard to integrate: the shim speaks gRPC and loads language-specific plugin code via STDIO or FFI.

---

# ✅ Example concrete improvements to implement next

1. **Define and stabilize the Transport interface** (include ctx/timeouts, metadata types).
2. **Create a plugin manifest schema and validator**.
3. **Prototype the RPC-based proxy transport** (a small Go server that exposes socket read/write over gRPC).
4. **Design a minimal, typed Metadata structure** (cert info, negotiated proto, ciphers).
5. **Implement sandboxing policy** for third-party plugins early.

---

# Quick checklist for you

- [ ] Decide whether orchestrator or plugin owns raw sockets (I recommend orchestrator).
- [ ] Formalize the plugin manifest & capability negotiation.
- [ ] Add context-aware I/O primitives for proper timeouts and cancellation.
- [ ] Implement observability (trace IDs + structured events).
- [ ] Plan plugin isolation & signing.

---

If you’d like, I can:

- Draft a more complete Go interface set with typed metadata structs and error models, or
- Produce a full proto file and a small example of a Go orchestrator that proxies a TCP socket to a gRPC plugin.

Which of those would help you most right now?

## 🔀 Problem: Sync vs Async plugin needs

### Typical differences:

| **Type**                  | **Expected I/O Pattern**         | **Example**                      |
| ------------------------- | -------------------------------- | -------------------------------- |
| **Synchronous**           | `Do X → wait for result`         | HTTP GET, TLS handshake          |
| **Asynchronous**          | `Send A, wait for B at any time` | MQTT pub/sub, WebSocket chat     |
| **Bi-directional stream** | Read/write at will, full-duplex  | SSH, Telnet, streaming protocols |

Many **application protocols are inherently asynchronous** (e.g., MQTT receives messages anytime). Others are very **strictly request-response** (e.g., HTTP/1.1). Some are **half-duplex** or follow more complex patterns.

---

## 🧱 Solution: Standardize on **stream-oriented transports** with a structured message model

Treat every plugin (transport or application) as speaking **structured framed messages** over a **stream-based interface**, and then:

- Let plugins **opt into** sync behavior (`CallAndWait()`), but **under the hood it's still a stream**.
- This allows:
    - Async protocols to work seamlessly
    - Sync-style plugins to “block” waiting for the next response

---

## ✅ Recommended Interface Model (Unified)

Use a **framed message stream** abstraction with the following capabilities:

```go
type Stream interface {
    Connect(ctx context.Context) error
    Send(ctx context.Context, msg *Frame) error
    Receive(ctx context.Context) (*Frame, error)
    Close() error
}
```

Where `Frame` is:

```go
type Frame struct {
    Type    string                 // e.g., "mqtt_publish", "mqtt_suback", "http_response"
    Payload []byte                 // Raw or structured
    Meta    map[string]string      // Optional metadata for routing/processing
}
```

Then, plugins implement **event-driven or polling-based handlers**, depending on their protocol’s needs.

---

## 🧩 Application Plugin Style Options

### Option 1: **Callback-based handlers** (async-capable)

For plugins with async needs:

```go
type MQTTPlugin struct {
    stream Stream
}

func (m *MQTTPlugin) Start(ctx context.Context) error {
    go m.listenLoop(ctx)

    m.stream.Send(ctx, &Frame{
        Type: "mqtt_subscribe",
        Payload: encodeSubscribe("topic/#"),
    })

    return nil
}

func (m *MQTTPlugin) listenLoop(ctx context.Context) {
    for {
        frame, err := m.stream.Receive(ctx)
        if err != nil {
            log.Error("recv error:", err)
            return
        }

        switch frame.Type {
        case "mqtt_publish":
            handlePublish(frame)
        }
    }
}
```

### Option 2: **Request-response helper on top of stream**

Create a utility that lets sync-expected plugins do this:

```go
frame := &Frame{Type: "http_request", Payload: reqBytes}
resp, err := CallAndWait(ctx, stream, frame, timeout)

func CallAndWait(ctx context.Context, s Stream, req *Frame, timeout time.Duration) (*Frame, error) {
    id := uuid.New().String()
    req.Meta["req_id"] = id

    // Send
    if err := s.Send(ctx, req); err != nil {
        return nil, err
    }

    // Wait for matching response
    ctx, cancel := context.WithTimeout(ctx, timeout)
    defer cancel()

    for {
        resp, err := s.Receive(ctx)
        if err != nil {
            return nil, err
        }

        if resp.Meta["req_id"] == id {
            return resp, nil
        }
    }
}
```

---

## 💡 Benefits of the Stream + Framed Message Model

- Works for sync, async, and full-duplex protocols
- Plugins can:
    - Read with `.Receive()` in a loop (async style)
    - Use `CallAndWait()` for blocking calls (sync style)

- You can add **message routing, ID correlation, filtering, backpressure,** etc.
- Easy to **proxy across gRPC** — just convert frames into RPC messages

---

## 🔄 How This Fits with Your Plugin Architecture

### Transports

- Provide a **framed, stream-based abstraction**, even if underlying transport is byte-oriented (TCP) or record-based (TLS).
- Example: TLS plugin reads TLS records, assembles `Frame{Type: "tls_data", Payload: ...}`

### Application Plugins

- MQTT plugin knows how to encode/decode MQTT frames into `Frame`
- HTTP plugin knows how to turn `GET /` into `Frame{Type: "http_request"}`

### God Plugins

- Bypass this if needed, but can still reuse stream interface for uniformity

---

## 🚨 Tips to Avoid Pitfalls

- **Avoid Read()/Write([]byte)** raw buffers across plugin boundaries — always **wrap messages** in typed frames (structured, self-describing).
- Use **message type + ID** for correlation in async flows.
- Have an internal **message broker** in orchestrator to route frames by plugin/session.
- Plugins should **tag frames** they send with an ID + plugin context.
- You can use **gRPC streaming RPC** for `Send()` and `Receive()` in remote plugins.

---

## 🧪 Bonus: Auto-adapt Sync Plugins

For plugins that don’t support async natively (e.g., a Python plugin that expects HTTP request/response), provide a small **adapter layer**:

```go
func AdaptSyncPlugin(ctx context.Context, stream Stream, handler func(Frame) Frame) {
    for {
        req, err := stream.Receive(ctx)
        if err != nil {
            log.Error(err)
            return
        }

        go func(req Frame) {
            resp := handler(req)
            stream.Send(ctx, &resp)
        }(req)
    }
}
```

This lets sync-style plugins live inside an async architecture.

---

## ✅ Summary: Your Best Option

**Standardize on a message-based stream abstraction (framed messaging), where sync behavior is opt-in and async is always supported.**

| 🔧 Component | ✅ Design Strategy                                   |
| ------------ | ---------------------------------------------------- |
| Transport    | Expose framed `Stream` interface (connect/send/recv) |
| Application  | Use stream; handle sync/async via utilities or loops |
| God Plugin   | Free to handle things directly (can wrap stream too) |
| Orchestrator | Route frames, manage timeouts, backpressure, logging |

---

Let me know if you want a small **Go interface implementation** of this framed stream system, or a **proto definition** for the gRPC equivalent — both are easy to mock up and plug into your system.
