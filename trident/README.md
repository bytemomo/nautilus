# Trident - Multi-Layer Network Conduit System

Trident is a comprehensive network communication library that provides a unified, layered abstraction for network I/O across all OSI layers. It enables protocol-agnostic communication through composable conduits that can be stacked to build complex network protocols.

## Overview

Trident provides a **conduit** abstraction that represents network connections at different layers of the network stack. Each conduit can be composed with others to create layered protocols (e.g., TCP → TLS → Application Protocol).

### Key Features

- **Layered Architecture** - Stack conduits to build complex protocols (TCP, TLS, UDP, DTLS, IP, Ethernet)
- **Unified API** - Consistent interface across all network layers
- **Zero-Copy Operations** - Pooled buffer system for efficient memory management
- **Context-Aware** - Built-in timeout and cancellation support via Go contexts
- **Type-Safe** - Generic interfaces ensure compile-time safety
- **Rich Metadata** - Detailed timing, addressing, and protocol information
- **Batch Operations** - Efficient batch send/receive for datagram protocols

## Architecture

Trident defines conduits for four network layers:

```
┌─────────────────────────────────────────────────────────┐
│  Layer 4: Transport                                     │
│  ┌─────────────┐  ┌──────────────┐                    │
│  │   Stream    │  │   Datagram   │                    │
│  │  TCP, TLS   │  │  UDP, DTLS   │                    │
│  └─────────────┘  └──────────────┘                    │
├─────────────────────────────────────────────────────────┤
│  Layer 3: Network                                       │
│  ┌─────────────────────────────────┐                   │
│  │         Network                 │                   │
│  │      Raw IP packets             │                   │
│  └─────────────────────────────────┘                   │
├─────────────────────────────────────────────────────────┤
│  Layer 2: Data Link                                     │
│  ┌─────────────────────────────────┐                   │
│  │          Frame                  │                   │
│  │      Ethernet frames            │                   │
│  └─────────────────────────────────┘                   │
└─────────────────────────────────────────────────────────┘
```

## Core Concepts

### Conduit Interface

All conduits implement the base `Conduit[V]` interface:

```go
type Conduit[V any] interface {
    Dial(ctx context.Context) error
    Close() error

    Kind() Kind
    Stack() []string

    Underlying() V
}
```

- **Generic Type `V`** - Specifies the layer interface (Stream, Datagram, Network, Frame)
- **Dial** - Establishes the connection (idempotent)
- **Close** - Closes the connection and releases resources
- **Kind** - Returns the conduit type (KindStream, KindDatagram, etc.)
- **Stack** - Returns the layer names (e.g., `["tls", "tcp"]`)
- **Underlying** - Returns the layer-specific interface

### Layer Interfaces

#### Stream (L4 - Connection-Oriented)

For byte stream protocols like TCP and TLS:

```go
type Stream interface {
    Recv(ctx context.Context, opts *RecvOptions) (*StreamChunk, error)
    Send(ctx context.Context, p []byte, buf Buffer, opts *SendOptions) (int, Metadata, error)

    Close() error
    CloseWrite() error

    SetDeadline(t time.Time) error
    LocalAddr() net.Addr
    RemoteAddr() net.Addr
}
```

#### Datagram (L4 - Connectionless)

For message-based protocols like UDP and DTLS:

```go
type Datagram interface {
    Recv(ctx context.Context, opts *RecvOptions) (*DatagramMsg, error)
    RecvBatch(ctx context.Context, msgs []*DatagramMsg, opts *RecvOptions) (int, error)

    Send(ctx context.Context, msg *DatagramMsg, opts *SendOptions) (int, Metadata, error)
    SendBatch(ctx context.Context, msgs []*DatagramMsg, opts *SendOptions) (int, error)

    SetDeadline(t time.Time) error
    LocalAddr() netip.AddrPort
    RemoteAddr() netip.AddrPort
}
```

#### Network (L3 - IP Layer)

For raw IP packet manipulation:

```go
type Network interface {
    Recv(ctx context.Context, opts *RecvOptions) (*IPPacket, error)
    RecvBatch(ctx context.Context, pkts []*IPPacket, opts *RecvOptions) (int, error)

    Send(ctx context.Context, pkt *IPPacket, opts *SendOptions) (int, Metadata, error)
    SendBatch(ctx context.Context, pkts []*IPPacket, opts *SendOptions) (int, error)

    SetDeadline(t time.Time) error
    LocalAddr() netip.Addr
    Proto() int
    IsIPv6() bool
}
```

#### Frame (L2 - Ethernet Layer)

For raw Ethernet frame manipulation:

```go
type Frame interface {
    Recv(ctx context.Context, opts *RecvOptions) (*FramePkt, error)
    RecvBatch(ctx context.Context, pkts []*FramePkt, opts *RecvOptions) (int, error)

    Send(ctx context.Context, pkt *FramePkt, opts *SendOptions) (int, Metadata, error)
    SendBatch(ctx context.Context, pkts []*FramePkt, opts *SendOptions) (int, error)

    SetDeadline(t time.Time) error
    Interface() *net.Interface
}
```

### Buffer Management

Trident uses a pooled buffer system to minimize allocations:

```go
type Buffer interface {
    Bytes() []byte
    Grow(n int) []byte
    Release()
}
```

Buffers are automatically managed:

- Allocated from a sync.Pool
- Must be released after use via `Release()`
- Reused for subsequent operations

### Metadata

Every send/receive operation returns rich metadata:

```go
type Metadata struct {
    Start   time.Time      // syscall start time
    End     time.Time      // syscall end time
    TS      Timestamp      // hardware/software timestamps
    IfIndex int            // interface index
    Proto   int            // protocol number
    Zone    string         // IPv6 zone
    Flags   MetaFlags      // operation flags
    Ext     map[string]any // extensible metadata
}
```

## Usage Examples

### TCP Client

```go
package main

import (
    "context"
    "fmt"

    "bytemomo/trident/conduit"
    "bytemomo/trident/conduit/transport"
)

func main() {
    // Create TCP conduit
    cond := transport.TCP("example.com:80")

    // Dial the connection
    ctx := context.Background()
    if err := cond.Dial(ctx); err != nil {
        panic(err)
    }
    defer cond.Close()

    // Get underlying stream
    stream := cond.Underlying()

    // Send HTTP request
    request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    n, md, err := stream.Send(ctx, request, nil, nil)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Sent %d bytes in %v\n", n, md.End.Sub(md.Start))

    // Receive response
    chunk, err := stream.Recv(ctx, &conduit.RecvOptions{MaxBytes: 4096})
    if err != nil {
        panic(err)
    }
    defer chunk.Data.Release()

    fmt.Printf("Received: %s\n", chunk.Data.Bytes())
}
```

### TLS Client (Layered)

```go
package main

import (
    "context"
    "crypto/tls"

    "bytemomo/trident/conduit"
    "bytemomo/trident/conduit/transport"
    tlscond "bytemomo/trident/conduit/transport/tls"
)

func main() {
    // Create layered conduit: TLS over TCP
    tcpCond := transport.TCP("example.com:443")
    tlsConfig := &tls.Config{ServerName: "example.com"}
    cond := tlscond.NewTlsClient(tcpCond, tlsConfig)

    ctx := context.Background()
    if err := cond.Dial(ctx); err != nil {
        panic(err)
    }
    defer cond.Close()

    // Stack shows layers: ["tls", "tcp"]
    fmt.Printf("Stack: %v\n", cond.Stack())

    stream := cond.Underlying()

    // Send HTTPS request
    request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    stream.Send(ctx, request, nil, nil)

    // Receive response
    chunk, _ := stream.Recv(ctx, nil)
    defer chunk.Data.Release()

    fmt.Printf("Response: %s\n", chunk.Data.Bytes())
}
```

### UDP Client

```go
package main

import (
    "context"
    "net/netip"

    "bytemomo/trident/conduit"
    "bytemomo/trident/conduit/transport"
)

func main() {
    cond := transport.UDP("8.8.8.8:53")

    ctx := context.Background()
    cond.Dial(ctx)
    defer cond.Close()

    datagram := cond.Underlying()

    // DNS query
    dnsQuery := []byte{/* DNS query bytes */}

    buf := conduit.GetBuf(len(dnsQuery))
    copy(buf.Bytes(), dnsQuery)

    msg := &conduit.DatagramMsg{
        Data: buf,
        Dst:  netip.MustParseAddrPort("8.8.8.8:53"),
    }

    datagram.Send(ctx, msg, nil)

    // Receive response
    resp, _ := datagram.Recv(ctx, &conduit.RecvOptions{MaxBytes: 512})
    defer resp.Data.Release()

    fmt.Printf("DNS response from %s: %d bytes\n", resp.Src, len(resp.Data.Bytes()))
}
```

### DTLS Client

```go
package main

import (
    "context"

    "bytemomo/trident/conduit"
    "bytemomo/trident/conduit/transport/tls"
    "github.com/pion/dtls/v3"
)

func main() {
    // DTLS client (handles UDP internally)
    dtlsConfig := &dtls.Config{
        InsecureSkipVerify: true,
    }
    cond := tls.NewDtlsClient("coap.server.com:5684", dtlsConfig)

    ctx := context.Background()
    cond.Dial(ctx)
    defer cond.Close()

    // Stack: ["dtls", "udp"]
    fmt.Printf("Stack: %v\n", cond.Stack())

    datagram := cond.Underlying()

    // Send CoAP request
    coapRequest := []byte{/* CoAP message */}
    buf := conduit.GetBuf(len(coapRequest))
    copy(buf.Bytes(), coapRequest)

    msg := &conduit.DatagramMsg{Data: buf}
    datagram.Send(ctx, msg, nil)

    // Receive CoAP response
    resp, _ := datagram.Recv(ctx, nil)
    defer resp.Data.Release()

    fmt.Printf("CoAP response: %d bytes\n", len(resp.Data.Bytes()))
}
```

### Raw IP (Network Layer)

```go
package main

import (
    "context"
    "net/netip"

    "bytemomo/trident/conduit"
    "bytemomo/trident/conduit/network"
)

func main() {
    // Raw ICMP (protocol 1)
    target := netip.MustParseAddr("8.8.8.8")
    cond := network.IPRaw(1, target)

    ctx := context.Background()
    cond.Dial(ctx)
    defer cond.Close()

    net := cond.Underlying()

    // Send ICMP echo request
    icmpEcho := []byte{8, 0, 0, 0, 0, 1, 0, 1} // simplified
    buf := conduit.GetBuf(len(icmpEcho))
    copy(buf.Bytes(), icmpEcho)

    pkt := &conduit.IPPacket{
        Data:  buf,
        Dst:   target,
        Proto: 1,
        V6:    false,
    }

    net.Send(ctx, pkt, nil)

    // Receive ICMP reply
    reply, _ := net.Recv(ctx, nil)
    defer reply.Data.Release()

    fmt.Printf("ICMP reply from %s\n", reply.Src)
}
```

### Ethernet Frames (Data Link Layer)

```go
package main

import (
    "context"
    "net"

    "bytemomo/trident/conduit"
    "bytemomo/trident/conduit/datalink"
)

func main() {
    // EtherCAT on eth0
    dstMAC, _ := net.ParseMAC("01:01:05:01:00:00")
    cond := datalink.Ethernet("eth0", dstMAC, 0x88A4)

    ctx := context.Background()
    cond.Dial(ctx)
    defer cond.Close()

    frame := cond.Underlying()

    // Send EtherCAT frame
    payload := []byte{/* EtherCAT payload */}
    buf := conduit.GetBuf(len(payload))
    copy(buf.Bytes(), payload)

    pkt := &conduit.FramePkt{
        Data:      buf,
        Dst:       dstMAC,
        EtherType: 0x88A4,
    }

    frame.Send(ctx, pkt, nil)

    // Receive response
    resp, _ := frame.Recv(ctx, nil)
    defer resp.Data.Release()

    fmt.Printf("Frame from %s: %d bytes\n", resp.Src, len(resp.Data.Bytes()))
}
```

## Building Custom Conduits

You can create custom conduits by implementing the required interfaces:

```go
type MyProtocolConduit struct {
    inner conduit.Conduit[conduit.Stream]
    // ... custom fields
}

func (c *MyProtocolConduit) Dial(ctx context.Context) error {
    // Dial inner conduit first
    if err := c.inner.Dial(ctx); err != nil {
        return err
    }

    // Perform protocol handshake
    // ...

    return nil
}

func (c *MyProtocolConduit) Close() error {
    // Cleanup
    return c.inner.Close()
}

func (c *MyProtocolConduit) Kind() conduit.Kind {
    return conduit.KindStream
}

func (c *MyProtocolConduit) Stack() []string {
    return append([]string{"myprotocol"}, c.inner.Stack()...)
}

func (c *MyProtocolConduit) Underlying() conduit.Stream {
    return &myProtocolStream{c}
}
```

## Advanced Features

### Logging Conduit

Wrap any conduit with logging for debugging:

```go
import "bytemomo/trident/conduit"

tcpCond := transport.TCP("server:80")
loggedCond := conduit.NewLoggingConduit("MyConnection", tcpCond)

loggedCond.Dial(ctx) // Logs: [MyConnection] Dialing...
// [MyConnection] Dial successful in 15ms

stream := loggedCond.Underlying()
stream.Send(ctx, data, nil, nil) // Logs: [MyConnection] Send(stream)...
// [MyConnection] Send(stream) successful in 2ms: 100 bytes
```

## Integration with Kraken

Trident is used by **Kraken** (the security testing orchestrator) to provide transport abstraction for security modules:

```yaml
# Kraken module configuration
exec:
    conduit:
        kind: 1 # Stream
        stack:
            - name: "tcp"
            - name: "tls"
              params:
                  skip_verify: true
                  min_version: "TLS1.2"
```

This allows security test modules to focus on protocol logic while Kraken handles the transport layer configuration.

## Design Patterns

### Decorator Pattern

Conduits use the decorator pattern for layering:

```
TLS Conduit
    └─> TCP Conduit
            └─> net.Conn
```

Each layer wraps the previous one, adding functionality.

### Factory Pattern

Constructor functions create configured conduits:

```go
func TCP(addr string, opts ...TCPOption) Conduit[Stream]
func UDP(addr string) Conduit[Datagram]
func NewTlsClient(inner cond.Conduit[cond.Stream], cfg *tls.Config) cond.Conduit[cond.Stream]
```

### Strategy Pattern

Different implementations of the same interface allow pluggable behavior:

- `TcpConduit` vs `TlsClient` - both implement `Conduit[Stream]`
- `UdpConduit` vs `DtlsClient` - both implement `Conduit[Datagram]`

## Testing

Trident includes test files for each layer:

```bash
go test ./...
```

## Dependencies

- `golang.org/x/net` - IPv4/IPv6 packet control
- `golang.org/x/sys` - Low-level system calls
- `github.com/pion/dtls/v3` - DTLS implementation
- `github.com/mdlayher/raw` - Raw socket support
- `github.com/mdlayher/packet` - Packet socket interface

## Future Enhancements

- [ ] QUIC support (L4 datagram + stream hybrid)
- [ ] SCTP support
- [ ] WebSocket conduit
- [ ] HTTP/2 and HTTP/3 conduits
- [ ] mTLS with certificate validation
- [ ] Connection pooling and load balancing
- [ ] Metrics and observability hooks
- [ ] Async/non-blocking mode
- [ ] io_uring backend (Linux)
