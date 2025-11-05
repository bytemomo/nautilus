# Trident

Trident is a small, self contained library that abstract away transports in a single
high level API called `Conduit`.

## Overview

Trident provides a `Conduit` abstraction that represents network connections at
different layers of the network stack. Each conduit can be composed with others
to create layered protocols (e.g., TCP → TLS → Application Protocol).

### Key Requirements

- **Layered Architecture**: Stack conduits to build complex protocols
- **Unified API**: Consistent interface across all network layers
- **Zero-Copy Operations**: Pooled buffer system for efficient memory management
- **Context-Aware**: Built-in timeout and cancellation support via Go contexts
- **Type-Safe**: Generic interfaces ensure compile-time safety
- **Metadata**: Detailed timing, addressing, and protocol information

## Architecture

Trident defines conduits for four network layers:

```text
┌───────────────────────────────────────────────────────┐
│  Layer 4: Transport                                   │
│  ┌─────────────┐  ┌──────────────┐                    │
│  │   Stream    │  │   Datagram   │                    │
│  │  TCP, TLS   │  │  UDP, DTLS   │                    │
│  └─────────────┘  └──────────────┘                    │
├───────────────────────────────────────────────────────┤
│  Layer 3: Network                                     │
│  ┌─────────────────────────────────┐                  │
│  │         Network                 │                  │
│  │      Raw IP packets             │                  │
│  └─────────────────────────────────┘                  │
├───────────────────────────────────────────────────────┤
│  Layer 2: Data Link                                   │
│  ┌─────────────────────────────────┐                  │
│  │          Frame                  │                  │
│  │      Ethernet frames            │                  │
│  └─────────────────────────────────┘                  │
└───────────────────────────────────────────────────────┘
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

- **Generic Type `V`**: Specifies the layer interface (Stream, Datagram, Network,
  Frame)
- **Dial**: Establishes the connection
- **Close**: Closes the connection and releases resources
- **Kind**: Returns the conduit type (KindStream, KindDatagram, etc.)
- **Stack**: Returns the stack layer names (e.g., `["tls", "tcp"]`)
- **Underlying**: Returns the layer-specific interface

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

type pooledBuf struct {
	b   []byte
	cap int
}

var bufPool = sync.Pool{
	New: func() any { return &pooledBuf{b: make([]byte, 32*1024), cap: 32 * 1024} },
}

func GetBuf(min int) *pooledBuf {
	p := bufPool.Get().(*pooledBuf)
	if cap(p.b) < min {
		p.b = make([]byte, min)
		p.cap = min
	} else {
		p.b = p.b[:min]
	}
	return p
}

func (p *pooledBuf) Bytes() []byte { return p.b }

func (p *pooledBuf) Grow(n int) []byte {
	if cap(p.b) < n {
		p.b = make([]byte, n)
		p.cap = n
	} else {
		p.b = p.b[:n]
	}
	return p.b
}

func (p *pooledBuf) ShrinkTo(n int) { p.b = p.b[:n] }

func (p *pooledBuf) Release() {
	p.b = p.b[:0]
	bufPool.Put(p)
}
```

Buffers are automatically managed:

- Allocated from a sync.Pool
- Must be released after use via `Release()`
- Reused for subsequent operations

### Metadata

Every send/receive operation returns metadata:

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

## Advanced Usage

### Building Custom Conduits

Custom conduits can be created by implementing the required interfaces:

```go
type MyProtocolConduit struct {
    inner conduit.Conduit[conduit.Stream] // Not mandatory
    // ... custom fields
}

func (c *MyProtocolConduit) Dial(ctx context.Context) error {
    // Not mandatory, there could be no inner conduit
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

### Logging Conduit

Wrap any conduit with logging for debugging:

```go
import "bytemomo/trident/conduit"

tcpCond := transport.TCP("server:80")
loggedCond := conduit.NewLoggingConduit("MyConnection", tcpCond)

loggedCond.Dial(ctx)
// [MyConnection] Dial successful in 15ms

stream := loggedCond.Underlying()
stream.Send(ctx, data, nil, nil)
// [MyConnection] Send(stream) successful in 2ms: 100 bytes
```

## Integration with Kraken

Trident is used by **Kraken** to provide transport abstraction for security modules:
This allows security test modules to focus on protocol logic while Kraken handles
the transport layer configuration.

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

- [ ] QUIC support
- [ ] SCTP support
- [ ] MQTT support
- [ ] RTSP(S), (S)RTP and (S)RTCP support
- [ ] HTTP(S) support
- [ ] EtherCAT support
- [ ] WebSocket conduit
- [ ] HTTP/2 and HTTP/3 conduits
- [ ] mTLS with certificate validation
- [ ] Connection pooling and load balancing
- [ ] Metrics and observability hooks
- [ ] Async/non-blocking mode
- [ ] io_uring backend (Linux)

> [!NOTE]
> The list of future enhancements is an unordered list.
