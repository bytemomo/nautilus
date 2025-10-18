package conduit

import (
	"context"
	"net"
	"net/netip"
	"time"
)

type Kind int

const (
	KindUnknown  Kind = iota
	KindStream        // bytestreams (TCP/TLS)
	KindDatagram      // messages (UDP/DTLS)
	KindNetwork       // raw IP packets
	KindFrame         // L2 frames
)

type Timestamp struct {
	Software time.Time
	Hardware time.Time
}

type Metadata struct {
	Start   time.Time      // when the syscall/IO started
	End     time.Time      // when it completed
	TS      Timestamp      // rx/tx timestamp if available
	IfIndex int            // ingress/egress interface index (0 if n/a)
	Proto   int            // e.g., EtherType or IP Proto where applicable
	Zone    string         // IPv6 zone if relevant
	Flags   MetaFlags      // see below
	Ext     map[string]any // optional extensions; keep this as a last resort
}

type MetaFlags uint64

const (
	MetaTimeout   MetaFlags = 1 << iota
	MetaTruncated           // kernel indicated truncation
	MetaChecksumOK
	MetaGSO
	MetaGSORaw
)

// Options provided when sending or as defaults on a conduit.
type SendOptions struct {
	TTL      int
	TOS      int
	IfIndex  int
	VLAN     int
	Deadline time.Time // per-op override
	NoCopy   bool      // best-effort zero-copy if supported
}

type RecvOptions struct {
	Deadline time.Time
	MaxBytes int // hint; allows pool sizing
	Batch    int // desired batch size for RecvBatch
}

// Buffer is a ref-counted or pooled payload.
// Data is valid until Release. Implementations may reuse memory after Release.
type Buffer interface {
	Bytes() []byte
	Grow(n int) []byte
	Release()
}

// ------------------------------------------------------------------------------------
// Message envelopes per layer
// ------------------------------------------------------------------------------------

type StreamChunk struct {
	Data Buffer
	MD   Metadata
	// Streams don’t change peer addrs mid-flight, so no addr here.
}

type DatagramMsg struct {
	Data Buffer
	Src  netip.AddrPort
	Dst  netip.AddrPort
	MD   Metadata
}

type IPPacket struct {
	Data  Buffer
	Src   netip.Addr
	Dst   netip.Addr
	Proto int  // IPv4/6 Next Header number (e.g., 1 ICMP, 6 TCP, 17 UDP)
	V6    bool // cache for fast path
	MD    Metadata
}

type FramePkt struct {
	Data      Buffer
	Src, Dst  net.HardwareAddr
	EtherType uint16
	IfIndex   int // for raw sockets bound to a device
	MD        Metadata
}

// ------------------------------------------------------------------------------------
// Conduit contract (unchanged idea, refined)
// ------------------------------------------------------------------------------------

type Conduit[V any] interface {
	Dial(ctx context.Context) error
	Close() error

	Kind() Kind
	Stack() []string

	Underlying() V
}

// ------------------------------------------------------------------------------------
// L4: Stream (TCP/TLS)
// ------------------------------------------------------------------------------------

type Stream interface {
	Recv(ctx context.Context, opts *RecvOptions) (*StreamChunk, error)
	Send(ctx context.Context, p []byte, buf Buffer, opts *SendOptions) (n int, md Metadata, err error)

	Close() error
	CloseWrite() error

	SetDeadline(t time.Time) error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

// ------------------------------------------------------------------------------------
// L4: Datagram (UDP/DTLS)
// ------------------------------------------------------------------------------------

type Datagram interface {
	Recv(ctx context.Context, opts *RecvOptions) (*DatagramMsg, error)
	RecvBatch(ctx context.Context, msgs []*DatagramMsg, opts *RecvOptions) (int, error)

	Send(ctx context.Context, msg *DatagramMsg, opts *SendOptions) (n int, md Metadata, err error)
	SendBatch(ctx context.Context, msgs []*DatagramMsg, opts *SendOptions) (int, error)

	SetDeadline(t time.Time) error
	LocalAddr() netip.AddrPort
	RemoteAddr() netip.AddrPort
}

// ------------------------------------------------------------------------------------
// L3: Network (Raw IP)
// ------------------------------------------------------------------------------------

type Network interface {
	Recv(ctx context.Context, opts *RecvOptions) (*IPPacket, error)
	RecvBatch(ctx context.Context, pkts []*IPPacket, opts *RecvOptions) (int, error)

	Send(ctx context.Context, pkt *IPPacket, opts *SendOptions) (n int, md Metadata, err error)
	SendBatch(ctx context.Context, pkts []*IPPacket, opts *SendOptions) (int, error)

	SetDeadline(t time.Time) error
	LocalAddr() netip.Addr
	Proto() int
	IsIPv6() bool
}

// ------------------------------------------------------------------------------------
// L2: Frame (Ethernet)
// ------------------------------------------------------------------------------------

type Frame interface {
	Recv(ctx context.Context, opts *RecvOptions) (*FramePkt, error)
	RecvBatch(ctx context.Context, pkts []*FramePkt, opts *RecvOptions) (int, error)

	Send(ctx context.Context, pkt *FramePkt, opts *SendOptions) (n int, md Metadata, err error)
	SendBatch(ctx context.Context, pkts []*FramePkt, opts *SendOptions) (int, error)

	SetDeadline(t time.Time) error
	Interface() *net.Interface
}
