package conduit

import (
	"context"
	"net"
	"net/netip"
	"time"
)

type Kind int

const (
	KindUnknown Kind = iota
	KindStream
	KindDatagram
	KindNetwork
	KindFrame
)

type Metadata struct {
	Start      time.Time
	End        time.Time
	Layer      string
	Remote     string
	Local      string
	Attributes map[string]any
}

type View[V any] struct {
	View V
}

type Conduit[V any] interface {
	Dial(ctx context.Context) error
	Close() error

	Kind() Kind
	Stack() []string

	AsView() View[V]
}

// ---------------------------- L4: Stream (TCP - UDP - TLS - DTLS) -------------------------------

type Stream interface {
	Read(ctx context.Context, p []byte) (n int, md Metadata, err error)
	Write(ctx context.Context, p []byte) (n int, md Metadata, err error)
	SetDeadline(t time.Time) error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

type Datagram interface {
	ReadFrom(ctx context.Context, p []byte) (n int, addr net.Addr, md Metadata, err error)
	WriteTo(ctx context.Context, p []byte, addr net.Addr) (n int, md Metadata, err error)
	SetDeadline(t time.Time) error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

// ---------------------------- L3: Network (Raw IP) -------------------------------

type Network interface {
	ReadIP(ctx context.Context, p []byte) (n int, src netip.Addr, md Metadata, err error)
	WriteIP(ctx context.Context, p []byte, dst netip.Addr) (n int, md Metadata, err error)
	SetDeadline(t time.Time) error
	LocalAddr() netip.Addr // zero if not bound
	Proto() int            // IP protocol number (e.g., 1=ICMP, 6=TCP, 17=UDP, 253/254 for testing)
	IsIPv6() bool
}

// ---------------------------- L2: Frame (Ethernet) -------------------------------

type Frame interface {
	ReadFrame(ctx context.Context, p []byte) (n int, src, dst net.HardwareAddr, etherType uint16, md Metadata, err error)
	WriteFrame(ctx context.Context, p []byte, dst net.HardwareAddr, etherType uint16) (n int, md Metadata, err error)
	SetDeadline(t time.Time) error
	Interface() *net.Interface
}
