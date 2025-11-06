package conduit

import (
	"bytemomo/trident/conduit/utils"
	"context"
	"net"
	"net/netip"
	"time"
)

// Kind identifies the operational layer of a Conduit.
type Kind int

const (
	// KindUnknown is the default zero value for a Kind.
	KindUnknown Kind = iota
	// KindStream represents a byte-stream oriented conduit, such as TCP or TLS.
	// These conduits operate on continuous streams of data.
	KindStream
	// KindDatagram represents a message-oriented conduit, such as UDP or DTLS.
	// These conduits operate on discrete packets (datagrams).
	KindDatagram
	// KindNetwork represents a conduit that operates at the raw IP packet level (Layer 3).
	KindNetwork
	// KindFrame represents a conduit that operates at the Ethernet frame level (Layer 2).
	KindFrame
)

// Timestamp captures hardware or software timestamps for I/O operations.
// Not all systems or network interfaces provide hardware timestamps.
type Timestamp struct {
	// Software is a timestamp taken by the kernel or application.
	Software time.Time
	// Hardware is a timestamp taken by the network interface controller (NIC).
	Hardware time.Time
}

// Metadata provides rich, optional information about a completed I/O operation.
type Metadata struct {
	// Start is the time just before the I/O operation (e.g., syscall) was initiated.
	Start time.Time
	// End is the time just after the I/O operation completed.
	End time.Time
	// TS holds hardware or software timestamps, if available.
	TS Timestamp
	// IfIndex is the network interface index for the operation.
	IfIndex int
	// Proto is the protocol number, such as EtherType or IP Protocol number.
	Proto int
	// Zone is the IPv6 zone, if applicable.
	Zone string
	// Flags provides additional bit-maskable details about the operation.
	Flags MetaFlags
	// Ext is a map for protocol-specific or experimental metadata. Use sparingly.
	Ext map[string]any
}

// MetaFlags provides bit-maskable details about an I/O operation.
type MetaFlags uint64

const (
	// MetaTimeout indicates that the operation timed out.
	MetaTimeout MetaFlags = 1 << iota
	// MetaTruncated indicates that a received message was truncated by the kernel.
	MetaTruncated
	// MetaChecksumOK indicates that the hardware verified the checksum and it was valid.
	MetaChecksumOK
	// MetaGSO indicates that Generic Segmentation Offload was performed.
	MetaGSO
	// MetaGSORaw indicates that raw Generic Segmentation Offload was performed.
	MetaGSORaw
)

// SendOptions provides parameters for a single send operation.
type SendOptions struct {
	// TTL is the time-to-live or hop limit for IP packets.
	TTL int
	// TOS is the type-of-service or traffic class field for IP packets.
	TOS int
	// IfIndex specifies the network interface index for the outgoing packet.
	IfIndex int
	// VLAN tag to apply to the outgoing frame.
	VLAN int
	// Deadline is a per-operation deadline, overriding any conduit-level deadline.
	Deadline time.Time
	// NoCopy indicates a hint to the conduit to use a zero-copy send if possible.
	// The caller must not modify the buffer's contents after the send call.
	NoCopy bool
}

// RecvOptions provides parameters for a single receive operation.
type RecvOptions struct {
	// Deadline is a per-operation deadline, overriding any conduit-level deadline.
	Deadline time.Time
	// MaxBytes provides a hint for buffer allocation size.
	MaxBytes int
	// Batch provides a hint for the desired number of messages to receive in a batch operation.
	Batch int
}

// Buffer is an interface for a managed, recyclable memory buffer.
// After calling Release, the underlying memory may be reused, and the slice
// returned by Bytes() should not be accessed.
type Buffer interface {
	// Bytes returns the byte slice held by the buffer.
	Bytes() []byte
	// Grow increases the buffer's capacity by at least n bytes.
	Grow(n int) []byte
	// Shrink decreases the buffer's capacity by n bytes.
	Shrink(n int) []byte
	// Release returns the buffer to its pool for reuse.
	Release()
}

// GetBuf retrieves a buffer from the pool with at least the given size.
func GetBuf(size int) Buffer {
	return utils.GetBuf(size)
}

// ------------------------------------------------------------------------------------
// Message envelopes per layer
// ------------------------------------------------------------------------------------

// StreamChunk represents a piece of data received from a stream-oriented conduit.
type StreamChunk struct {
	// Data is the buffer containing the received data.
	Data Buffer
	// MD is the metadata associated with the receive operation.
	MD Metadata
}

// DatagramMsg represents a single message from a datagram-oriented conduit.
type DatagramMsg struct {
	// Data is the buffer containing the message payload.
	Data Buffer
	// Src is the source address of the message.
	Src netip.AddrPort
	// Dst is the destination address of the message.
	Dst netip.AddrPort
	// MD is the metadata associated with the I/O operation.
	MD Metadata
}

// IPPacket represents a single IP packet from a network-layer conduit.
type IPPacket struct {
	// Data is the buffer containing the packet payload.
	Data Buffer
	// Src is the source IP address.
	Src netip.Addr
	// Dst is the destination IP address.
	Dst netip.Addr
	// Proto is the IP protocol number (e.g., 1 for ICMP, 6 for TCP, 17 for UDP).
	Proto int
	// V6 is true if the packet is IPv6.
	V6 bool
	// MD is the metadata associated with the I/O operation.
	MD Metadata
}

// FramePkt represents a single Ethernet frame from a datalink-layer conduit.
type FramePkt struct {
	// Data is the buffer containing the frame payload.
	Data Buffer
	// Src is the source MAC address.
	Src net.HardwareAddr
	// Dst is the destination MAC address.
	Dst net.HardwareAddr
	// EtherType specifies the protocol of the encapsulated payload.
	EtherType uint16
	// IfIndex is the interface index where the frame was received.
	IfIndex int
	// MD is the metadata associated with the I/O operation.
	MD Metadata
}

// ------------------------------------------------------------------------------------
// Conduit contract (unchanged idea, refined)
// ------------------------------------------------------------------------------------

// Conduit is the core abstraction in Trident, representing a connection or socket
// at a specific network layer. Conduits are composable, allowing for the creation
// of protocol stacks (e.g., TLS over TCP).
// The generic type V specifies the underlying layer-specific interface (e.g., Stream, Datagram).
type Conduit[V any] interface {
	// Dial establishes the connection or prepares the socket for use.
	// It is idempotent; subsequent calls should have no effect.
	Dial(ctx context.Context) error
	// Close tears down the connection and releases all associated resources.
	Close() error

	// Kind returns the operational layer of the conduit.
	Kind() Kind
	// Stack returns a slice of strings representing the protocol stack,
	// from the outermost layer to the innermost (e.g., ["tls", "tcp"]).
	Stack() []string

	// Underlying returns the layer-specific interface for performing I/O.
	// For example, a TCP conduit would return an implementation of the Stream interface.
	Underlying() V
}

// ------------------------------------------------------------------------------------
// L4: Stream (TCP/TLS)
// ------------------------------------------------------------------------------------

// Stream is an interface for connection-oriented, byte-stream protocols like TCP and TLS.
type Stream interface {
	// Recv reads data from the stream. It blocks until data is available or an error occurs.
	// An io.EOF error is returned when the peer closes the connection.
	Recv(ctx context.Context, opts *RecvOptions) (*StreamChunk, error)
	// Send writes data to the stream. It blocks until the data is sent or an error occurs.
	// It accepts either a raw byte slice `p` or a managed Buffer `buf`. If both are provided, `buf` is preferred.
	Send(ctx context.Context, p []byte, buf Buffer, opts *SendOptions) (n int, md Metadata, err error)

	// Close fully closes the connection.
	Close() error
	// CloseWrite shuts down the sending side of the connection.
	// Subsequent writes will return an error. Useful for signaling EOF to the peer.
	CloseWrite() error

	// SetDeadline sets the read and write deadlines for the connection.
	SetDeadline(t time.Time) error
	// LocalAddr returns the local network address.
	LocalAddr() net.Addr
	// RemoteAddr returns the remote network address.
	RemoteAddr() net.Addr
}

// ------------------------------------------------------------------------------------
// L4: Datagram (UDP/DTLS)
// ------------------------------------------------------------------------------------

// Datagram is an interface for connectionless, message-oriented protocols like UDP and DTLS.
type Datagram interface {
	// Recv reads a single datagram. It blocks until a message is available or an error occurs.
	Recv(ctx context.Context, opts *RecvOptions) (*DatagramMsg, error)
	// RecvBatch reads multiple datagrams in a single call for efficiency.
	// It returns the number of messages read.
	RecvBatch(ctx context.Context, msgs []*DatagramMsg, opts *RecvOptions) (int, error)

	// Send writes a single datagram.
	Send(ctx context.Context, msg *DatagramMsg, opts *SendOptions) (n int, md Metadata, err error)
	// SendBatch writes multiple datagrams in a single call for efficiency.
	// It returns the number of messages sent.
	SendBatch(ctx context.Context, msgs []*DatagramMsg, opts *SendOptions) (int, error)

	// SetDeadline sets the read and write deadlines for the connection.
	SetDeadline(t time.Time) error
	// LocalAddr returns the local network address as a netip.AddrPort.
	LocalAddr() netip.AddrPort
	// RemoteAddr returns the remote network address if the socket is connected.
	RemoteAddr() netip.AddrPort
}

// ------------------------------------------------------------------------------------
// L3: Network (Raw IP)
// ------------------------------------------------------------------------------------

// Network is an interface for raw IP packet manipulation (Layer 3).
type Network interface {
	// Recv reads a single IP packet.
	Recv(ctx context.Context, opts *RecvOptions) (*IPPacket, error)
	// RecvBatch reads multiple IP packets in a single call.
	RecvBatch(ctx context.Context, pkts []*IPPacket, opts *RecvOptions) (int, error)

	// Send writes a single IP packet.
	Send(ctx context.Context, pkt *IPPacket, opts *SendOptions) (n int, md Metadata, err error)
	// SendBatch writes multiple IP packets in a single call.
	SendBatch(ctx context.Context, pkts []*IPPacket, opts *SendOptions) (int, error)

	// SetDeadline sets the read and write deadlines.
	SetDeadline(t time.Time) error
	// LocalAddr returns the local IP address.
	LocalAddr() netip.Addr
	// Proto returns the IP protocol number this conduit is configured for.
	Proto() int
	// IsIPv6 returns true if the conduit is configured for IPv6.
	IsIPv6() bool
}

// ------------------------------------------------------------------------------------
// L2: Frame (Ethernet)
// ------------------------------------------------------------------------------------

// Frame is an interface for raw Ethernet frame manipulation (Layer 2).
type Frame interface {
	// Recv reads a single Ethernet frame.
	Recv(ctx context.Context, opts *RecvOptions) (*FramePkt, error)
	// RecvBatch reads multiple Ethernet frames in a single call.
	RecvBatch(ctx context.Context, pkts []*FramePkt, opts *RecvOptions) (int, error)

	// Send writes a single Ethernet frame.
	Send(ctx context.Context, pkt *FramePkt, opts *SendOptions) (n int, md Metadata, err error)
	// SendBatch writes multiple Ethernet frames in a single call.
	SendBatch(ctx context.Context, pkts []*FramePkt, opts *SendOptions) (int, error)

	// SetDeadline sets the read and write deadlines.
	SetDeadline(t time.Time) error
	// Interface returns the network interface this conduit is bound to.
	Interface() *net.Interface
}
