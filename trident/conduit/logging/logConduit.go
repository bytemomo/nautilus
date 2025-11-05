package logging

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"bytemomo/trident/conduit"
)

// LoggingConduit is a decorator that wraps any conduit to provide detailed logging
// of its operations. This is useful for debugging network interactions.
// It uses the standard fmt package for output, but could be adapted for any
// structured logging library.
type LoggingConduit[V any] struct {
	inner conduit.Conduit[V]
	name  string
}

// NewLoggingConduit creates a new logging conduit decorator.
//
// name provides a descriptive name for the connection, used as a prefix in log messages.
// inner is the conduit to be wrapped.
func NewLoggingConduit[V any](name string, inner conduit.Conduit[V]) conduit.Conduit[V] {
	return &LoggingConduit[V]{inner: inner, name: name}
}

func (l *LoggingConduit[V]) Dial(ctx context.Context) error {
	fmt.Printf("[%s] Dialing...\n", l.name)
	start := time.Now()
	err := l.inner.Dial(ctx)
	duration := time.Since(start)
	if err != nil {
		fmt.Printf("[%s] Dial failed in %s: %v\n", l.name, duration, err)
		return err
	}
	fmt.Printf("[%s] Dial successful in %s\n", l.name, duration)
	return nil
}

func (l *LoggingConduit[V]) Close() error {
	fmt.Printf("[%s] Closing...\n", l.name)
	err := l.inner.Close()
	if err != nil {
		fmt.Printf("[%s] Close failed: %v\n", l.name, err)
		return err
	}
	fmt.Printf("[%s] Closed.\n", l.name)
	return nil
}

func (l *LoggingConduit[V]) Kind() conduit.Kind {
	kind := l.inner.Kind()
	fmt.Printf("[%s] Kind() -> %v\n", l.name, kind)
	return kind
}

func (l *LoggingConduit[V]) Stack() []string {
	stack := l.inner.Stack()
	fmt.Printf("[%s] Stack() -> %v\n", l.name, stack)
	return stack
}

func (l *LoggingConduit[V]) Underlying() V {
	innerV := l.inner.Underlying()
	switch v := any(innerV).(type) {
	case conduit.Stream:
		return any(&loggingStream{inner: v, name: l.name}).(V)
	case conduit.Datagram:
		return any(&loggingDatagram{inner: v, name: l.name}).(V)
	case conduit.Network:
		return any(&loggingNetwork{inner: v, name: l.name}).(V)
	case conduit.Frame:
		return any(&loggingFrame{inner: v, name: l.name}).(V)
	default:
		return innerV
	}
}

type loggingNetwork struct {
	inner conduit.Network
	name  string
}

func (l *loggingNetwork) Recv(ctx context.Context, opts *conduit.RecvOptions) (*conduit.IPPacket, error) {
	fmt.Printf("[%s] Recv(network)...\n", l.name)
	start := time.Now()
	pkt, err := l.inner.Recv(ctx, opts)
	duration := time.Since(start)
	if err != nil {
		fmt.Printf("[%s] Recv(network) failed in %s: %v\n", l.name, duration, err)
		return nil, err
	}
	if pkt != nil && pkt.Data != nil {
		fmt.Printf("[%s] Recv(network) successful in %s: %d bytes from %s\n", l.name, duration, len(pkt.Data.Bytes()), pkt.Src)
	} else {
		fmt.Printf("[%s] Recv(network) successful in %s: empty packet\n", l.name, duration)
	}
	return pkt, nil
}

func (l *loggingNetwork) RecvBatch(ctx context.Context, pkts []*conduit.IPPacket, opts *conduit.RecvOptions) (int, error) {
	fmt.Printf("[%s] RecvBatch(network)...\n", l.name)
	start := time.Now()
	n, err := l.inner.RecvBatch(ctx, pkts, opts)
	duration := time.Since(start)
	if err != nil {
		fmt.Printf("[%s] RecvBatch(network) failed in %s: %v\n", l.name, duration, err)
		return 0, err
	}
	fmt.Printf("[%s] RecvBatch(network) successful in %s: %d packets\n", l.name, duration, n)
	return n, nil
}

func (l *loggingNetwork) Send(ctx context.Context, pkt *conduit.IPPacket, opts *conduit.SendOptions) (int, conduit.Metadata, error) {
	fmt.Printf("[%s] Send(network)...\n", l.name)
	start := time.Now()
	n, md, err := l.inner.Send(ctx, pkt, opts)
	duration := time.Since(start)
	if err != nil {
		fmt.Printf("[%s] Send(network) failed in %s: %v\n", l.name, duration, err)
		return 0, md, err
	}
	if pkt != nil && pkt.Data != nil {
		fmt.Printf("[%s] Send(network) successful in %s: %d bytes to %s\n", l.name, duration, n, pkt.Dst)
	} else {
		fmt.Printf("[%s] Send(network) successful in %s: empty packet\n", l.name, duration)
	}
	return n, md, nil
}

func (l *loggingNetwork) SendBatch(ctx context.Context, pkts []*conduit.IPPacket, opts *conduit.SendOptions) (int, error) {
	fmt.Printf("[%s] SendBatch(network)...\n", l.name)
	start := time.Now()
	n, err := l.inner.SendBatch(ctx, pkts, opts)
	duration := time.Since(start)
	if err != nil {
		fmt.Printf("[%s] SendBatch(network) failed in %s: %v\n", l.name, duration, err)
		return 0, err
	}
	fmt.Printf("[%s] SendBatch(network) successful in %s: %d packets\n", l.name, duration, n)
	return n, nil
}

func (l *loggingNetwork) SetDeadline(t time.Time) error {
	fmt.Printf("[%s] SetDeadline(network) -> %s\n", l.name, t)
	return l.inner.SetDeadline(t)
}

func (l *loggingNetwork) LocalAddr() netip.Addr {
	addr := l.inner.LocalAddr()
	fmt.Printf("[%s] LocalAddr(network) -> %s\n", l.name, addr)
	return addr
}

func (l *loggingNetwork) Proto() int {
	proto := l.inner.Proto()
	fmt.Printf("[%s] Proto(network) -> %d\n", l.name, proto)
	return proto
}

func (l *loggingNetwork) IsIPv6() bool {
	isIPv6 := l.inner.IsIPv6()
	fmt.Printf("[%s] IsIPv6(network) -> %t\n", l.name, isIPv6)
	return isIPv6
}

type loggingFrame struct {
	inner conduit.Frame
	name  string
}

func (l *loggingFrame) Recv(ctx context.Context, opts *conduit.RecvOptions) (*conduit.FramePkt, error) {
	fmt.Printf("[%s] Recv(frame)...\n", l.name)
	start := time.Now()
	pkt, err := l.inner.Recv(ctx, opts)
	duration := time.Since(start)
	if err != nil {
		fmt.Printf("[%s] Recv(frame) failed in %s: %v\n", l.name, duration, err)
		return nil, err
	}
	if pkt != nil && pkt.Data != nil {
		fmt.Printf("[%s] Recv(frame) successful in %s: %d bytes from %s\n", l.name, duration, len(pkt.Data.Bytes()), pkt.Src)
	} else {
		fmt.Printf("[%s] Recv(frame) successful in %s: empty frame\n", l.name, duration)
	}
	return pkt, nil
}

func (l *loggingFrame) RecvBatch(ctx context.Context, pkts []*conduit.FramePkt, opts *conduit.RecvOptions) (int, error) {
	fmt.Printf("[%s] RecvBatch(frame)...\n", l.name)
	start := time.Now()
	n, err := l.inner.RecvBatch(ctx, pkts, opts)
	duration := time.Since(start)
	if err != nil {
		fmt.Printf("[%s] RecvBatch(frame) failed in %s: %v\n", l.name, duration, err)
		return 0, err
	}
	fmt.Printf("[%s] RecvBatch(frame) successful in %s: %d frames\n", l.name, duration, n)
	return n, nil
}

func (l *loggingFrame) Send(ctx context.Context, pkt *conduit.FramePkt, opts *conduit.SendOptions) (int, conduit.Metadata, error) {
	fmt.Printf("[%s] Send(frame)...\n", l.name)
	start := time.Now()
	n, md, err := l.inner.Send(ctx, pkt, opts)
	duration := time.Since(start)
	if err != nil {
		fmt.Printf("[%s] Send(frame) failed in %s: %v\n", l.name, duration, err)
		return 0, md, err
	}
	if pkt != nil && pkt.Data != nil {
		fmt.Printf("[%s] Send(frame) successful in %s: %d bytes to %s\n", l.name, duration, n, pkt.Dst)
	} else {
		fmt.Printf("[%s] Send(frame) successful in %s: empty frame\n", l.name, duration)
	}
	return n, md, nil
}

func (l *loggingFrame) SendBatch(ctx context.Context, pkts []*conduit.FramePkt, opts *conduit.SendOptions) (int, error) {
	fmt.Printf("[%s] SendBatch(frame)...\n", l.name)
	start := time.Now()
	n, err := l.inner.SendBatch(ctx, pkts, opts)
	duration := time.Since(start)
	if err != nil {
		fmt.Printf("[%s] SendBatch(frame) failed in %s: %v\n", l.name, duration, err)
		return 0, err
	}
	fmt.Printf("[%s] SendBatch(frame) successful in %s: %d frames\n", l.name, duration, n)
	return n, nil
}

func (l *loggingFrame) SetDeadline(t time.Time) error {
	fmt.Printf("[%s] SetDeadline(frame) -> %s\n", l.name, t)
	return l.inner.SetDeadline(t)
}

func (l *loggingFrame) Interface() *net.Interface {
	intf := l.inner.Interface()
	fmt.Printf("[%s] Interface(frame) -> %v\n", l.name, intf)
	return intf
}


type loggingStream struct {
	inner conduit.Stream
	name  string
}

func (l *loggingStream) Recv(ctx context.Context, opts *conduit.RecvOptions) (*conduit.StreamChunk, error) {
	fmt.Printf("[%s] Recv(stream)...\n", l.name)
	start := time.Now()
	chunk, err := l.inner.Recv(ctx, opts)
	duration := time.Since(start)
	if err != nil {
		fmt.Printf("[%s] Recv(stream) failed in %s: %v\n", l.name, duration, err)
		return nil, err
	}
	if chunk != nil && chunk.Data != nil {
		fmt.Printf("[%s] Recv(stream) successful in %s: %d bytes\n", l.name, duration, len(chunk.Data.Bytes()))
	} else {
		fmt.Printf("[%s] Recv(stream) successful in %s: empty chunk\n", l.name, duration)
	}
	return chunk, nil
}

func (l *loggingStream) Send(ctx context.Context, p []byte, buf conduit.Buffer, opts *conduit.SendOptions) (int, conduit.Metadata, error) {
	fmt.Printf("[%s] Send(stream)...\n", l.name)
	start := time.Now()
	n, md, err := l.inner.Send(ctx, p, buf, opts)
	duration := time.Since(start)
	if err != nil {
		fmt.Printf("[%s] Send(stream) failed in %s: %v\n", l.name, duration, err)
		return 0, md, err
	}
	fmt.Printf("[%s] Send(stream) successful in %s: %d bytes\n", l.name, duration, n)
	return n, md, nil
}

func (l *loggingStream) Close() error {
	fmt.Printf("[%s] Close(stream)...\n", l.name)
	return l.inner.Close()
}

func (l *loggingStream) CloseWrite() error {
	fmt.Printf("[%s] CloseWrite(stream)...\n", l.name)
	return l.inner.CloseWrite()
}

func (l *loggingStream) SetDeadline(t time.Time) error {
	fmt.Printf("[%s] SetDeadline(stream) -> %s\n", l.name, t)
	return l.inner.SetDeadline(t)
}

func (l *loggingStream) LocalAddr() net.Addr {
	addr := l.inner.LocalAddr()
	fmt.Printf("[%s] LocalAddr(stream) -> %s\n", l.name, addr)
	return addr
}

func (l *loggingStream) RemoteAddr() net.Addr {
	addr := l.inner.RemoteAddr()
	fmt.Printf("[%s] RemoteAddr(stream) -> %s\n", l.name, addr)
	return addr
}

type loggingDatagram struct {
	inner conduit.Datagram
	name  string
}

func (l *loggingDatagram) Recv(ctx context.Context, opts *conduit.RecvOptions) (*conduit.DatagramMsg, error) {
	fmt.Printf("[%s] Recv(datagram)...\n", l.name)
	start := time.Now()
	msg, err := l.inner.Recv(ctx, opts)
	duration := time.Since(start)
	if err != nil {
		fmt.Printf("[%s] Recv(datagram) failed in %s: %v\n", l.name, duration, err)
		return nil, err
	}
	if msg != nil && msg.Data != nil {
		fmt.Printf("[%s] Recv(datagram) successful in %s: %d bytes from %s\n", l.name, duration, len(msg.Data.Bytes()), msg.Src)
	} else {
		fmt.Printf("[%s] Recv(datagram) successful in %s: empty message\n", l.name, duration)
	}
	return msg, nil
}

func (l *loggingDatagram) RecvBatch(ctx context.Context, msgs []*conduit.DatagramMsg, opts *conduit.RecvOptions) (int, error) {
	fmt.Printf("[%s] RecvBatch(datagram)...\n", l.name)
	start := time.Now()
	n, err := l.inner.RecvBatch(ctx, msgs, opts)
	duration := time.Since(start)
	if err != nil {
		fmt.Printf("[%s] RecvBatch(datagram) failed in %s: %v\n", l.name, duration, err)
		return 0, err
	}
	fmt.Printf("[%s] RecvBatch(datagram) successful in %s: %d messages\n", l.name, duration, n)
	return n, nil
}

func (l *loggingDatagram) Send(ctx context.Context, msg *conduit.DatagramMsg, opts *conduit.SendOptions) (int, conduit.Metadata, error) {
	fmt.Printf("[%s] Send(datagram)...\n", l.name)
	start := time.Now()
	n, md, err := l.inner.Send(ctx, msg, opts)
	duration := time.Since(start)
	if err != nil {
		fmt.Printf("[%s] Send(datagram) failed in %s: %v\n", l.name, duration, err)
		return 0, md, err
	}
	if msg != nil && msg.Data != nil {
		fmt.Printf("[%s] Send(datagram) successful in %s: %d bytes to %s\n", l.name, duration, n, msg.Dst)
	} else {
		fmt.Printf("[%s] Send(datagram) successful in %s: empty message\n", l.name, duration)
	}
	return n, md, nil
}

func (l *loggingDatagram) SendBatch(ctx context.Context, msgs []*conduit.DatagramMsg, opts *conduit.SendOptions) (int, error) {
	fmt.Printf("[%s] SendBatch(datagram)...\n", l.name)
	start := time.Now()
	n, err := l.inner.SendBatch(ctx, msgs, opts)
	duration := time.Since(start)
	if err != nil {
		fmt.Printf("[%s] SendBatch(datagram) failed in %s: %v\n", l.name, duration, err)
		return 0, err
	}
	fmt.Printf("[%s] SendBatch(datagram) successful in %s: %d messages\n", l.name, duration, n)
	return n, nil
}

func (l *loggingDatagram) SetDeadline(t time.Time) error {
	fmt.Printf("[%s] SetDeadline(datagram) -> %s\n", l.name, t)
	return l.inner.SetDeadline(t)
}

func (l *loggingDatagram) LocalAddr() netip.AddrPort {
	addr := l.inner.LocalAddr()
	fmt.Printf("[%s] LocalAddr(datagram) -> %s\n", l.name, addr)
	return addr
}

func (l *loggingDatagram) RemoteAddr() netip.AddrPort {
	addr := l.inner.RemoteAddr()
	fmt.Printf("[%s] RemoteAddr(datagram) -> %s\n", l.name, addr)
	return addr
}
