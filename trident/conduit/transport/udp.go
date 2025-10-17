package transport

import (
	cond "bytemomo/trident/conduit"
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

type UdpConduit struct {
	addr string
	mu   sync.Mutex
	pc   net.PacketConn
	peer net.Addr
}

type udpDatagram UdpConduit

func UDP(addr string) cond.Conduit[cond.Datagram] { return &UdpConduit{addr: addr} }

func (u *UdpConduit) Dial(ctx context.Context) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.pc != nil {
		return nil
	}
	raddr, err := net.ResolveUDPAddr("udp", u.addr)
	if err != nil {
		return err
	}
	c, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return err
	}
	u.pc = c
	u.peer = raddr
	return nil
}

func (u *UdpConduit) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.pc != nil {
		_ = u.pc.Close()
		u.pc = nil
		u.peer = nil
	}
	return nil
}
func (u *UdpConduit) Kind() cond.Kind { return cond.KindDatagram }
func (u *UdpConduit) Stack() []string { return []string{"udp"} }

func (u *UdpConduit) AsView() cond.View[cond.Datagram] {
	return cond.View[cond.Datagram]{View: (*udpDatagram)(u)}
}

func (u *udpDatagram) pkt() (net.PacketConn, error) {
	if u.pc == nil {
		return nil, errors.New("udp: not ready")
	}
	return u.pc, nil
}

func (u *udpDatagram) ReadFrom(ctx context.Context, p []byte) (int, net.Addr, cond.Metadata, error) {
	pc, err := u.pkt()
	if err != nil {
		return 0, nil, cond.Metadata{}, err
	}
	start := time.Now()
	var n int
	var addr net.Addr
	var rerr error
	done := make(chan struct{})
	go func() { n, addr, rerr = pc.ReadFrom(p); close(done) }()
	select {
	case <-ctx.Done():
		_ = pc.SetReadDeadline(time.Now().Add(-time.Second))
		<-done
		md := cond.Metadata{Start: start, End: time.Now(), Layer: "udp", Local: pc.LocalAddr().String(), Remote: cond.AddrString(addr)}
		return n, addr, md, ctx.Err()
	case <-done:
		md := cond.Metadata{Start: start, End: time.Now(), Layer: "udp", Local: pc.LocalAddr().String(), Remote: cond.AddrString(addr)}
		return n, addr, md, rerr
	}
}

func (u *udpDatagram) WriteTo(ctx context.Context, p []byte, addr net.Addr) (int, cond.Metadata, error) {
	pc, err := u.pkt()
	if err != nil {
		return 0, cond.Metadata{}, err
	}
	if addr == nil {
		addr = u.peer
	}
	start := time.Now()
	var n int
	var werr error
	done := make(chan struct{})
	go func() { n, werr = pc.WriteTo(p, addr); close(done) }()
	select {
	case <-ctx.Done():
		_ = pc.SetWriteDeadline(time.Now().Add(-time.Second))
		<-done
		md := cond.Metadata{Start: start, End: time.Now(), Layer: "udp", Local: pc.LocalAddr().String(), Remote: cond.AddrString(addr)}
		return n, md, ctx.Err()
	case <-done:
		md := cond.Metadata{Start: start, End: time.Now(), Layer: "udp", Local: pc.LocalAddr().String(), Remote: cond.AddrString(addr)}
		return n, md, werr
	}
}

func (u *udpDatagram) SetDeadline(t time.Time) error {
	pc, err := u.pkt()
	if err != nil {
		return err
	}
	return pc.SetDeadline(t)
}
func (u *udpDatagram) LocalAddr() net.Addr {
	pc, _ := u.pkt()
	if pc == nil {
		return nil
	}
	return pc.LocalAddr()
}
func (u *udpDatagram) RemoteAddr() net.Addr       { return u.peer }
func (u *udpDatagram) PacketConn() net.PacketConn { return u.pc }
