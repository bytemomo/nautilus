package network

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	cond "bytemomo/trident/conduit"
)

type IpCounduit struct {
	mu    sync.Mutex
	v6    bool
	proto int
	laddr netip.Addr
	raddr netip.Addr
	pc    net.PacketConn
	p4    *ipv4.PacketConn
	p6    *ipv6.PacketConn
}

type ipNetwork IpCounduit

// IPRaw creates a raw IP network-level conduit.
// proto: IP protocol number (e.g., 1 ICMP, 17 UDP, 253/254 experimental)
// raddr: optional default destination (netip.Addr{}) for none
func IPRaw(proto int, raddr netip.Addr) cond.Conduit[cond.Network] {
	return &IpCounduit{v6: raddr.Is6(), proto: proto, raddr: raddr}
}

func (i *IpCounduit) Dial(ctx context.Context) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.pc != nil {
		return nil
	}
	var (
		lc  net.ListenConfig
		pc  net.PacketConn
		err error
	)
	if i.v6 {
		pc, err = lc.ListenPacket(ctx, "ip6:", net.IPv6unspecified.String())
		if err != nil {
			return err
		}
		i.pc = pc
		i.p6 = ipv6.NewPacketConn(pc)
		_ = i.p6.SetControlMessage(ipv6.FlagTrafficClass|ipv6.FlagHopLimit|ipv6.FlagDst, true)
	} else {
		pc, err = lc.ListenPacket(ctx, "ip4:", "0.0.0.0")
		if err != nil {
			return err
		}
		i.pc = pc
		i.p4 = ipv4.NewPacketConn(pc)
		_ = i.p4.SetControlMessage(ipv4.FlagTTL|ipv4.FlagDst, true)
	}
	return nil
}

func (i *IpCounduit) Close() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.pc != nil {
		_ = i.pc.Close()
		i.pc = nil
		i.p4 = nil
		i.p6 = nil
	}
	return nil
}

func (i *IpCounduit) Kind() cond.Kind { return cond.KindNetwork }
func (i *IpCounduit) Stack() []string {
	if i.v6 {
		return []string{"ip6"}
	}
	return []string{"ip4"}
}

func (i *IpCounduit) AsView() cond.View[cond.Network] {
	return cond.View[cond.Network]{View: (*ipNetwork)(i)}
}

func (i *ipNetwork) pkt() (net.PacketConn, error) {
	if i.pc == nil {
		return nil, errors.New("ip: not open")
	}
	return i.pc, nil
}
func (i *ipNetwork) IsIPv6() bool          { return i.v6 }
func (i *ipNetwork) LocalAddr() netip.Addr { return i.laddr }
func (i *ipNetwork) Proto() int            { return i.proto }

func (i *ipNetwork) ReadIP(ctx context.Context, p []byte) (int, netip.Addr, cond.Metadata, error) {
	pc, err := i.pkt()
	if err != nil {
		return 0, netip.Addr{}, cond.Metadata{}, err
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
		md := cond.Metadata{Start: start, End: time.Now(), Layer: cond.Tern(i.v6, "ip6", "ip4"), Local: pc.LocalAddr().String(), Remote: cond.AddrString(addr)}
		nip := cond.ToNetip(addr)
		return n, nip, md, ctx.Err()
	case <-done:
		md := cond.Metadata{Start: start, End: time.Now(), Layer: cond.Tern(i.v6, "ip6", "ip4"), Local: pc.LocalAddr().String(), Remote: cond.AddrString(addr)}
		nip := cond.ToNetip(addr)
		return n, nip, md, rerr
	}
}

func (i *ipNetwork) WriteIP(ctx context.Context, p []byte, dst netip.Addr) (int, cond.Metadata, error) {
	pc, err := i.pkt()
	if err != nil {
		return 0, cond.Metadata{}, err
	}
	if !dst.IsValid() {
		dst = i.raddr
	}
	if !dst.IsValid() {
		return 0, cond.Metadata{}, errors.New("ip: destination required")
	}
	var raddr net.Addr = &net.IPAddr{IP: dst.AsSlice()}
	start := time.Now()
	var n int
	var werr error
	done := make(chan struct{})
	go func() { n, werr = pc.WriteTo(p, raddr); close(done) }()
	select {
	case <-ctx.Done():
		_ = pc.SetWriteDeadline(time.Now().Add(-time.Second))
		<-done
		md := cond.Metadata{Start: start, End: time.Now(), Layer: cond.Tern(i.v6, "ip6", "ip4"), Local: pc.LocalAddr().String(), Remote: raddr.String()}
		return n, md, ctx.Err()
	case <-done:
		md := cond.Metadata{Start: start, End: time.Now(), Layer: cond.Tern(i.v6, "ip6", "ip4"), Local: pc.LocalAddr().String(), Remote: raddr.String()}
		return n, md, werr
	}
}

func (i *ipNetwork) SetDeadline(t time.Time) error {
	pc, err := i.pkt()
	if err != nil {
		return err
	}
	return pc.SetDeadline(t)
}
