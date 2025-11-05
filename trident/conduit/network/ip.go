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

	"bytemomo/trident/conduit"
	"bytemomo/trident/conduit/utils"
)

type IpConduit struct {
	mu    sync.Mutex
	v6    bool
	proto int
	laddr netip.Addr
	raddr netip.Addr
	pc    net.PacketConn
	p4    *ipv4.PacketConn
	p6    *ipv6.PacketConn
}

type ipNetwork IpConduit

// IPRaw creates a raw IP network-level conduit.
// proto: IP protocol number (e.g., 1 ICMP, 17 UDP, 253/254 experimental)
// raddr: optional default destination (netip.Addr{}) for none
func IPRaw(proto int, raddr netip.Addr) conduit.Conduit[conduit.Network] {
	return &IpConduit{v6: raddr.Is6(), proto: proto, raddr: raddr}
}

func (i *IpConduit) Dial(ctx context.Context) error {
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

func (i *IpConduit) Close() error {
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

func (i *IpConduit) Kind() conduit.Kind { return conduit.KindNetwork }
func (i *IpConduit) Stack() []string {
	if i.v6 {
		return []string{"ip6"}
	}
	return []string{"ip4"}
}

func (i *IpConduit) Underlying() conduit.Network { return (*ipNetwork)(i) }

func (i *ipNetwork) pkt() (net.PacketConn, error) {
	if i.pc == nil {
		return nil, errors.New("ip: not open")
	}
	return i.pc, nil
}
func (i *ipNetwork) IsIPv6() bool          { return i.v6 }
func (i *ipNetwork) LocalAddr() netip.Addr { return i.laddr }
func (i *ipNetwork) Proto() int            { return i.proto }

func (i *ipNetwork) Recv(ctx context.Context, opts *conduit.RecvOptions) (*conduit.IPPacket, error) {
	pc, err := i.pkt()
	if err != nil {
		return nil, err
	}

	buf := utils.GetBuf(1500)
	b := buf.Bytes()

	start := time.Now()
	var (
		n int
		addr net.Addr
		rerr error
	)
	done := make(chan struct{})
	go func() { n, addr, rerr = pc.ReadFrom(b); close(done) }()
	select {
	case <-ctx.Done():
		_ = pc.SetReadDeadline(time.Now().Add(-time.Second))
		<-done
		if n > 0 {
			buf.ShrinkTo(n)
		} else {
			buf.Release()
		}
		md := conduit.Metadata{Start: start, End: time.Now(), Proto: i.proto}
		nip := utils.ToNetip(addr)
		return &conduit.IPPacket{Data: buf, Src: nip, Dst: i.laddr, Proto: i.proto, V6: i.v6, MD: md}, ctx.Err()
	case <-done:
		if n > 0 {
			buf.ShrinkTo(n)
		} else {
			buf.Release()
		}
		md := conduit.Metadata{Start: start, End: time.Now(), Proto: i.proto}
		nip := utils.ToNetip(addr)
		return &conduit.IPPacket{Data: buf, Src: nip, Dst: i.laddr, Proto: i.proto, V6: i.v6, MD: md}, rerr
	}
}

func (i *ipNetwork) RecvBatch(ctx context.Context, pkts []*conduit.IPPacket, opts *conduit.RecvOptions) (int, error) {
	// Not implemented
	return 0, errors.New("not implemented")
}

func (i *ipNetwork) Send(ctx context.Context, pkt *conduit.IPPacket, opts *conduit.SendOptions) (int, conduit.Metadata, error) {
	pc, err := i.pkt()
	if err != nil {
		return 0, conduit.Metadata{}, err
	}
	dst := pkt.Dst
	if !dst.IsValid() {
		dst = i.raddr
	}
	if !dst.IsValid() {
		return 0, conduit.Metadata{}, errors.New("ip: destination required")
	}
	var raddr net.Addr = &net.IPAddr{IP: dst.AsSlice()}
	start := time.Now()
	var n int
	var werr error
	done := make(chan struct{})
	go func() { n, werr = pc.WriteTo(pkt.Data.Bytes(), raddr); close(done) }()
	select {
	case <-ctx.Done():
		_ = pc.SetWriteDeadline(time.Now().Add(-time.Second))
		<-done
		md := conduit.Metadata{Start: start, End: time.Now(), Proto: i.proto}
		return n, md, ctx.Err()
	case <-done:
		md := conduit.Metadata{Start: start, End: time.Now(), Proto: i.proto}
		return n, md, werr
	}
}

func (i *ipNetwork) SendBatch(ctx context.Context, pkts []*conduit.IPPacket, opts *conduit.SendOptions) (int, error) {
	// Not implemented
	return 0, errors.New("not implemented")
}

func (i *ipNetwork) SetDeadline(t time.Time) error {
	pc, err := i.pkt()
	if err != nil {
		return err
	}
	return pc.SetDeadline(t)
}
