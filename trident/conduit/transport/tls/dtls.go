package tls

import (
	cond "bytemomo/trident/conduit"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/pion/dtls/v3"
)

// =====================================================================================
// DTLS Client Conduit
// =====================================================================================

type DtlsClient struct {
	addr string
	cfg  *dtls.Config

	mu   sync.Mutex
	conn *dtls.Conn
}

type dtlsDatagram DtlsClient

func NewDtlsClient(addr string, cfg *dtls.Config) cond.Conduit[cond.Datagram] {
	return &DtlsClient{addr: addr, cfg: cfg}
}

func (d *DtlsClient) Dial(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn != nil {
		return nil
	}

	raddr, err := net.ResolveUDPAddr("udp", d.addr)
	if err != nil {
		return err
	}

	// TODO: Change dtls coduit API to take a net.PacketConn so that has an equivalent API
	// to the tls conduit

	c, err := dtls.Dial("udp", raddr, d.cfg)
	if err != nil {
		return err
	}

	d.conn = c
	return nil
}

func (d *DtlsClient) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn != nil {
		_ = d.conn.Close()
		d.conn = nil
	}
	return nil
}

func (d *DtlsClient) Kind() cond.Kind { return cond.KindDatagram }

func (d *DtlsClient) Stack() []string {
	return []string{"dtls", "udp"}
}

func (d *DtlsClient) Underlying() cond.Datagram { return (*dtlsDatagram)(d) }

// =====================================================================================
// dtlsDatagram implements cond.Datagram over *dtls.Conn
// =====================================================================================

func (d *dtlsDatagram) c() (*dtls.Conn, error) {
	if d.conn == nil {
		return nil, errors.New("dtls: not connected")
	}
	return d.conn, nil
}

func armDeadline(ctx context.Context, c net.Conn, isRead bool) (cancel func()) {
	dl, ok := ctx.Deadline()
	if !ok {
		return func() {}
	}

	if isRead {
		_ = c.SetReadDeadline(dl)
		return func() { _ = c.SetReadDeadline(time.Time{}) }
	}
	_ = c.SetWriteDeadline(dl)
	return func() { _ = c.SetWriteDeadline(time.Time{}) }
}

func (d *dtlsDatagram) Recv(ctx context.Context, opts *cond.RecvOptions) (*cond.DatagramMsg, error) {
	c, err := d.c()
	if err != nil {
		return nil, err
	}

	// Buffer sizing
	size := 64 * 1024
	if opts != nil && opts.MaxBytes > 0 {
		size = opts.MaxBytes
	}
	buf := cond.GetBuf(size)
	b := buf.Bytes()

	start := time.Now()
	cancel := armDeadline(ctx, c, true)
	n, rerr := c.Read(b)
	cancel()

	if n > 0 {
		buf.ShrinkTo(n)
	} else {
		buf.Release()
	}

	local := addrToAddrPort(c.LocalAddr())
	remote := addrToAddrPort(c.RemoteAddr())

	md := cond.Metadata{
		Start: start,
		End:   time.Now(),
		Proto: 17, // UDP (DTLS over UDP)
		Ext: map[string]any{
			"layer":  "dtls",
			"local":  local.String(),
			"remote": remote.String(),
		},
	}

	if ctxErr := ctx.Err(); ctxErr != nil && rerr == nil {
		rerr = ctxErr
	}

	if n <= 0 {
		return &cond.DatagramMsg{Data: nil, Src: remote, Dst: local, MD: md}, rerr
	}
	return &cond.DatagramMsg{Data: buf, Src: remote, Dst: local, MD: md}, rerr
}

func (d *dtlsDatagram) RecvBatch(ctx context.Context, msgs []*cond.DatagramMsg, opts *cond.RecvOptions) (int, error) {
	count := 0
	var err error
	for i := range msgs {
		msgs[i], err = d.Recv(ctx, opts)
		if err != nil {
			if count > 0 {
				return count, nil
			}
			return 0, err
		}
		count++
	}
	return count, nil
}

func (d *dtlsDatagram) Send(ctx context.Context, msg *cond.DatagramMsg, _ *cond.SendOptions) (int, cond.Metadata, error) {
	c, err := d.c()
	if err != nil {
		return 0, cond.Metadata{}, err
	}
	var payload []byte
	if msg != nil && msg.Data != nil {
		payload = msg.Data.Bytes()
	}

	start := time.Now()
	cancel := armDeadline(ctx, c, false)
	n, werr := c.Write(payload)
	cancel()

	local := addrToAddrPort(c.LocalAddr())
	remote := addrToAddrPort(c.RemoteAddr())

	md := cond.Metadata{
		Start: start,
		End:   time.Now(),
		Proto: 17, // UDP
		Ext: map[string]any{
			"layer":  "dtls",
			"local":  local.String(),
			"remote": remote.String(),
		},
	}
	return n, md, werr
}

func (d *dtlsDatagram) SendBatch(ctx context.Context, msgs []*cond.DatagramMsg, opts *cond.SendOptions) (int, error) {
	sent := 0
	for _, m := range msgs {
		_, _, err := d.Send(ctx, m, opts)
		if err != nil {
			if sent > 0 {
				return sent, nil
			}
			return 0, err
		}
		sent++
	}
	return sent, nil
}

func (d *dtlsDatagram) SetDeadline(t time.Time) error {
	c, err := d.c()
	if err != nil {
		return err
	}
	return c.SetDeadline(t)
}

func (d *dtlsDatagram) LocalAddr() netip.AddrPort {
	c, _ := d.c()
	if c == nil {
		return netip.AddrPort{}
	}
	return addrToAddrPort(c.LocalAddr())
}

func (d *dtlsDatagram) RemoteAddr() netip.AddrPort {
	c, _ := d.c()
	if c == nil {
		return netip.AddrPort{}
	}
	return addrToAddrPort(c.RemoteAddr())
}

// =====================================================================================
// Helpers
// =====================================================================================

func addrToAddrPort(a net.Addr) netip.AddrPort {
	ua, _ := a.(*net.UDPAddr)
	if ua == nil {
		return netip.AddrPort{}
	}
	ip, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return netip.AddrPort{}
	}
	if ua.Zone != "" && ip.Is6() {
		ip = ip.WithZone(ua.Zone)
	}
	return netip.AddrPortFrom(ip, uint16(ua.Port))
}

func addrPortToUDPAddr(p netip.AddrPort) *net.UDPAddr {
	if !p.IsValid() {
		return nil
	}
	return &net.UDPAddr{
		IP:   p.Addr().AsSlice(),
		Port: int(p.Port()),
		Zone: p.Addr().Zone(),
	}
}
