package tls

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"bytemomo/trident/conduit"
	"bytemomo/trident/conduit/utils"

	"github.com/pion/dtls/v3"
)

// =====================================================================================
// DTLS Client Conduit
// =====================================================================================

// DtlsClient is a conduit that wraps another datagram conduit (like UDP)
// to provide a DTLS-encrypted channel. It acts as a client-side DTLS decorator.
type DtlsClient struct {
	inner conduit.Conduit[conduit.Datagram]
	cfg   *dtls.Config

	mu   sync.Mutex
	conn *dtls.Conn
}

type dtlsDatagram DtlsClient

// NewDtlsClient creates a new DTLS client conduit.
// It takes an inner conduit (e.g., a UDP conduit) and a DTLS configuration.
func NewDtlsClient(inner conduit.Conduit[conduit.Datagram], cfg *dtls.Config) conduit.Conduit[conduit.Datagram] {
	return &DtlsClient{inner: inner, cfg: cfg}
}

// Dial first dials the inner conduit, and then performs a DTLS handshake over it.
func (d *DtlsClient) Dial(ctx context.Context) (err error) {
	err = d.inner.Dial(ctx)
	if err == nil {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.conn == nil {
			packetConn := &datagramToPacketConn{D: d.inner.Underlying()}
			var dtlsConn *dtls.Conn
			dtlsConn, err = dtls.Client(packetConn, addrPortToUDPAddr(d.inner.Underlying().RemoteAddr()), d.cfg)
			if err == nil {
				d.conn = dtlsConn
			}
		}
	}
	return
}

// Close closes both the DTLS connection and the inner conduit.
func (d *DtlsClient) Close() (err error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.conn != nil {
		err = d.conn.Close()
		d.conn = nil
	}

	if err == nil {
		err = d.inner.Close()
	}

	return
}

// Kind returns the conduit's kind, which is KindDatagram.
func (d *DtlsClient) Kind() conduit.Kind { return conduit.KindDatagram }

// Stack returns the protocol stack, prepending "dtls" to the inner stack.
func (d *DtlsClient) Stack() []string {
	return append([]string{"dtls"}, d.inner.Stack()...)
}

// Underlying returns the Datagram interface for I/O operations.
func (d *DtlsClient) Underlying() conduit.Datagram { return (*dtlsDatagram)(d) }

// =====================================================================================
// dtlsDatagram implements conduit.Datagram over *dtls.Conn
// =====================================================================================

func (d *dtlsDatagram) c() (*dtls.Conn, error) {
	if d.conn == nil {
		return nil, errors.New("dtls: not connected")
	}
	return d.conn, nil
}

func (d *dtlsDatagram) Recv(ctx context.Context, opts *conduit.RecvOptions) (*conduit.DatagramMsg, error) {
	c, err := d.c()
	if err != nil {
		return nil, err
	}

	size := 64 * 1024
	if opts != nil && opts.MaxBytes > 0 {
		size = opts.MaxBytes
	}
	buf := utils.GetBuf(size)
	b := buf.Bytes()

	start := time.Now()
	cancel := armDeadlinee(ctx, c, true)
	n, rerr := c.Read(b)
	cancel()

	if n > 0 {
		buf.ShrinkTo(n)
	} else {
		buf.Release()
	}

	local := addrToAddrPort(c.LocalAddr())
	remote := addrToAddrPort(c.RemoteAddr())

	md := conduit.Metadata{
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
		return &conduit.DatagramMsg{Data: nil, Src: remote, Dst: local, MD: md}, rerr
	}
	return &conduit.DatagramMsg{Data: buf, Src: remote, Dst: local, MD: md}, rerr
}

func (d *dtlsDatagram) RecvBatch(ctx context.Context, msgs []*conduit.DatagramMsg, opts *conduit.RecvOptions) (int, error) {
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

func (d *dtlsDatagram) Send(ctx context.Context, msg *conduit.DatagramMsg, _ *conduit.SendOptions) (int, conduit.Metadata, error) {
	c, err := d.c()
	if err != nil {
		return 0, conduit.Metadata{}, err
	}
	var payload []byte
	if msg != nil && msg.Data != nil {
		payload = msg.Data.Bytes()
	}

	start := time.Now()
	cancel := armDeadlinee(ctx, c, false)
	n, werr := c.Write(payload)
	cancel()

	local := addrToAddrPort(c.LocalAddr())
	remote := addrToAddrPort(c.RemoteAddr())

	md := conduit.Metadata{
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

func (d *dtlsDatagram) SendBatch(ctx context.Context, msgs []*conduit.DatagramMsg, opts *conduit.SendOptions) (int, error) {
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
// net.PacketConn adapter around conduit.Datagram — used only for dtls.Client handshake
// =====================================================================================

type datagramToPacketConn struct {
	D conduit.Datagram

	mu           sync.Mutex
	rdl, wdl     time.Time
	bothDeadline time.Time
}

func (d *datagramToPacketConn) deadline(isRead bool) (time.Time, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	dl := d.bothDeadline
	if isRead {
		if !d.rdl.IsZero() {
			dl = d.rdl
		}
	} else {
		if !d.wdl.IsZero() {
			dl = d.wdl
		}
	}
	if dl.IsZero() {
		return time.Time{}, false
	}
	return dl, true
}

func (d *datagramToPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	ctx := context.Background()
	if dl, ok := d.deadline(true); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, dl)
		defer cancel()
	}
	msg, err := d.D.Recv(ctx, &conduit.RecvOptions{MaxBytes: len(p)})
	if err != nil && (msg == nil || msg.Data == nil) {
		return 0, nil, err
	}
	n := 0
	if msg != nil && msg.Data != nil {
		b := msg.Data.Bytes()
		if len(b) > len(p) {
			b = b[:len(p)]
		}
		n = copy(p, b)
		msg.Data.Release()
	}
	return n, addrPortToUDPAddr(msg.Src), err
}

func (d *datagramToPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	ctx := context.Background()
	if dl, ok := d.deadline(false); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, dl)
		defer cancel()
	}

	udpAddr, _ := addr.(*net.UDPAddr)
	dst := addrToAddrPort(udpAddr)
	msg := &conduit.DatagramMsg{
		Data: utils.GetBuf(len(p)),
		Dst:  dst,
	}

	n, _, err := d.D.Send(ctx, msg, nil)
	return n, err
}

func (d *datagramToPacketConn) Close() error                 { return nil }
func (d *datagramToPacketConn) LocalAddr() net.Addr          { return addrPortToUDPAddr(d.D.LocalAddr()) }
func (d *datagramToPacketConn) SetDeadline(t time.Time) error { return d.D.SetDeadline(t) }
func (d *datagramToPacketConn) SetReadDeadline(t time.Time) error {
	d.mu.Lock()
	d.rdl = t
	d.mu.Unlock()
	return d.D.SetDeadline(t)
}
func (d *datagramToPacketConn) SetWriteDeadline(t time.Time) error {
	d.mu.Lock()
	d.wdl = t
	d.mu.Unlock()
	return d.D.SetDeadline(t)
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
