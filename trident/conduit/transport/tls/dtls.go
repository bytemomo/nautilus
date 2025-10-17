package tls

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	cond "bytemomo/trident/conduit"

	"github.com/pion/dtls"
)

type DtlsClient struct {
	inner cond.Conduit[cond.Datagram]
	cfg   *dtls.Config
	mu    sync.Mutex
	conn  *dtls.Conn
}

type dtlsDatagram DtlsClient

func NewDtlsClient(inner cond.Conduit[cond.Datagram], cfg *dtls.Config) cond.Conduit[cond.Datagram] {
	return &DtlsClient{inner: inner, cfg: cfg}
}

func (d *DtlsClient) Dial(ctx context.Context) error {
	if err := d.inner.Dial(ctx); err != nil {
		return err
	}

	dg := d.inner.AsView()
	pc, ok := packetToPacketConn(dg.View)
	if !ok {
		return errors.New("dtls: inner cannot expose net.PacketConn")
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn != nil {
		return nil
	}
	c, err := dtls.Client(pc, d.cfg)
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
	return d.inner.Close()
}
func (d *DtlsClient) Kind() cond.Kind { return cond.KindDatagram }
func (d *DtlsClient) Stack() []string { return append([]string{"dtls"}, d.inner.Stack()...) }
func (d *DtlsClient) AsView() cond.View[cond.Datagram] {
	return cond.View[cond.Datagram]{View: (*dtlsDatagram)(d)}
}

func (d *dtlsDatagram) c() (*dtls.Conn, error) {
	if d.conn == nil {
		return nil, errors.New("dtls: not connected")
	}
	return d.conn, nil
}

func (d *dtlsDatagram) ReadFrom(ctx context.Context, p []byte) (int, net.Addr, cond.Metadata, error) {
	c, err := d.c()
	if err != nil {
		return 0, nil, cond.Metadata{}, err
	}
	start := time.Now()
	var n int
	var rerr error
	done := make(chan struct{})
	go func() { n, rerr = c.Read(p); close(done) }()
	select {
	case <-ctx.Done():
		_ = c.SetReadDeadline(time.Now().Add(-time.Second))
		<-done
		md := cond.Metadata{Start: start, End: time.Now(), Layer: "dtls", Local: c.LocalAddr().String(), Remote: c.RemoteAddr().String()}
		return n, c.RemoteAddr(), md, ctx.Err()
	case <-done:
		md := cond.Metadata{Start: start, End: time.Now(), Layer: "dtls", Local: c.LocalAddr().String(), Remote: c.RemoteAddr().String()}
		return n, c.RemoteAddr(), md, rerr
	}
}

func (d *dtlsDatagram) WriteTo(ctx context.Context, p []byte, _ net.Addr) (int, cond.Metadata, error) {
	c, err := d.c()
	if err != nil {
		return 0, cond.Metadata{}, err
	}
	start := time.Now()
	var n int
	var werr error
	done := make(chan struct{})
	go func() { n, werr = c.Write(p); close(done) }()
	select {
	case <-ctx.Done():
		_ = c.SetWriteDeadline(time.Now().Add(-time.Second))
		<-done
		md := cond.Metadata{Start: start, End: time.Now(), Layer: "dtls", Local: c.LocalAddr().String(), Remote: c.RemoteAddr().String()}
		return n, md, ctx.Err()
	case <-done:
		md := cond.Metadata{Start: start, End: time.Now(), Layer: "dtls", Local: c.LocalAddr().String(), Remote: c.RemoteAddr().String()}
		return n, md, werr
	}
}

func (d *dtlsDatagram) SetDeadline(t time.Time) error {
	c, err := d.c()
	if err != nil {
		return err
	}
	return c.SetDeadline(t)
}
func (d *dtlsDatagram) LocalAddr() net.Addr {
	c, _ := d.c()
	if c == nil {
		return nil
	}
	return c.LocalAddr()
}
func (d *dtlsDatagram) RemoteAddr() net.Addr {
	c, _ := d.c()
	if c == nil {
		return nil
	}
	return c.RemoteAddr()
}

type packetConnProvider interface{ PacketConn() net.Conn }

func packetToPacketConn(p cond.Datagram) (net.Conn, bool) {
	if pp, ok := p.(packetConnProvider); ok {
		return pp.PacketConn(), true
	}
	return nil, false
}
