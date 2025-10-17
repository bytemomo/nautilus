package tls

import (
	cond "bytemomo/trident/conduit"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"
)

type TlsClient struct {
	inner cond.Conduit[cond.Stream]
	cfg   *tls.Config
	mu    sync.Mutex
	conn  *tls.Conn
}

type tlsStream TlsClient

func NewTlsClient(inner cond.Conduit[cond.Stream], cfg *tls.Config) cond.Conduit[cond.Stream] {
	return &TlsClient{inner: inner, cfg: cfg}
}

func (t *TlsClient) Dial(ctx context.Context) error {
	if err := t.inner.Dial(ctx); err != nil {
		return err
	}

	st := t.inner.AsView()
	baseConn := streamToConn{st.View}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn != nil {
		return nil
	}
	c := tls.Client(baseConn, t.cfg)
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if err := c.HandshakeContext(ctx); err != nil {
		_ = c.Close()
		return err
	}
	t.conn = c
	return nil
}

func (t *TlsClient) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn != nil {
		_ = t.conn.Close()
		t.conn = nil
	}
	return t.inner.Close()
}
func (t *TlsClient) Kind() cond.Kind { return cond.KindStream }
func (t *TlsClient) Stack() []string { return append([]string{"tls"}, t.inner.Stack()...) }
func (t *TlsClient) AsView() cond.View[cond.Stream] {
	return cond.View[cond.Stream]{View: (*tlsStream)(t)}
}

func (t *tlsStream) c() (*tls.Conn, error) {
	if t.conn == nil {
		return nil, errors.New("tls: not connected")
	}
	return t.conn, nil
}

func (t *tlsStream) Read(ctx context.Context, p []byte) (int, cond.Metadata, error) {
	c, err := t.c()
	if err != nil {
		return 0, cond.Metadata{}, err
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
		return n, cond.Metadata{Start: start, End: time.Now(), Layer: "tls", Local: c.LocalAddr().String(), Remote: c.RemoteAddr().String()}, ctx.Err()
	case <-done:
		return n, cond.Metadata{Start: start, End: time.Now(), Layer: "tls", Local: c.LocalAddr().String(), Remote: c.RemoteAddr().String()}, rerr
	}
}

func (t *tlsStream) Write(ctx context.Context, p []byte) (int, cond.Metadata, error) {
	c, err := t.c()
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
		return n, cond.Metadata{Start: start, End: time.Now(), Layer: "tls", Local: c.LocalAddr().String(), Remote: c.RemoteAddr().String()}, ctx.Err()
	case <-done:
		return n, cond.Metadata{Start: start, End: time.Now(), Layer: "tls", Local: c.LocalAddr().String(), Remote: c.RemoteAddr().String()}, werr
	}
}

func (t *tlsStream) SetDeadline(tt time.Time) error {
	c, err := t.c()
	if err != nil {
		return err
	}
	return c.SetDeadline(tt)
}
func (t *tlsStream) LocalAddr() net.Addr {
	c, _ := t.c()
	if c == nil {
		return nil
	}
	return c.LocalAddr()
}
func (t *tlsStream) RemoteAddr() net.Addr {
	c, _ := t.c()
	if c == nil {
		return nil
	}
	return c.RemoteAddr()
}

type streamToConn struct{ s cond.Stream }

func (w streamToConn) Read(p []byte) (int, error) {
	n, _, err := w.s.Read(context.Background(), p)
	return n, err
}
func (w streamToConn) Write(p []byte) (int, error) {
	n, _, err := w.s.Write(context.Background(), p)
	return n, err
}
func (w streamToConn) Close() error                       { return nil }
func (w streamToConn) LocalAddr() net.Addr                { return w.s.LocalAddr() }
func (w streamToConn) RemoteAddr() net.Addr               { return w.s.RemoteAddr() }
func (w streamToConn) SetDeadline(t time.Time) error      { return w.s.SetDeadline(t) }
func (w streamToConn) SetReadDeadline(t time.Time) error  { return w.s.SetDeadline(t) }
func (w streamToConn) SetWriteDeadline(t time.Time) error { return w.s.SetDeadline(t) }
