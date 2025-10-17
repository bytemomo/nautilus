package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	cond "bytemomo/trident/conduit"
)

// type TcpConduit struct {
// 	addr string
// 	mu   sync.Mutex
// 	c    net.Conn
// }

// type tcpStream TcpConduit

// func TCP(addr string) cond.Conduit[cond.Stream] {
// 	return &TcpConduit{addr: addr}
// }

// func (t *TcpConduit) Dial(ctx context.Context) error {
// 	t.mu.Lock()
// 	defer t.mu.Unlock()
// 	if t.c != nil {
// 		return nil
// 	}
// 	var d net.Dialer
// 	c, err := d.DialContext(ctx, "tcp", t.addr)
// 	if err != nil {
// 		return err
// 	}
// 	t.c = c
// 	return nil
// }

// func (t *TcpConduit) Close() error {
// 	t.mu.Lock()
// 	defer t.mu.Unlock()
// 	if t.c != nil {
// 		_ = t.c.Close()
// 		t.c = nil
// 	}
// 	return nil
// }
// func (t *TcpConduit) Kind() cond.Kind { return cond.KindStream }
// func (t *TcpConduit) Stack() []string { return []string{"tcp"} }
// func (t *TcpConduit) AsView() cond.View[cond.Stream] {
// 	return cond.View[cond.Stream]{View: (*tcpStream)(t)}
// }

// func (t *tcpStream) conn() (net.Conn, error) {
// 	if t.c == nil {
// 		return nil, errors.New("tcp: not connected")
// 	}
// 	return t.c, nil
// }

// func (t *tcpStream) Read(ctx context.Context, p []byte) (int, cond.Metadata, error) {
// 	c, err := t.conn()
// 	if err != nil {
// 		return 0, cond.Metadata{}, err
// 	}
// 	start := time.Now()
// 	var n int
// 	var rerr error
// 	done := make(chan struct{})
// 	go func() { n, rerr = c.Read(p); close(done) }()
// 	select {
// 	case <-ctx.Done():
// 		_ = c.SetReadDeadline(time.Now().Add(-time.Second))
// 		<-done
// 		return n, cond.Metadata{Start: start, End: time.Now(), Layer: "tcp", Local: c.LocalAddr().String(), Remote: c.RemoteAddr().String()}, ctx.Err()
// 	case <-done:
// 		return n, cond.Metadata{Start: start, End: time.Now(), Layer: "tcp", Local: c.LocalAddr().String(), Remote: c.RemoteAddr().String()}, rerr
// 	}
// }

// func (t *tcpStream) Write(ctx context.Context, p []byte) (int, cond.Metadata, error) {
// 	c, err := t.conn()
// 	if err != nil {
// 		return 0, cond.Metadata{}, err
// 	}
// 	start := time.Now()
// 	var n int
// 	var werr error
// 	done := make(chan struct{})
// 	go func() { n, werr = c.Write(p); close(done) }()
// 	select {
// 	case <-ctx.Done():
// 		_ = c.SetWriteDeadline(time.Now().Add(-time.Second))
// 		<-done
// 		return n, cond.Metadata{Start: start, End: time.Now(), Layer: "tcp", Local: c.LocalAddr().String(), Remote: c.RemoteAddr().String()}, ctx.Err()
// 	case <-done:
// 		return n, cond.Metadata{Start: start, End: time.Now(), Layer: "tcp", Local: c.LocalAddr().String(), Remote: c.RemoteAddr().String()}, werr
// 	}
// }

// func (t *tcpStream) SetDeadline(tt time.Time) error {
// 	c, err := t.conn()
// 	if err != nil {
// 		return err
// 	}
// 	return c.SetDeadline(tt)
// }
// func (t *tcpStream) LocalAddr() net.Addr {
// 	c, _ := t.conn()
// 	if c == nil {
// 		return nil
// 	}
// 	return c.LocalAddr()
// }
// func (t *tcpStream) RemoteAddr() net.Addr {
// 	c, _ := t.conn()
// 	if c == nil {
// 		return nil
// 	}
// 	return c.RemoteAddr()
// }

// ================================ TCP (Stream) ====================================
// Behavior: the TCP conduit will NOT close the underlying connection until the
// peer has disconnected (EOF). Calling Close() will by default perform a
// half-close (CloseWrite) and leave the socket open until a subsequent Read()
// observes io.EOF, at which point the socket is fully closed internally.
// You can force immediate teardown via WithImmediateCloseOnClose(true).

type TcpConduit struct {
	addr string

	mu sync.Mutex
	c  net.Conn

	lingerUntilPeer bool // if true (default), Close() does CloseWrite and waits for peer EOF to fully close
	keepAlive       time.Duration
	immediateClose  bool // if true, Close() closes immediately (overrides lingerUntilPeer)
}

type tcpStream TcpConduit

type TCPOption func(*TcpConduit)

// WithKeepAlive enables TCP keepalive with the provided period (0 disables).
func WithKeepAlive(period time.Duration) TCPOption {
	return func(t *TcpConduit) { t.keepAlive = period }
}

// WithLingerUntilPeer controls whether Close() should keep the connection
func WithLingerUntilPeer(v bool) TCPOption {
	return func(t *TcpConduit) { t.lingerUntilPeer = v }
}

// This overrides WithLingerUntilPeer.
func WithImmediateCloseOnClose(v bool) TCPOption {
	return func(t *TcpConduit) { t.immediateClose = v }
}

func TCP(addr string, opts ...TCPOption) cond.Conduit[cond.Stream] {
	t := &TcpConduit{
		addr:            addr,
		lingerUntilPeer: true,
	}
	for _, opt := range opts {
		opt(t)
	}
	return t
}

func (t *TcpConduit) Dial(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.c != nil {
		return nil
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", t.addr)
	if err != nil {
		return err
	}
	// Apply keepalive if requested.
	if tc, ok := c.(*net.TCPConn); ok && t.keepAlive > 0 {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(t.keepAlive)
	}
	t.c = c
	return nil
}

func (t *TcpConduit) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.c == nil {
		return nil
	}

	if t.immediateClose || !t.lingerUntilPeer {
		err := t.c.Close()
		t.c = nil
		return err
	}
	if tc, ok := t.c.(*net.TCPConn); ok {
		_ = tc.CloseWrite() // best-effort; peer will eventually send FIN/EOF
		// We intentionally DO NOT Close() here; full teardown happens when Read() hits EOF.
		return nil
	}
	return nil
}

func (t *TcpConduit) Kind() cond.Kind { return cond.KindStream }
func (t *TcpConduit) Stack() []string { return []string{"tcp"} }
func (t *TcpConduit) AsView() cond.View[cond.Stream] {
	return cond.View[cond.Stream]{View: (*tcpStream)(t)}
}

// tcpStream is the Stream view of TcpConduit.

func (t *tcpStream) conn() (net.Conn, error) {
	if t.c == nil {
		return nil, errors.New("tcp: not connected")
	}
	return t.c, nil
}

func (t *tcpStream) Read(ctx context.Context, p []byte) (int, cond.Metadata, error) {
	c, err := t.conn()
	if err != nil {
		return 0, cond.Metadata{}, err
	}
	start := time.Now()
	var (
		n    int
		rerr error
	)
	done := make(chan struct{})
	go func() { n, rerr = c.Read(p); close(done) }()
	select {
	case <-ctx.Done():
		_ = c.SetReadDeadline(time.Now().Add(-time.Second))
		<-done
		return n, cond.Metadata{
			Start: start, End: time.Now(), Layer: "tcp",
			Local: c.LocalAddr().String(), Remote: c.RemoteAddr().String(),
		}, ctx.Err()
	case <-done:
		md := cond.Metadata{
			Start: start, End: time.Now(), Layer: "tcp",
			Local: c.LocalAddr().String(), Remote: c.RemoteAddr().String(),
		}
		// If peer disconnected (EOF), fully close and clear the socket now.
		if errors.Is(rerr, io.EOF) {
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.CloseRead() // best-effort; ensures read side drained
			}
			t.mu.Lock()
			_ = c.Close() // full close now that we've seen EOF
			t.c = nil
			t.mu.Unlock()
		}
		return n, md, rerr
	}
}

func (t *tcpStream) Write(ctx context.Context, p []byte) (int, cond.Metadata, error) {
	c, err := t.conn()
	if err != nil {
		return 0, cond.Metadata{}, err
	}
	start := time.Now()
	var (
		n    int
		werr error
	)
	done := make(chan struct{})
	go func() { n, werr = c.Write(p); close(done) }()
	select {
	case <-ctx.Done():
		_ = c.SetWriteDeadline(time.Now().Add(-time.Second)) // interrupt the write
		<-done
		return n, cond.Metadata{
			Start: start, End: time.Now(), Layer: "tcp",
			Local: c.LocalAddr().String(), Remote: c.RemoteAddr().String(),
		}, ctx.Err()
	case <-done:
		md := cond.Metadata{
			Start: start, End: time.Now(), Layer: "tcp",
			Local: c.LocalAddr().String(), Remote: c.RemoteAddr().String(),
		}
		// If the peer has already closed and Write fails with EOF/ECONNRESET,
		// leave cleanup to Read path (or explicit ForceClose via option).
		return n, md, werr
	}
}

func (t *tcpStream) SetDeadline(tt time.Time) error {
	c, err := t.conn()
	if err != nil {
		return err
	}
	return c.SetDeadline(tt)
}

func (t *tcpStream) LocalAddr() net.Addr {
	c, _ := t.conn()
	if c == nil {
		return nil
	}
	return c.LocalAddr()
}

func (t *tcpStream) RemoteAddr() net.Addr {
	c, _ := t.conn()
	if c == nil {
		return nil
	}
	return c.RemoteAddr()
}
