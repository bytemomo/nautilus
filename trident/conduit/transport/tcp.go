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

// =====================================================================================
// TCP Conduit
// =====================================================================================

type TcpConduit struct {
	addr string

	mu sync.Mutex
	c  net.Conn

	lingerUntilPeer bool
	keepAlive       time.Duration
	immediateClose  bool
}

type tcpStream TcpConduit

type TCPOption func(*TcpConduit)

func WithKeepAlive(period time.Duration) TCPOption {
	return func(t *TcpConduit) { t.keepAlive = period }
}

func WithLingerUntilPeer(v bool) TCPOption {
	return func(t *TcpConduit) { t.lingerUntilPeer = v }
}

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
	c := t.c
	t.c = nil

	if t.immediateClose || !t.lingerUntilPeer {
		return c.Close()
	}
	if tc, ok := c.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	return c.Close()
}

func (t *TcpConduit) Kind() cond.Kind         { return cond.KindStream }
func (t *TcpConduit) Stack() []string         { return []string{"tcp"} }
func (t *TcpConduit) Underlying() cond.Stream { return (*tcpStream)(t) }

// =====================================================================================
// tcpStream implements cond.Stream
// =====================================================================================

func (t *tcpStream) conn() (net.Conn, error) {
	if t.c == nil {
		return nil, errors.New("tcp: not connected")
	}
	return t.c, nil
}

func (t *tcpStream) Close() error { return (*TcpConduit)(t).Close() }

func (t *tcpStream) CloseWrite() error {
	c, err := t.conn()
	if err != nil {
		return err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	return nil
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

func (t *tcpStream) Recv(ctx context.Context, opts *cond.RecvOptions) (*cond.StreamChunk, error) {
	c, err := t.conn()
	if err != nil {
		return nil, err
	}

	size := 32 * 1024
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

	md := cond.Metadata{
		Start: start,
		End:   time.Now(),
		Proto: 6, // TCP
		Ext: map[string]any{
			"layer":  "tcp",
			"local":  c.LocalAddr().String(),
			"remote": c.RemoteAddr().String(),
		},
	}

	if errors.Is(rerr, io.EOF) || errors.Is(rerr, net.ErrClosed) {
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.CloseRead()
		}
		(*TcpConduit)(t).mu.Lock()
		_ = c.Close()
		if (*TcpConduit)(t).c == c {
			(*TcpConduit)(t).c = nil
		}
		(*TcpConduit)(t).mu.Unlock()
	}

	if ctxErr := ctx.Err(); ctxErr != nil && rerr == nil {
		rerr = ctxErr
	}

	if n <= 0 {
		return &cond.StreamChunk{Data: nil, MD: md}, rerr
	}
	return &cond.StreamChunk{Data: buf, MD: md}, rerr
}

func (t *tcpStream) Send(ctx context.Context, p []byte, buf cond.Buffer, _ *cond.SendOptions) (int, cond.Metadata, error) {
	c, err := t.conn()
	if err != nil {
		return 0, cond.Metadata{}, err
	}

	var payload []byte
	if buf != nil {
		payload = buf.Bytes()
	} else {
		payload = p
	}

	start := time.Now()
	cancel := armDeadline(ctx, c, false)
	n, werr := c.Write(payload)
	cancel()

	md := cond.Metadata{
		Start: start,
		End:   time.Now(),
		Proto: 6, // TCP
		Ext: map[string]any{
			"layer":  "tcp",
			"local":  c.LocalAddr().String(),
			"remote": c.RemoteAddr().String(),
		},
	}

	if ctxErr := ctx.Err(); ctxErr != nil && werr == nil {
		werr = ctxErr
	}
	return n, md, werr
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
