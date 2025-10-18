package transport

import (
	cond "bytemomo/trident/conduit"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestTCP_Dial_Close_Idempotent_AndBasics(t *testing.T) {
	t.Parallel()

	s := startTCPEcho(t)
	defer s.stop()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	c := TCP(s.addr(), WithKeepAlive(30*time.Second)).(*TcpConduit)

	// Dial twice should be fine
	if err := c.Dial(ctx); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := c.Dial(ctx); err != nil {
		t.Fatalf("Dial (idempotent): %v", err)
	}

	if got := c.Kind(); got != cond.KindStream {
		t.Fatalf("Kind=%v, want KindStream", got)
	}
	if stack := c.Stack(); len(stack) != 1 || stack[0] != "tcp" {
		t.Fatalf("Stack=%v, want [tcp]", stack)
	}

	stream := c.AsView().View
	if stream.LocalAddr() == nil || stream.RemoteAddr() == nil {
		t.Fatalf("expected addrs after Dial, got local=%v remote=%v", stream.LocalAddr(), stream.RemoteAddr())
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestTCPClientEcho_Simple(t *testing.T) {
	t.Parallel()

	s := startTCPEcho(t)
	defer s.stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conduit := TCP(s.addr(), WithKeepAlive(30*time.Second))
	if err := conduit.Dial(ctx); err != nil {
		t.Fatalf("client Dial: %v", err)
	}
	defer conduit.Close()

	stream := conduit.AsView().View
	msg := []byte("hello over TCP")
	if _, wmd, err := stream.Write(ctx, msg); err != nil {
		t.Fatalf("Write: %v", err)
	} else {
		assertTCPMeta(t, wmd)
	}

	buf := make([]byte, 1024)
	if n, rmd, err := stream.Read(ctx, buf); err != nil {
		t.Fatalf("Read: %v", err)
	} else {
		if got := string(buf[:n]); got != string(msg) {
			t.Fatalf("echo mismatch: got %q want %q", got, msg)
		}
		assertTCPMeta(t, rmd)
	}
}

func TestTCPPersistentLoop(t *testing.T) {
	t.Parallel()

	s := startTCPEcho(t)
	defer s.stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conduit := TCP(s.addr(),
		WithKeepAlive(30*time.Second),
		WithLingerUntilPeer(true),
	)
	if err := conduit.Dial(ctx); err != nil {
		t.Fatalf("client Dial: %v", err)
	}
	stream := conduit.AsView().View

	const iters = 200
	buf := make([]byte, 64<<10)
	for i := 0; i < iters; i++ {
		msg := []byte("hello-" + strconv.Itoa(i))
		if _, _, err := stream.Write(ctx, msg); err != nil {
			t.Fatalf("iter %d: Write: %v", i, err)
		}
		n, _, err := stream.Read(ctx, buf)
		if err != nil {
			t.Fatalf("iter %d: Read: %v", i, err)
		}
		if got := string(buf[:n]); got != string(msg) {
			t.Fatalf("iter %d: echo mismatch: got %q want %q", i, got, msg)
		}
		time.Sleep(2 * time.Millisecond)
	}

	if err := conduit.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}

	readCtx, cancelRead := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelRead()

	drain := make([]byte, 1024)
	_, _, err := stream.Read(readCtx, drain)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF after CloseWrite/Close(), got: %v", err)
	}
}

func TestTCP_Read_ContextCancel(t *testing.T) {
	t.Parallel()

	s := startTCPEcho(t)
	defer s.stop()

	c := TCP(s.addr())
	if err := c.Dial(context.Background()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	stream := c.AsView().View

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	buf := make([]byte, 256)
	_, md, err := stream.Read(ctx, buf)
	if err == nil {
		t.Fatalf("expected read error due to context timeout")
	}
	assertTCPMeta(t, md)
}

func TestTCP_SetDeadline_LingerVsImmediate(t *testing.T) {
	t.Parallel()

	s := startTCPEcho(t)
	defer s.stop()

	linger := TCP(s.addr(), WithLingerUntilPeer(true))
	if err := linger.Dial(context.Background()); err != nil {
		t.Fatal(err)
	}

	lstream := linger.AsView().View
	if err := lstream.SetDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	_ = linger.Close()
	if err := lstream.SetDeadline(time.Now()); err != nil {
		t.Fatalf("linger: SetDeadline should still succeed after Close(); got %v", err)
	}

	imm := TCP(s.addr(), WithImmediateCloseOnClose(true))
	if err := imm.Dial(context.Background()); err != nil {
		t.Fatal(err)
	}

	istream := imm.AsView().View
	if err := istream.SetDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_ = imm.Close()
	if err := istream.SetDeadline(time.Now()); err == nil {
		t.Fatalf("immediate: expected SetDeadline error after Close()")
	}
}

func TestTCP_ImmediateClose(t *testing.T) {
	t.Parallel()

	s := startTCPEcho(t)
	defer s.stop()

	c := TCP(s.addr(), WithImmediateCloseOnClose(true))
	if err := c.Dial(context.Background()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	stream := c.AsView().View

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	if _, _, err := stream.Write(ctx, []byte("x")); err == nil {
		t.Fatalf("Write should fail after immediate close")
	}
	buf := make([]byte, 8)
	if _, _, err := stream.Read(ctx, buf); err == nil {
		t.Fatalf("Read should fail after immediate close")
	}
}

func TestTCP_NotConnected_Errors(t *testing.T) {
	t.Parallel()

	c := &TcpConduit{addr: "127.0.0.1:65535"}
	stream := c.AsView().View

	if stream.LocalAddr() != nil || stream.RemoteAddr() != nil {
		t.Fatalf("expected nil addrs without Dial, got local=%v remote=%v", stream.LocalAddr(), stream.RemoteAddr())
	}

	buf := make([]byte, 16)
	if _, _, err := stream.Read(context.Background(), buf); err == nil {
		t.Fatalf("Read without Dial should error")
	}

	if _, _, err := stream.Write(context.Background(), []byte("x")); err == nil {
		t.Fatalf("Write without Dial should error")
	}
}

// ---- test helpers ----

type tcpEcho struct {
	ln      net.Listener
	conns   sync.Map
	stopped chan struct{}
}

func startTCPEcho(t *testing.T) *tcpEcho {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	s := &tcpEcho{ln: ln, stopped: make(chan struct{})}

	go func() {
		defer close(s.stopped)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.conns.Store(c, struct{}{})
			go func(conn net.Conn) {
				defer func() {
					_ = conn.Close()
					s.conns.Delete(conn)
				}()
				buf := make([]byte, 64<<10)
				for {
					n, rerr := conn.Read(buf)
					if errors.Is(rerr, io.EOF) {
						return
					}
					if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
						continue
					}
					if rerr != nil {
						return
					}
					_, _ = conn.Write(buf[:n])
				}
			}(c)
		}
	}()
	return s
}

func (s *tcpEcho) addr() string { return s.ln.Addr().String() }

func (s *tcpEcho) stop() {
	_ = s.ln.Close()
	s.conns.Range(func(k, _ any) bool {
		_ = k.(net.Conn).Close()
		return true
	})
	<-s.stopped
}

func assertTCPMeta(t *testing.T, md cond.Metadata) {
	t.Helper()
	if md.Layer != "tcp" {
		t.Fatalf("expected md.Layer=tcp, got %q", md.Layer)
	}
	if md.Local == "" || md.Remote == "" {
		t.Fatalf("expected md.Local and md.Remote to be set: %+v", md)
	}
	if md.Start.IsZero() || md.End.IsZero() || md.End.Before(md.Start) {
		t.Fatalf("expected valid Start/End, got %+v", md)
	}
}
