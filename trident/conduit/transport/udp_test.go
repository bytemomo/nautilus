package transport

import (
	cond "bytemomo/trident/conduit"
	"context"
	"net"
	"testing"
	"time"
)

func TestUDP_Dial_Close_AndBasics(t *testing.T) {
	s := startUDPEcho(t)
	defer s.stop()

	u := UDP(s.addr()).(*UdpConduit)
	ctx := context.Background()

	if err := u.Dial(ctx); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := u.Dial(ctx); err != nil {
		t.Fatalf("Dial (idempotent): %v", err)
	}

	if got := u.Kind(); got != cond.KindDatagram {
		t.Fatalf("Kind = %v, want KindDatagram", got)
	}
	if stack := u.Stack(); len(stack) != 1 || stack[0] != "udp" {
		t.Fatalf("Stack = %v, want [udp]", stack)
	}

	view := u.AsView()
	dg := view.View
	if dg.LocalAddr() == nil {
		t.Fatalf("LocalAddr is nil after Dial")
	}
	if dg.RemoteAddr() == nil {
		t.Fatalf("RemoteAddr is nil after Dial")
	}

	if err := u.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if addr := dg.LocalAddr(); addr != nil {
		t.Fatalf("LocalAddr after Close = %v, want nil", addr)
	}

	if addr := dg.RemoteAddr(); addr != nil {
		t.Fatalf("RemoteAddr after Close = %v, want nil", addr)
	}
}

func TestUDP_WriteTo_ReadFrom_Roundtrip(t *testing.T) {
	s := startUDPEcho(t)
	defer s.stop()

	u := UDP(s.addr()).(*UdpConduit)
	if err := u.Dial(context.Background()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = u.Close() })

	dg := u.AsView().View
	msg := []byte("ping-udp")
	n, wmd, err := dg.WriteTo(context.Background(), msg, nil)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	if n != len(msg) {
		t.Fatalf("WriteTo n=%d, want %d", n, len(msg))
	}

	assertMetaUDP(t, wmd)
	if wmd.Remote == "" {
		t.Fatalf("expected write md.Remote to be set")
	}

	buf := make([]byte, 64)
	n, addr, rmd, err := dg.ReadFrom(context.Background(), buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}

	if addr == nil {
		t.Fatalf("ReadFrom addr is nil")
	}

	if got := string(buf[:n]); got != string(msg) {
		t.Fatalf("ReadFrom got %q, want %q", got, string(msg))
	}

	assertMetaUDP(t, rmd)
	if rmd.Remote == "" {
		t.Fatalf("expected read md.Remote to be set")
	}

	if rmd.Local == "" || dg.LocalAddr() == nil || rmd.Local != dg.LocalAddr().String() {
		t.Fatalf("metadata Local %q != PacketConn Local %v", rmd.Local, dg.LocalAddr())
	}
}

func TestUDP_ReadFrom_ContextCancel(t *testing.T) {
	s := startUDPEcho(t)
	defer s.stop()

	u := UDP(s.addr()).(*UdpConduit)
	if err := u.Dial(context.Background()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = u.Close() })

	dg := u.AsView().View

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	buf := make([]byte, 64)
	_, _, md, err := dg.ReadFrom(ctx, buf)
	if err == nil {
		t.Fatalf("ReadFrom expected error due to context cancel")
	}

	if ctx.Err() == nil {
		t.Fatalf("ctx.Err() should be non-nil (cancel/timeout)")
	}
	assertMetaUDP(t, md)
}

func TestUDP_SetDeadline_PassThrough(t *testing.T) {
	s := startUDPEcho(t)
	defer s.stop()

	u := UDP(s.addr()).(*UdpConduit)
	if err := u.Dial(context.Background()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = u.Close() })

	dg := u.AsView().View
	if err := dg.SetDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetDeadline (ready): %v", err)
	}

	_ = u.Close()
	if err := dg.SetDeadline(time.Now()); err == nil {
		t.Fatalf("SetDeadline after Close expected error")
	}
}

func TestUDP_NotReady_Errors(t *testing.T) {
	u := &UdpConduit{addr: "127.0.0.1:9999"}
	dg := u.AsView().View

	if dg.LocalAddr() != nil {
		t.Fatalf("LocalAddr without Dial should be nil")
	}

	if dg.RemoteAddr() != nil {
		t.Fatalf("RemoteAddr without Dial should be nil")
	}

	buf := make([]byte, 1)
	_, _, _, err := dg.ReadFrom(context.Background(), buf)
	if err == nil {
		t.Fatalf("ReadFrom without Dial expected error")
	}

	_, _, err = dg.WriteTo(context.Background(), []byte("x"), nil)
	if err == nil {
		t.Fatalf("WriteTo without Dial expected error")
	}
}

// ---- test helpers ----

type udpEcho struct {
	pc   net.PacketConn
	done chan struct{}
}

func startUDPEcho(t *testing.T) *udpEcho {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}

	s := &udpEcho{
		pc:   pc,
		done: make(chan struct{}),
	}

	go func() {
		buf := make([]byte, 2048)
		for {
			_ = pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, addr, err := pc.ReadFrom(buf)
			select {
			case <-s.done:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	return s
}

func (s *udpEcho) addr() string { return s.pc.LocalAddr().String() }

func (s *udpEcho) stop() {
	close(s.done)
	_ = s.pc.Close()
}

func assertMetaUDP(t *testing.T, md cond.Metadata) {
	t.Helper()
	if md.Layer != "udp" {
		t.Fatalf("expected md.Layer=udp, got %q", md.Layer)
	}
	if md.Start.IsZero() || md.End.IsZero() {
		t.Fatalf("expected Start/End set, got %+v", md)
	}
	if md.End.Before(md.Start) {
		t.Fatalf("expected End >= Start, got %+v", md)
	}
	if md.Local == "" {
		t.Fatalf("expected Local non-empty")
	}
}
