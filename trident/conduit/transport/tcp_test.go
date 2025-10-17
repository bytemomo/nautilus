package transport

import (
	"context"
	"errors"
	"io"
	"strconv"
	"testing"
	"time"
)

func TestTCPClientEcho(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	base := TCP("127.0.0.1:8080", WithKeepAlive(30*time.Second))

	conduit := base
	if err := conduit.Dial(ctx); err != nil {
		t.Fatalf("client Dial: %v", err)
	}
	defer conduit.Close()

	stream := conduit.AsView().View
	msg := []byte("hello over TCP")
	if _, _, err := stream.Write(ctx, msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	buf := make([]byte, 1024)
	if n, md, err := stream.Read(ctx, buf); err != nil {
		t.Fatalf("Read: %v", err)
	} else {
		if got := string(buf[:n]); got != string(msg) {
			t.Fatalf("echo mismatch: got %q want %q", got, msg)
		}

		if md.Layer == "" || md.Layer != "tcp" {
			t.Fatalf("expected Metadata.Layer=tls, got %q", md.Layer)
		}
	}

}

// TestTCPPersistentLoop spins up a plain TCP echo server and verifies that our
// TCP conduit survives many request/response iterations (simulating a long-
// lived connection). It also verifies the "linger until peer disconnects"
// behavior: Close() performs a half-close (CloseWrite), and we continue to
// read until the server echoes remaining data and then sends EOF.
func TestTCPPersistentLoop(t *testing.T) {
	t.Parallel()

	// Build client: TCP with keepalive and "linger until peer disconnects".
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conduit := TCP("127.0.0.1:8080",
		WithKeepAlive(30*time.Second),
		WithLingerUntilPeer(true),
	)
	if err := conduit.Dial(ctx); err != nil {
		t.Fatalf("client Dial: %v", err)
	}
	defer conduit.Close()

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

		// Small pacing to emulate a long-lived session without hammering.
		time.Sleep(3 * time.Millisecond)
	}

	// Now request graceful close semantics: Close() should do CloseWrite() and
	// *not* tear down immediately. We should still be able to Read() until EOF,
	// after the server finishes echoing (if anything pending) and then closes.
	if err := conduit.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}

	// After CloseWrite, we expect the server to see EOF (read FIN), close the
	// socket, and then our Read() should eventually return io.EOF.
	readCtx, cancelRead := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelRead()

	// Drain until EOF (nothing more should be sent by us, so server won't echo).
	// Some stacks may immediately return EOF; others might need a tiny wait.
	drain := make([]byte, 1024)
	_, _, err := stream.Read(readCtx, drain)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF after CloseWrite/Close(), got: %v", err)
	}
}
