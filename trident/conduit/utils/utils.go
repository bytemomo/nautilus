package utils

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Itoa is a fast, allocation-free integer-to-string conversion function.
func Itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		p--
		b[p] = '-'
	}
	return string(b[p:])
}

// AddrString safely converts a net.Addr to its string representation.
func AddrString(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

// DeadlineFromContext extracts the deadline from a context, returning a zero time if not set.
func DeadlineFromContext(ctx context.Context) time.Time {
	if dl, ok := ctx.Deadline(); ok {
		return dl
	}
	return time.Time{}
}

// Tern is a generic ternary operator.
func Tern[T any](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}

// ToNetip converts a net.Addr to a netip.Addr, returning a zero value if conversion fails.
func ToNetip(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.IPAddr:
		if ip, ok := netip.AddrFromSlice([]byte(v.IP.String())); ok {
			return ip
		}
	case *net.UDPAddr:
		if ip, ok := netip.AddrFromSlice([]byte(v.IP.String())); ok {
			return ip
		}
	case *net.TCPAddr:
		if ip, ok := netip.AddrFromSlice([]byte(v.IP.String())); ok {
			return ip
		}
	}
	return netip.Addr{}
}

// =====================================================================================
// Minimal pooled Buffer implementation
// =====================================================================================

// PooledBuf is a simple, non-thread-safe buffer implementation that uses a sync.Pool
// to reduce allocations. It is intended for use with the conduit interfaces.
type PooledBuf struct {
	B   []byte
	Cap int
}

var bufPool = sync.Pool{
	New: func() any { return &PooledBuf{B: make([]byte, 32*1024), Cap: 32 * 1024} },
}

// GetBuf retrieves a buffer from the pool, ensuring it has at least `min` capacity.
func GetBuf(min int) *PooledBuf {
	p := bufPool.Get().(*PooledBuf)
	if cap(p.B) < min {
		p.B = make([]byte, min)
		p.Cap = min
	} else {
		p.B = p.B[:min]
	}
	return p
}

// Bytes returns the byte slice of the buffer.
func (p *PooledBuf) Bytes() []byte { return p.B }

// Grow ensures the buffer has at least `n` capacity, growing it if necessary.
func (p *PooledBuf) Grow(n int) []byte {
	if cap(p.B) < n {
		p.B = make([]byte, n)
		p.Cap = n
	} else {
		p.B = p.B[:n]
	}
	return p.B
}

func (p *PooledBuf) Shrink(n int) []byte {
	if cap(p.B) > n {
		p.B = p.B[:n]
	} else {
		p.B = make([]byte, n)
		p.Cap = n
	}
	return p.B
}

// ShrinkTo reduces the buffer's length to `n`, without reallocating.
func (p *PooledBuf) ShrinkTo(n int) { p.B = p.B[:n] }

// Release returns the buffer to the pool.
func (p *PooledBuf) Release() {
	p.B = p.B[:0]
	bufPool.Put(p)
}
