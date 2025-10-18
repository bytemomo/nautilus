package conduit

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"
)

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

func AddrString(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

func DeadlineFromContext(ctx context.Context) time.Time {
	if dl, ok := ctx.Deadline(); ok {
		return dl
	}
	return time.Time{}
}

func Tern[T any](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}

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
// Minimal pooled Buffer implementation (delete if you already have one in cond)
// =====================================================================================

type pooledBuf struct {
	b   []byte
	cap int
}

var bufPool = sync.Pool{
	New: func() any { return &pooledBuf{b: make([]byte, 32*1024), cap: 32 * 1024} },
}

func GetBuf(min int) *pooledBuf {
	p := bufPool.Get().(*pooledBuf)
	if cap(p.b) < min {
		p.b = make([]byte, min)
		p.cap = min
	} else {
		p.b = p.b[:min]
	}
	return p
}

func (p *pooledBuf) Bytes() []byte { return p.b }

func (p *pooledBuf) Grow(n int) []byte {
	if cap(p.b) < n {
		p.b = make([]byte, n)
		p.cap = n
	} else {
		p.b = p.b[:n]
	}
	return p.b
}

func (p *pooledBuf) ShrinkTo(n int) { p.b = p.b[:n] }

func (p *pooledBuf) Release() {
	p.b = p.b[:0]
	bufPool.Put(p)
}

var _ Buffer = (*pooledBuf)(nil)
