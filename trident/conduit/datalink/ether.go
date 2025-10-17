//go:build linux
// +build linux

package datalink

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	packetpkg "github.com/mdlayher/packet"

	cond "bytemomo/trident/conduit"
)

const (
	EtherTypeEtherCAT = 0x88A4
	ethPAll           = 0x0003 // ETH_P_ALL
)

type EthernetConduit struct {
	ifc       *net.Interface
	mu        sync.Mutex
	conn      *packetpkg.Conn
	dst       net.HardwareAddr
	etherType uint16 // optional filter; 0 => ETH_P_ALL
}

type ethFrame EthernetConduit

func Ethernet(ifaceName string, defaultDst net.HardwareAddr, etherType uint16) cond.Conduit[cond.Frame] {
	return &EthernetConduit{
		ifc:       &net.Interface{Name: ifaceName},
		dst:       defaultDst,
		etherType: etherType,
	}
}

func (e *EthernetConduit) Dial(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.conn != nil {
		return nil
	}

	ifc, err := net.InterfaceByName(e.ifc.Name)
	if err != nil {
		return err
	}
	e.ifc = ifc

	// Choose protocol: specific EtherType or ETH_P_ALL.
	proto := uint16(ethPAll)
	if e.etherType != 0 {
		proto = e.etherType
	}

	c, err := packetpkg.Listen(ifc, packetpkg.Raw, int(htons(proto)), nil)
	if err != nil {
		return err
	}

	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	e.conn = c
	return nil
}

func (e *EthernetConduit) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.conn != nil {
		_ = e.conn.Close()
		e.conn = nil
	}
	return nil
}

func (e *EthernetConduit) Kind() cond.Kind { return cond.KindFrame }
func (e *EthernetConduit) Stack() []string { return []string{"eth"} }
func (e *EthernetConduit) AsView() cond.View[cond.Frame] {
	return cond.View[cond.Frame]{View: (*ethFrame)(e)}
}

func (e *ethFrame) c() (*packetpkg.Conn, error) {
	if e.conn == nil {
		return nil, errors.New("eth: not open")
	}
	return e.conn, nil
}

func (e *ethFrame) SetDeadline(t time.Time) error {
	c, err := e.c()
	if err != nil {
		return err
	}
	return c.SetDeadline(t)
}
func (e *ethFrame) Interface() *net.Interface { return e.ifc }

func (e *ethFrame) ReadFrame(ctx context.Context, p []byte) (int, net.HardwareAddr, net.HardwareAddr, uint16, cond.Metadata, error) {
	c, err := e.c()
	if err != nil {
		return 0, nil, nil, 0, cond.Metadata{}, err
	}
	start := time.Now()
	var (
		n    int
		addr net.Addr
		rerr error
	)
	done := make(chan struct{})
	go func() { n, addr, rerr = c.ReadFrom(p); close(done) }()
	select {
	case <-ctx.Done():
		_ = c.SetReadDeadline(time.Now().Add(-time.Second))
		<-done
		md := cond.Metadata{Start: start, End: time.Now(), Layer: "eth", Local: e.ifc.Name, Remote: cond.AddrString(addr)}
		src, dst, et := parseEthernetHeader(p[:n])
		return n, src, dst, et, md, ctx.Err()
	case <-done:
		md := cond.Metadata{Start: start, End: time.Now(), Layer: "eth", Local: e.ifc.Name, Remote: cond.AddrString(addr)}
		src, dst, et := parseEthernetHeader(p[:n])
		return n, src, dst, et, md, rerr
	}
}

func (e *ethFrame) WriteFrame(ctx context.Context, payload []byte, dst net.HardwareAddr, etherType uint16) (int, cond.Metadata, error) {
	c, err := e.c()
	if err != nil {
		return 0, cond.Metadata{}, err
	}
	if dst == nil {
		dst = e.dst
	}
	if etherType == 0 {
		etherType = e.etherType
	}
	if len(dst) != 6 {
		return 0, cond.Metadata{}, errors.New("eth: dst MAC required")
	}
	src := e.ifc.HardwareAddr
	frame := buildEthernetFrame(src, dst, etherType, payload)

	start := time.Now()
	var (
		n    int
		werr error
	)
	addr := &packetpkg.Addr{HardwareAddr: dst}
	done := make(chan struct{})
	go func() { n, werr = c.WriteTo(frame, addr); close(done) }()
	select {
	case <-ctx.Done():
		_ = c.SetWriteDeadline(time.Now().Add(-time.Second))
		<-done
		md := cond.Metadata{Start: start, End: time.Now(), Layer: "eth", Local: e.ifc.Name, Remote: dst.String()}
		return n, md, ctx.Err()
	case <-done:
		md := cond.Metadata{Start: start, End: time.Now(), Layer: "eth", Local: e.ifc.Name, Remote: dst.String()}
		return n, md, werr
	}
}

func htons(u uint16) uint16 { return (u<<8)&0xFF00 | (u>>8)&0x00FF }

func buildEthernetFrame(src, dst net.HardwareAddr, etherType uint16, payload []byte) []byte {
	frame := make([]byte, 14+len(payload))
	copy(frame[0:6], dst)
	copy(frame[6:12], src)
	frame[12] = byte(etherType >> 8)
	frame[13] = byte(etherType)
	copy(frame[14:], payload)
	if len(frame) < 60 {
		frame = append(frame, make([]byte, 60-len(frame))...)
	}
	return frame
}

func parseEthernetHeader(b []byte) (src, dst net.HardwareAddr, etherType uint16) {
	if len(b) < 14 {
		return nil, nil, 0
	}
	dst = net.HardwareAddr(append([]byte(nil), b[0:6]...))
	src = net.HardwareAddr(append([]byte(nil), b[6:12]...))
	etherType = uint16(b[12])<<8 | uint16(b[13])
	return
}
