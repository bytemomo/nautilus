package datalink

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	packetpkg "github.com/mdlayher/packet"

	"bytemomo/trident/conduit"
	"bytemomo/trident/conduit/utils"
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
	etherType uint16
}

type ethFrame EthernetConduit

func Ethernet(ifaceName string, defaultDst net.HardwareAddr, etherType uint16) conduit.Conduit[conduit.Frame] {
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

func (e *EthernetConduit) Kind() conduit.Kind { return conduit.KindFrame }
func (e *EthernetConduit) Stack() []string { return []string{"eth"} }
func (e *EthernetConduit) Underlying() conduit.Frame { return (*ethFrame)(e) }

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

func (e *ethFrame) Recv(ctx context.Context, opts *conduit.RecvOptions) (*conduit.FramePkt, error) {
	c, err := e.c()
	if err != nil {
		return nil, err
	}

	buf := utils.GetBuf(1500)
	b := buf.Bytes()

	start := time.Now()
	var (
		n    int
		addr net.Addr
		rerr error
	)
	done := make(chan struct{})
	go func() { n, addr, rerr = c.ReadFrom(b); close(done) }()
	select {
	case <-ctx.Done():
		_ = c.SetReadDeadline(time.Now().Add(-time.Second))
		<-done
		_ = addr
		md := conduit.Metadata{Start: start, End: time.Now(), IfIndex: e.ifc.Index}
		src, dst, et := parseEthernetHeader(b[:n])
		return &conduit.FramePkt{Data: buf, Src: src, Dst: dst, EtherType: et, IfIndex: e.ifc.Index, MD: md}, ctx.Err()
	case <-done:
		_ = addr
		md := conduit.Metadata{Start: start, End: time.Now(), IfIndex: e.ifc.Index}
		src, dst, et := parseEthernetHeader(b[:n])
		return &conduit.FramePkt{Data: buf, Src: src, Dst: dst, EtherType: et, IfIndex: e.ifc.Index, MD: md}, rerr
	}
}

func (e *ethFrame) RecvBatch(ctx context.Context, pkts []*conduit.FramePkt, opts *conduit.RecvOptions) (int, error) {
	count := 0
	var err error
	for i := range pkts {
		pkts[i], err = e.Recv(ctx, opts)
		if err != nil {
			if count > 0 {
				return count, nil
			}
			return 0, err
		}
		count++
	}
	return count, nil
}

func (e *ethFrame) Send(ctx context.Context, pkt *conduit.FramePkt, opts *conduit.SendOptions) (int, conduit.Metadata, error) {
	c, err := e.c()
	if err != nil {
		return 0, conduit.Metadata{}, err
	}
	dst := pkt.Dst
	if dst == nil {
		dst = e.dst
	}
	etherType := pkt.EtherType
	if etherType == 0 {
		etherType = e.etherType
	}
	if len(dst) != 6 {
		return 0, conduit.Metadata{}, errors.New("eth: dst MAC required")
	}
	src := e.ifc.HardwareAddr
	frame := buildEthernetFrame(src, dst, etherType, pkt.Data.Bytes())

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
		md := conduit.Metadata{Start: start, End: time.Now(), IfIndex: e.ifc.Index}
		return n, md, ctx.Err()
	case <-done:
		md := conduit.Metadata{Start: start, End: time.Now(), IfIndex: e.ifc.Index}
		return n, md, werr
	}
}

func (e *ethFrame) SendBatch(ctx context.Context, pkts []*conduit.FramePkt, opts *conduit.SendOptions) (int, error) {
	sent := 0
	for _, p := range pkts {
		_, _, err := e.Send(ctx, p, opts)
		if err != nil {
			if sent > 0 {
				return sent, nil
			}
			return 0, err
		}
		sent++
	}
	return sent, nil
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
