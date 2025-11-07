package ebpf

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	snapLen = 256
)

//go:embed program/xdp_proxy.bpf.o
var objectFile []byte

// FlowDirection represents ingress/egress direction.
type FlowDirection uint8

const (
	FlowDirectionIngress FlowDirection = iota
	FlowDirectionEgress
)

const etherTypeEtherCAT = 0x88a4

// TargetKind identifies how a target entry should be matched.
type TargetKind uint8

const (
	TargetKindAny TargetKind = iota
	TargetKindIP
	TargetKindIPPort
	TargetKindMAC
	TargetKindEtherCAT
)

// Target describes a selector for deciding whether to intercept traffic.
type Target struct {
	Kind     TargetKind
	IP       net.IP
	Port     uint16
	MAC      [6]byte
	EtherCAT uint16
}

// PacketEvent contains the payload copied by the XDP program.
type PacketEvent struct {
	Timestamp     time.Time
	Interface     int
	Proto         uint8
	EtherType     uint16
	Direction     FlowDirection
	SrcIP         net.IP
	DstIP         net.IP
	SrcPort       uint16
	DstPort       uint16
	Length        uint32
	Capture       []byte
	PayloadOffset uint16
	EtherCAT      uint16
	SrcMAC        net.HardwareAddr
	DstMAC        net.HardwareAddr
}

// FlowKey identifies a 5-tuple flow.
type FlowKey struct {
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	Proto    uint8
	EtherCAT uint16
}

// FlowActionType enumerates supported eBPF actions.
type FlowActionType uint32

const (
	FlowActionNone FlowActionType = 0
	FlowActionDrop FlowActionType = 1
)

// FlowAction instructs the eBPF program on how to treat a flow.
type FlowAction struct {
	Type     FlowActionType
	Duration time.Duration
}

// ManagerConfig controls the eBPF data plane.
type ManagerConfig struct {
	Interface string
}

// Manager owns the eBPF lifecycle.
type Manager struct {
	cfg         ManagerConfig
	collection  *ebpf.Collection
	program     *ebpf.Program
	events      *ebpf.Map
	flowActions *ebpf.Map
	targets     *ebpf.Map
	link        link.Link
	linkMu      sync.Mutex
	startOnce   sync.Once
	stopOnce    sync.Once
}

// NewManager builds a Manager with the given config.
func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.Interface == "" {
		return nil, errors.New("ebpf: interface is required")
	}
	return &Manager{cfg: cfg}, nil
}

// Start loads the eBPF objects and attaches the XDP program.
func (m *Manager) Start() error {
	var err error
	m.startOnce.Do(func() {
		err = m.start()
	})
	return err
}

func (m *Manager) start() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("ebpf: remove memlock: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(objectFile))
	if err != nil {
		return fmt.Errorf("ebpf: load collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("ebpf: load collection: %w", err)
	}

	prog, ok := coll.Programs["siren_xdp"]
	if !ok {
		coll.Close()
		return errors.New("ebpf: program 'siren_xdp' missing")
	}
	events, ok := coll.Maps["events"]
	if !ok {
		coll.Close()
		return errors.New("ebpf: map 'events' missing")
	}
	flowActions, ok := coll.Maps["flow_actions"]
	if !ok {
		coll.Close()
		return errors.New("ebpf: map 'flow_actions' missing")
	}
	targets, ok := coll.Maps["targets"]
	if !ok {
		coll.Close()
		return errors.New("ebpf: map 'targets' missing")
	}

	iface, err := net.InterfaceByName(m.cfg.Interface)
	if err != nil {
		coll.Close()
		return fmt.Errorf("ebpf: resolve interface %s: %w", m.cfg.Interface, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	})
	if err != nil {
		return fmt.Errorf("ebpf: attach XDP to %s: %w", m.cfg.Interface, err)
	}

	m.collection = coll
	m.program = prog
	m.events = events
	m.flowActions = flowActions
	m.targets = targets
	m.linkMu.Lock()
	m.link = l
	m.linkMu.Unlock()
	return nil
}

// Stop detaches the program and closes resources.
func (m *Manager) Stop() error {
	var err error
	m.stopOnce.Do(func() {
		err = m.stop()
	})
	return err
}

func (m *Manager) stop() error {
	m.linkMu.Lock()
	if m.link != nil {
		_ = m.link.Close()
		m.link = nil
	}
	m.linkMu.Unlock()

	if m.collection != nil {
		m.collection.Close()
		m.collection = nil
		m.program = nil
		m.events = nil
		m.flowActions = nil
		m.targets = nil
	}
	return nil
}

// Read drains the ring buffer and invokes handler for each packet.
func (m *Manager) Read(ctx context.Context, handler func(*PacketEvent)) error {
	if handler == nil {
		return errors.New("ebpf: handler required")
	}
	reader, err := ringbuf.NewReader(m.events)
	if err != nil {
		return fmt.Errorf("ebpf: create ring reader: %w", err)
	}
	defer reader.Close()

	go func() {
		<-ctx.Done()
		reader.Close()
	}()

	for {
		rec, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return nil
			}
			if errors.Is(err, context.Canceled) {
				return nil
			}
			continue
		}

		ev, err := decodePacketEvent(rec.RawSample)
		if err == nil {
			handler(ev)
		}
	}
}

func decodePacketEvent(data []byte) (*PacketEvent, error) {
	var raw packetEvent
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &raw); err != nil {
		return nil, fmt.Errorf("ebpf: decode event: %w", err)
	}

	captureLen := int(raw.CaptureLen)
	if captureLen > snapLen {
		captureLen = snapLen
	}
	capture := make([]byte, captureLen)
	copy(capture, raw.Payload[:captureLen])

	var srcMAC, dstMAC net.HardwareAddr
	srcMAC = append(srcMAC, raw.SrcMac[:]...)
	dstMAC = append(dstMAC, raw.DstMac[:]...)

	return &PacketEvent{
		Timestamp:     time.Unix(0, int64(raw.Ts)),
		Interface:     int(raw.Ifindex),
		Proto:         raw.Proto,
		EtherType:     raw.EtherType,
		Direction:     FlowDirection(raw.Direction),
		SrcIP:         u32ToIP(raw.Saddr),
		DstIP:         u32ToIP(raw.Daddr),
		SrcPort:       bpfToHost16(raw.Sport),
		DstPort:       bpfToHost16(raw.Dport),
		Length:        raw.Len,
		Capture:       capture,
		PayloadOffset: raw.PayloadOff,
		EtherCAT:      raw.Ethercat,
		SrcMAC:        srcMAC,
		DstMAC:        dstMAC,
	}, nil
}

func u32ToIP(v uint32) net.IP {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return net.IP(b)
}

func bpfToHost16(v uint16) uint16 {
	return binary.BigEndian.Uint16([]byte{byte(v >> 8), byte(v)})
}

// FlowKeyFromEvent builds a flow key from a packet event.
func FlowKeyFromEvent(ev *PacketEvent) FlowKey {
	return FlowKey{
		SrcIP:    ipToU32(ev.SrcIP),
		DstIP:    ipToU32(ev.DstIP),
		SrcPort:  ev.SrcPort,
		DstPort:  ev.DstPort,
		Proto:    ev.Proto,
		EtherCAT: ev.EtherCAT,
	}
}

// ApplyAction writes a flow action to the map.
func (m *Manager) ApplyAction(key FlowKey, action FlowAction) error {
	monons, err := monotonicNs()
	if err != nil {
		return err
	}
	expires := uint64(0)
	if action.Duration > 0 {
		expires = monons + uint64(action.Duration)
	}
	bpfKey := bpfFlowKey{
		SrcIP:    key.SrcIP,
		DstIP:    key.DstIP,
		SrcPort:  key.SrcPort,
		DstPort:  key.DstPort,
		Proto:    key.Proto,
		EtherCAT: key.EtherCAT,
	}
	bpfVal := bpfFlowAction{
		Action:    uint32(action.Type),
		ExpiresNs: expires,
	}
	return m.flowActions.Put(&bpfKey, &bpfVal)
}

// ClearAction removes a flow action.
func (m *Manager) ClearAction(key FlowKey) error {
	bpfKey := bpfFlowKey{
		SrcIP:    key.SrcIP,
		DstIP:    key.DstIP,
		SrcPort:  key.SrcPort,
		DstPort:  key.DstPort,
		Proto:    key.Proto,
		EtherCAT: key.EtherCAT,
	}
	return m.flowActions.Delete(&bpfKey)
}

// SetTargets programs the target allowlist. Empty list captures everything.
func (m *Manager) SetTargets(targets []Target) error {
	if m.targets == nil {
		return errors.New("ebpf: targets map not available")
	}

	// Clear existing entries.
	iter := m.targets.Iterate()
	var key targetKey
	for iter.Next(&key, nil) {
		_ = m.targets.Delete(&key)
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("ebpf: iterate targets: %w", err)
	}

	value := uint8(1)
	if len(targets) == 0 {
		key := targetKey{Kind: uint8(TargetKindAny)}
		return m.targets.Put(&key, &value)
	}

	for _, tgt := range targets {
		key := targetKey{Kind: uint8(tgt.Kind)}
		switch tgt.Kind {
		case TargetKindIP:
			key.IP = ipToU32(tgt.IP)
		case TargetKindIPPort:
			key.IP = ipToU32(tgt.IP)
			key.Port = tgt.Port
		case TargetKindMAC:
			key.MAC = tgt.MAC
		case TargetKindEtherCAT:
			key.EtherCAT = tgt.EtherCAT
		default:
			continue
		}
		if err := m.targets.Put(&key, &value); err != nil {
			return fmt.Errorf("ebpf: set target: %w", err)
		}
	}
	return nil
}

func monotonicNs() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, fmt.Errorf("ebpf: clock_gettime: %w", err)
	}
	return uint64(ts.Sec)*uint64(time.Second) + uint64(ts.Nsec), nil
}

// GenerateFlowID returns a random flow identifier string.
func GenerateFlowID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%x", b)
}

func ipToU32(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(v4)
}

type packetEvent struct {
	Ts         uint64
	Len        uint32
	Ifindex    uint32
	EtherType  uint16
	CaptureLen uint16
	PayloadOff uint16
	Proto      uint8
	Direction  uint8
	Sport      uint16
	Dport      uint16
	Saddr      uint32
	Daddr      uint32
	Ethercat   uint16
	SrcMac     [6]byte
	DstMac     [6]byte
	Payload    [snapLen]byte
}

type targetKey struct {
	Kind     uint8
	_        uint8
	Port     uint16
	IP       uint32
	EtherCAT uint16
	Pad      uint16
	MAC      [6]byte
}

type bpfFlowKey struct {
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	Proto    uint8
	_        uint8
	EtherCAT uint16
}

type bpfFlowAction struct {
	Action    uint32
	ExpiresNs uint64
}
