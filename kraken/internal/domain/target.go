package domain

import (
	"fmt"
	"net"
	"strconv"
)

// TargetKind identifies the type of target.
type TargetKind string

const (
	TargetKindNetwork  TargetKind = "network"
	TargetKindEtherCAT TargetKind = "ethercat"
)

// Target is the unified interface for scan targets.
type Target interface {
	Kind() TargetKind
	String() string
	Key() string
}

// EtherCATSlave represents a discovered EtherCAT slave device.
type EtherCATSlave struct {
	Interface   string // Network interface (e.g., "eth0")
	Position    uint16 // Auto-increment position (0-based)
	StationAddr uint16 // Configured station address
	AliasAddr   uint16 // Alias from EEPROM
	VendorID    uint32
	ProductCode uint32
	RevisionNo  uint32
	SerialNo    uint32
	PortStatus  uint16 // DL Status register (port link states)
}

func (e EtherCATSlave) Kind() TargetKind { return TargetKindEtherCAT }

func (e EtherCATSlave) String() string {
	return fmt.Sprintf("ethercat://%s/slave/%d", e.Interface, e.Position)
}

func (e EtherCATSlave) Key() string {
	return fmt.Sprintf("ecat:%s:%d", e.Interface, e.Position)
}

// Ensure HostPort implements Target interface.
var _ Target = HostPort{}

// Kind returns the target kind for HostPort.
func (h HostPort) Kind() TargetKind { return TargetKindNetwork }

// String returns the host:port representation.
func (h HostPort) String() string {
	return net.JoinHostPort(h.Host, strconv.Itoa(int(h.Port)))
}

// Key returns a unique identifier for deduplication.
func (h HostPort) Key() string { return h.String() }
