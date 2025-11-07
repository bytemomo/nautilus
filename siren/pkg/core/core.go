package core

import (
	"net"
	"sync"
	"time"

	"bytemomo/siren/intercept"
)

// Direction indicates the flow of traffic.
type Direction int

const (
	ClientToServer Direction = iota
	ServerToClient
)

func (d Direction) String() string {
	switch d {
	case ClientToServer:
		return "client_to_server"
	case ServerToClient:
		return "server_to_client"
	default:
		return "unknown"
	}
}

func (d Direction) Opposite() Direction {
	if d == ClientToServer {
		return ServerToClient
	}
	return ClientToServer
}

// ConnectionState represents the lifecycle stage of a connection.
type ConnectionState int

const (
	StateConnecting ConnectionState = iota
	StateActive
	StateClosed
)

// Connection encapsulates metadata about a proxied connection or flow.
type Connection struct {
	ID           string
	ClientAddr   net.Addr
	ServerAddr   net.Addr
	Protocol     string
	State        ConnectionState
	StartTime    time.Time
	LastActivity time.Time
	Stats        *ConnectionStats
}

// UpdateActivity updates the last activity timestamp.
func (c *Connection) UpdateActivity() {
	c.LastActivity = time.Now()
}

// ConnectionStats stores per-connection counters.
type ConnectionStats struct {
	mu sync.RWMutex

	StartTime time.Time

	bytesC2S uint64
	bytesS2C uint64

	drops         uint64
	modifications uint64
}

// Duration returns how long the connection has been active.
func (cs *ConnectionStats) Duration() time.Duration {
	if cs == nil || cs.StartTime.IsZero() {
		return 0
	}
	return time.Since(cs.StartTime)
}

// TotalBytes returns the aggregate transferred bytes.
func (cs *ConnectionStats) TotalBytes() uint64 {
	if cs == nil {
		return 0
	}
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.bytesC2S + cs.bytesS2C
}

// RecordBytes increments counters for the given direction.
func (cs *ConnectionStats) RecordBytes(dir Direction, n int) {
	if cs == nil || n <= 0 {
		return
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if dir == ClientToServer {
		cs.bytesC2S += uint64(n)
	} else {
		cs.bytesS2C += uint64(n)
	}
}

// RecordDrop increments the drop counter.
func (cs *ConnectionStats) RecordDrop() {
	if cs == nil {
		return
	}
	cs.mu.Lock()
	cs.drops++
	cs.mu.Unlock()
}

// RecordModify increments the modification counter.
func (cs *ConnectionStats) RecordModify() {
	if cs == nil {
		return
	}
	cs.mu.Lock()
	cs.modifications++
	cs.mu.Unlock()
}

// TrafficContext contains the payload and metadata for processing.
type TrafficContext struct {
	Conn      *Connection
	Direction Direction
	Payload   []byte
	Size      int
	Frame     []byte
	Metadata  map[string]interface{}
}

// ProcessingResult captures the outcome of rule/manipulator execution.
type ProcessingResult struct {
	Action          intercept.ActionType
	Drop            bool
	Disconnect      bool
	Delay           time.Duration
	Duplicate       int
	ModifiedPayload []byte
	Metadata        map[string]interface{}
}
