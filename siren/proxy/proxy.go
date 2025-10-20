package proxy

import (
	"context"
	"net"
	"sync"
	"time"

	"bytemomo/siren/intercept"
	"bytemomo/siren/recorder"
	"bytemomo/trident/conduit"
)

// Direction indicates traffic flow direction
type Direction int

const (
	ClientToServer Direction = iota
	ServerToClient
)

func (d Direction) String() string {
	switch d {
	case ClientToServer:
		return "client->server"
	case ServerToClient:
		return "server->client"
	default:
		return "unknown"
	}
}

// ConnectionStats tracks statistics for a proxied connection
type ConnectionStats struct {
	mu sync.RWMutex

	StartTime         time.Time
	EndTime           time.Time
	BytesClientServer uint64
	BytesServerClient uint64
	PacketsClientServer uint64
	PacketsServerClient uint64
	Dropped           uint64
	Modified          uint64
}

func (s *ConnectionStats) RecordBytes(dir Direction, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if dir == ClientToServer {
		s.BytesClientServer += uint64(n)
		s.PacketsClientServer++
	} else {
		s.BytesServerClient += uint64(n)
		s.PacketsServerClient++
	}
}

func (s *ConnectionStats) RecordDrop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Dropped++
}

func (s *ConnectionStats) RecordModify() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Modified++
}

func (s *ConnectionStats) Duration() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.EndTime.IsZero() {
		return time.Since(s.StartTime)
	}
	return s.EndTime.Sub(s.StartTime)
}

func (s *ConnectionStats) TotalBytes() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.BytesClientServer + s.BytesServerClient
}

// Proxy is the common interface for all proxy types
type Proxy interface {
	// Start begins accepting connections and proxying traffic
	Start(ctx context.Context) error

	// Stop gracefully shuts down the proxy
	Stop() error

	// Stats returns current proxy statistics
	Stats() *ProxyStats
}

// ProxyStats aggregates statistics across all connections
type ProxyStats struct {
	mu sync.RWMutex

	ActiveConnections   int
	TotalConnections    uint64
	BytesProxied        uint64
	PacketsProxied      uint64
	PacketsDropped      uint64
	PacketsModified     uint64
	RulesMatched        uint64
	StartTime           time.Time
}

func NewProxyStats() *ProxyStats {
	return &ProxyStats{
		StartTime: time.Now(),
	}
}

func (s *ProxyStats) AddConnection() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ActiveConnections++
	s.TotalConnections++
}

func (s *ProxyStats) RemoveConnection() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ActiveConnections--
}

func (s *ProxyStats) RecordBytes(n uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.BytesProxied += n
	s.PacketsProxied++
}

func (s *ProxyStats) RecordDrop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PacketsDropped++
}

func (s *ProxyStats) RecordModify() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PacketsModified++
}

func (s *ProxyStats) RecordRuleMatch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.RulesMatched++
}

func (s *ProxyStats) Uptime() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.StartTime)
}

// ProxyConfig holds common configuration for all proxy types
type ProxyConfig struct {
	ListenAddr        string
	TargetAddr        string
	MaxConnections    int
	ConnectionTimeout time.Duration
	BufferSize        int
	EnableRecording   bool
	EnableLogging     bool
}

// DefaultProxyConfig returns default configuration
func DefaultProxyConfig() *ProxyConfig {
	return &ProxyConfig{
		MaxConnections:    1000,
		ConnectionTimeout: 30 * time.Second,
		BufferSize:        32 * 1024, // 32KB
		EnableRecording:   false,
		EnableLogging:     true,
	}
}

// Connection represents a proxied connection
type Connection struct {
	ID            string
	ClientAddr    net.Addr
	ServerAddr    net.Addr
	Stats         *ConnectionStats
	StartTime     time.Time
	LastActivity  time.Time
	Protocol      string
	State         ConnectionState
	mu            sync.RWMutex
}

type ConnectionState int

const (
	StateConnecting ConnectionState = iota
	StateEstablished
	StateClosing
	StateClosed
)

func (s ConnectionState) String() string {
	switch s {
	case StateConnecting:
		return "connecting"
	case StateEstablished:
		return "established"
	case StateClosing:
		return "closing"
	case StateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

func NewConnection(id string, clientAddr, serverAddr net.Addr, protocol string) *Connection {
	now := time.Now()
	return &Connection{
		ID:           id,
		ClientAddr:   clientAddr,
		ServerAddr:   serverAddr,
		Stats:        &ConnectionStats{StartTime: now},
		StartTime:    now,
		LastActivity: now,
		Protocol:     protocol,
		State:        StateConnecting,
	}
}

func (c *Connection) SetState(state ConnectionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.State = state
}

func (c *Connection) GetState() ConnectionState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.State
}

func (c *Connection) UpdateActivity() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.LastActivity = time.Now()
}

func (c *Connection) IdleDuration() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return time.Since(c.LastActivity)
}

// TrafficContext provides context for traffic interception
type TrafficContext struct {
	Conn      *Connection
	Direction Direction
	Payload   []byte
	Size      int
	Metadata  *conduit.Metadata
}

// ProcessingResult contains the result of traffic processing
type ProcessingResult struct {
	Action         intercept.ActionType
	ModifiedPayload []byte
	Delay          time.Duration
	Drop           bool
	Disconnect     bool
	Duplicate      int
	Metadata       map[string]interface{}
}

// TrafficProcessor processes traffic based on rules
type TrafficProcessor struct {
	engine   *intercept.Engine
	recorder *recorder.Recorder
	stats    *ProxyStats
}

func NewTrafficProcessor(engine *intercept.Engine, rec *recorder.Recorder, stats *ProxyStats) *TrafficProcessor {
	return &TrafficProcessor{
		engine:   engine,
		recorder: rec,
		stats:    stats,
	}
}

// Process applies rules to traffic and returns the result
func (tp *TrafficProcessor) Process(ctx context.Context, tc *TrafficContext) (*ProcessingResult, error) {
	result := &ProcessingResult{
		ModifiedPayload: tc.Payload,
	}

	// Apply interception rules if engine is available
	if tp.engine != nil {
		action, err := tp.engine.Evaluate(ctx, &intercept.TrafficInfo{
			ConnectionID:  tc.Conn.ID,
			Direction:     convertDirection(tc.Direction),
			Payload:       tc.Payload,
			Size:          tc.Size,
			ConnectionAge: tc.Conn.Stats.Duration(),
			TotalBytes:    tc.Conn.Stats.TotalBytes(),
		})

		if err != nil {
			return nil, err
		}

		if action != nil {
			result.Action = action.Type
			result.Drop = action.Drop
			result.Disconnect = action.Disconnect
			result.Delay = action.Delay
			result.Duplicate = action.Duplicate
			result.ModifiedPayload = action.ModifiedPayload
			result.Metadata = action.Metadata

			if action.Drop {
				tp.stats.RecordDrop()
				tc.Conn.Stats.RecordDrop()
			}
			if action.Modified {
				tp.stats.RecordModify()
				tc.Conn.Stats.RecordModify()
			}

			tp.stats.RecordRuleMatch()
		}
	}

	// Record traffic if recorder is available
	if tp.recorder != nil {
		tp.recorder.Record(&recorder.TrafficRecord{
			Timestamp:    time.Now(),
			ConnectionID: tc.Conn.ID,
			Direction:    tc.Direction.String(),
			Payload:      result.ModifiedPayload,
			Size:         len(result.ModifiedPayload),
			Dropped:      result.Drop,
			Modified:     result.ModifiedPayload != nil && len(result.ModifiedPayload) != len(tc.Payload),
		})
	}

	return result, nil
}

func convertDirection(d Direction) intercept.Direction {
	if d == ClientToServer {
		return intercept.DirectionClientToServer
	}
	return intercept.DirectionServerToClient
}
