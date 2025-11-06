package proxy

import (
	"context"
	"net"
	"sync"
	"time"

	"bytemomo/siren/intercept"
	"bytemomo/siren/pkg/core"
	"bytemomo/siren/pkg/manipulator"
	"bytemomo/siren/pkg/sirenerr"
	"bytemomo/siren/recorder"

	"github.com/sirupsen/logrus"
)

// Proxy is the common interface for all proxy types
type Proxy interface {
	Start(ctx context.Context) error
	Stop() error
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
}

// DefaultProxyConfig returns default configuration
func DefaultProxyConfig() *ProxyConfig {
	return &ProxyConfig{
		MaxConnections:    1000,
		ConnectionTimeout: 30 * time.Second,
		BufferSize:        32 * 1024, // 32KB
		EnableRecording:   false,
	}
}

func NewConnection(id string, clientAddr, serverAddr net.Addr, protocol string) *core.Connection {
	now := time.Now()
	return &core.Connection{
		ID:           id,
		ClientAddr:   clientAddr,
		ServerAddr:   serverAddr,
		Stats:        &core.ConnectionStats{StartTime: now},
		StartTime:    now,
		LastActivity: now,
		Protocol:     protocol,
		State:        core.StateConnecting,
	}
}

// TrafficProcessor processes traffic based on rules
type TrafficProcessor struct {
	engine       *intercept.Engine
	recorder     *recorder.Recorder
	stats        *ProxyStats
	log          *logrus.Entry
	manipulators []manipulator.Manipulator
}

func NewTrafficProcessor(engine *intercept.Engine, rec *recorder.Recorder, stats *ProxyStats, log *logrus.Entry, manipulators []manipulator.Manipulator) *TrafficProcessor {
	return &TrafficProcessor{
		engine:       engine,
		recorder:     rec,
		stats:        stats,
		log:          log,
		manipulators: manipulators,
	}
}

// Process applies rules to traffic and returns the result
func (tp *TrafficProcessor) Process(ctx context.Context, tc *core.TrafficContext) (*core.ProcessingResult, error) {
	op := "proxy.TrafficProcessor.Process"
	result := &core.ProcessingResult{
		ModifiedPayload: tc.Payload,
	}

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
			return nil, sirenerr.E(op, "failed to evaluate rule", 0, err)
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

	for _, m := range tp.manipulators {
		var err error
		result, err = m.Process(ctx, tc, result)
		if err != nil {
			return nil, sirenerr.E(op, "failed to process manipulator", 0, err)
		}
	}

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

func convertDirection(d core.Direction) intercept.Direction {
	if d == core.ClientToServer {
		return intercept.DirectionClientToServer
	}
	return intercept.DirectionServerToClient
}
