package proxy

import (
	"context"
	"fmt"
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

	ActiveConnections int
	TotalConnections  uint64
	BytesProxied      uint64
	PacketsProxied    uint64
	PacketsDropped    uint64
	PacketsModified   uint64
	RulesMatched      uint64
	StartTime         time.Time
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

// Process applies the full interception and manipulation pipeline to a traffic context.
func (tp *TrafficProcessor) Process(ctx context.Context, tc *core.TrafficContext) (*core.ProcessingResult, error) {
	// 1. Evaluate rules
	result, err := tp.evaluateRules(ctx, tc)
	if err != nil {
		return nil, err
	}

	// 2. Apply manipulators
	result, err = tp.applyManipulators(ctx, tc, result)
	if err != nil {
		return nil, err
	}

	// 3. Record traffic
	tp.recordTraffic(tc, result)

	// 4. Update stats
	tp.updateStats(tc, result)

	return result, nil
}

func (tp *TrafficProcessor) evaluateRules(ctx context.Context, tc *core.TrafficContext) (*core.ProcessingResult, error) {
	if tp.engine == nil {
		return &core.ProcessingResult{ModifiedPayload: tc.Payload}, nil
	}

	info := &intercept.TrafficInfo{
		ConnectionID:  tc.Conn.ID,
		Direction:     convertDirection(tc.Direction),
		Payload:       tc.Payload,
		Size:          tc.Size,
		ConnectionAge: tc.Conn.Stats.Duration(),
		TotalBytes:    tc.Conn.Stats.TotalBytes(),
	}

	actionResult, err := tp.engine.Evaluate(ctx, info)
	if err != nil {
		return nil, sirenerr.E("proxy.TrafficProcessor.evaluateRules", "failed to evaluate rules", 0, err)
	}

	return &core.ProcessingResult{
		Action:          actionResult.Type,
		Drop:            actionResult.Drop,
		Disconnect:      actionResult.Disconnect,
		Delay:           actionResult.Delay,
		Duplicate:       actionResult.Duplicate,
		ModifiedPayload: actionResult.ModifiedPayload,
		Metadata:        actionResult.Metadata,
	}, nil
}

func (tp *TrafficProcessor) applyManipulators(ctx context.Context, tc *core.TrafficContext, initialResult *core.ProcessingResult) (*core.ProcessingResult, error) {
	if len(tp.manipulators) == 0 {
		return initialResult, nil
	}

	result := initialResult
	var err error
	for _, m := range tp.manipulators {
		result, err = m.Process(ctx, tc, result)
		if err != nil {
			return nil, sirenerr.E("proxy.TrafficProcessor.applyManipulators", fmt.Sprintf("failed to process manipulator %s", m.Name()), 0, err)
		}
	}
	return result, nil
}

func (tp *TrafficProcessor) recordTraffic(tc *core.TrafficContext, result *core.ProcessingResult) {
	if tp.recorder == nil {
		return
	}

	tp.recorder.Record(&recorder.TrafficRecord{
		Timestamp:    time.Now(),
		ConnectionID: tc.Conn.ID,
		Direction:    tc.Direction.String(),
		Payload:      result.ModifiedPayload,
		Size:         len(result.ModifiedPayload),
		Dropped:      result.Drop,
		Modified:     len(result.ModifiedPayload) != len(tc.Payload),
		Data:         tc.Frame,
		OriginalLen:  len(tc.Frame),
		Metadata:     result.Metadata,
	})
}

func (tp *TrafficProcessor) updateStats(tc *core.TrafficContext, result *core.ProcessingResult) {
	if result.Action != intercept.ActionPass {
		tp.stats.RecordRuleMatch()
	}
	if result.Drop {
		tp.stats.RecordDrop()
		tc.Conn.Stats.RecordDrop()
	}
	if len(result.ModifiedPayload) != len(tc.Payload) {
		tp.stats.RecordModify()
		tc.Conn.Stats.RecordModify()
	}
}

func convertDirection(d core.Direction) intercept.Direction {
	if d == core.ClientToServer {
		return intercept.DirectionClientToServer
	}
	return intercept.DirectionServerToClient
}
