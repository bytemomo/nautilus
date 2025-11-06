package proxy

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"bytemomo/siren/intercept"
	"bytemomo/siren/pkg/core"
	"bytemomo/trident/conduit/transport"

	"github.com/sirupsen/logrus"
)

func TestConnectionStats(t *testing.T) {
	stats := &core.ConnectionStats{
		StartTime: time.Now(),
	}

	stats.RecordBytes(core.ClientToServer, 100)
	stats.RecordBytes(core.ServerToClient, 200)

	if stats.BytesClientServer != 100 {
		t.Errorf("Expected BytesClientServer=100, got %d", stats.BytesClientServer)
	}

	if stats.BytesServerClient != 200 {
		t.Errorf("Expected BytesServerClient=200, got %d", stats.BytesServerClient)
	}

	if stats.PacketsClientServer != 1 {
		t.Errorf("Expected PacketsClientServer=1, got %d", stats.PacketsClientServer)
	}

	if stats.PacketsServerClient != 1 {
		t.Errorf("Expected PacketsServerClient=1, got %d", stats.PacketsServerClient)
	}

	total := stats.TotalBytes()
	if total != 300 {
		t.Errorf("Expected TotalBytes=300, got %d", total)
	}

	stats.RecordDrop()
	if stats.Dropped != 1 {
		t.Errorf("Expected Dropped=1, got %d", stats.Dropped)
	}

	stats.RecordModify()
	if stats.Modified != 1 {
		t.Errorf("Expected Modified=1, got %d", stats.Modified)
	}

	time.Sleep(10 * time.Millisecond)
	duration := stats.Duration()
	if duration < 10*time.Millisecond {
		t.Errorf("Expected duration >= 10ms, got %v", duration)
	}
}

func TestProxyStats(t *testing.T) {
	stats := NewProxyStats()

	stats.AddConnection()
	stats.AddConnection()

	if stats.ActiveConnections != 2 {
		t.Errorf("Expected ActiveConnections=2, got %d", stats.ActiveConnections)
	}

	if stats.TotalConnections != 2 {
		t.Errorf("Expected TotalConnections=2, got %d", stats.TotalConnections)
	}

	stats.RemoveConnection()

	if stats.ActiveConnections != 1 {
		t.Errorf("Expected ActiveConnections=1, got %d", stats.ActiveConnections)
	}

	if stats.TotalConnections != 2 {
		t.Errorf("Expected TotalConnections=2 (should not decrease), got %d", stats.TotalConnections)
	}

	stats.RecordBytes(1000)
	stats.RecordBytes(500)

	if stats.BytesProxied != 1500 {
		t.Errorf("Expected BytesProxied=1500, got %d", stats.BytesProxied)
	}

	if stats.PacketsProxied != 2 {
		t.Errorf("Expected PacketsProxied=2, got %d", stats.PacketsProxied)
	}

	stats.RecordDrop()
	if stats.PacketsDropped != 1 {
		t.Errorf("Expected PacketsDropped=1, got %d", stats.PacketsDropped)
	}

	stats.RecordModify()
	if stats.PacketsModified != 1 {
		t.Errorf("Expected PacketsModified=1, got %d", stats.PacketsModified)
	}

	stats.RecordRuleMatch()
	if stats.RulesMatched != 1 {
		t.Errorf("Expected RulesMatched=1, got %d", stats.RulesMatched)
	}

	time.Sleep(10 * time.Millisecond)
	uptime := stats.Uptime()
	if uptime < 10*time.Millisecond {
		t.Errorf("Expected uptime >= 10ms, got %v", uptime)
	}
}

func TestConnection(t *testing.T) {
	clientAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	serverAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 80}

	conn := NewConnection("test-123", clientAddr, serverAddr, "tcp")

	if conn.ID != "test-123" {
		t.Errorf("Expected ID='test-123', got %s", conn.ID)
	}

	if conn.Protocol != "tcp" {
		t.Errorf("Expected Protocol='tcp', got %s", conn.Protocol)
	}

	if conn.State != core.StateConnecting {
		t.Errorf("Expected initial state=StateConnecting, got %s", conn.State)
	}

	conn.State = core.StateEstablished
	if conn.State != core.StateEstablished {
		t.Errorf("Expected state=StateEstablished, got %s", conn.State)
	}
}

func TestTrafficProcessor(t *testing.T) {
	rule := &intercept.Rule{
		Name:     "Drop Large Packets",
		Enabled:  true,
		Priority: 100,
		Match: &intercept.MatchCriteria{
			Direction: intercept.DirectionBoth,
			SizeGT:    intPtr(100),
		},
		Action: &intercept.Action{
			Type: intercept.ActionDrop,
		},
	}

	ruleSet := &intercept.RuleSet{
		Name:  "Test Rules",
		Rules: []*intercept.Rule{rule},
	}

	engine, err := intercept.NewEngine(ruleSet, &intercept.DefaultLogger{})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	stats := NewProxyStats()
	log := logrus.NewEntry(logrus.New())
	processor := NewTrafficProcessor(engine, nil, stats, log, nil)

	conn := NewConnection("test-conn", nil, nil, "tcp")
	ctx := context.Background()

	tc := &core.TrafficContext{
		Conn:      conn,
		Direction: core.ClientToServer,
		Payload:   make([]byte, 50),
		Size:      50,
	}

	result, err := processor.Process(ctx, tc)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	if result.Drop {
		t.Error("Expected small packet to pass, but it was dropped")
	}

	tc.Payload = make([]byte, 200)
	tc.Size = 200

	result, err = processor.Process(ctx, tc)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	if !result.Drop {
		t.Error("Expected large packet to be dropped, but it passed")
	}

	if stats.PacketsDropped != 1 {
		t.Errorf("Expected PacketsDropped=1, got %d", stats.PacketsDropped)
	}

	if stats.RulesMatched != 1 {
		t.Errorf("Expected RulesMatched=1, got %d", stats.RulesMatched)
	}
}

func TestDefaultProxyConfig(t *testing.T) {
	cfg := DefaultProxyConfig()

	if cfg.MaxConnections != 1000 {
		t.Errorf("Expected MaxConnections=1000, got %d", cfg.MaxConnections)
	}

	if cfg.ConnectionTimeout != 30*time.Second {
		t.Errorf("Expected ConnectionTimeout=30s, got %v", cfg.ConnectionTimeout)
	}

	if cfg.BufferSize != 32*1024 {
		t.Errorf("Expected BufferSize=32KB, got %d", cfg.BufferSize)
	}

	if cfg.EnableRecording != false {
		t.Error("Expected EnableRecording=false by default")
	}
}

func TestStreamProxyIntegration(t *testing.T) {
	echoServer, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create echo server: %v", err)
	}
	defer echoServer.Close()

	go func() {
		for {
			conn, err := echoServer.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	serverAddr := echoServer.Addr().String()

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create proxy listener: %v", err)
	}
	defer proxyListener.Close()

	proxyAddr := proxyListener.Addr().String()

	serverConduit := transport.TCP(serverAddr)

	cfg := &ProxyConfig{
		ListenAddr:        proxyAddr,
		TargetAddr:        serverAddr,
		MaxConnections:    10,
		ConnectionTimeout: 5 * time.Second,
		BufferSize:        4096,
		EnableRecording:   false,
	}

	log := logrus.NewEntry(logrus.New())
	streamProxy := NewStreamProxy(cfg, proxyListener, serverConduit, nil, nil, log, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := streamProxy.Start(ctx); err != nil {
		t.Fatalf("Failed to start proxy: %v", err)
	}
	defer streamProxy.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer client.Close()

	testData := []byte("Hello, Siren!")
	if _, err := client.Write(testData); err != nil {
		t.Fatalf("Failed to write to proxy: %v", err)
	}

	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("Failed to read from proxy: %v", err)
	}

	if string(buf) != string(testData) {
		t.Errorf("Echo mismatch: got %q, want %q", buf, testData)
	}

	stats := streamProxy.Stats()
	if stats.TotalConnections != 1 {
		t.Errorf("Expected TotalConnections=1, got %d", stats.TotalConnections)
	}
}

func intPtr(i int) *int {
	return &i
}
