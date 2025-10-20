package proxy

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"bytemomo/siren/intercept"
	"bytemomo/trident/conduit/transport"
)

func TestConnectionStats(t *testing.T) {
	stats := &ConnectionStats{
		StartTime: time.Now(),
	}

	// Test recording bytes
	stats.RecordBytes(ClientToServer, 100)
	stats.RecordBytes(ServerToClient, 200)

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

	// Test total bytes
	total := stats.TotalBytes()
	if total != 300 {
		t.Errorf("Expected TotalBytes=300, got %d", total)
	}

	// Test drop recording
	stats.RecordDrop()
	if stats.Dropped != 1 {
		t.Errorf("Expected Dropped=1, got %d", stats.Dropped)
	}

	// Test modify recording
	stats.RecordModify()
	if stats.Modified != 1 {
		t.Errorf("Expected Modified=1, got %d", stats.Modified)
	}

	// Test duration
	time.Sleep(10 * time.Millisecond)
	duration := stats.Duration()
	if duration < 10*time.Millisecond {
		t.Errorf("Expected duration >= 10ms, got %v", duration)
	}
}

func TestProxyStats(t *testing.T) {
	stats := NewProxyStats()

	// Test connection tracking
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

	// Test bytes recording
	stats.RecordBytes(1000)
	stats.RecordBytes(500)

	if stats.BytesProxied != 1500 {
		t.Errorf("Expected BytesProxied=1500, got %d", stats.BytesProxied)
	}

	if stats.PacketsProxied != 2 {
		t.Errorf("Expected PacketsProxied=2, got %d", stats.PacketsProxied)
	}

	// Test drop recording
	stats.RecordDrop()
	if stats.PacketsDropped != 1 {
		t.Errorf("Expected PacketsDropped=1, got %d", stats.PacketsDropped)
	}

	// Test modify recording
	stats.RecordModify()
	if stats.PacketsModified != 1 {
		t.Errorf("Expected PacketsModified=1, got %d", stats.PacketsModified)
	}

	// Test rule match recording
	stats.RecordRuleMatch()
	if stats.RulesMatched != 1 {
		t.Errorf("Expected RulesMatched=1, got %d", stats.RulesMatched)
	}

	// Test uptime
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

	if conn.GetState() != StateConnecting {
		t.Errorf("Expected initial state=StateConnecting, got %s", conn.GetState())
	}

	// Test state transitions
	conn.SetState(StateEstablished)
	if conn.GetState() != StateEstablished {
		t.Errorf("Expected state=StateEstablished, got %s", conn.GetState())
	}

	// Test activity tracking
	initialActivity := conn.LastActivity
	time.Sleep(10 * time.Millisecond)
	conn.UpdateActivity()

	if !conn.LastActivity.After(initialActivity) {
		t.Error("Expected LastActivity to be updated")
	}

	idleDuration := conn.IdleDuration()
	if idleDuration >= 10*time.Millisecond {
		t.Errorf("Expected IdleDuration < 10ms after update, got %v", idleDuration)
	}
}

func TestTrafficProcessor(t *testing.T) {
	// Create a simple rule: drop packets > 100 bytes
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
	processor := NewTrafficProcessor(engine, nil, stats)

	conn := NewConnection("test-conn", nil, nil, "tcp")
	ctx := context.Background()

	// Test small packet (should pass)
	tc := &TrafficContext{
		Conn:      conn,
		Direction: ClientToServer,
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

	// Test large packet (should drop)
	tc.Payload = make([]byte, 200)
	tc.Size = 200

	result, err = processor.Process(ctx, tc)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	if !result.Drop {
		t.Error("Expected large packet to be dropped, but it passed")
	}

	// Verify stats were updated
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

	if cfg.EnableLogging != true {
		t.Error("Expected EnableLogging=true by default")
	}
}

func TestDirectionString(t *testing.T) {
	tests := []struct {
		dir      Direction
		expected string
	}{
		{ClientToServer, "client->server"},
		{ServerToClient, "server->client"},
		{Direction(999), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.dir.String(); got != tt.expected {
			t.Errorf("Direction(%d).String() = %s, want %s", tt.dir, got, tt.expected)
		}
	}
}

func TestConnectionStateString(t *testing.T) {
	tests := []struct {
		state    ConnectionState
		expected string
	}{
		{StateConnecting, "connecting"},
		{StateEstablished, "established"},
		{StateClosing, "closing"},
		{StateClosed, "closed"},
		{ConnectionState(999), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.expected {
			t.Errorf("ConnectionState(%d).String() = %s, want %s", tt.state, got, tt.expected)
		}
	}
}

// Test with a real TCP echo server
func TestStreamProxyIntegration(t *testing.T) {
	// This is a simplified integration test
	// In a real scenario, you'd set up an echo server and test the full proxy

	// Create echo server
	echoServer, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create echo server: %v", err)
	}
	defer echoServer.Close()

	// Handle echo connections
	go func() {
		for {
			conn, err := echoServer.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c) // Echo back
			}(conn)
		}
	}()

	serverAddr := echoServer.Addr().String()

	// Create proxy listener
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create proxy listener: %v", err)
	}
	defer proxyListener.Close()

	proxyAddr := proxyListener.Addr().String()

	// Create Trident conduit for server connection
	serverConduit := transport.TCP(serverAddr)

	// Create proxy config
	cfg := &ProxyConfig{
		ListenAddr:        proxyAddr,
		TargetAddr:        serverAddr,
		MaxConnections:    10,
		ConnectionTimeout: 5 * time.Second,
		BufferSize:        4096,
		EnableRecording:   false,
		EnableLogging:     false,
	}

	// Create stream proxy
	streamProxy := NewStreamProxy(cfg, proxyListener, serverConduit, nil, nil)

	// Start proxy
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := streamProxy.Start(ctx); err != nil {
		t.Fatalf("Failed to start proxy: %v", err)
	}
	defer streamProxy.Stop()

	// Give proxy time to start
	time.Sleep(100 * time.Millisecond)

	// Connect through proxy
	client, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer client.Close()

	// Send data
	testData := []byte("Hello, Siren!")
	if _, err := client.Write(testData); err != nil {
		t.Fatalf("Failed to write to proxy: %v", err)
	}

	// Read echo
	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("Failed to read from proxy: %v", err)
	}

	if string(buf) != string(testData) {
		t.Errorf("Echo mismatch: got %q, want %q", buf, testData)
	}

	// Verify stats
	stats := streamProxy.Stats()
	if stats.TotalConnections != 1 {
		t.Errorf("Expected TotalConnections=1, got %d", stats.TotalConnections)
	}
}

func intPtr(i int) *int {
	return &i
}
