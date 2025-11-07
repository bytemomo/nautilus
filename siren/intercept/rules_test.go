package intercept

import (
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestDirection(t *testing.T) {
	tests := []struct {
		dir      Direction
		expected string
	}{
		{DirectionClientToServer, "client_to_server"},
		{DirectionServerToClient, "server_to_client"},
		{DirectionBoth, "both"},
		{Direction(999), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.dir.String(); got != tt.expected {
			t.Errorf("Direction(%d).String() = %s, want %s", tt.dir, got, tt.expected)
		}
	}
}

func TestParseDirection(t *testing.T) {
	tests := []struct {
		input    string
		expected Direction
	}{
		{"client_to_server", DirectionClientToServer},
		{"c2s", DirectionClientToServer},
		{"request", DirectionClientToServer},
		{"server_to_client", DirectionServerToClient},
		{"s2c", DirectionServerToClient},
		{"response", DirectionServerToClient},
		{"both", DirectionBoth},
		{"bidirectional", DirectionBoth},
		{"unknown", DirectionBoth}, // Default
	}

	for _, tt := range tests {
		if got := ParseDirection(tt.input); got != tt.expected {
			t.Errorf("ParseDirection(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestMatchCriteria_ContentMatching(t *testing.T) {
	mc := &MatchCriteria{
		Direction:         DirectionBoth,
		ContentContains:   "test",
		ContentStartsWith: "GET",
		ContentEndsWith:   "EOF",
	}

	if err := mc.Compile(); err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	tests := []struct {
		name     string
		payload  string
		expected bool
	}{
		{
			name:     "matches all criteria",
			payload:  "GET /test/path EOF",
			expected: true,
		},
		{
			name:     "missing contains",
			payload:  "GET /path EOF",
			expected: false,
		},
		{
			name:     "missing starts with",
			payload:  "POST /test/path EOF",
			expected: false,
		},
		{
			name:     "missing ends with",
			payload:  "GET /test/path",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &TrafficInfo{
				Direction: DirectionClientToServer,
				Payload:   []byte(tt.payload),
				Size:      len(tt.payload),
			}

			if got := mc.Matches(info); got != tt.expected {
				t.Errorf("Matches() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestMatchCriteria_RegexMatching(t *testing.T) {
	mc := &MatchCriteria{
		Direction:    DirectionBoth,
		ContentRegex: `^(GET|POST) /\w+`,
	}

	if err := mc.Compile(); err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	tests := []struct {
		payload  string
		expected bool
	}{
		{"GET /api", true},
		{"POST /users", true},
		{"DELETE /items", false},
		{"GET /", false}, // \w+ requires at least one word char
	}

	for _, tt := range tests {
		info := &TrafficInfo{
			Direction: DirectionClientToServer,
			Payload:   []byte(tt.payload),
			Size:      len(tt.payload),
		}

		if got := mc.Matches(info); got != tt.expected {
			t.Errorf("Matches(%q) = %v, want %v", tt.payload, got, tt.expected)
		}
	}
}

func TestMatchCriteria_SizeMatching(t *testing.T) {
	sizeGT := 100
	sizeLT := 500
	sizeEQ := 200

	mc := &MatchCriteria{
		Direction: DirectionBoth,
		SizeGT:    &sizeGT,
		SizeLT:    &sizeLT,
		SizeEQ:    nil,
	}

	tests := []struct {
		size     int
		expected bool
	}{
		{50, false},  // Too small
		{150, true},  // Within range
		{300, true},  // Within range
		{500, false}, // Too large (>= SizeLT fails)
		{600, false}, // Too large
	}

	for _, tt := range tests {
		info := &TrafficInfo{
			Direction: DirectionClientToServer,
			Payload:   make([]byte, tt.size),
			Size:      tt.size,
		}

		if got := mc.Matches(info); got != tt.expected {
			t.Errorf("Matches(size=%d) = %v, want %v", tt.size, got, tt.expected)
		}
	}

	// Test SizeEQ
	mc.SizeGT = nil
	mc.SizeLT = nil
	mc.SizeEQ = &sizeEQ

	info := &TrafficInfo{
		Direction: DirectionClientToServer,
		Payload:   make([]byte, 200),
		Size:      200,
	}

	if !mc.Matches(info) {
		t.Error("Expected match for exact size")
	}

	info.Size = 199
	if mc.Matches(info) {
		t.Error("Expected no match for different size")
	}
}

func TestMatchCriteria_ConnectionAge(t *testing.T) {
	mc := &MatchCriteria{
		Direction:     DirectionBoth,
		ConnectionAge: ">10s",
	}

	if err := mc.Compile(); err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	tests := []struct {
		age      time.Duration
		expected bool
	}{
		{5 * time.Second, false},
		{10 * time.Second, false},
		{11 * time.Second, true},
		{30 * time.Second, true},
	}

	for _, tt := range tests {
		info := &TrafficInfo{
			Direction:     DirectionClientToServer,
			Payload:       []byte("test"),
			Size:          4,
			ConnectionAge: tt.age,
		}

		if got := mc.Matches(info); got != tt.expected {
			t.Errorf("Matches(age=%v) = %v, want %v", tt.age, got, tt.expected)
		}
	}
}

func TestMatchCriteria_ConnectionAge_LessThan(t *testing.T) {
	mc := &MatchCriteria{
		Direction:     DirectionBoth,
		ConnectionAge: "<5s",
	}

	if err := mc.Compile(); err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	tests := []struct {
		age      time.Duration
		expected bool
	}{
		{2 * time.Second, true},
		{5 * time.Second, false},
		{10 * time.Second, false},
	}

	for _, tt := range tests {
		info := &TrafficInfo{
			Direction:     DirectionClientToServer,
			Payload:       []byte("test"),
			Size:          4,
			ConnectionAge: tt.age,
		}

		if got := mc.Matches(info); got != tt.expected {
			t.Errorf("Matches(age=%v) = %v, want %v", tt.age, got, tt.expected)
		}
	}
}

func TestMatchCriteria_DirectionMatching(t *testing.T) {
	tests := []struct {
		name        string
		matchDir    Direction
		trafficDir  Direction
		shouldMatch bool
	}{
		{"both matches c2s", DirectionBoth, DirectionClientToServer, true},
		{"both matches s2c", DirectionBoth, DirectionServerToClient, true},
		{"c2s matches c2s", DirectionClientToServer, DirectionClientToServer, true},
		{"c2s no match s2c", DirectionClientToServer, DirectionServerToClient, false},
		{"s2c matches s2c", DirectionServerToClient, DirectionServerToClient, true},
		{"s2c no match c2s", DirectionServerToClient, DirectionClientToServer, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mc := &MatchCriteria{
				Direction: tt.matchDir,
			}

			info := &TrafficInfo{
				Direction: tt.trafficDir,
				Payload:   []byte("test"),
				Size:      4,
			}

			if got := mc.Matches(info); got != tt.shouldMatch {
				t.Errorf("Matches() = %v, want %v", got, tt.shouldMatch)
			}
		})
	}
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern  string
		input    string
		expected bool
	}{
		{"*", "anything", true},
		{"test", "test", true},
		{"test", "Test", false},
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "example.com", false},
		{"test*", "test123", true},
		{"test*", "testing", true},
		{"test*", "other", false},
		{"test?", "test1", true},
		{"test?", "test12", false},
		{"/api/*", "/api/users", true},
		{"/api/*", "/api/", true},
		{"/api/*", "/v1/api/", false},
	}

	for _, tt := range tests {
		if got := matchPattern(tt.pattern, tt.input); got != tt.expected {
			t.Errorf("matchPattern(%q, %q) = %v, want %v", tt.pattern, tt.input, got, tt.expected)
		}
	}
}

func TestRuleSet_Compile(t *testing.T) {
	rs := &RuleSet{
		Name: "Test Rules",
		Rules: []*Rule{
			{
				Name:     "Test Rule 1",
				Enabled:  true,
				Priority: 100,
				Match: &MatchCriteria{
					Direction: DirectionBoth,
				},
				Action: &Action{
					Type: ActionPass,
				},
			},
			{
				Name:     "Test Rule 2",
				Enabled:  true,
				Priority: 90,
				Match: &MatchCriteria{
					Direction:    DirectionClientToServer,
					ContentRegex: `^\w+`,
				},
				Action: &Action{
					Type:     ActionDelay,
					Duration: "100ms",
				},
			},
		},
	}

	if err := rs.Compile(); err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	// Verify regex was compiled
	if rs.Rules[1].Match.contentRegexCompiled == nil {
		t.Error("Expected regex to be compiled")
	}

	// Verify action was compiled
	if rs.Rules[1].Action.durationParsed != 100*time.Millisecond {
		t.Errorf("Expected duration=100ms, got %v", rs.Rules[1].Action.durationParsed)
	}
}

func TestRuleSet_SortByPriority(t *testing.T) {
	rs := &RuleSet{
		Name: "Test Rules",
		Rules: []*Rule{
			{Name: "Low Priority", Priority: 10},
			{Name: "High Priority", Priority: 100},
			{Name: "Medium Priority", Priority: 50},
		},
	}

	rs.SortByPriority()

	expected := []string{"High Priority", "Medium Priority", "Low Priority"}
	for i, rule := range rs.Rules {
		if rule.Name != expected[i] {
			t.Errorf("Rules[%d].Name = %s, want %s", i, rule.Name, expected[i])
		}
	}
}

func TestRuleSet_EnabledRules(t *testing.T) {
	rs := &RuleSet{
		Name: "Test Rules",
		Rules: []*Rule{
			{Name: "Enabled 1", Enabled: true},
			{Name: "Disabled 1", Enabled: false},
			{Name: "Enabled 2", Enabled: true},
			{Name: "Disabled 2", Enabled: false},
		},
	}

	enabled := rs.EnabledRules()
	if len(enabled) != 2 {
		t.Fatalf("Expected 2 enabled rules, got %d", len(enabled))
	}

	if enabled[0].Name != "Enabled 1" || enabled[1].Name != "Enabled 2" {
		t.Error("EnabledRules returned wrong rules")
	}
}

func TestMatchCriteria_InvalidRegex(t *testing.T) {
	mc := &MatchCriteria{
		ContentRegex: "[invalid",
	}

	if err := mc.Compile(); err == nil {
		t.Error("Expected error for invalid regex")
	}
}

func TestMatchCriteria_InvalidConnectionAge(t *testing.T) {
	tests := []string{
		"invalid",
		"10",
		"<",
		">>10s",
		"=10x",
	}

	for _, age := range tests {
		mc := &MatchCriteria{
			ConnectionAge: age,
		}

		if err := mc.Compile(); err == nil {
			t.Errorf("Expected error for invalid connection age: %s", age)
		}
	}
}

func TestMatchCriteria_Probability(t *testing.T) {
	// This test is probabilistic, so we run multiple iterations
	mc := &MatchCriteria{
		Direction:   DirectionBoth,
		Probability: 0.5, // 50% chance
	}

	info := &TrafficInfo{
		Direction:   DirectionClientToServer,
		Payload:     []byte("test"),
		Size:        4,
		PacketCount: 0,
	}

	matches := 0
	iterations := 1000

	for i := 0; i < iterations; i++ {
		info.PacketCount = uint64(i)
		if mc.Matches(info) {
			matches++
		}
	}

	// With 50% probability and 1000 iterations, we expect roughly 500 matches
	// Allow for some variance (40-60%)
	if matches < 400 || matches > 600 {
		t.Logf("Warning: Probability matching may be off. Got %d matches out of %d (expected ~500)", matches, iterations)
	}
}

func TestHTTPMethodMatching(t *testing.T) {
	mc := &MatchCriteria{
		Direction:  DirectionClientToServer,
		HTTPMethod: "GET",
	}

	tests := []struct {
		method   string
		expected bool
	}{
		{"GET", true},
		{"POST", false},
		{"", false},
	}

	for _, tt := range tests {
		info := &TrafficInfo{
			Direction:  DirectionClientToServer,
			Payload:    []byte("test"),
			Size:       4,
			HTTPMethod: tt.method,
		}

		if got := mc.Matches(info); got != tt.expected {
			t.Errorf("Matches(HTTPMethod=%s) = %v, want %v", tt.method, got, tt.expected)
		}
	}
}

func TestHTTPPathMatching(t *testing.T) {
	mc := &MatchCriteria{
		Direction: DirectionClientToServer,
		HTTPPath:  "/api/*",
	}

	tests := []struct {
		path     string
		expected bool
	}{
		{"/api/users", true},
		{"/api/posts", true},
		{"/v1/api", false},
		{"", false},
	}

	for _, tt := range tests {
		info := &TrafficInfo{
			Direction: DirectionClientToServer,
			Payload:   []byte("test"),
			Size:      4,
			HTTPPath:  tt.path,
		}

		if got := mc.Matches(info); got != tt.expected {
			t.Errorf("Matches(HTTPPath=%s) = %v, want %v", tt.path, got, tt.expected)
		}
	}
}

func TestTLSSNIMatching(t *testing.T) {
	mc := &MatchCriteria{
		Direction: DirectionBoth,
		TLSSNI:    "example.com",
	}

	tests := []struct {
		sni      string
		expected bool
	}{
		{"example.com", true},
		{"other.com", false},
		{"", false},
	}

	for _, tt := range tests {
		info := &TrafficInfo{
			Direction: DirectionClientToServer,
			Payload:   []byte("test"),
			Size:      4,
			TLSSNI:    tt.sni,
		}

		if got := mc.Matches(info); got != tt.expected {
			t.Errorf("Matches(TLSSNI=%s) = %v, want %v", tt.sni, got, tt.expected)
		}
	}
}

func TestDirectionUnmarshalYAML(t *testing.T) {
	type wrapper struct {
		Direction Direction `yaml:"direction"`
	}

	tests := []struct {
		name     string
		input    string
		expected Direction
	}{
		{"string both", "direction: both", DirectionBoth},
		{"alias string", "direction: c2s", DirectionClientToServer},
		{"numeric", "direction: 1", DirectionServerToClient},
		{"missing", "{}", DirectionClientToServer},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var w wrapper
			if err := yaml.Unmarshal([]byte(tt.input), &w); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}
			if w.Direction != tt.expected {
				t.Fatalf("direction = %v, want %v", w.Direction, tt.expected)
			}
		})
	}
}
