package intercept

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Direction indicates traffic flow direction
type Direction int

const (
	DirectionClientToServer Direction = iota
	DirectionServerToClient
	DirectionBoth
)

func (d Direction) String() string {
	switch d {
	case DirectionClientToServer:
		return "client_to_server"
	case DirectionServerToClient:
		return "server_to_client"
	case DirectionBoth:
		return "both"
	default:
		return "unknown"
	}
}

// ParseDirection converts string to Direction
func ParseDirection(s string) Direction {
	switch strings.ToLower(s) {
	case "client_to_server", "c2s", "request":
		return DirectionClientToServer
	case "server_to_client", "s2c", "response":
		return DirectionServerToClient
	case "both", "bidirectional":
		return DirectionBoth
	default:
		return DirectionBoth
	}
}

// UnmarshalYAML allows Direction to be specified as either a string or number.
func (d *Direction) UnmarshalYAML(value *yaml.Node) error {
	switch value.Tag {
	case "!!str":
		*d = ParseDirection(value.Value)
		return nil
	case "!!int":
		var tmp int
		if err := value.Decode(&tmp); err != nil {
			return err
		}
		*d = Direction(tmp)
		return nil
	case "!!null":
		*d = DirectionBoth
		return nil
	default:
		// Attempt generic decode (covers bool/float errors gracefully)
		var v string
		if err := value.Decode(&v); err != nil {
			return fmt.Errorf("direction: unsupported type %s", value.Tag)
		}
		*d = ParseDirection(v)
		return nil
	}
}

// Rule defines a traffic interception rule
type Rule struct {
	Name        string         `yaml:"name" json:"name"`
	Description string         `yaml:"description,omitempty" json:"description,omitempty"`
	Enabled     bool           `yaml:"enabled" json:"enabled"`
	Priority    int            `yaml:"priority,omitempty" json:"priority,omitempty"` // Higher priority rules evaluated first
	Match       *MatchCriteria `yaml:"match" json:"match"`
	Action      *Action        `yaml:"action" json:"action"`
}

// MatchCriteria defines criteria for matching traffic
type MatchCriteria struct {
	// Direction
	Direction Direction `yaml:"direction,omitempty" json:"direction,omitempty"`

	// Content matching
	ContentContains      string `yaml:"content_contains,omitempty" json:"content_contains,omitempty"`
	ContentStartsWith    string `yaml:"content_starts_with,omitempty" json:"content_starts_with,omitempty"`
	ContentEndsWith      string `yaml:"content_ends_with,omitempty" json:"content_ends_with,omitempty"`
	ContentRegex         string `yaml:"content_regex,omitempty" json:"content_regex,omitempty"`
	contentRegexCompiled *regexp.Regexp

	// Size matching
	SizeGT *int `yaml:"size_gt,omitempty" json:"size_gt,omitempty"` // Greater than
	SizeLT *int `yaml:"size_lt,omitempty" json:"size_lt,omitempty"` // Less than
	SizeEQ *int `yaml:"size_eq,omitempty" json:"size_eq,omitempty"` // Equal to

	// Connection state
	ConnectionAge         string `yaml:"connection_age,omitempty" json:"connection_age,omitempty"` // e.g., ">10s", "<1m"
	connectionAgeDuration time.Duration
	connectionAgeOp       string
	PacketCount           string `yaml:"packet_count,omitempty" json:"packet_count,omitempty"`           // e.g., ">100"
	BytesTransferred      string `yaml:"bytes_transferred,omitempty" json:"bytes_transferred,omitempty"` // e.g., ">1MB"

	// Probability
	Probability float64 `yaml:"probability,omitempty" json:"probability,omitempty"` // 0.0 to 1.0

	// Protocol-specific
	HTTPMethod string `yaml:"http_method,omitempty" json:"http_method,omitempty"`
	HTTPPath   string `yaml:"http_path,omitempty" json:"http_path,omitempty"`
	HTTPHeader string `yaml:"http_header,omitempty" json:"http_header,omitempty"`
	TLSSNI     string `yaml:"tls_sni,omitempty" json:"tls_sni,omitempty"`

	// Custom conditions
	Custom map[string]interface{} `yaml:"custom,omitempty" json:"custom,omitempty"`
}

// Compile prepares the match criteria for evaluation
func (mc *MatchCriteria) Compile() error {
	// Compile regex if provided
	if mc.ContentRegex != "" {
		re, err := regexp.Compile(mc.ContentRegex)
		if err != nil {
			return fmt.Errorf("invalid regex pattern: %w", err)
		}
		mc.contentRegexCompiled = re
	}

	// Parse connection age
	if mc.ConnectionAge != "" {
		if err := mc.parseConnectionAge(); err != nil {
			return fmt.Errorf("invalid connection_age: %w", err)
		}
	}

	return nil
}

// parseConnectionAge parses connection age string like ">10s", "<1m"
func (mc *MatchCriteria) parseConnectionAge() error {
	age := strings.TrimSpace(mc.ConnectionAge)
	if len(age) < 2 {
		return fmt.Errorf("invalid format: %s", age)
	}

	op := age[0]
	if op != '>' && op != '<' && op != '=' {
		return fmt.Errorf("invalid operator: %c (expected >, <, or =)", op)
	}

	mc.connectionAgeOp = string(op)
	durationStr := age[1:]
	if mc.connectionAgeOp == "=" && age[1] == '=' {
		durationStr = age[2:]
	}

	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}

	mc.connectionAgeDuration = duration
	return nil
}

// TrafficInfo contains information about traffic to be matched
type TrafficInfo struct {
	ConnectionID  string
	Direction     Direction
	Payload       []byte
	Size          int
	ConnectionAge time.Duration
	PacketCount   uint64
	TotalBytes    uint64

	// Protocol-specific
	HTTPMethod  string
	HTTPPath    string
	HTTPHeaders map[string]string
	TLSSNI      string

	// Custom data
	Custom map[string]interface{}
}

// Matches evaluates if the traffic matches the criteria
func (mc *MatchCriteria) Matches(info *TrafficInfo) bool {
	// Check direction
	if mc.Direction != DirectionBoth {
		if mc.Direction != info.Direction {
			return false
		}
	}

	// Check content matching
	if mc.ContentContains != "" {
		if !strings.Contains(string(info.Payload), mc.ContentContains) {
			return false
		}
	}

	if mc.ContentStartsWith != "" {
		if !strings.HasPrefix(string(info.Payload), mc.ContentStartsWith) {
			return false
		}
	}

	if mc.ContentEndsWith != "" {
		if !strings.HasSuffix(string(info.Payload), mc.ContentEndsWith) {
			return false
		}
	}

	if mc.contentRegexCompiled != nil {
		if !mc.contentRegexCompiled.Match(info.Payload) {
			return false
		}
	}

	// Check size matching
	if mc.SizeGT != nil && info.Size <= *mc.SizeGT {
		return false
	}

	if mc.SizeLT != nil && info.Size >= *mc.SizeLT {
		return false
	}

	if mc.SizeEQ != nil && info.Size != *mc.SizeEQ {
		return false
	}

	// Check connection age
	if mc.ConnectionAge != "" {
		if !mc.matchConnectionAge(info.ConnectionAge) {
			return false
		}
	}

	// Check packet count (simplified - would need proper parsing)
	if mc.PacketCount != "" {
		// TODO: Implement packet count matching
	}

	// Check bytes transferred (simplified - would need proper parsing)
	if mc.BytesTransferred != "" {
		// TODO: Implement bytes transferred matching
	}

	// Check HTTP-specific criteria
	if mc.HTTPMethod != "" && mc.HTTPMethod != info.HTTPMethod {
		return false
	}

	if mc.HTTPPath != "" {
		if info.HTTPPath == "" || !matchPattern(mc.HTTPPath, info.HTTPPath) {
			return false
		}
	}

	if mc.HTTPHeader != "" {
		// TODO: Implement HTTP header matching
	}

	if mc.TLSSNI != "" && mc.TLSSNI != info.TLSSNI {
		return false
	}

	// Check probability (random sampling)
	if mc.Probability > 0 && mc.Probability < 1.0 {
		// This would need a proper random number generator
		// For now, we'll use a simple modulo approach based on packet count
		threshold := uint64(mc.Probability * 1000)
		if (info.PacketCount % 1000) > threshold {
			return false
		}
	}

	return true
}

// matchConnectionAge checks if connection age matches the criteria
func (mc *MatchCriteria) matchConnectionAge(age time.Duration) bool {
	switch mc.connectionAgeOp {
	case ">":
		return age > mc.connectionAgeDuration
	case "<":
		return age < mc.connectionAgeDuration
	case "=":
		// Allow some tolerance for equality (±100ms)
		diff := age - mc.connectionAgeDuration
		if diff < 0 {
			diff = -diff
		}
		return diff < 100*time.Millisecond
	default:
		return false
	}
}

// matchPattern matches a pattern with wildcards (* and ?)
func matchPattern(pattern, s string) bool {
	// Simple wildcard matching
	if pattern == "*" {
		return true
	}

	if !strings.Contains(pattern, "*") && !strings.Contains(pattern, "?") {
		return pattern == s
	}

	// Convert to regex
	regexPattern := "^" + regexp.QuoteMeta(pattern)
	regexPattern = strings.ReplaceAll(regexPattern, "\\*", ".*")
	regexPattern = strings.ReplaceAll(regexPattern, "\\?", ".")
	regexPattern += "$"

	re, err := regexp.Compile(regexPattern)
	if err != nil {
		return false
	}

	return re.MatchString(s)
}

// RuleSet is a collection of rules
type RuleSet struct {
	Name        string  `yaml:"name" json:"name"`
	Description string  `yaml:"description,omitempty" json:"description,omitempty"`
	Rules       []*Rule `yaml:"rules" json:"rules"`
}

// Compile prepares all rules in the set
func (rs *RuleSet) Compile() error {
	for i, rule := range rs.Rules {
		if rule.Match == nil {
			return fmt.Errorf("rule %d (%s) has no match criteria", i, rule.Name)
		}
		if rule.Action == nil {
			return fmt.Errorf("rule %d (%s) has no action", i, rule.Name)
		}
		if err := rule.Match.Compile(); err != nil {
			return fmt.Errorf("rule %d (%s): %w", i, rule.Name, err)
		}
		if err := rule.Action.Compile(); err != nil {
			return fmt.Errorf("rule %d (%s): %w", i, rule.Name, err)
		}
	}
	return nil
}

// SortByPriority sorts rules by priority (higher first)
func (rs *RuleSet) SortByPriority() {
	// Simple bubble sort for now
	n := len(rs.Rules)
	for i := 0; i < n-1; i++ {
		for j := 0; j < n-i-1; j++ {
			if rs.Rules[j].Priority < rs.Rules[j+1].Priority {
				rs.Rules[j], rs.Rules[j+1] = rs.Rules[j+1], rs.Rules[j]
			}
		}
	}
}

// EnabledRules returns only enabled rules
func (rs *RuleSet) EnabledRules() []*Rule {
	var enabled []*Rule
	for _, rule := range rs.Rules {
		if rule.Enabled {
			enabled = append(enabled, rule)
		}
	}
	return enabled
}
