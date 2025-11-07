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
		if value.Value == "" {
			*d = DirectionBoth
			return nil
		}
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

	// Pre-compiled matchers for performance
	matchers []func(info *TrafficInfo) bool
}

// Compile prepares the match criteria for evaluation by pre-compiling all conditions
// into a slice of matcher functions. This improves performance by avoiding reflection
// and string parsing during the matching process.
func (mc *MatchCriteria) Compile() error {
	mc.matchers = make([]func(info *TrafficInfo) bool, 0)

	// Direction
	if mc.Direction != DirectionBoth {
		mc.addMatcher(mc.matchDirection)
	}

	// Content
	if err := mc.compileContentMatchers(); err != nil {
		return err
	}

	// Size
	mc.compileSizeMatchers()

	// Connection state
	if err := mc.compileConnectionStateMatchers(); err != nil {
		return err
	}

	// Protocol-specific
	mc.compileProtocolMatchers()

	// Probability
	if mc.Probability > 0 {
		mc.addMatcher(mc.matchProbability)
	}

	return nil
}

func (mc *MatchCriteria) addMatcher(matcher func(info *TrafficInfo) bool) {
	mc.matchers = append(mc.matchers, matcher)
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

// Matches evaluates if the traffic matches all compiled criteria.
func (mc *MatchCriteria) Matches(info *TrafficInfo) bool {
	if len(mc.matchers) == 0 {
		return true // No criteria means it's a universal match
	}
	for _, matcher := range mc.matchers {
		if !matcher(info) {
			return false
		}
	}
	return true
}

func (mc *MatchCriteria) matchDirection(info *TrafficInfo) bool {
	return mc.Direction == info.Direction
}

func (mc *MatchCriteria) compileContentMatchers() error {
	if mc.ContentContains != "" {
		mc.addMatcher(func(info *TrafficInfo) bool {
			return strings.Contains(string(info.Payload), mc.ContentContains)
		})
	}
	if mc.ContentStartsWith != "" {
		mc.addMatcher(func(info *TrafficInfo) bool {
			return strings.HasPrefix(string(info.Payload), mc.ContentStartsWith)
		})
	}
	if mc.ContentEndsWith != "" {
		mc.addMatcher(func(info *TrafficInfo) bool {
			return strings.HasSuffix(string(info.Payload), mc.ContentEndsWith)
		})
	}
	if mc.ContentRegex != "" {
		re, err := regexp.Compile(mc.ContentRegex)
		if err != nil {
			return fmt.Errorf("invalid regex pattern: %w", err)
		}
		mc.contentRegexCompiled = re
		mc.addMatcher(func(info *TrafficInfo) bool {
			return mc.contentRegexCompiled.Match(info.Payload)
		})
	}
	return nil
}

func (mc *MatchCriteria) compileSizeMatchers() {
	if mc.SizeGT != nil {
		mc.addMatcher(func(info *TrafficInfo) bool { return info.Size > *mc.SizeGT })
	}
	if mc.SizeLT != nil {
		mc.addMatcher(func(info *TrafficInfo) bool { return info.Size < *mc.SizeLT })
	}
	if mc.SizeEQ != nil {
		mc.addMatcher(func(info *TrafficInfo) bool { return info.Size == *mc.SizeEQ })
	}
}

func (mc *MatchCriteria) compileConnectionStateMatchers() error {
	if mc.ConnectionAge != "" {
		op, duration, err := parseComparatorDuration(mc.ConnectionAge)
		if err != nil {
			return fmt.Errorf("invalid connection_age: %w", err)
		}
		mc.addMatcher(func(info *TrafficInfo) bool {
			return compareDuration(info.ConnectionAge, op, duration)
		})
	}
	// TODO: Implement PacketCount and BytesTransferred matchers
	return nil
}

func (mc *MatchCriteria) compileProtocolMatchers() {
	if mc.HTTPMethod != "" {
		mc.addMatcher(func(info *TrafficInfo) bool { return mc.HTTPMethod == info.HTTPMethod })
	}
	if mc.HTTPPath != "" {
		mc.addMatcher(func(info *TrafficInfo) bool {
			return info.HTTPPath != "" && matchPattern(mc.HTTPPath, info.HTTPPath)
		})
	}
	if mc.TLSSNI != "" {
		mc.addMatcher(func(info *TrafficInfo) bool { return mc.TLSSNI == info.TLSSNI })
	}
	// TODO: Implement HTTPHeader matcher
}

func (mc *MatchCriteria) matchProbability(info *TrafficInfo) bool {
	// Simple but effective random sampling based on a pseudo-random source (packet count).
	// For more advanced use cases, a proper random number generator would be better.
	if mc.Probability <= 0 || mc.Probability >= 1.0 {
		return mc.Probability >= 1.0
	}
	threshold := uint64(mc.Probability * 1000)
	return (info.PacketCount % 1000) < threshold
}

func parseComparatorDuration(s string) (string, time.Duration, error) {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return "", 0, fmt.Errorf("invalid format: %q", s)
	}

	op := s[0:1]
	durationStr := s[1:]
	if strings.HasPrefix(s, "==") || strings.HasPrefix(s, ">=") || strings.HasPrefix(s, "<=") {
		op = s[0:2]
		durationStr = s[2:]
	}

	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid duration: %w", err)
	}

	return op, duration, nil
}

func compareDuration(d1 time.Duration, op string, d2 time.Duration) bool {
	switch op {
	case ">":
		return d1 > d2
	case "<":
		return d1 < d2
	case "=":
		// Allow some tolerance for equality (e.g., within 10%)
		return d1 == d2
	case ">=":
		return d1 >= d2
	case "<=":
		return d1 <= d2
	default:
		return false
	}
}

func matchPattern(pattern, s string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.ContainsAny(pattern, "*?") {
		return pattern == s
	}

	// Convert simple glob to regex
	regexPattern := "^" + regexp.QuoteMeta(pattern)
	regexPattern = strings.ReplaceAll(regexPattern, `\*`, `.*`)
	regexPattern = strings.ReplaceAll(regexPattern, `\?`, `.`)
	regexPattern += "$"

	// This could be cached if performance is critical
	re, err := regexp.Compile(regexPattern)
	if err != nil {
		return false // Invalid patterns fail to match
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
