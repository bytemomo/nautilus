package classifier

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"bytemomo/orca/internal/config"
	"bytemomo/orca/internal/entity"
)

// Classifier defines the interface for mapping targets to campaign steps
type Classifier interface {
	// Classify maps targets to applicable campaign steps
	Classify(ctx context.Context, targets []entity.Target, steps []config.Step) (*ClassificationResult, error)

	// MatchTarget determines if a target matches a step selector
	MatchTarget(target entity.Target, selector config.Selector) (bool, error)

	// GetCandidateSteps returns all steps that could apply to a target
	GetCandidateSteps(target entity.Target, steps []config.Step) ([]config.Step, error)
}

// ClassificationResult contains the results of target classification
type ClassificationResult struct {
	Mappings         []TargetStepMapping `json:"mappings"`
	UnmatchedTargets []entity.Target     `json:"unmatched_targets"`
	UnusedSteps      []config.Step       `json:"unused_steps"`
	Stats            ClassificationStats `json:"stats"`
}

// TargetStepMapping represents a target matched to a step
type TargetStepMapping struct {
	Target   entity.Target  `json:"target"`
	Step     config.Step    `json:"step"`
	Score    float64        `json:"score"`  // Confidence score for the match
	Reason   string         `json:"reason"` // Why this target was matched
	Metadata map[string]any `json:"metadata,omitempty"`
}

// ClassificationStats provides statistics about the classification process
type ClassificationStats struct {
	TotalTargets   int `json:"total_targets"`
	MatchedTargets int `json:"matched_targets"`
	TotalSteps     int `json:"total_steps"`
	UsedSteps      int `json:"used_steps"`
	TotalMappings  int `json:"total_mappings"`
}

// RuleBasedClassifier implements target classification using rule-based matching
type RuleBasedClassifier struct {
	rules       []ClassificationRule
	protocolMap map[string][]string // Maps ports to likely protocols
}

// ClassificationRule defines a rule for mapping services to protocols/steps
type ClassificationRule struct {
	Name        string            `yaml:"name" json:"name"`
	Ports       []int             `yaml:"ports,omitempty" json:"ports,omitempty"`
	Protocols   []string          `yaml:"protocols,omitempty" json:"protocols,omitempty"`
	Services    []string          `yaml:"services,omitempty" json:"services,omitempty"`
	Patterns    []string          `yaml:"patterns,omitempty" json:"patterns,omitempty"`
	Tags        map[string]string `yaml:"tags,omitempty" json:"tags,omitempty"`
	Priority    int               `yaml:"priority,omitempty" json:"priority,omitempty"`
	Description string            `yaml:"description,omitempty" json:"description,omitempty"`
}

// NewRuleBasedClassifier creates a new rule-based classifier
func NewRuleBasedClassifier() *RuleBasedClassifier {
	classifier := &RuleBasedClassifier{
		rules:       getDefaultRules(),
		protocolMap: getDefaultProtocolMap(),
	}
	return classifier
}

// Classify maps targets to applicable campaign steps
func (c *RuleBasedClassifier) Classify(ctx context.Context, targets []entity.Target, steps []config.Step) (*ClassificationResult, error) {
	result := &ClassificationResult{
		Stats: ClassificationStats{
			TotalTargets: len(targets),
			TotalSteps:   len(steps),
		},
	}

	usedSteps := make(map[string]bool)
	matchedTargets := make(map[string]bool)

	// For each target, find matching steps
	for _, target := range targets {
		matched := false

		for _, step := range steps {
			if !step.Enabled {
				continue
			}

			isMatch, err := c.MatchTarget(target, step.Selector)
			if err != nil {
				return nil, fmt.Errorf("failed to match target %s against step %s: %w", target.ID, step.ID, err)
			}

			if isMatch {
				score := c.calculateMatchScore(target, step.Selector)
				reason := c.generateMatchReason(target, step.Selector)

				mapping := TargetStepMapping{
					Target: target,
					Step:   step,
					Score:  score,
					Reason: reason,
					Metadata: map[string]any{
						"target_endpoint": target.Endpoint,
						"step_kind":       step.Kind,
						"step_name":       step.Name,
					},
				}

				result.Mappings = append(result.Mappings, mapping)
				usedSteps[step.ID] = true
				matchedTargets[target.ID] = true
				matched = true
			}
		}

		if !matched {
			result.UnmatchedTargets = append(result.UnmatchedTargets, target)
		}
	}

	// Find unused steps
	for _, step := range steps {
		if step.Enabled && !usedSteps[step.ID] {
			result.UnusedSteps = append(result.UnusedSteps, step)
		}
	}

	// Update stats
	result.Stats.MatchedTargets = len(matchedTargets)
	result.Stats.UsedSteps = len(usedSteps)
	result.Stats.TotalMappings = len(result.Mappings)

	return result, nil
}

// MatchTarget determines if a target matches a step selector
func (c *RuleBasedClassifier) MatchTarget(target entity.Target, selector config.Selector) (bool, error) {
	// Check exclusion rules first
	if selector.Exclude != nil {
		excluded, err := c.MatchTarget(target, *selector.Exclude)
		if err != nil {
			return false, err
		}
		if excluded {
			return false, nil
		}
	}

	// Port matching
	if len(selector.Ports) > 0 && target.Service != nil {
		matched := false
		for _, port := range selector.Ports {
			if target.Service.Port == port {
				matched = true
				break
			}
		}
		if !matched {
			return false, nil
		}
	}

	// Protocol matching
	if len(selector.Protocols) > 0 {
		matched := false
		for _, protocol := range selector.Protocols {
			if target.Protocol == protocol {
				matched = true
				break
			}
		}
		if !matched {
			return false, nil
		}
	}

	// Protocol guesses matching (heuristic-based)
	if len(selector.ProtoGuesses) > 0 && target.Service != nil {
		matched := c.matchProtocolGuesses(target, selector.ProtoGuesses)
		if !matched {
			return false, nil
		}
	}

	// Service name matching
	if len(selector.Services) > 0 && target.Service != nil {
		matched := false
		for _, serviceName := range selector.Services {
			if strings.EqualFold(target.Service.ServiceName, serviceName) {
				matched = true
				break
			}
		}
		if !matched {
			return false, nil
		}
	}

	// Hostname matching
	if len(selector.Hostnames) > 0 && target.Host != nil {
		matched := false
		for _, hostname := range selector.Hostnames {
			if target.Host.Hostname != "" && c.matchHostname(target.Host.Hostname, hostname) {
				matched = true
				break
			}
		}
		if !matched {
			return false, nil
		}
	}

	// IP range matching
	if len(selector.IPRanges) > 0 && target.Host != nil {
		matched := false
		for _, ipRange := range selector.IPRanges {
			if c.matchIPRange(target.Host.IP, ipRange) {
				matched = true
				break
			}
		}
		if !matched {
			return false, nil
		}
	}

	// Tag matching
	if len(selector.Tags) > 0 {
		for key, value := range selector.Tags {
			if targetValue, exists := target.Tags[key]; !exists || targetValue != value {
				return false, nil
			}
		}
	}

	// Expression matching (CEL - simplified for now)
	if selector.Expression != "" {
		matched, err := c.evaluateExpression(target, selector.Expression)
		if err != nil {
			return false, fmt.Errorf("failed to evaluate expression: %w", err)
		}
		if !matched {
			return false, nil
		}
	}

	return true, nil
}

// GetCandidateSteps returns all steps that could apply to a target
func (c *RuleBasedClassifier) GetCandidateSteps(target entity.Target, steps []config.Step) ([]config.Step, error) {
	var candidates []config.Step

	for _, step := range steps {
		if !step.Enabled {
			continue
		}

		matched, err := c.MatchTarget(target, step.Selector)
		if err != nil {
			return nil, err
		}

		if matched {
			candidates = append(candidates, step)
		}
	}

	return candidates, nil
}

// matchProtocolGuesses uses heuristics to match protocol guesses
func (c *RuleBasedClassifier) matchProtocolGuesses(target entity.Target, protoGuesses []string) bool {
	if target.Service == nil {
		return false
	}

	// Get likely protocols for this port
	likelyProtocols := c.protocolMap[strconv.Itoa(target.Service.Port)]

	// Check banner/service name for protocol hints
	banner := strings.ToLower(target.Service.Banner)
	serviceName := strings.ToLower(target.Service.ServiceName)

	for _, guess := range protoGuesses {
		guessLower := strings.ToLower(guess)

		// Check against likely protocols
		for _, likely := range likelyProtocols {
			if strings.Contains(likely, guessLower) {
				return true
			}
		}

		// Check banner for protocol hints
		if banner != "" && strings.Contains(banner, guessLower) {
			return true
		}

		// Check service name
		if serviceName != "" && strings.Contains(serviceName, guessLower) {
			return true
		}

		// Special cases
		switch guessLower {
		case "tls", "ssl":
			if target.Service.Port == 443 || target.Service.Port == 8443 || target.Service.Port == 8883 {
				return true
			}
			if strings.Contains(banner, "ssl") || strings.Contains(banner, "tls") {
				return true
			}
		case "http":
			if target.Service.Port == 80 || target.Service.Port == 8080 || target.Service.Port == 8000 {
				return true
			}
		case "https":
			if target.Service.Port == 443 || target.Service.Port == 8443 {
				return true
			}
		case "mqtt":
			if target.Service.Port == 1883 || target.Service.Port == 8883 {
				return true
			}
		case "mqtt-tls":
			if target.Service.Port == 8883 {
				return true
			}
		}
	}

	return false
}

// matchHostname matches hostname patterns (supports wildcards)
func (c *RuleBasedClassifier) matchHostname(hostname, pattern string) bool {
	// Simple wildcard matching
	if pattern == "*" {
		return true
	}

	if strings.Contains(pattern, "*") {
		// Convert to regex
		regexPattern := strings.ReplaceAll(pattern, "*", ".*")
		regexPattern = "^" + regexPattern + "$"
		matched, _ := regexp.MatchString(regexPattern, hostname)
		return matched
	}

	return strings.EqualFold(hostname, pattern)
}

// matchIPRange checks if an IP falls within a range
func (c *RuleBasedClassifier) matchIPRange(ip net.IP, rangeStr string) bool {
	// Check if it's a CIDR
	if strings.Contains(rangeStr, "/") {
		_, network, err := net.ParseCIDR(rangeStr)
		if err == nil && network.Contains(ip) {
			return true
		}
	}

	// Check if it's a single IP
	rangeIP := net.ParseIP(rangeStr)
	if rangeIP != nil && rangeIP.Equal(ip) {
		return true
	}

	return false
}

// evaluateExpression evaluates a CEL expression (simplified implementation)
func (c *RuleBasedClassifier) evaluateExpression(target entity.Target, expression string) (bool, error) {
	// This is a simplified implementation of expression evaluation
	// In a real implementation, you would use the CEL library

	// For now, support basic expressions like "port == 80" or "protocol == 'tcp'"
	expression = strings.TrimSpace(expression)

	if strings.Contains(expression, "port") && target.Service != nil {
		if strings.Contains(expression, "== 80") {
			return target.Service.Port == 80, nil
		}
		if strings.Contains(expression, "== 443") {
			return target.Service.Port == 443, nil
		}
	}

	if strings.Contains(expression, "protocol") {
		if strings.Contains(expression, "== 'tcp'") {
			return target.Protocol == "tcp", nil
		}
		if strings.Contains(expression, "== 'udp'") {
			return target.Protocol == "udp", nil
		}
	}

	// Default to true for unsupported expressions
	return true, nil
}

// calculateMatchScore calculates a confidence score for the match
func (c *RuleBasedClassifier) calculateMatchScore(target entity.Target, selector config.Selector) float64 {
	score := 0.0
	factors := 0

	// Port match contributes highly
	if len(selector.Ports) > 0 && target.Service != nil {
		for _, port := range selector.Ports {
			if target.Service.Port == port {
				score += 0.4
				break
			}
		}
		factors++
	}

	// Protocol match
	if len(selector.Protocols) > 0 {
		for _, protocol := range selector.Protocols {
			if target.Protocol == protocol {
				score += 0.3
				break
			}
		}
		factors++
	}

	// Service name match
	if len(selector.Services) > 0 && target.Service != nil {
		for _, serviceName := range selector.Services {
			if strings.EqualFold(target.Service.ServiceName, serviceName) {
				score += 0.5
				break
			}
		}
		factors++
	}

	// Protocol guesses match
	if len(selector.ProtoGuesses) > 0 && target.Service != nil {
		if c.matchProtocolGuesses(target, selector.ProtoGuesses) {
			score += 0.2
		}
		factors++
	}

	// Tag matches
	if len(selector.Tags) > 0 {
		matchedTags := 0
		for key, value := range selector.Tags {
			if targetValue, exists := target.Tags[key]; exists && targetValue == value {
				matchedTags++
			}
		}
		if matchedTags > 0 {
			score += 0.1 * float64(matchedTags) / float64(len(selector.Tags))
		}
		factors++
	}

	if factors == 0 {
		return 1.0 // Perfect match if no specific criteria
	}

	return score
}

// generateMatchReason generates a human-readable reason for the match
func (c *RuleBasedClassifier) generateMatchReason(target entity.Target, selector config.Selector) string {
	var reasons []string

	if len(selector.Ports) > 0 && target.Service != nil {
		for _, port := range selector.Ports {
			if target.Service.Port == port {
				reasons = append(reasons, fmt.Sprintf("port %d", port))
				break
			}
		}
	}

	if len(selector.Protocols) > 0 {
		for _, protocol := range selector.Protocols {
			if target.Protocol == protocol {
				reasons = append(reasons, fmt.Sprintf("protocol %s", protocol))
				break
			}
		}
	}

	if len(selector.Services) > 0 && target.Service != nil {
		for _, serviceName := range selector.Services {
			if strings.EqualFold(target.Service.ServiceName, serviceName) {
				reasons = append(reasons, fmt.Sprintf("service %s", serviceName))
				break
			}
		}
	}

	if len(selector.ProtoGuesses) > 0 {
		reasons = append(reasons, "protocol heuristics")
	}

	if len(selector.Tags) > 0 {
		reasons = append(reasons, "tag matching")
	}

	if selector.Expression != "" {
		reasons = append(reasons, "custom expression")
	}

	if len(reasons) == 0 {
		return "default match"
	}

	return strings.Join(reasons, ", ")
}

// getDefaultProtocolMap returns a default mapping of ports to likely protocols
func getDefaultProtocolMap() map[string][]string {
	return map[string][]string{
		"21":   {"ftp"},
		"22":   {"ssh"},
		"23":   {"telnet"},
		"25":   {"smtp"},
		"53":   {"dns"},
		"80":   {"http"},
		"110":  {"pop3"},
		"143":  {"imap"},
		"443":  {"https", "tls"},
		"993":  {"imaps", "tls"},
		"995":  {"pop3s", "tls"},
		"1883": {"mqtt"},
		"3306": {"mysql"},
		"5432": {"postgresql"},
		"8080": {"http"},
		"8443": {"https", "tls"},
		"8883": {"mqtt-tls", "mqtt", "tls"},
	}
}

// getDefaultRules returns default classification rules
func getDefaultRules() []ClassificationRule {
	return []ClassificationRule{
		{
			Name:        "HTTP Services",
			Ports:       []int{80, 8080, 8000, 8888},
			Protocols:   []string{"http"},
			Services:    []string{"http", "httpd", "apache", "nginx"},
			Priority:    100,
			Description: "HTTP web servers",
		},
		{
			Name:        "HTTPS Services",
			Ports:       []int{443, 8443},
			Protocols:   []string{"https", "tls"},
			Services:    []string{"https", "http-ssl"},
			Priority:    100,
			Description: "HTTPS web servers",
		},
		{
			Name:        "SSH Services",
			Ports:       []int{22},
			Protocols:   []string{"ssh"},
			Services:    []string{"ssh", "openssh"},
			Priority:    100,
			Description: "SSH servers",
		},
		{
			Name:        "MQTT Services",
			Ports:       []int{1883, 8883},
			Protocols:   []string{"mqtt"},
			Services:    []string{"mqtt"},
			Priority:    90,
			Description: "MQTT brokers",
		},
		{
			Name:        "Database Services",
			Ports:       []int{3306, 5432, 1433, 5984},
			Services:    []string{"mysql", "postgresql", "mssql", "couchdb"},
			Priority:    80,
			Description: "Database servers",
		},
	}
}
