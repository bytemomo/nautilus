package intercept

import (
	"crypto/rand"
	"fmt"
	"strings"
	"time"
)

// ActionType represents the type of action to perform
type ActionType int

const (
	ActionPass ActionType = iota
	ActionDrop
	ActionDelay
	ActionModify
	ActionDuplicate
	ActionThrottle
	ActionDisconnect
	ActionLog
	ActionChain
)

func (at ActionType) String() string {
	switch at {
	case ActionPass:
		return "pass"
	case ActionDrop:
		return "drop"
	case ActionDelay:
		return "delay"
	case ActionModify:
		return "modify"
	case ActionDuplicate:
		return "duplicate"
	case ActionThrottle:
		return "throttle"
	case ActionDisconnect:
		return "disconnect"
	case ActionLog:
		return "log"
	case ActionChain:
		return "chain"
	default:
		return "unknown"
	}
}

// ParseActionType converts string to ActionType
func ParseActionType(s string) ActionType {
	switch strings.ToLower(s) {
	case "pass", "allow":
		return ActionPass
	case "drop", "block":
		return ActionDrop
	case "delay", "sleep":
		return ActionDelay
	case "modify", "transform", "mutate":
		return ActionModify
	case "duplicate", "dup", "clone":
		return ActionDuplicate
	case "throttle", "limit", "rate_limit":
		return ActionThrottle
	case "disconnect", "close", "terminate":
		return ActionDisconnect
	case "log", "record":
		return ActionLog
	case "chain", "sequence":
		return ActionChain
	default:
		return ActionPass
	}
}

// Action defines an action to perform on matched traffic
type Action struct {
	Type ActionType `yaml:"type" json:"type"`

	// Drop action
	Probability float64 `yaml:"probability,omitempty" json:"probability,omitempty"` // 0.0 to 1.0

	// Delay action
	Duration string `yaml:"duration,omitempty" json:"duration,omitempty"` // e.g., "100ms", "1s"
	Jitter   string `yaml:"jitter,omitempty" json:"jitter,omitempty"`     // e.g., "50ms"
	durationParsed time.Duration
	jitterParsed   time.Duration

	// Modify action
	Operation   string   `yaml:"operation,omitempty" json:"operation,omitempty"` // replace, corrupt_bytes, truncate, append
	Pattern     string   `yaml:"pattern,omitempty" json:"pattern,omitempty"`
	Replacement string   `yaml:"replacement,omitempty" json:"replacement,omitempty"`
	Positions   []int    `yaml:"positions,omitempty" json:"positions,omitempty"` // For corrupt_bytes
	Bytes       []byte   `yaml:"bytes,omitempty" json:"bytes,omitempty"`         // For append
	TruncateAt  *int     `yaml:"truncate_at,omitempty" json:"truncate_at,omitempty"`

	// Duplicate action
	Count int    `yaml:"count,omitempty" json:"count,omitempty"` // Number of duplicates (default 1)
	Delay string `yaml:"delay,omitempty" json:"delay,omitempty"` // Delay between duplicates
	delayParsed time.Duration

	// Throttle action
	Rate  string `yaml:"rate,omitempty" json:"rate,omitempty"`   // e.g., "10KB/s", "1MB/s"
	Burst string `yaml:"burst,omitempty" json:"burst,omitempty"` // e.g., "1KB"
	rateBytesPerSec int
	burstBytes      int

	// Disconnect action
	CloseType string `yaml:"close_type,omitempty" json:"close_type,omitempty"` // "abrupt" or "graceful"

	// Log action
	Level       string `yaml:"level,omitempty" json:"level,omitempty"`               // info, debug, trace
	Message     string `yaml:"message,omitempty" json:"message,omitempty"`
	DumpPayload bool   `yaml:"dump_payload,omitempty" json:"dump_payload,omitempty"`

	// Chain action
	Actions []*Action `yaml:"actions,omitempty" json:"actions,omitempty"`

	// Custom metadata
	Metadata map[string]interface{} `yaml:"metadata,omitempty" json:"metadata,omitempty"`
}

// Compile prepares the action for execution
func (a *Action) Compile() error {
	switch a.Type {
	case ActionDelay:
		if a.Duration == "" {
			return fmt.Errorf("delay action requires duration")
		}
		dur, err := time.ParseDuration(a.Duration)
		if err != nil {
			return fmt.Errorf("invalid duration: %w", err)
		}
		a.durationParsed = dur

		if a.Jitter != "" {
			jit, err := time.ParseDuration(a.Jitter)
			if err != nil {
				return fmt.Errorf("invalid jitter: %w", err)
			}
			a.jitterParsed = jit
		}

	case ActionModify:
		if a.Operation == "" {
			return fmt.Errorf("modify action requires operation")
		}
		// Validate operation
		switch a.Operation {
		case "replace", "corrupt_bytes", "truncate", "append":
			// Valid operations
		default:
			return fmt.Errorf("invalid operation: %s", a.Operation)
		}

	case ActionDuplicate:
		if a.Count == 0 {
			a.Count = 1 // Default to 1 duplicate (2 total packets)
		}
		if a.Delay != "" {
			dur, err := time.ParseDuration(a.Delay)
			if err != nil {
				return fmt.Errorf("invalid delay: %w", err)
			}
			a.delayParsed = dur
		}

	case ActionThrottle:
		if a.Rate != "" {
			rate, err := parseDataRate(a.Rate)
			if err != nil {
				return fmt.Errorf("invalid rate: %w", err)
			}
			a.rateBytesPerSec = rate
		}
		if a.Burst != "" {
			burst, err := parseDataSize(a.Burst)
			if err != nil {
				return fmt.Errorf("invalid burst: %w", err)
			}
			a.burstBytes = burst
		}

	case ActionChain:
		if len(a.Actions) == 0 {
			return fmt.Errorf("chain action requires at least one action")
		}
		for i, childAction := range a.Actions {
			if err := childAction.Compile(); err != nil {
				return fmt.Errorf("chain action %d: %w", i, err)
			}
		}
	}

	return nil
}

// ActionResult contains the result of applying an action
type ActionResult struct {
	Type            ActionType
	Drop            bool
	Disconnect      bool
	Delay           time.Duration
	Duplicate       int
	ModifiedPayload []byte
	Modified        bool
	Logged          bool
	Metadata        map[string]interface{}
}

// Apply executes the action on the payload
func (a *Action) Apply(payload []byte) (*ActionResult, error) {
	result := &ActionResult{
		Type:     a.Type,
		Metadata: make(map[string]interface{}),
	}

	// Copy custom metadata
	for k, v := range a.Metadata {
		result.Metadata[k] = v
	}

	switch a.Type {
	case ActionPass:
		// Do nothing, pass through
		return result, nil

	case ActionDrop:
		// Check probability
		if a.Probability > 0 && a.Probability < 1.0 {
			if randomFloat() > a.Probability {
				return result, nil // Don't drop
			}
		}
		result.Drop = true
		return result, nil

	case ActionDelay:
		delay := a.durationParsed
		if a.jitterParsed > 0 {
			// Add random jitter: ±jitter
			jitter := time.Duration(randomFloat()*2.0-1.0) * a.jitterParsed
			delay += jitter
			if delay < 0 {
				delay = 0
			}
		}
		result.Delay = delay
		return result, nil

	case ActionModify:
		modified, err := a.applyModification(payload)
		if err != nil {
			return nil, err
		}
		result.ModifiedPayload = modified
		result.Modified = true
		return result, nil

	case ActionDuplicate:
		result.Duplicate = a.Count
		result.Delay = a.delayParsed
		return result, nil

	case ActionThrottle:
		// Throttle calculation would be handled by the proxy
		// Here we just mark the action
		result.Metadata["rate"] = a.rateBytesPerSec
		result.Metadata["burst"] = a.burstBytes
		return result, nil

	case ActionDisconnect:
		result.Disconnect = true
		result.Metadata["close_type"] = a.CloseType
		return result, nil

	case ActionLog:
		result.Logged = true
		result.Metadata["level"] = a.Level
		result.Metadata["message"] = a.Message
		result.Metadata["dump_payload"] = a.DumpPayload
		return result, nil

	case ActionChain:
		// Apply actions in sequence
		currentPayload := payload
		for _, childAction := range a.Actions {
			childResult, err := childAction.Apply(currentPayload)
			if err != nil {
				return nil, err
			}

			// Aggregate results
			if childResult.Drop {
				result.Drop = true
				return result, nil // Stop processing on drop
			}
			if childResult.Disconnect {
				result.Disconnect = true
			}
			if childResult.Delay > result.Delay {
				result.Delay = childResult.Delay
			}
			if childResult.Duplicate > result.Duplicate {
				result.Duplicate = childResult.Duplicate
			}
			if childResult.Modified {
				currentPayload = childResult.ModifiedPayload
				result.Modified = true
			}
			if childResult.Logged {
				result.Logged = true
			}

			// Merge metadata
			for k, v := range childResult.Metadata {
				result.Metadata[k] = v
			}
		}

		if result.Modified {
			result.ModifiedPayload = currentPayload
		}
		return result, nil

	default:
		return result, nil
	}
}

// applyModification applies the modification operation
func (a *Action) applyModification(payload []byte) ([]byte, error) {
	switch a.Operation {
	case "replace":
		if a.Pattern == "" {
			return payload, nil
		}
		// Simple string replacement
		modified := strings.ReplaceAll(string(payload), a.Pattern, a.Replacement)
		return []byte(modified), nil

	case "corrupt_bytes":
		if len(a.Positions) == 0 {
			return payload, nil
		}
		// Copy payload
		modified := make([]byte, len(payload))
		copy(modified, payload)

		// Corrupt bytes at specified positions
		for _, pos := range a.Positions {
			if pos >= 0 && pos < len(modified) {
				// Flip random bits
				modified[pos] ^= byte(randomInt(256))
			}
		}
		return modified, nil

	case "truncate":
		if a.TruncateAt == nil {
			return payload, nil
		}
		truncateAt := *a.TruncateAt
		if truncateAt < 0 {
			truncateAt = 0
		}
		if truncateAt > len(payload) {
			return payload, nil
		}
		modified := make([]byte, truncateAt)
		copy(modified, payload[:truncateAt])
		return modified, nil

	case "append":
		if len(a.Bytes) == 0 {
			return payload, nil
		}
		modified := make([]byte, len(payload)+len(a.Bytes))
		copy(modified, payload)
		copy(modified[len(payload):], a.Bytes)
		return modified, nil

	default:
		return payload, fmt.Errorf("unknown operation: %s", a.Operation)
	}
}

// parseDataRate parses data rate strings like "10KB/s", "1MB/s"
func parseDataRate(s string) (int, error) {
	s = strings.TrimSpace(strings.ToUpper(s))

	// Remove "/s" or "/SEC" suffix
	s = strings.TrimSuffix(s, "/S")
	s = strings.TrimSuffix(s, "/SEC")

	return parseDataSize(s)
}

// parseDataSize parses data size strings like "1KB", "10MB"
func parseDataSize(s string) (int, error) {
	s = strings.TrimSpace(strings.ToUpper(s))

	multipliers := map[string]int{
		"B":  1,
		"KB": 1024,
		"MB": 1024 * 1024,
		"GB": 1024 * 1024 * 1024,
	}

	for suffix, multiplier := range multipliers {
		if strings.HasSuffix(s, suffix) {
			numStr := strings.TrimSpace(strings.TrimSuffix(s, suffix))
			var num int
			_, err := fmt.Sscanf(numStr, "%d", &num)
			if err != nil {
				return 0, err
			}
			return num * multiplier, nil
		}
	}

	// Try parsing as plain number (bytes)
	var num int
	_, err := fmt.Sscanf(s, "%d", &num)
	if err != nil {
		return 0, fmt.Errorf("invalid data size: %s", s)
	}
	return num, nil
}

// randomFloat returns a random float64 between 0.0 and 1.0
func randomFloat() float64 {
	b := make([]byte, 8)
	rand.Read(b)
	// Convert to uint64 and normalize to [0, 1]
	val := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
	return float64(val) / float64(^uint64(0))
}

// randomInt returns a random int between 0 and max-1
func randomInt(max int) int {
	if max <= 0 {
		return 0
	}
	return int(randomFloat() * float64(max))
}
