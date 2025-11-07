package intercept

import (
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
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

// ParseActionType converts a string to an ActionType, returning an error if unknown.
func ParseActionType(s string) (ActionType, error) {
	switch strings.ToLower(s) {
	case "pass", "allow":
		return ActionPass, nil
	case "drop", "block":
		return ActionDrop, nil
	case "delay", "sleep":
		return ActionDelay, nil
	case "modify", "transform", "mutate":
		return ActionModify, nil
	case "duplicate", "dup", "clone":
		return ActionDuplicate, nil
	case "throttle", "limit", "rate_limit":
		return ActionThrottle, nil
	case "disconnect", "close", "terminate":
		return ActionDisconnect, nil
	case "log", "record":
		return ActionLog, nil
	case "chain", "sequence":
		return ActionChain, nil
	default:
		return ActionPass, fmt.Errorf("unknown action type: %q", s)
	}
}

// UnmarshalYAML allows specifying action types as human-readable strings.
func (at *ActionType) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("action type must be a string, got %v", value.Tag)
	}
	parsed, err := ParseActionType(value.Value)
	if err != nil {
		return err
	}
	*at = parsed
	return nil
}

// Action defines a single, executable action on matched traffic.
// It uses dedicated structs for parameters to improve clarity and type safety.
type Action struct {
	Type     ActionType             `yaml:"type" json:"type"`
	Metadata map[string]interface{} `yaml:"metadata,omitempty" json:"metadata,omitempty"`

	// Action-specific parameters
	DropParams       *DropParams       `yaml:"drop,omitempty" json:"drop,omitempty"`
	DelayParams      *DelayParams      `yaml:"delay,omitempty" json:"delay,omitempty"`
	ModifyParams     *ModifyParams     `yaml:"modify,omitempty" json:"modify,omitempty"`
	DuplicateParams  *DuplicateParams  `yaml:"duplicate,omitempty" json:"duplicate,omitempty"`
	ThrottleParams   *ThrottleParams   `yaml:"throttle,omitempty" json:"throttle,omitempty"`
	DisconnectParams *DisconnectParams `yaml:"disconnect,omitempty" json:"disconnect,omitempty"`
	LogParams        *LogParams        `yaml:"log,omitempty" json:"log,omitempty"`
	ChainParams      *ChainParams      `yaml:"chain,omitempty" json:"chain,omitempty"`
}

// DropParams holds parameters for the Drop action.
type DropParams struct {
	Probability float64 `yaml:"probability,omitempty" json:"probability,omitempty"` // 0.0 to 1.0
}

// DelayParams holds parameters for the Delay action.
type DelayParams struct {
	Duration       string `yaml:"duration" json:"duration"` // e.g., "100ms", "1s"
	Jitter         string `yaml:"jitter,omitempty" json:"jitter,omitempty"`     // e.g., "50ms"
	durationParsed time.Duration
	jitterParsed   time.Duration
}

// ModifyParams holds parameters for the Modify action.
type ModifyParams struct {
	Operation   string `yaml:"operation" json:"operation"` // replace, corrupt_bytes, truncate, append
	Pattern     string `yaml:"pattern,omitempty" json:"pattern,omitempty"`
	Replacement string `yaml:"replacement,omitempty" json:"replacement,omitempty"`
	Positions   []int  `yaml:"positions,omitempty" json:"positions,omitempty"` // For corrupt_bytes
	Bytes       []byte `yaml:"bytes,omitempty" json:"bytes,omitempty"`         // For append
	TruncateAt  *int   `yaml:"truncate_at,omitempty" json:"truncate_at,omitempty"`
}

// DuplicateParams holds parameters for the Duplicate action.
type DuplicateParams struct {
	Count       int    `yaml:"count,omitempty" json:"count,omitempty"` // Number of duplicates (default 1)
	Delay       string `yaml:"delay,omitempty" json:"delay,omitempty"` // Delay between duplicates
	delayParsed time.Duration
}

// ThrottleParams holds parameters for the Throttle action.
type ThrottleParams struct {
	Rate            string `yaml:"rate" json:"rate"`   // e.g., "10KB/s", "1MB/s"
	Burst           string `yaml:"burst,omitempty" json:"burst,omitempty"` // e.g., "1KB"
	rateBytesPerSec int
	burstBytes      int
}

// DisconnectParams holds parameters for the Disconnect action.
type DisconnectParams struct {
	CloseType string `yaml:"close_type,omitempty" json:"close_type,omitempty"` // "abrupt" or "graceful"
}

// LogParams holds parameters for the Log action.
type LogParams struct {
	Level       string `yaml:"level,omitempty" json:"level,omitempty"` // info, debug, trace
	Message     string `yaml:"message" json:"message"`
	DumpPayload bool   `yaml:"dump_payload,omitempty" json:"dump_payload,omitempty"`
}

// ChainParams holds parameters for the Chain action.
type ChainParams struct {
	Actions []*Action `yaml:"actions" json:"actions"`
}

// Compile prepares the action and its parameters for execution.
func (a *Action) Compile() error {
	var err error
	switch a.Type {
	case ActionDelay:
		if a.DelayParams == nil {
			return fmt.Errorf("delay action requires parameters")
		}
		err = a.DelayParams.compile()
	case ActionModify:
		if a.ModifyParams == nil {
			return fmt.Errorf("modify action requires parameters")
		}
		err = a.ModifyParams.compile()
	case ActionDuplicate:
		// Params are optional, use defaults if nil
		if a.DuplicateParams == nil {
			a.DuplicateParams = &DuplicateParams{}
		}
		err = a.DuplicateParams.compile()
	case ActionThrottle:
		if a.ThrottleParams == nil {
			return fmt.Errorf("throttle action requires parameters")
		}
		err = a.ThrottleParams.compile()
	case ActionChain:
		if a.ChainParams == nil || len(a.ChainParams.Actions) == 0 {
			return fmt.Errorf("chain action requires at least one sub-action")
		}
		err = a.ChainParams.compile()
	case ActionLog:
		if a.LogParams == nil {
			return fmt.Errorf("log action requires parameters")
		}
	case ActionDrop, ActionPass, ActionDisconnect:
	default:
		return fmt.Errorf("unknown action type: %s", a.Type)
	}
	return err
}

func (p *DelayParams) compile() error {
	if p.Duration == "" {
		return fmt.Errorf("delay action requires duration")
	}
	dur, err := time.ParseDuration(p.Duration)
	if err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}
	p.durationParsed = dur

	if p.Jitter != "" {
		jit, err := time.ParseDuration(p.Jitter)
		if err != nil {
			return fmt.Errorf("invalid jitter: %w", err)
		}
		p.jitterParsed = jit
	}
	return nil
}

func (p *ModifyParams) compile() error {
	switch p.Operation {
	case "replace", "corrupt_bytes", "truncate", "append":
		return nil
	default:
		return fmt.Errorf("invalid modify operation: %s", p.Operation)
	}
}

func (p *DuplicateParams) compile() error {
	if p.Count <= 0 {
		p.Count = 1 // Default to 1 duplicate
	}
	if p.Delay != "" {
		dur, err := time.ParseDuration(p.Delay)
		if err != nil {
			return fmt.Errorf("invalid delay: %w", err)
		}
		p.delayParsed = dur
	}
	return nil
}

func (p *ThrottleParams) compile() error {
	rate, err := parseDataRate(p.Rate)
	if err != nil {
		return fmt.Errorf("invalid rate: %w", err)
	}
	p.rateBytesPerSec = rate

	if p.Burst != "" {
		burst, err := parseDataSize(p.Burst)
		if err != nil {
			return fmt.Errorf("invalid burst: %w", err)
		}
		p.burstBytes = burst
	}
	return nil
}

func (p *ChainParams) compile() error {
	for i, childAction := range p.Actions {
		if err := childAction.Compile(); err != nil {
			return fmt.Errorf("compiling action %d in chain: %w", i, err)
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

// Apply executes the action on the payload and returns the result.
func (a *Action) Apply(payload []byte) (*ActionResult, error) {
	result := &ActionResult{
		Type:     a.Type,
		Metadata: make(map[string]interface{}),
	}

	// Copy custom metadata from the action definition
	for k, v := range a.Metadata {
		result.Metadata[k] = v
	}

	switch a.Type {
	case ActionPass:
		return result, nil
	case ActionDrop:
		return a.applyDrop(result)
	case ActionDelay:
		return a.applyDelay(result)
	case ActionModify:
		return a.applyModify(result, payload)
	case ActionDuplicate:
		return a.applyDuplicate(result)
	case ActionThrottle:
		return a.applyThrottle(result)
	case ActionDisconnect:
		return a.applyDisconnect(result)
	case ActionLog:
		return a.applyLog(result)
	case ActionChain:
		return a.applyChain(result, payload)
	default:
		return nil, fmt.Errorf("cannot apply unknown action type: %s", a.Type)
	}
}

func (a *Action) applyDrop(result *ActionResult) (*ActionResult, error) {
	p := a.DropParams
	if p != nil && p.Probability > 0 && p.Probability < 1.0 {
		if randomFloat() > p.Probability {
			return result, nil
		}
	}
	result.Drop = true
	return result, nil
}

func (a *Action) applyDelay(result *ActionResult) (*ActionResult, error) {
	p := a.DelayParams
	delay := p.durationParsed
	if p.jitterParsed > 0 {
		jitter := time.Duration(randomFloat()*2-1) * p.jitterParsed
		delay += jitter
		if delay < 0 {
			delay = 0
		}
	}
	result.Delay = delay
	return result, nil
}

func (a *Action) applyModify(result *ActionResult, payload []byte) (*ActionResult, error) {
	modified, err := a.ModifyParams.apply(payload)
	if err != nil {
		return nil, err
	}
	result.ModifiedPayload = modified
	result.Modified = true
	return result, nil
}

func (a *Action) applyDuplicate(result *ActionResult) (*ActionResult, error) {
	p := a.DuplicateParams
	result.Duplicate = p.Count
	result.Delay = p.delayParsed
	return result, nil
}

func (a *Action) applyThrottle(result *ActionResult) (*ActionResult, error) {
	p := a.ThrottleParams
	result.Metadata["rate"] = p.rateBytesPerSec
	result.Metadata["burst"] = p.burstBytes
	return result, nil
}

func (a *Action) applyDisconnect(result *ActionResult) (*ActionResult, error) {
	p := a.DisconnectParams
	result.Disconnect = true
	if p != nil {
		result.Metadata["close_type"] = p.CloseType
	}
	return result, nil
}

func (a *Action) applyLog(result *ActionResult) (*ActionResult, error) {
	p := a.LogParams
	result.Logged = true
	result.Metadata["level"] = p.Level
	result.Metadata["message"] = p.Message
	result.Metadata["dump_payload"] = p.DumpPayload
	return result, nil
}

func (a *Action) applyChain(result *ActionResult, payload []byte) (*ActionResult, error) {
	currentPayload := payload
	finalResult := result

	for _, childAction := range a.ChainParams.Actions {
		childResult, err := childAction.Apply(currentPayload)
		if err != nil {
			return nil, err
		}

		if childResult.Drop {
			finalResult.Drop = true
			return finalResult, nil
		}
		if childResult.Disconnect {
			finalResult.Disconnect = true
		}
		if childResult.Delay > finalResult.Delay {
			finalResult.Delay = childResult.Delay
		}
		if childResult.Duplicate > finalResult.Duplicate {
			finalResult.Duplicate = childResult.Duplicate
		}
		if childResult.Modified {
			currentPayload = childResult.ModifiedPayload
			finalResult.Modified = true
		}
		if childResult.Logged {
			finalResult.Logged = true
		}
		for k, v := range childResult.Metadata {
			finalResult.Metadata[k] = v
		}
	}

	if finalResult.Modified {
		finalResult.ModifiedPayload = currentPayload
	}
	return finalResult, nil
}

// apply applies the modification operation to the payload.
func (p *ModifyParams) apply(payload []byte) ([]byte, error) {
	switch p.Operation {
	case "replace":
		if p.Pattern == "" {
			return payload, nil
		}
		return []byte(strings.ReplaceAll(string(payload), p.Pattern, p.Replacement)), nil
	case "corrupt_bytes":
		if len(p.Positions) == 0 {
			return payload, nil
		}
		modified := make([]byte, len(payload))
		copy(modified, payload)
		for _, pos := range p.Positions {
			if pos >= 0 && pos < len(modified) {
				modified[pos] ^= byte(randomInt(256))
			}
		}
		return modified, nil
	case "truncate":
		if p.TruncateAt == nil {
			return payload, nil
		}
		truncateAt := *p.TruncateAt
		if truncateAt < 0 {
			truncateAt = 0
		}
		if truncateAt > len(payload) {
			return payload, nil
		}
		return payload[:truncateAt], nil
	case "append":
		if len(p.Bytes) == 0 {
			return payload, nil
		}
		return append(payload, p.Bytes...), nil
	default:
		return nil, fmt.Errorf("unknown modify operation: %s", p.Operation)
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

func randomFloat() float64 {
	b := make([]byte, 8)
	rand.Read(b)
	val := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
	return float64(val) / float64(^uint64(0))
}

func randomInt(max int) int {
	if max <= 0 {
		return 0
	}
	return int(randomFloat() * float64(max))
}
