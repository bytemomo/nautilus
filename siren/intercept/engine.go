package intercept

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// Engine evaluates traffic against rules and executes actions
type Engine struct {
	ruleSet *RuleSet
	mu      sync.RWMutex
	stats   *EngineStats
	logger  Logger
}

// EngineStats tracks engine statistics
type EngineStats struct {
	mu               sync.RWMutex
	TotalEvaluations uint64
	RulesMatched     uint64
	RulesFailed      uint64
	ActionsExecuted  uint64
	ActionsFailed    uint64
}

// Logger interface for engine logging
type Logger interface {
	Trace(args ...interface{})
	Debug(args ...interface{})
	Info(args ...interface{})
	Warn(args ...interface{})
	Error(args ...interface{})
}

// NewEngine creates a new interception engine
func NewEngine(ruleSet *RuleSet, logger Logger) (*Engine, error) {
	if ruleSet == nil {
		return nil, fmt.Errorf("rule set cannot be nil")
	}

	// Compile rules
	if err := ruleSet.Compile(); err != nil {
		return nil, fmt.Errorf("failed to compile rules: %w", err)
	}

	// Sort by priority
	ruleSet.SortByPriority()

	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	return &Engine{
		ruleSet: ruleSet,
		stats:   &EngineStats{},
		logger:  logger,
	}, nil
}

// Evaluate evaluates traffic against all matching rules and combines their actions.
// It processes rules in priority order. If multiple rules modify the payload,
// the modifications are chained. Terminal actions like Drop or Disconnect
// take precedence. All log actions are executed.
func (e *Engine) Evaluate(ctx context.Context, info *TrafficInfo) (*ActionResult, error) {
	e.logger.Trace("Evaluating packet: %+v", info)
	e.stats.mu.Lock()
	e.stats.TotalEvaluations++
	e.stats.mu.Unlock()

	e.mu.RLock()
	rules := e.ruleSet.EnabledRules()
	e.mu.RUnlock()

	finalResult := &ActionResult{
		Type:            ActionPass,
		ModifiedPayload: info.Payload,
		Metadata:        make(map[string]interface{}),
	}
	currentPayload := info.Payload
	var rulesMatched bool

	// Evaluate rules in priority order
	e.logger.Trace("Number of enabled rules: %d", len(rules))
	for _, rule := range rules {
		e.logger.Trace("Evaluating rule: %s", rule.Name)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Use a copy of TrafficInfo for matching, with the potentially modified payload
		matchInfo := *info
		matchInfo.Payload = currentPayload
		matchInfo.Size = len(currentPayload)

		// Check if rule matches
		if !rule.Match.Matches(&matchInfo) {
			continue
		}

		rulesMatched = true
		e.stats.mu.Lock()
		e.stats.RulesMatched++
		e.stats.mu.Unlock()

		e.logger.Debug("Rule matched: %s (priority: %d)", rule.Name, rule.Priority)

		// Execute action on the current state of the payload
		result, err := rule.Action.Apply(currentPayload)
		if err != nil {
			e.stats.mu.Lock()
			e.stats.ActionsFailed++
			e.stats.mu.Unlock()

			e.logger.Error("Action failed for rule %s: %v", rule.Name, err)
			continue // Skip to next rule
		}

		e.stats.mu.Lock()
		e.stats.ActionsExecuted++
		e.stats.mu.Unlock()

		// Add rule info to result metadata, useful for logging and debugging
		if result.Metadata == nil {
			result.Metadata = make(map[string]interface{})
		}
		result.Metadata["rule_name"] = rule.Name
		result.Metadata["rule_priority"] = rule.Priority

		// Log the action
		if result.Logged {
			finalResult.Logged = true
			e.logAction(rule, result, &matchInfo)
		}

		// Update payload for the next rule in the chain
		if result.Modified {
			currentPayload = result.ModifiedPayload
			finalResult.Modified = true
		}

		// Merge results: highest precedence action wins
		if result.Disconnect {
			finalResult.Disconnect = true
		}
		if result.Drop {
			finalResult.Drop = true
		}
		if result.Delay > finalResult.Delay {
			finalResult.Delay = result.Delay
		}
		if result.Duplicate > finalResult.Duplicate {
			finalResult.Duplicate = result.Duplicate
		}

		// Merge metadata (later rule with same key wins)
		for k, v := range result.Metadata {
			finalResult.Metadata[k] = v
		}
	}

	// If no rules matched, return the default pass-through result
	if !rulesMatched {
		return &ActionResult{Type: ActionPass}, nil
	}

	// Finalize the result
	finalResult.ModifiedPayload = currentPayload

	// Set final action type based on precedence
	if finalResult.Disconnect {
		finalResult.Type = ActionDisconnect
	} else if finalResult.Drop {
		finalResult.Type = ActionDrop
	} else if finalResult.Modified {
		finalResult.Type = ActionModify
	} else {
		// If rules matched but didn't result in a terminal action (e.g., only log actions),
		// we consider the final action as a pass-through. The logging has already occurred.
		finalResult.Type = ActionPass
	}

	return finalResult, nil
}

// logAction logs the action execution with improved formatting.
func (e *Engine) logAction(rule *Rule, result *ActionResult, info *TrafficInfo) {
	level := "info"
	message := "Action executed"

	if msg, ok := result.Metadata["message"].(string); ok {
		message = msg
	}
	if lvl, ok := result.Metadata["level"].(string); ok {
		level = lvl
	}

	logMsg := fmt.Sprintf("%s - Rule: %q, Direction: %s, Size: %d bytes",
		message, rule.Name, info.Direction, info.Size)

	if dumpPayload, ok := result.Metadata["dump_payload"].(bool); ok && dumpPayload {
		const maxPayloadLogSize = 256
		payloadStr := fmt.Sprintf("%q", info.Payload)
		if len(payloadStr) > maxPayloadLogSize {
			payloadStr = payloadStr[:maxPayloadLogSize] + "..."
		}
		logMsg += fmt.Sprintf("\nPayload: %s", payloadStr)
	}

	switch strings.ToLower(level) {
	case "debug", "trace":
		e.logger.Debug("%s", logMsg)
	case "warn", "warning":
		e.logger.Warn("%s", logMsg)
	case "error":
		e.logger.Error("%s", logMsg)
	default:
		e.logger.Info("%s", logMsg)
	}
}

// UpdateRuleSet updates the engine's rule set
func (e *Engine) UpdateRuleSet(ruleSet *RuleSet) error {
	if ruleSet == nil {
		return fmt.Errorf("rule set cannot be nil")
	}

	// Compile rules
	if err := ruleSet.Compile(); err != nil {
		return fmt.Errorf("failed to compile rules: %w", err)
	}

	// Sort by priority
	ruleSet.SortByPriority()

	e.mu.Lock()
	defer e.mu.Unlock()
	e.ruleSet = ruleSet

	e.logger.Info("Rule set updated: %d rules", len(ruleSet.Rules))
	return nil
}

// AddRule adds a single rule to the engine
func (e *Engine) AddRule(rule *Rule) error {
	if rule == nil {
		return fmt.Errorf("rule cannot be nil")
	}

	if rule.Match == nil {
		return fmt.Errorf("rule must have match criteria")
	}

	if rule.Action == nil {
		return fmt.Errorf("rule must have an action")
	}

	// Compile rule
	if err := rule.Match.Compile(); err != nil {
		return fmt.Errorf("failed to compile match criteria: %w", err)
	}

	if err := rule.Action.Compile(); err != nil {
		return fmt.Errorf("failed to compile action: %w", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Add to rule set
	e.ruleSet.Rules = append(e.ruleSet.Rules, rule)

	// Re-sort by priority
	e.ruleSet.SortByPriority()

	e.logger.Info("Rule added: %s (priority: %d)", rule.Name, rule.Priority)
	return nil
}

// RemoveRule removes a rule by name
func (e *Engine) RemoveRule(name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i, rule := range e.ruleSet.Rules {
		if rule.Name == name {
			// Remove rule
			e.ruleSet.Rules = append(e.ruleSet.Rules[:i], e.ruleSet.Rules[i+1:]...)
			e.logger.Info("Rule removed: %s", name)
			return nil
		}
	}

	return fmt.Errorf("rule not found: %s", name)
}

// EnableRule enables a rule by name
func (e *Engine) EnableRule(name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, rule := range e.ruleSet.Rules {
		if rule.Name == name {
			rule.Enabled = true
			e.logger.Info("Rule enabled: %s", name)
			return nil
		}
	}

	return fmt.Errorf("rule not found: %s", name)
}

// DisableRule disables a rule by name
func (e *Engine) DisableRule(name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, rule := range e.ruleSet.Rules {
		if rule.Name == name {
			rule.Enabled = false
			e.logger.Info("Rule disabled: %s", name)
			return nil
		}
	}

	return fmt.Errorf("rule not found: %s", name)
}

// GetRule retrieves a rule by name
func (e *Engine) GetRule(name string) (*Rule, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, rule := range e.ruleSet.Rules {
		if rule.Name == name {
			return rule, nil
		}
	}

	return nil, fmt.Errorf("rule not found: %s", name)
}

// GetAllRules returns all rules
func (e *Engine) GetAllRules() []*Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Return a copy to prevent external modification
	rules := make([]*Rule, len(e.ruleSet.Rules))
	copy(rules, e.ruleSet.Rules)
	return rules
}

// Stats returns engine statistics
func (e *Engine) Stats() *EngineStats {
	e.stats.mu.RLock()
	defer e.stats.mu.RUnlock()

	// Return a copy
	return &EngineStats{
		TotalEvaluations: e.stats.TotalEvaluations,
		RulesMatched:     e.stats.RulesMatched,
		RulesFailed:      e.stats.RulesFailed,
		ActionsExecuted:  e.stats.ActionsExecuted,
		ActionsFailed:    e.stats.ActionsFailed,
	}
}

// ResetStats resets engine statistics
func (e *Engine) ResetStats() {
	e.stats.mu.Lock()
	defer e.stats.mu.Unlock()

	e.stats.TotalEvaluations = 0
	e.stats.RulesMatched = 0
	e.stats.RulesFailed = 0
	e.stats.ActionsExecuted = 0
	e.stats.ActionsFailed = 0

	e.logger.Info("Engine statistics reset")
}

// GetRuleSet returns the current rule set
func (e *Engine) GetRuleSet() *RuleSet {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.ruleSet
}
