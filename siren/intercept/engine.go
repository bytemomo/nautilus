package intercept

import (
	"context"
	"fmt"
	"log"
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
	mu              sync.RWMutex
	TotalEvaluations uint64
	RulesMatched     uint64
	RulesFailed      uint64
	ActionsExecuted  uint64
	ActionsFailed    uint64
}

// Logger interface for engine logging
type Logger interface {
	Debug(format string, args ...interface{})
	Info(format string, args ...interface{})
	Warn(format string, args ...interface{})
	Error(format string, args ...interface{})
}

// DefaultLogger is a simple logger implementation
type DefaultLogger struct {
	enabled bool
}

func (l *DefaultLogger) Debug(format string, args ...interface{}) {
	if l.enabled {
		log.Printf("[DEBUG] "+format, args...)
	}
}

func (l *DefaultLogger) Info(format string, args ...interface{}) {
	if l.enabled {
		log.Printf("[INFO] "+format, args...)
	}
}

func (l *DefaultLogger) Warn(format string, args ...interface{}) {
	if l.enabled {
		log.Printf("[WARN] "+format, args...)
	}
}

func (l *DefaultLogger) Error(format string, args ...interface{}) {
	if l.enabled {
		log.Printf("[ERROR] "+format, args...)
	}
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
		logger = &DefaultLogger{enabled: true}
	}

	return &Engine{
		ruleSet: ruleSet,
		stats:   &EngineStats{},
		logger:  logger,
	}, nil
}

// Evaluate evaluates traffic against rules and returns the action to execute
func (e *Engine) Evaluate(ctx context.Context, info *TrafficInfo) (*ActionResult, error) {
	e.stats.mu.Lock()
	e.stats.TotalEvaluations++
	e.stats.mu.Unlock()

	e.mu.RLock()
	rules := e.ruleSet.EnabledRules()
	e.mu.RUnlock()

	// Evaluate rules in priority order
	for _, rule := range rules {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Check if rule matches
		if !rule.Match.Matches(info) {
			continue
		}

		// Rule matched
		e.stats.mu.Lock()
		e.stats.RulesMatched++
		e.stats.mu.Unlock()

		e.logger.Debug("Rule matched: %s (priority: %d)", rule.Name, rule.Priority)

		// Execute action
		result, err := rule.Action.Apply(info.Payload)
		if err != nil {
			e.stats.mu.Lock()
			e.stats.ActionsFailed++
			e.stats.mu.Unlock()

			e.logger.Error("Action failed for rule %s: %v", rule.Name, err)
			continue
		}

		e.stats.mu.Lock()
		e.stats.ActionsExecuted++
		e.stats.mu.Unlock()

		// Add rule info to result metadata
		if result.Metadata == nil {
			result.Metadata = make(map[string]interface{})
		}
		result.Metadata["rule_name"] = rule.Name
		result.Metadata["rule_priority"] = rule.Priority

		// Log the action if it's a log action or has logging enabled
		if result.Logged {
			e.logAction(rule, result, info)
		}

		// Return first matching rule's action (unless it's just a log action)
		if result.Type != ActionLog {
			return result, nil
		}
	}

	// No rules matched, pass through
	return &ActionResult{
		Type: ActionPass,
	}, nil
}

// logAction logs the action execution
func (e *Engine) logAction(rule *Rule, result *ActionResult, info *TrafficInfo) {
	level := "info"
	message := "Action executed"

	if msg, ok := result.Metadata["message"].(string); ok {
		message = msg
	}
	if lvl, ok := result.Metadata["level"].(string); ok {
		level = lvl
	}

	logMsg := fmt.Sprintf("[%s] %s - Rule: %s, Direction: %s, Size: %d bytes",
		level, message, rule.Name, info.Direction, info.Size)

	if dumpPayload, ok := result.Metadata["dump_payload"].(bool); ok && dumpPayload {
		logMsg += fmt.Sprintf("\nPayload: %q", info.Payload)
	}

	switch level {
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
