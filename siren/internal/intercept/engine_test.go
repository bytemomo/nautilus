package intercept

import (
	"context"
	"testing"
	"time"
)

func TestEngine_Evaluate_SingleRule(t *testing.T) {
	ruleSet := &RuleSet{
		Rules: []*Rule{
			{
				Name:    "Log all",
				Enabled: true,
				Match:   &MatchCriteria{},
				Action: &Action{
					Type: ActionLog,
					LogParams: &LogParams{
						Message: "test log",
					},
				},
			},
		},
	}
	engine, err := NewEngine(ruleSet, nil)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	info := &TrafficInfo{
		Payload: []byte("some data"),
	}

	result, err := engine.Evaluate(context.Background(), info)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if result.Type != ActionPass {
		t.Errorf("Evaluate() result.Type = %v, want %v", result.Type, ActionPass)
	}
	if !result.Logged {
		t.Error("Evaluate() result.Logged = false, want true")
	}
}

func TestEngine_Evaluate_MultipleRules(t *testing.T) {
	ruleSet := &RuleSet{
		Rules: []*Rule{
			{
				Name:     "Delay rule",
				Enabled:  true,
				Priority: 10,
				Match:    &MatchCriteria{},
				Action: &Action{
					Type: ActionDelay,
					DelayParams: &DelayParams{
						Duration: "10ms",
					},
				},
			},
			{
				Name:     "Log all",
				Enabled:  true,
				Priority: 0,
				Match:    &MatchCriteria{},
				Action: &Action{
					Type: ActionLog,
					LogParams: &LogParams{
						Message: "test log",
					},
				},
			},
		},
	}
	engine, err := NewEngine(ruleSet, nil)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	info := &TrafficInfo{
		Payload: []byte("some data"),
	}

	result, err := engine.Evaluate(context.Background(), info)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if result.Type != ActionPass {
		t.Errorf("Evaluate() result.Type = %v, want %v", result.Type, ActionPass)
	}
	if !result.Logged {
		t.Error("Evaluate() result.Logged = false, want true")
	}
	if result.Delay != 10*time.Millisecond {
		t.Errorf("Evaluate() result.Delay = %v, want %v", result.Delay, 10*time.Millisecond)
	}
}

func TestEngine_Evaluate_DropTakesPrecedence(t *testing.T) {
	ruleSet := &RuleSet{
		Rules: []*Rule{
			{
				Name:     "Drop rule",
				Enabled:  true,
				Priority: 10,
				Match:    &MatchCriteria{},
				Action:   &Action{Type: ActionDrop},
			},
			{
				Name:     "Log all",
				Enabled:  true,
				Priority: 0,
				Match:    &MatchCriteria{},
				Action: &Action{
					Type: ActionLog,
					LogParams: &LogParams{
						Message: "test log",
					},
				},
			},
		},
	}
	engine, err := NewEngine(ruleSet, nil)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	info := &TrafficInfo{
		Payload: []byte("some data"),
	}

	result, err := engine.Evaluate(context.Background(), info)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if result.Type != ActionDrop {
		t.Errorf("Evaluate() result.Type = %v, want %v", result.Type, ActionDrop)
	}
	if !result.Drop {
		t.Error("Evaluate() result.Drop = false, want true")
	}
	if !result.Logged {
		t.Error("Evaluate() result.Logged = false, want true")
	}
}
