package domain

import (
	"context"
	"time"

	"bytemomo/kraken/internal/module"
)

// ModuleExecutor is the interface for module-based executors
// Supports both V1 and V2 modules
type ModuleExecutor interface {
	Supports(m *module.Module) bool
	Run(ctx context.Context, m *module.Module, params map[string]any, t HostPort, timeout time.Duration) (RunResult, error)
}

type ResultRepo interface {
	Save(target HostPort, res RunResult) error
}

type ReportWriter interface {
	Aggregate(all []RunResult) (string, error)
}
