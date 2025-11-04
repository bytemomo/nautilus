package runner

import (
	"context"
	"time"

	"bytemomo/kraken/internal/domain"
)

// ModuleExecutor is an interface for running modules.
type ModuleExecutor interface {
	Supports(m *domain.Module) bool
	Run(ctx context.Context, m *domain.Module, params map[string]any, t domain.HostPort, timeout time.Duration) (domain.RunResult, error)
}
