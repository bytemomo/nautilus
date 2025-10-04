package domain

import (
	"context"
	"time"
)

type PluginExecutor interface {
	Supports(transport string) bool
	Run(ctx context.Context, params map[string]string, t HostPort, timeout time.Duration) (RunResult, error)
}

type ResultRepo interface {
	Save(target HostPort, res RunResult) error
}

type ReportWriter interface {
	Aggregate(all []RunResult) (string, error)
}
