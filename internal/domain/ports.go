package domain

import "context"

type PluginExecutor interface {
	// ORCA sends only {host,port}
	Run(ctx context.Context, endpoint string, t HostPort) (RunResult, error)
}

type ResultRepo interface {
	Save(target HostPort, res RunResult) error
}

type ReportWriter interface {
	Aggregate(all []RunResult) (string, error)
}
