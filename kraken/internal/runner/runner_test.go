package runner

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"bytemomo/kraken/internal/domain"
	"github.com/sirupsen/logrus"
)

func TestRunnerStopsModuleExecutionOnContextCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exec := &cancelingExecutor{cancel: cancel}

	logger := logrus.New()
	logger.SetOutput(io.Discard)

	r := &Runner{
		Log:       logrus.NewEntry(logger),
		Executors: []ModuleExecutor{exec},
		Store:     noopResultStore{},
		Config: domain.RunnerConfig{
			ResultDirectory: "results",
		},
	}

	campaign := domain.Campaign{
		Tasks: []*domain.Module{
			{ModuleID: "first"},
			{ModuleID: "second"},
		},
	}

	classified := []domain.ClassifiedTarget{
		{Target: domain.HostPort{Host: "localhost", Port: 443}},
	}

	results, err := r.Execute(ctx, campaign, classified)
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected results for 1 target, got %d", len(results))
	}

	executed := exec.Executed()
	if len(executed) != 1 {
		t.Fatalf("expected only one module execution, got %v", executed)
	}

	if executed[0] != "first" {
		t.Fatalf("expected first module to run, got %s", executed[0])
	}
}

type cancelingExecutor struct {
	cancel context.CancelFunc

	mu       sync.Mutex
	executed []string
}

func (e *cancelingExecutor) Supports(*domain.Module) bool { return true }

func (e *cancelingExecutor) Run(ctx context.Context, m *domain.Module, params map[string]any, t domain.HostPort, timeout time.Duration) (domain.RunResult, error) {
	e.mu.Lock()
	e.executed = append(e.executed, m.ModuleID)
	callIndex := len(e.executed)
	e.mu.Unlock()

	if callIndex == 1 && e.cancel != nil {
		e.cancel()
		<-ctx.Done()
	}

	return domain.RunResult{Target: t}, ctx.Err()
}

func (e *cancelingExecutor) Executed() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, len(e.executed))
	copy(out, e.executed)
	return out
}

type noopResultStore struct{}

func (noopResultStore) Save(domain.HostPort, domain.RunResult) error { return nil }
