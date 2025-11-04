package adapter

import (
	"context"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/runner/cli"
)

// CLIModuleAdapter is a runner for CLI modules.
type CLIModuleAdapter struct {
	module *cli.CLIModule
}

// NewCLIModuleAdapter creates a new CLI module adapter.
func NewCLIModuleAdapter() *CLIModuleAdapter {
	return &CLIModuleAdapter{
		module: cli.New(),
	}
}

// Supports returns true if the module is a CLI module.
func (a *CLIModuleAdapter) Supports(m *domain.Module) bool {
	if m == nil {
		return false
	}
	return m.ExecConfig.CLI != nil && m.Type == domain.Cli
}

// Run runs the CLI module.
func (a *CLIModuleAdapter) Run(ctx context.Context, m *domain.Module, params map[string]any, t domain.HostPort, timeout time.Duration) (domain.RunResult, error) {
	cliConfig := &domain.CLIConfig{
		Executable: m.ExecConfig.CLI.Executable,
		Command:    m.ExecConfig.CLI.Command,
	}

	cliCtx := context.WithValue(ctx, "cli", cliConfig)
	return a.module.Run(cliCtx, params, t, timeout)
}
