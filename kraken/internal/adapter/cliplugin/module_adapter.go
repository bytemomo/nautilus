package cliplugin

import (
	"context"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/module"
)

// ModuleAdapter adapts the legacy CLI client to work with the module system
type ModuleAdapter struct {
	client *Client
}

// NewModuleAdapter creates a new module adapter for CLI execution
func NewModuleAdapter() *ModuleAdapter {
	return &ModuleAdapter{
		client: New(),
	}
}

// Supports checks if this adapter can handle the given module
func (a *ModuleAdapter) Supports(m *module.Module) bool {
	if m == nil {
		return false
	}
	// Only supports V1 modules with CLI config
	return m.Version == module.ModuleV1 && m.ExecConfig.CLI != nil
}

// Run executes a CLI module
func (a *ModuleAdapter) Run(ctx context.Context, m *module.Module, params map[string]any, t domain.HostPort, timeout time.Duration) (domain.RunResult, error) {
	// Create a context with CLI config embedded (legacy API requirement)
	cliConfig := &domain.CLIConfig{
		Path: m.ExecConfig.CLI.Path,
	}

	cliCtx := context.WithValue(ctx, "cli", cliConfig)
	// Delegate to the legacy client
	return a.client.Run(cliCtx, params, t, timeout)
}
