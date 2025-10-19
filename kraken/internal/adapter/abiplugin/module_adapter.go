package abiplugin

import (
	"context"
	"strings"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/module"
)

// ModuleAdapter adapts the ABI client to work with the module system
// Supports both V1 and V2 APIs
type ModuleAdapter struct {
	client *Client
}

// NewModuleAdapter creates a new module adapter for ABI execution
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
	// Supports both V1 and V2 modules with ABI config
	return m.ExecConfig.ABI != nil && (m.Type == module.Lib || m.Type == module.Native)
}

// Run executes an ABI module (V1 or V2)
func (a *ModuleAdapter) Run(ctx context.Context, m *module.Module, params map[string]any, t domain.HostPort, timeout time.Duration) (domain.RunResult, error) {
	// Merge module params with runtime overrides
	mergedParams := make(map[string]any)
	for k, v := range m.ExecConfig.Params {
		mergedParams[k] = v
	}
	for k, v := range params {
		mergedParams[k] = v
	}

	// Create a context with ABI config embedded (legacy API requirement)
	abiConfig := &domain.ABIConfig{
		LibraryPath: m.ExecConfig.ABI.LibraryPath,
		Symbol:      m.ExecConfig.ABI.Symbol,
	}

	// Remove file extension if present - the client will add the correct one
	libPath := abiConfig.LibraryPath
	libPath = strings.TrimSuffix(libPath, ".so")
	libPath = strings.TrimSuffix(libPath, ".dylib")
	libPath = strings.TrimSuffix(libPath, ".dll")
	abiConfig.LibraryPath = libPath

	abiCtx := context.WithValue(ctx, "abi", abiConfig)

	// Delegate to the client which handles both V1 and V2
	return a.client.Run(abiCtx, mergedParams, t, timeout)
}
