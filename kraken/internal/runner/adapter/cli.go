package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/runner/contextkeys"
)

// CLIModuleAdapter is a runner for CLI modules.
type CLIModuleAdapter struct {
}

// NewCLIModuleAdapter creates a new CLI module adapter.
func NewCLIModuleAdapter() *CLIModuleAdapter {
	return &CLIModuleAdapter{}
}

// Supports returns true if the module is a CLI module.
func (a *CLIModuleAdapter) Supports(m *domain.Module) bool {
	if m == nil {
		return false
	}
	return m.ExecConfig.CLI != nil && (m.Type == domain.Cli || m.Type == domain.Fuzz)
}

// Run runs the CLI module.
func (a *CLIModuleAdapter) Run(ctx context.Context, m *domain.Module, params map[string]any, t domain.HostPort, timeout time.Duration) (domain.RunResult, error) {

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	var result domain.RunResult

	args := []string{m.ExecConfig.CLI.Command}

	if m.Type != domain.Fuzz && (t.Host != "" || t.Port != 0) {
		args = append(args, "--host", t.Host, "--port", fmt.Sprintf("%d", t.Port))
	}

	if outDir, ok := ctx.Value(contextkeys.OutDir).(*string); ok && *outDir != "" {
		args = append(args, "--output-dir", *outDir)
	}

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, k, fmt.Sprintf("%v", params[k]))
	}

	cmd := exec.CommandContext(ctx, m.ExecConfig.CLI.Executable, args...)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Run(); err != nil {
		return result, fmt.Errorf("error running module %s: %w: %s", m.ExecConfig.CLI.Command, err, out.String())
	} else {
		fmt.Printf("Running cmd: %s %v", m.ExecConfig.CLI.Command, args)
	}

	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		return result, fmt.Errorf("error unmarshaling module output: %w", err)
	}

	return result, nil
}
