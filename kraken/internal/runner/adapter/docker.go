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

// DockerModuleAdapter executes modules packaged as Docker images.
// It expects the container to emit a domain.RunResult JSON payload on stdout.
type DockerModuleAdapter struct{}

// NewDockerModuleAdapter creates a new Docker module adapter.
func NewDockerModuleAdapter() *DockerModuleAdapter { return &DockerModuleAdapter{} }

// Supports returns true if the module defines a docker execution block.
func (a *DockerModuleAdapter) Supports(m *domain.Module) bool {
	if m == nil {
		return false
	}
	return m.ExecConfig.Docker != nil && (m.Type == domain.Cli || m.Type == domain.Fuzz)
}

// Run executes the configured container image.
func (a *DockerModuleAdapter) Run(ctx context.Context, m *domain.Module, params map[string]any, t domain.HostPort, timeout time.Duration) (domain.RunResult, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	var result domain.RunResult

	if m.ExecConfig.Docker.AutoPull {
		if err := exec.CommandContext(ctx, "docker", "pull", m.ExecConfig.Docker.Image).Run(); err != nil {
			return result, fmt.Errorf("pull docker image %s: %w", m.ExecConfig.Docker.Image, err)
		}
	}

	args := []string{"run", "--rm"}
	if m.ExecConfig.Docker.Workdir != "" {
		args = append(args, "-w", m.ExecConfig.Docker.Workdir)
	}
	if m.ExecConfig.Docker.User != "" {
		args = append(args, "-u", m.ExecConfig.Docker.User)
	}
	if m.ExecConfig.Docker.Network != "" {
		args = append(args, "--network", m.ExecConfig.Docker.Network)
	}

	if outDir, ok := ctx.Value(contextkeys.OutDir).(*string); ok && *outDir != "" {
		args = append(args, "-v", fmt.Sprintf("%s:%s", *outDir, *outDir))
	}

	args = append(args, m.ExecConfig.Docker.Image)
	if m.ExecConfig.Docker.Command != "" {
		args = append(args, m.ExecConfig.Docker.Command)
	}
	if m.Type != domain.Fuzz && (t.Host != "" || t.Port != 0) {
		args = append(args, "--host", t.Host, "--port", fmt.Sprintf("%d", t.Port))
	}

	// Keep parameter ordering stable for reproducibility.
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, k, fmt.Sprintf("%v", params[k]))
	}

	cmd := exec.CommandContext(ctx, "docker", args...)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Run(); err != nil {
		return result, fmt.Errorf("error running docker module %s: %w: %s", m.ModuleID, err, out.String())
	}

	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		return result, fmt.Errorf("error unmarshaling module output: %w", err)
	}

	return result, nil
}
