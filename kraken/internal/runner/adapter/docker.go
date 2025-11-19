package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"bytemomo/kraken/internal/domain"
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

	cidFile, err := os.CreateTemp("", "kraken-cid-*")
	if err != nil {
		return result, fmt.Errorf("creating cidfile: %w", err)
	}
	if err := cidFile.Close(); err != nil {
		return result, fmt.Errorf("closing cidfile: %w", err)
	}
	defer os.Remove(cidFile.Name())

	args := []string{"run", "--rm", "--cidfile", cidFile.Name()}
	for _, mount := range m.ExecConfig.Docker.Mounts {
		spec := fmt.Sprintf("%s:%s", mount.HostPath, mount.ContainerPath)
		if mount.ReadOnly {
			spec = spec + ":ro"
		}
		args = append(args, "-v", spec)
	}

	args = append(args, m.ExecConfig.Docker.Image)
	if len(m.ExecConfig.Docker.Command) > 0 {
		args = append(args, m.ExecConfig.Docker.Command...)
	}
	if m.Type != domain.Fuzz && (t.Host != "" || t.Port != 0) {
		args = append(args, "--host", t.Host, "--port", fmt.Sprintf("%d", t.Port))
	}

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, k, fmt.Sprintf("%v", params[k]))
	}

	runtimeBin := m.ExecConfig.Docker.Runtime
	if runtimeBin == "" {
		runtimeBin = os.Getenv("KRAKEN_CONTAINER_RUNTIME")
	}
	if runtimeBin == "" {
		runtimeBin = "podman"
	}
	cmd := exec.CommandContext(ctx, runtimeBin, args...)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Run(); err != nil {
		cleanupContainer(runtimeBin, cidFile.Name())
		return result, fmt.Errorf("error running docker module %s: %w: %s", m.ModuleID, err, out.String())
	}
	cleanupContainer(runtimeBin, cidFile.Name())

	if out.Available() == 0 {
		return result, fmt.Errorf("error the module did not output any data")
	}

	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		return result, fmt.Errorf("error unmarshaling module output: %w: %s", err, out.String())
	}

	return result, nil
}

func cleanupContainer(runtimeBin, cidFilePath string) {
	data, err := os.ReadFile(cidFilePath)
	if err != nil {
		return
	}
	cid := strings.TrimSpace(string(data))
	if cid == "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, runtimeBin, "rm", "-f", cid)
	_ = cmd.Run()
}
