package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/runner/contextkeys"
)

type CLIModule struct {
}

func New() *CLIModule { return &CLIModule{} }

func (c *CLIModule) Supports(transport string) bool {
	return strings.EqualFold(transport, "cli")
}

// This will accept every module with the following api: ./module --host <HOST> --port <PORT> --output-dir <DIR> <OTHER_PARAMS>
// OTHER_PARAMS can be passed using the campaign params field in the following way:
//
// params:
//	param-flag: param-value
//
// will translate into: ./module --host <HOST> --port <PORT> --output-dir <DIR> param-flag param-value

func (c *CLIModule) Run(ctx context.Context, params map[string]any, t domain.HostPort, timeout time.Duration) (domain.RunResult, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	var result domain.RunResult

	config, ok := ctx.Value(contextkeys.CLIConfig).(*domain.CLIConfig)
	if !ok {
		return result, errors.New("cli key not found in yaml")
	}

	args := []string{
		config.Command,
		"--host", t.Host,
		"--port", fmt.Sprintf("%d", t.Port),
	}

	if outDir, ok := ctx.Value(contextkeys.OutDir).(*string); ok {
		args = append(args, "--output-dir", *outDir)
	}

	for k, v := range params {
		args = append(args, k, fmt.Sprintf("%v", v))
	}

	cmd := exec.CommandContext(ctx, config.Executable, args...)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Run(); err != nil {
		return result, fmt.Errorf("error running module %s: %w: %s", config.Command, err, out.String())
	} else {
		fmt.Printf("Running cmd: %s %v", config.Command, args)
	}

	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		return result, fmt.Errorf("error unmarshaling module output: %w", err)
	}

	return result, nil
}
