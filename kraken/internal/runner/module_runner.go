package runner

import (
	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/runner/abi"
	cli "bytemomo/kraken/internal/runner/cli"
	"bytemomo/kraken/internal/runner/grpc"
	cnd "bytemomo/trident/conduit"
	"bytemomo/trident/conduit/transport"
	tlscond "bytemomo/trident/conduit/transport/tls"
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/pion/dtls/v3"
)

type ModuleExecutor interface {
	Supports(m *domain.Module) bool
	Run(ctx context.Context, m *domain.Module, params map[string]any, t domain.HostPort, timeout time.Duration) (domain.RunResult, error)
}

// CLI --------------------------------------------------

type CLIModuleAdapter struct {
	client *cli.Client
}

func NewCLIModuleAdapter() *CLIModuleAdapter {
	return &CLIModuleAdapter{
		client: cli.New(),
	}
}

func (a *CLIModuleAdapter) Supports(m *domain.Module) bool {
	if m == nil {
		return false
	}
	return m.ExecConfig.CLI != nil && m.Type == domain.Cli
}

func (a *CLIModuleAdapter) Run(ctx context.Context, m *domain.Module, params map[string]any, t domain.HostPort, timeout time.Duration) (domain.RunResult, error) {
	cliConfig := &domain.CLIConfig{
		Executable: m.ExecConfig.CLI.Executable,
		Command:    m.ExecConfig.CLI.Command,
	}

	cliCtx := context.WithValue(ctx, "cli", cliConfig)
	return a.client.Run(cliCtx, params, t, timeout)
}

// ABI --------------------------------------------------

type ABIModuleAdapter struct {
	client *abi.Client
}

func NewABIModuleAdapter() *ABIModuleAdapter {
	return &ABIModuleAdapter{
		client: abi.New(),
	}
}

func (a *ABIModuleAdapter) Supports(m *domain.Module) bool {
	if m == nil {
		return false
	}
	return m.ExecConfig.ABI != nil && (m.Type == domain.Lib || m.Type == domain.Native)
}

func (a *ABIModuleAdapter) Run(ctx context.Context, m *domain.Module, params map[string]any, t domain.HostPort, timeout time.Duration) (domain.RunResult, error) {
	mergedParams := make(map[string]any)
	for k, v := range m.ExecConfig.Params {
		mergedParams[k] = v
	}
	for k, v := range params {
		mergedParams[k] = v
	}

	abiConfig := &domain.ABIConfig{
		LibraryPath: m.ExecConfig.ABI.LibraryPath,
		Symbol:      m.ExecConfig.ABI.Symbol,
	}

	libPath := abiConfig.LibraryPath
	libPath = strings.TrimSuffix(libPath, ".so")
	libPath = strings.TrimSuffix(libPath, ".dylib")
	libPath = strings.TrimSuffix(libPath, ".dll")
	abiConfig.LibraryPath = libPath

	abiCtx := context.WithValue(ctx, "abi", abiConfig)

	var conduit interface{}
	var closeConduit func()

	if m.ExecConfig.ABI.Version == domain.ModuleV2 && m.ExecConfig.Conduit != nil {
		addr := fmt.Sprintf("%s:%d", t.Host, t.Port)
		cfg := m.ExecConfig.Conduit

		switch cfg.Kind {
		case cnd.KindStream:
			streamConduit, err := a.buildStreamConduit(addr, cfg.Stack)
			if err != nil {
				return domain.RunResult{Target: t}, fmt.Errorf("failed to build stream conduit: %w", err)
			}

			err = streamConduit.Dial(ctx)
			if err != nil {
				return domain.RunResult{Target: t}, fmt.Errorf("failed to dial stream conduit: %w", err)
			}

			conduit = streamConduit.Underlying()
			closeConduit = func() { streamConduit.Close() }

		case cnd.KindDatagram:
			datagramConduit, err := a.buildDatagramConduit(addr, cfg.Stack)
			if err != nil {
				return domain.RunResult{Target: t}, fmt.Errorf("failed to build datagram conduit: %w", err)
			}

			err = datagramConduit.Dial(ctx)
			if err != nil {
				return domain.RunResult{Target: t}, fmt.Errorf("failed to dial datagram conduit: %w", err)
			}

			conduit = datagramConduit.Underlying()
			closeConduit = func() { datagramConduit.Close() }

		default:
			return domain.RunResult{Target: t}, fmt.Errorf("unsupported conduit kind: %v", cfg.Kind)
		}

		if closeConduit != nil {
			defer closeConduit()
		}
	}

	return a.client.RunWithConduit(abiCtx, mergedParams, t, timeout, conduit)
}

func (a *ABIModuleAdapter) buildStreamConduit(addr string, stack []domain.LayerHint) (cnd.Conduit[cnd.Stream], error) {
	var current cnd.Conduit[cnd.Stream] = transport.TCP(addr)

	for _, layer := range stack {
		switch strings.ToLower(layer.Name) {
		case "tcp":
			continue
		case "tls":
			tlsConfig := a.buildTLSConfig(layer.Params)
			current = tlscond.NewTlsClient(current, tlsConfig)
		default:
			return nil, fmt.Errorf("unknown stream layer: %s", layer.Name)
		}
	}

	return current, nil
}

func (a *ABIModuleAdapter) buildDatagramConduit(addr string, stack []domain.LayerHint) (cnd.Conduit[cnd.Datagram], error) {
	for _, layer := range stack {
		if strings.ToLower(layer.Name) == "dtls" {
			dtlsConfig := a.buildDTLSConfig(layer.Params)
			return tlscond.NewDtlsClient(addr, dtlsConfig), nil
		}
	}
	return transport.UDP(addr), nil
}

func (a *ABIModuleAdapter) buildTLSConfig(params map[string]any) *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if params == nil {
		return cfg
	}

	if serverName, ok := params["server_name"].(string); ok && serverName != "" {
		cfg.ServerName = serverName
	}

	if skipVerify, ok := params["skip_verify"].(bool); ok {
		cfg.InsecureSkipVerify = skipVerify
	}

	if minVersion, ok := params["min_version"].(string); ok {
		switch strings.ToUpper(minVersion) {
		case "TLS1.0", "TLS10":
			cfg.MinVersion = tls.VersionTLS10
		case "TLS1.1", "TLS11":
			cfg.MinVersion = tls.VersionTLS11
		case "TLS1.2", "TLS12":
			cfg.MinVersion = tls.VersionTLS12
		case "TLS1.3", "TLS13":
			cfg.MinVersion = tls.VersionTLS13
		}
	}

	return cfg
}

func (a *ABIModuleAdapter) buildDTLSConfig(params map[string]any) *dtls.Config {
	cfg := &dtls.Config{}

	if params == nil {
		return cfg
	}

	if skipVerify, ok := params["skip_verify"].(bool); ok && skipVerify {
		cfg.InsecureSkipVerify = true
	}

	return cfg
}

// GRPC --------------------------------------------------

type GRPCModuleAdapter struct {
	client *grpc.Client
}

func NewGRPCModuleAdapter() *GRPCModuleAdapter {
	return &GRPCModuleAdapter{
		client: grpc.New(),
	}
}

func (a *GRPCModuleAdapter) Supports(m *domain.Module) bool {
	if m == nil {
		return false
	}

	return m.ExecConfig.GRPC != nil && m.Type == domain.Grpc
}

func (a *GRPCModuleAdapter) Run(ctx context.Context, m *domain.Module, params map[string]any, t domain.HostPort, timeout time.Duration) (domain.RunResult, error) {
	grpcConfig := &domain.GRPCConfig{
		Server: m.ExecConfig.GRPC.ServerAddr,
	}

	cliCtx := context.WithValue(ctx, "grpc", grpcConfig)
	return a.client.Run(cliCtx, params, t, timeout)
}
