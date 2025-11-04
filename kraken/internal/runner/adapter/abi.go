package adapter

import (
	"context"
	"fmt"
	"strings"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/runner/abi"
	"bytemomo/kraken/internal/transport"
	cnd "bytemomo/trident/conduit"
	tridenttransport "bytemomo/trident/conduit/transport"
	tlscond "bytemomo/trident/conduit/transport/tls"
)

// ABIModuleAdapter is a runner for ABI modules.
type ABIModuleAdapter struct {
	module *abi.LIBModule
}

// NewABIModuleAdapter creates a new ABI module adapter.
func NewABIModuleAdapter() *ABIModuleAdapter {
	return &ABIModuleAdapter{
		module: abi.New(),
	}
}

// Supports returns true if the module is an ABI module.
func (a *ABIModuleAdapter) Supports(m *domain.Module) bool {
	if m == nil {
		return false
	}
	return m.ExecConfig.ABI != nil && (m.Type == domain.Lib || m.Type == domain.Native)
}

// Run runs the ABI module.
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

	return a.module.RunWithConduit(abiCtx, mergedParams, t, timeout, conduit)
}

func (a *ABIModuleAdapter) buildStreamConduit(addr string, stack []domain.LayerHint) (cnd.Conduit[cnd.Stream], error) {
	var current cnd.Conduit[cnd.Stream] = tridenttransport.TCP(addr)

	for _, layer := range stack {
		switch strings.ToLower(layer.Name) {
		case "tcp":
			continue
		case "tls":
			tlsConfig := transport.BuildTLSConfig(layer.Params)
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
			dtlsConfig := transport.BuildDTLSConfig(layer.Params)
			return tlscond.NewDtlsClient(addr, dtlsConfig), nil
		}
	}
	return tridenttransport.UDP(addr), nil
}
