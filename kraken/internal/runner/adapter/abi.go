package adapter

import (
	"context"
	"fmt"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/loader"
	"bytemomo/kraken/internal/runner/contextkeys"
	"bytemomo/kraken/internal/transport"
	cnd "bytemomo/trident/conduit"
)

// ABIModuleAdapter is a runner for ABI modules.
type ABIModuleAdapter struct{}

// NewABIModuleAdapter creates a new ABI module adapter.
func NewABIModuleAdapter() *ABIModuleAdapter {
	return &ABIModuleAdapter{}
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

	abiCtx := context.WithValue(ctx, contextkeys.ABIConfig, abiConfig)

	var conduit interface{}
	var closeConduit func()
	var stackLayers []string

	// For ABI v2 modules, prepare a conduit factory so modules can request reconnections.
	var factory contextkeys.ConduitFactoryFunc

	if m.ExecConfig.ABI.Version == domain.ModuleV2 && m.ExecConfig.Conduit != nil {
		addr := fmt.Sprintf("%s:%d", t.Host, t.Port)
		cfg := m.ExecConfig.Conduit

		factory = func(timeout time.Duration) (interface{}, func(), []string, error) {
			dialCtx := context.Background()
			if timeout > 0 {
				var cancel context.CancelFunc
				dialCtx, cancel = context.WithTimeout(context.Background(), timeout)
				defer cancel()
			}

			layers := make([]string, 0, len(cfg.Stack))
			for _, l := range cfg.Stack {
				layers = append(layers, l.Name)
			}

			switch cfg.Kind {
			case cnd.KindStream:
				streamConduit, err := transport.BuildStreamConduit(addr, cfg.Stack)
				if err != nil {
					return nil, nil, nil, err
				}
				if err := streamConduit.Dial(dialCtx); err != nil {
					return nil, nil, nil, err
				}
				return streamConduit.Underlying(), func() { streamConduit.Close() }, layers, nil
			case cnd.KindDatagram:
				datagramConduit, err := transport.BuildDatagramConduit(addr, cfg.Stack)
				if err != nil {
					return nil, nil, nil, err
				}
				if err := datagramConduit.Dial(dialCtx); err != nil {
					return nil, nil, nil, err
				}
				return datagramConduit.Underlying(), func() { datagramConduit.Close() }, layers, nil
			default:
				return nil, nil, nil, fmt.Errorf("unsupported conduit kind: %v", cfg.Kind)
			}
		}

		var err error
		conduit, closeConduit, stackLayers, err = factory(timeout)
		if err != nil {
			return domain.RunResult{Target: t}, fmt.Errorf("failed to dial conduit: %w", err)
		}
		if closeConduit != nil {
			defer closeConduit()
		}

		abiCtx = context.WithValue(abiCtx, contextkeys.ConduitFactory, factory)
		abiCtx = context.WithValue(abiCtx, contextkeys.StackLayers, stackLayers)
	}

	module, err := loader.Load(abiConfig.LibraryPath)
	if err != nil {
		return domain.RunResult{}, fmt.Errorf("failed to load module: %w", err)
	}
	defer module.Close()

	return module.Run(abiCtx, mergedParams, t, timeout, conduit)
}
