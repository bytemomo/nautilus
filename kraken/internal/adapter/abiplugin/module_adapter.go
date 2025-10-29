package abiplugin

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/module"
	cnd "bytemomo/trident/conduit"
	"bytemomo/trident/conduit/transport"
	tlscond "bytemomo/trident/conduit/transport/tls"

	"github.com/pion/dtls/v3"
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

	// For V2 modules with conduit config, build and dial the conduit
	var conduit interface{}
	var closeConduit func()

	if m.Version == module.ModuleV2 && m.ExecConfig.Conduit != nil {
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

	// Delegate to the client which handles both V1 and V2
	return a.client.RunWithConduit(abiCtx, mergedParams, t, timeout, conduit)
}

// buildStreamConduit builds a stream-based conduit (TCP/TLS)
func (a *ModuleAdapter) buildStreamConduit(addr string, stack []module.LayerHint) (cnd.Conduit[cnd.Stream], error) {
	// Start with TCP as the base
	var current cnd.Conduit[cnd.Stream] = transport.TCP(addr)

	// Apply stack layers in order
	for _, layer := range stack {
		switch strings.ToLower(layer.Name) {
		case "tcp":
			// TCP is the base, already applied
			continue
		case "tls":
			// Wrap current conduit with TLS
			tlsConfig := a.buildTLSConfig(layer.Params)
			current = tlscond.NewTlsClient(current, tlsConfig)
		default:
			return nil, fmt.Errorf("unknown stream layer: %s", layer.Name)
		}
	}

	return current, nil
}

// buildDatagramConduit builds a datagram-based conduit (UDP/DTLS)
func (a *ModuleAdapter) buildDatagramConduit(addr string, stack []module.LayerHint) (cnd.Conduit[cnd.Datagram], error) {
	// Check if we need DTLS (it replaces UDP completely)
	for _, layer := range stack {
		if strings.ToLower(layer.Name) == "dtls" {
			// DTLS conduit handles UDP internally
			dtlsConfig := a.buildDTLSConfig(layer.Params)
			return tlscond.NewDtlsClient(addr, dtlsConfig), nil
		}
	}

	// Otherwise use plain UDP
	return transport.UDP(addr), nil
}

// buildTLSConfig creates a tls.Config from layer parameters
func (a *ModuleAdapter) buildTLSConfig(params map[string]any) *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if params == nil {
		return cfg
	}

	// Server name for SNI
	if serverName, ok := params["server_name"].(string); ok && serverName != "" {
		cfg.ServerName = serverName
	}

	// Skip verification (for testing)
	if skipVerify, ok := params["skip_verify"].(bool); ok {
		cfg.InsecureSkipVerify = skipVerify
	}

	// Minimum TLS version
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

// buildDTLSConfig creates a dtls.Config from layer parameters
func (a *ModuleAdapter) buildDTLSConfig(params map[string]any) *dtls.Config {
	cfg := &dtls.Config{}

	if params == nil {
		return cfg
	}

	// Skip verification (for testing)
	if skipVerify, ok := params["skip_verify"].(bool); ok && skipVerify {
		cfg.InsecureSkipVerify = true
	}

	return cfg
}
