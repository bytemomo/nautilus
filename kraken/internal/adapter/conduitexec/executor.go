package conduitexec

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/netip"
	"strings"
	"time"

	cnd "bytemomo/trident/conduit"
	"bytemomo/trident/conduit/transport"
	tlscond "bytemomo/trident/conduit/transport/tls"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/module"

	"github.com/pion/dtls/v3"
)

// Executor handles execution of V2 modules over conduits
type Executor struct {
	registry *module.Registry
}

// New creates a new conduit-based executor
func New(registry *module.Registry) *Executor {
	return &Executor{
		registry: registry,
	}
}

// Supports checks if this executor can handle the given module
func (e *Executor) Supports(m *module.Module) bool {
	if m == nil {
		return false
	}
	// Only supports V2 modules with conduit config
	return m.Version == module.ModuleV2 && m.ExecConfig.Conduit != nil
}

// Run executes a module over a conduit connection
func (e *Executor) Run(ctx context.Context, m *module.Module, params map[string]any, target domain.HostPort, timeout time.Duration) (domain.RunResult, error) {
	result := domain.RunResult{Target: target}

	if !e.Supports(m) {
		return result, fmt.Errorf("module %q is not supported by conduit executor", m.ModuleID)
	}

	// Merge module params with runtime overrides
	mergedParams := make(map[string]any)
	for k, v := range m.ExecConfig.Params {
		mergedParams[k] = v
	}
	for k, v := range params {
		mergedParams[k] = v
	}

	addr := fmt.Sprintf("%s:%d", target.Host, target.Port)
	cfg := m.ExecConfig.Conduit

	// Execute based on conduit kind
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch cfg.Kind {
	case cnd.KindStream:
		// Build stream conduit
		streamConduit, err := e.buildStreamConduit(addr, cfg.Stack)
		if err != nil {
			return result, fmt.Errorf("failed to build stream conduit: %w", err)
		}

		// Dial
		dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
		err = streamConduit.Dial(dialCtx)
		dialCancel()
		if err != nil {
			return result, fmt.Errorf("failed to dial stream conduit: %w", err)
		}
		defer streamConduit.Close()

		return e.executeStream(execCtx, streamConduit, m, mergedParams, target, timeout)

	case cnd.KindDatagram:
		// Build datagram conduit
		datagramConduit, err := e.buildDatagramConduit(addr, cfg.Stack)
		if err != nil {
			return result, fmt.Errorf("failed to build datagram conduit: %w", err)
		}

		// Dial
		dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
		err = datagramConduit.Dial(dialCtx)
		dialCancel()
		if err != nil {
			return result, fmt.Errorf("failed to dial datagram conduit: %w", err)
		}
		defer datagramConduit.Close()

		return e.executeDatagram(execCtx, datagramConduit, m, mergedParams, target, timeout)

	default:
		return result, fmt.Errorf("unsupported conduit kind: %v", cfg.Kind)
	}
}



// buildStreamConduit builds a stream-based conduit (TCP/TLS)
func (e *Executor) buildStreamConduit(addr string, stack []module.LayerHint) (cnd.Conduit[cnd.Stream], error) {
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
			tlsConfig := buildTLSConfig(layer.Params)
			current = tlscond.NewTlsClient(current, tlsConfig)
		default:
			return nil, fmt.Errorf("unknown stream layer: %s", layer.Name)
		}
	}

	return current, nil
}

// buildDatagramConduit builds a datagram-based conduit (UDP/DTLS)
func (e *Executor) buildDatagramConduit(addr string, stack []module.LayerHint) (cnd.Conduit[cnd.Datagram], error) {
	// Check if we need DTLS (it replaces UDP completely)
	for _, layer := range stack {
		if strings.ToLower(layer.Name) == "dtls" {
			// DTLS conduit handles UDP internally
			dtlsConfig := buildDTLSConfig(layer.Params)
			return tlscond.NewDtlsClient(addr, dtlsConfig), nil
		}
	}

	// Otherwise use plain UDP
	return transport.UDP(addr), nil
}

// buildTLSConfig creates a tls.Config from layer parameters
func buildTLSConfig(params map[string]any) *tls.Config {
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
func buildDTLSConfig(params map[string]any) *dtls.Config {
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

// executeStream executes module logic over a stream conduit
func (e *Executor) executeStream(ctx context.Context, conduit cnd.Conduit[cnd.Stream], m *module.Module, params map[string]any, target domain.HostPort, timeout time.Duration) (domain.RunResult, error) {
	result := domain.RunResult{Target: target}

	stream := conduit.Underlying()

	// Execute the module-specific protocol logic
	// For now, this is a placeholder that modules would extend
	// In a real implementation, you'd have module-specific handlers here

	findings, logs, err := e.executeModuleProtocol(ctx, stream, m, params, target)
	if err != nil {
		result.Logs = append(result.Logs, fmt.Sprintf("execution error: %v", err))
		return result, err
	}

	result.Findings = findings
	result.Logs = logs

	return result, nil
}

// executeDatagram executes module logic over a datagram conduit
func (e *Executor) executeDatagram(ctx context.Context, conduit cnd.Conduit[cnd.Datagram], m *module.Module, params map[string]any, target domain.HostPort, timeout time.Duration) (domain.RunResult, error) {
	result := domain.RunResult{Target: target}

	datagram := conduit.Underlying()

	// Execute the module-specific protocol logic
	findings, logs, err := e.executeModuleDatagramProtocol(ctx, datagram, m, params, target)
	if err != nil {
		result.Logs = append(result.Logs, fmt.Sprintf("execution error: %v", err))
		return result, err
	}

	result.Findings = findings
	result.Logs = logs

	return result, nil
}

// executeModuleProtocol handles the actual protocol logic for stream-based modules
// This is where module-specific communication happens
func (e *Executor) executeModuleProtocol(ctx context.Context, stream cnd.Stream, m *module.Module, params map[string]any, target domain.HostPort) ([]domain.Finding, []string, error) {
	var findings []domain.Finding
	var logs []string

	logs = append(logs, fmt.Sprintf("executing module %s over stream conduit", m.ModuleID))

	// Example: Send a request and receive response
	// In a real implementation, this would be module-specific
	// For now, we demonstrate the conduit API usage

	// Send data
	payload := []byte("PROBE\n")
	n, md, err := stream.Send(ctx, payload, nil, &cnd.SendOptions{})
	if err != nil {
		return findings, logs, fmt.Errorf("send failed: %w", err)
	}
	logs = append(logs, fmt.Sprintf("sent %d bytes (took %v)", n, md.End.Sub(md.Start)))

	// Receive response
	chunk, err := stream.Recv(ctx, &cnd.RecvOptions{MaxBytes: 4096})
	if err != nil {
		return findings, logs, fmt.Errorf("recv failed: %w", err)
	}

	if chunk.Data != nil {
		defer chunk.Data.Release()
		response := chunk.Data.Bytes()
		logs = append(logs, fmt.Sprintf("received %d bytes (took %v)", len(response), chunk.MD.End.Sub(chunk.MD.Start)))

		// Create a finding based on the response
		finding := domain.Finding{
			ID:          fmt.Sprintf("%s-%d", m.ModuleID, time.Now().Unix()),
			PluginID:    m.ModuleID,
			Success:     true,
			Title:       fmt.Sprintf("%s probe result", m.ModuleID),
			Severity:    "info",
			Description: fmt.Sprintf("Received response from target"),
			Evidence: map[string]any{
				"response_size": len(response),
				"response":      string(response),
			},
			Timestamp: time.Now().Unix(),
			Target:    target,
		}
		findings = append(findings, finding)
	}

	return findings, logs, nil
}

// executeModuleDatagramProtocol handles protocol logic for datagram-based modules
func (e *Executor) executeModuleDatagramProtocol(ctx context.Context, datagram cnd.Datagram, m *module.Module, params map[string]any, target domain.HostPort) ([]domain.Finding, []string, error) {
	var findings []domain.Finding
	var logs []string

	logs = append(logs, fmt.Sprintf("executing module %s over datagram conduit", m.ModuleID))

	// Parse target address
	addr, err := netip.ParseAddr(target.Host)
	if err != nil {
		return findings, logs, fmt.Errorf("invalid target address: %w", err)
	}

	targetAddr := netip.AddrPortFrom(addr, target.Port)

	// Send datagram
	payload := []byte("PROBE")
	buf := cnd.GetBuf(len(payload))
	copy(buf.Bytes(), payload)

	msg := &cnd.DatagramMsg{
		Data: buf,
		Dst:  targetAddr,
	}

	n, md, err := datagram.Send(ctx, msg, &cnd.SendOptions{})
	if err != nil {
		buf.Release()
		return findings, logs, fmt.Errorf("send failed: %w", err)
	}
	logs = append(logs, fmt.Sprintf("sent %d bytes (took %v)", n, md.End.Sub(md.Start)))

	// Receive response
	respMsg, err := datagram.Recv(ctx, &cnd.RecvOptions{MaxBytes: 4096})
	if err != nil {
		return findings, logs, fmt.Errorf("recv failed: %w", err)
	}

	if respMsg.Data != nil {
		defer respMsg.Data.Release()
		response := respMsg.Data.Bytes()
		logs = append(logs, fmt.Sprintf("received %d bytes from %s (took %v)",
			len(response), respMsg.Src.String(), respMsg.MD.End.Sub(respMsg.MD.Start)))

		// Create a finding
		finding := domain.Finding{
			ID:          fmt.Sprintf("%s-%d", m.ModuleID, time.Now().Unix()),
			PluginID:    m.ModuleID,
			Success:     true,
			Title:       fmt.Sprintf("%s probe result", m.ModuleID),
			Severity:    "info",
			Description: fmt.Sprintf("Received datagram response from target"),
			Evidence: map[string]any{
				"response_size": len(response),
				"response":      string(response),
				"source":        respMsg.Src.String(),
			},
			Timestamp: time.Now().Unix(),
			Target:    target,
		}
		findings = append(findings, finding)
	}

	return findings, logs, nil
}
