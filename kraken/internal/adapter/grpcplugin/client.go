package grpcplugin

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/module"
	plugpb "bytemomo/kraken/pkg/plugpb"
	cnd "bytemomo/trident/conduit"
	"bytemomo/trident/conduit/transport"
	tlscond "bytemomo/trident/conduit/transport/tls"

	"github.com/pion/dtls/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"

	log "github.com/sirupsen/logrus"
)

// Client implements V2 gRPC plugin execution with bidirectional streaming
type Client struct {
	requestCounter atomic.Uint64
}

func New() *Client {
	return &Client{}
}

// Supports checks if this client supports the given module
func (c *Client) Supports(m *module.Module) bool {
	if m == nil {
		return false
	}
	// Only supports V2 modules with gRPC config and conduit
	return m.Version == module.ModuleV2 && m.ExecConfig.GRPC != nil && m.ExecConfig.Conduit != nil
}

// Run executes a gRPC V2 module over a connected conduit
// This method matches the ModuleExecutor interface
func (c *Client) Run(ctx context.Context, m *module.Module, params map[string]any, target domain.HostPort, timeout time.Duration) (domain.RunResult, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	result := domain.RunResult{Target: target}

	if !c.Supports(m) {
		return result, fmt.Errorf("module %q not supported by gRPC V2 client (requires V2 with gRPC and conduit config)", m.ModuleID)
	}

	// Merge module params with runtime overrides
	mergedParams := make(map[string]any)
	for k, v := range m.ExecConfig.Params {
		mergedParams[k] = v
	}
	for k, v := range params {
		mergedParams[k] = v
	}

	// Build conduit based on module configuration
	addr := fmt.Sprintf("%s:%d", target.Host, target.Port)
	cfg := m.ExecConfig.Conduit

	var conduit interface{}
	var closeConduit func()

	switch cfg.Kind {
	case cnd.KindStream:
		streamConduit, err := c.buildStreamConduit(addr, cfg.Stack)
		if err != nil {
			return result, fmt.Errorf("failed to build stream conduit: %w", err)
		}

		err = streamConduit.Dial(ctx)
		if err != nil {
			return result, fmt.Errorf("failed to dial stream conduit: %w", err)
		}

		conduit = streamConduit.Underlying()
		closeConduit = func() { streamConduit.Close() }

	case cnd.KindDatagram:
		datagramConduit, err := c.buildDatagramConduit(addr, cfg.Stack)
		if err != nil {
			return result, fmt.Errorf("failed to build datagram conduit: %w", err)
		}

		err = datagramConduit.Dial(ctx)
		if err != nil {
			return result, fmt.Errorf("failed to dial datagram conduit: %w", err)
		}

		conduit = datagramConduit.Underlying()
		closeConduit = func() { datagramConduit.Close() }

	default:
		return result, fmt.Errorf("unsupported conduit kind: %v", cfg.Kind)
	}

	defer closeConduit()

	// Connect to gRPC server
	endpoint := m.ExecConfig.GRPC.ServerAddr
	if endpoint == "" {
		return result, fmt.Errorf("grpc server_addr not configured")
	}

	conn, err := grpc.DialContext(ctx, endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return result, fmt.Errorf("failed to dial %s: %w", endpoint, err)
	}
	defer conn.Close()

	// Create V2 client and establish stream
	client := plugpb.NewOrcaPluginV2Client(conn)
	stream, err := client.RunWithConnection(ctx)
	if err != nil {
		return result, fmt.Errorf("failed to create stream: %w", err)
	}

	// Execute the module with the connected conduit
	return c.executeModule(stream, m, mergedParams, target, timeout, conduit)
}

// executeModule handles the bidirectional streaming protocol
func (c *Client) executeModule(stream grpc.BidiStreamingClient[plugpb.RunnerToPlugin, plugpb.PluginToRunner], m *module.Module, params map[string]any, target domain.HostPort, timeout time.Duration, conduit interface{}) (domain.RunResult, error) {
	result := domain.RunResult{Target: target}

	// Setup communication channels
	errChan := make(chan error, 1)
	doneChan := make(chan *plugpb.RunResult, 1)

	// Convert conduit to connection info
	connInfo := c.buildConnectionInfo(conduit)

	// Start receiving messages from plugin
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := c.handlePluginMessages(stream, conduit, doneChan, errChan); err != nil {
			select {
			case errChan <- err:
			default:
			}
		}
	}()

	// Send StartExecution message
	paramsVals := make(map[string]*structpb.Value, len(params))
	for k, v := range params {
		pv, err := structpb.NewValue(v)
		if err != nil {
			return result, fmt.Errorf("failed to convert param %s: %w", k, err)
		}
		paramsVals[k] = pv
	}

	startMsg := &plugpb.RunnerToPlugin{
		Message: &plugpb.RunnerToPlugin_Start{
			Start: &plugpb.StartExecution{
				Connection: connInfo,
				Target: &plugpb.Target{
					Host: target.Host,
					Port: uint32(target.Port),
				},
				TimeoutMs: uint32(timeout.Milliseconds()),
				Params:    paramsVals,
			},
		},
	}

	if err := stream.Send(startMsg); err != nil {
		return result, fmt.Errorf("failed to send start: %w", err)
	}

	// Wait for completion or error
	select {
	case err := <-errChan:
		return result, err
	case res := <-doneChan:
		return c.convertResult(res), nil
	case <-stream.Context().Done():
		return result, stream.Context().Err()
	}
}

// handlePluginMessages processes messages from the plugin
func (c *Client) handlePluginMessages(stream grpc.BidiStreamingClient[plugpb.RunnerToPlugin, plugpb.PluginToRunner], conduit interface{}, doneChan chan *plugpb.RunResult, errChan chan error) error {
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("stream recv error: %w", err)
		}

		switch m := msg.Message.(type) {
		case *plugpb.PluginToRunner_Ready:
			// Plugin is ready
			log.WithFields(log.Fields{
				"plugin":  m.Ready.PluginId,
				"version": m.Ready.Version,
			}).Debug("Plugin ready")

		case *plugpb.PluginToRunner_Write:
			// Plugin wants to write data
			if err := c.handleWrite(stream, m.Write, conduit); err != nil {
				return fmt.Errorf("write failed: %w", err)
			}

		case *plugpb.PluginToRunner_Read:
			// Plugin wants to read data
			if err := c.handleRead(stream, m.Read, conduit); err != nil {
				return fmt.Errorf("read failed: %w", err)
			}

		case *plugpb.PluginToRunner_Complete:
			// Plugin finished execution
			doneChan <- m.Complete.Result
			return nil

		case *plugpb.PluginToRunner_Error:
			// Plugin encountered error
			if m.Error.Fatal {
				return fmt.Errorf("plugin error: %s", m.Error.Error)
			}
			log.WithField("error", m.Error.Error).Warn("Plugin non-fatal error")

		case *plugpb.PluginToRunner_Log:
			// Plugin log message
			level := m.Log.Level
			msg := m.Log.Message
			switch level {
			case "debug":
				log.Debug(msg)
			case "info":
				log.Info(msg)
			case "warn":
				log.Warn(msg)
			case "error":
				log.Error(msg)
			default:
				log.Info(msg)
			}

		default:
			log.Warn("Unknown message type from plugin")
		}
	}
}

// handleWrite processes a write request from the plugin
func (c *Client) handleWrite(stream grpc.BidiStreamingClient[plugpb.RunnerToPlugin, plugpb.PluginToRunner], req *plugpb.WriteRequest, conduit interface{}) error {
	// Determine conduit type and perform write
	switch conn := conduit.(type) {
	case cnd.Stream:
		ctx := context.Background()
		if req.TimeoutMs > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Duration(req.TimeoutMs)*time.Millisecond)
			defer cancel()
		}

		_, _, err := conn.Send(ctx, req.Data, nil, &cnd.SendOptions{})
		if err != nil {
			return stream.Send(&plugpb.RunnerToPlugin{
				Message: &plugpb.RunnerToPlugin_Error{
					Error: &plugpb.RunnerError{
						Error: err.Error(),
						Fatal: false,
					},
				},
			})
		}

	case cnd.Datagram:
		// TODO: Handle datagram write
		return stream.Send(&plugpb.RunnerToPlugin{
			Message: &plugpb.RunnerToPlugin_Error{
				Error: &plugpb.RunnerError{
					Error: "datagram write not implemented",
					Fatal: false,
				},
			},
		})

	default:
		return stream.Send(&plugpb.RunnerToPlugin{
			Message: &plugpb.RunnerToPlugin_Error{
				Error: &plugpb.RunnerError{
					Error: "unsupported conduit type",
					Fatal: false,
				},
			},
		})
	}

	// Send acknowledgment
	ack := &plugpb.RunnerToPlugin{
		Message: &plugpb.RunnerToPlugin_Data{
			Data: &plugpb.DataChunk{
				RequestId: req.RequestId,
				Data:      []byte{},
				Eof:       false,
			},
		},
	}

	return stream.Send(ack)
}

// handleRead processes a read request from the plugin
func (c *Client) handleRead(stream grpc.BidiStreamingClient[plugpb.RunnerToPlugin, plugpb.PluginToRunner], req *plugpb.ReadRequest, conduit interface{}) error {
	var data []byte
	var eof bool

	// Determine conduit type and perform read
	switch conn := conduit.(type) {
	case cnd.Stream:
		ctx := context.Background()
		if req.TimeoutMs > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Duration(req.TimeoutMs)*time.Millisecond)
			defer cancel()
		}

		maxBytes := int(req.MaxBytes)
		if maxBytes == 0 {
			maxBytes = 4096
		}

		chunk, err := conn.Recv(ctx, &cnd.RecvOptions{MaxBytes: maxBytes})
		if err == io.EOF {
			eof = true
		} else if err != nil {
			// Send error as empty data chunk
			return stream.Send(&plugpb.RunnerToPlugin{
				Message: &plugpb.RunnerToPlugin_Error{
					Error: &plugpb.RunnerError{
						Error: err.Error(),
						Fatal: false,
					},
				},
			})
		}

		if chunk != nil && chunk.Data != nil {
			data = chunk.Data.Bytes()
			chunk.Data.Release()
		}

	case cnd.Datagram:
		// TODO: Handle datagram read
		return stream.Send(&plugpb.RunnerToPlugin{
			Message: &plugpb.RunnerToPlugin_Error{
				Error: &plugpb.RunnerError{
					Error: "datagram read not implemented",
					Fatal: false,
				},
			},
		})

	default:
		return stream.Send(&plugpb.RunnerToPlugin{
			Message: &plugpb.RunnerToPlugin_Error{
				Error: &plugpb.RunnerError{
					Error: "unsupported conduit type",
					Fatal: false,
				},
			},
		})
	}

	// Send data chunk
	dataMsg := &plugpb.RunnerToPlugin{
		Message: &plugpb.RunnerToPlugin_Data{
			Data: &plugpb.DataChunk{
				RequestId: req.RequestId,
				Data:      data,
				Eof:       eof,
			},
		},
	}

	return stream.Send(dataMsg)
}

// buildConnectionInfo creates connection info from conduit
func (c *Client) buildConnectionInfo(conduit interface{}) *plugpb.ConnectionInfo {
	info := &plugpb.ConnectionInfo{
		Type:        plugpb.ConnectionType_CONNECTION_TYPE_UNSPECIFIED,
		StackLayers: []string{},
		Metadata:    make(map[string]string),
	}

	switch conn := conduit.(type) {
	case cnd.Conduit[cnd.Stream]:
		info.Type = plugpb.ConnectionType_CONNECTION_TYPE_STREAM
		info.StackLayers = conn.Stack()

		underlying := conn.Underlying()
		if underlying.LocalAddr() != nil {
			info.LocalAddr = underlying.LocalAddr().String()
		}
		if underlying.RemoteAddr() != nil {
			info.RemoteAddr = underlying.RemoteAddr().String()
		}

	case cnd.Conduit[cnd.Datagram]:
		info.Type = plugpb.ConnectionType_CONNECTION_TYPE_DATAGRAM
		info.StackLayers = conn.Stack()

		underlying := conn.Underlying()
		if underlying.LocalAddr().IsValid() {
			info.LocalAddr = underlying.LocalAddr().String()
		}
		if underlying.RemoteAddr().IsValid() {
			info.RemoteAddr = underlying.RemoteAddr().String()
		}
	}

	return info
}

// convertResult converts protobuf result to domain result
func (c *Client) convertResult(pbResult *plugpb.RunResult) domain.RunResult {
	result := domain.RunResult{
		Target: domain.HostPort{
			Host: pbResult.Target.Host,
			Port: uint16(pbResult.Target.Port),
		},
		Logs: pbResult.Logs,
	}

	for _, f := range pbResult.Findings {
		evidence := make(map[string]any)
		for k, v := range f.Evidence {
			evidence[k] = v
		}

		var tags []domain.Tag
		for _, t := range f.Tags {
			tags = append(tags, domain.Tag(t))
		}

		result.Findings = append(result.Findings, domain.Finding{
			ID:          f.Id,
			PluginID:    f.ModuleId,
			Success:     f.Success,
			Title:       f.Title,
			Severity:    f.Severity,
			Description: f.Description,
			Evidence:    evidence,
			Tags:        tags,
			Timestamp:   f.Timestamp,
			Target: domain.HostPort{
				Host: f.Target.Host,
				Port: uint16(f.Target.Port),
			},
		})
	}

	return result
}

// Metadata fetches plugin metadata
func (c *Client) Metadata(ctx context.Context, endpoint string) (*plugpb.ModuleMetadata, error) {
	conn, err := grpc.DialContext(ctx, endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := plugpb.NewOrcaPluginV2Client(conn)
	return client.Metadata(ctx, &emptypb.Empty{})
}

// Ping checks if the plugin server is alive
func (c *Client) Ping(ctx context.Context, endpoint string) error {
	conn, err := grpc.DialContext(ctx, endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()

	client := plugpb.NewOrcaPluginV2Client(conn)
	_, err = client.Ping(ctx, &emptypb.Empty{})
	return err
}

// buildStreamConduit builds a stream-based conduit (TCP/TLS)
func (c *Client) buildStreamConduit(addr string, stack []module.LayerHint) (cnd.Conduit[cnd.Stream], error) {
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
			tlsConfig := c.buildTLSConfig(layer.Params)
			current = tlscond.NewTlsClient(current, tlsConfig)
		default:
			return nil, fmt.Errorf("unknown stream layer: %s", layer.Name)
		}
	}

	return current, nil
}

// buildDatagramConduit builds a datagram-based conduit (UDP/DTLS)
func (c *Client) buildDatagramConduit(addr string, stack []module.LayerHint) (cnd.Conduit[cnd.Datagram], error) {
	// Check if we need DTLS (it replaces UDP completely)
	for _, layer := range stack {
		if strings.ToLower(layer.Name) == "dtls" {
			// DTLS conduit handles UDP internally
			dtlsConfig := c.buildDTLSConfig(layer.Params)
			return tlscond.NewDtlsClient(addr, dtlsConfig), nil
		}
	}

	// Otherwise use plain UDP
	return transport.UDP(addr), nil
}

// buildTLSConfig creates a tls.Config from layer parameters
func (c *Client) buildTLSConfig(params map[string]any) *tls.Config {
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
func (c *Client) buildDTLSConfig(params map[string]any) *dtls.Config {
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
