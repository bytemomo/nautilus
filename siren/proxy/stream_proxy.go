package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"bytemomo/siren/intercept"
	"bytemomo/siren/recorder"
	"bytemomo/trident/conduit"
)

// StreamProxy handles TCP/TLS stream-based connections
type StreamProxy struct {
	config    *ProxyConfig
	listener  net.Listener
	conduit   conduit.Conduit[conduit.Stream]
	processor *TrafficProcessor
	stats     *ProxyStats

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	connections sync.Map // map[string]*Connection
	mu          sync.RWMutex
	running     bool
}

// NewStreamProxy creates a new stream-based proxy
func NewStreamProxy(
	config *ProxyConfig,
	listener net.Listener,
	conduit conduit.Conduit[conduit.Stream],
	engine *intercept.Engine,
	rec *recorder.Recorder,
) *StreamProxy {
	stats := NewProxyStats()
	return &StreamProxy{
		config:    config,
		listener:  listener,
		conduit:   conduit,
		processor: NewTrafficProcessor(engine, rec, stats),
		stats:     stats,
	}
}

// Start begins accepting connections and proxying traffic
func (sp *StreamProxy) Start(ctx context.Context) error {
	sp.mu.Lock()
	if sp.running {
		sp.mu.Unlock()
		return fmt.Errorf("proxy already running")
	}
	sp.running = true
	sp.ctx, sp.cancel = context.WithCancel(ctx)
	sp.mu.Unlock()

	if sp.config.EnableLogging {
		log.Printf("[StreamProxy] Starting on %s -> %s", sp.listener.Addr(), sp.config.TargetAddr)
	}

	sp.wg.Add(1)
	go sp.acceptLoop()

	return nil
}

// Stop gracefully shuts down the proxy
func (sp *StreamProxy) Stop() error {
	sp.mu.Lock()
	if !sp.running {
		sp.mu.Unlock()
		return nil
	}
	sp.running = false
	sp.mu.Unlock()

	if sp.config.EnableLogging {
		log.Printf("[StreamProxy] Stopping...")
	}

	// Stop accepting new connections
	if err := sp.listener.Close(); err != nil {
		log.Printf("[StreamProxy] Error closing listener: %v", err)
	}

	// Cancel context to stop all goroutines
	sp.cancel()

	// Wait for all connections to finish
	sp.wg.Wait()

	if sp.config.EnableLogging {
		log.Printf("[StreamProxy] Stopped")
	}

	return nil
}

// Stats returns current proxy statistics
func (sp *StreamProxy) Stats() *ProxyStats {
	return sp.stats
}

// acceptLoop accepts incoming client connections
func (sp *StreamProxy) acceptLoop() {
	defer sp.wg.Done()

	for {
		clientConn, err := sp.listener.Accept()
		if err != nil {
			select {
			case <-sp.ctx.Done():
				return
			default:
				if sp.config.EnableLogging {
					log.Printf("[StreamProxy] Accept error: %v", err)
				}
				continue
			}
		}

		// Check connection limit
		if sp.stats.ActiveConnections >= sp.config.MaxConnections {
			if sp.config.EnableLogging {
				log.Printf("[StreamProxy] Connection limit reached, rejecting %s", clientConn.RemoteAddr())
			}
			clientConn.Close()
			continue
		}

		sp.wg.Add(1)
		go sp.handleConnection(clientConn)
	}
}

// handleConnection handles a single client connection
func (sp *StreamProxy) handleConnection(clientConn net.Conn) {
	defer sp.wg.Done()

	// Generate connection ID
	connID := generateConnectionID()

	// Create connection object
	conn := NewConnection(
		connID,
		clientConn.RemoteAddr(),
		nil, // Will be set after dialing server
		"stream",
	)

	// Register connection
	sp.connections.Store(connID, conn)
	sp.stats.AddConnection()

	defer func() {
		conn.SetState(StateClosed)
		conn.Stats.EndTime = time.Now()
		sp.connections.Delete(connID)
		sp.stats.RemoveConnection()
		clientConn.Close()

		if sp.config.EnableLogging {
			log.Printf("[StreamProxy][%s] Connection closed. Duration: %v, C->S: %d bytes, S->C: %d bytes, Dropped: %d, Modified: %d",
				connID[:8],
				conn.Stats.Duration(),
				conn.Stats.BytesClientServer,
				conn.Stats.BytesServerClient,
				conn.Stats.Dropped,
				conn.Stats.Modified,
			)
		}
	}()

	// Set connection timeout if configured
	if sp.config.ConnectionTimeout > 0 {
		clientConn.SetDeadline(time.Now().Add(sp.config.ConnectionTimeout))
	}

	// Create a new conduit instance for this connection (clone the prototype)
	serverConduit := sp.cloneConduit()

	// Dial server using Trident conduit
	dialCtx, dialCancel := context.WithTimeout(sp.ctx, 10*time.Second)
	defer dialCancel()

	if err := serverConduit.Dial(dialCtx); err != nil {
		if sp.config.EnableLogging {
			log.Printf("[StreamProxy][%s] Failed to dial server: %v", connID[:8], err)
		}
		return
	}

	serverStream := serverConduit.Underlying()
	conn.ServerAddr = serverStream.RemoteAddr()
	conn.SetState(StateEstablished)

	defer serverConduit.Close()

	if sp.config.EnableLogging {
		log.Printf("[StreamProxy][%s] Connection established: %s -> %s (stack: %v)",
			connID[:8],
			clientConn.RemoteAddr(),
			serverStream.RemoteAddr(),
			serverConduit.Stack(),
		)
	}

	// Create context for this connection
	connCtx, connCancel := context.WithCancel(sp.ctx)
	defer connCancel()

	// Bidirectional proxy
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Server
	go func() {
		defer wg.Done()
		sp.proxyStream(connCtx, conn, clientConn, serverStream, ClientToServer)
	}()

	// Server -> Client
	go func() {
		defer wg.Done()
		sp.proxyStream(connCtx, conn, serverStream, clientConn, ServerToClient)
	}()

	wg.Wait()
}

// proxyStream proxies data from src to dst with interception
func (sp *StreamProxy) proxyStream(
	ctx context.Context,
	conn *Connection,
	src io.Reader,
	dst conduit.Stream,
	direction Direction,
) {
	if netConn, ok := src.(net.Conn); ok {
		sp.proxyFromNetConn(ctx, conn, netConn, dst, direction)
	} else {
		sp.proxyFromStream(ctx, conn, src.(conduit.Stream), dst, direction)
	}
}

// proxyFromNetConn proxies from net.Conn to conduit.Stream
func (sp *StreamProxy) proxyFromNetConn(
	ctx context.Context,
	conn *Connection,
	src net.Conn,
	dst conduit.Stream,
	direction Direction,
) {
	buffer := make([]byte, sp.config.BufferSize)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Read from source
		n, err := src.Read(buffer)
		if n > 0 {
			conn.UpdateActivity()

			// Process through interception engine
			tc := &TrafficContext{
				Conn:      conn,
				Direction: direction,
				Payload:   buffer[:n],
				Size:      n,
			}

			result, procErr := sp.processor.Process(ctx, tc)
			if procErr != nil {
				if sp.config.EnableLogging {
					log.Printf("[StreamProxy][%s] Processing error: %v", conn.ID[:8], procErr)
				}
				return
			}

			// Handle disconnect action
			if result.Disconnect {
				if sp.config.EnableLogging {
					log.Printf("[StreamProxy][%s] Disconnect triggered by rule", conn.ID[:8])
				}
				return
			}

			// Handle delay action
			if result.Delay > 0 {
				select {
				case <-time.After(result.Delay):
				case <-ctx.Done():
					return
				}
			}

			// Handle drop action
			if result.Drop {
				if sp.config.EnableLogging {
					log.Printf("[StreamProxy][%s] Packet dropped (%d bytes)", conn.ID[:8], n)
				}
				continue
			}

			// Send to destination
			payload := result.ModifiedPayload
			if payload == nil {
				payload = buffer[:n]
			}

			// Handle duplicate action
			sendCount := 1
			if result.Duplicate > 0 {
				sendCount = result.Duplicate + 1
			}

			for i := 0; i < sendCount; i++ {
				sent, _, sendErr := dst.Send(ctx, payload, nil, nil)
				if sendErr != nil {
					if sp.config.EnableLogging {
						log.Printf("[StreamProxy][%s] Send error: %v", conn.ID[:8], sendErr)
					}
					return
				}

				conn.Stats.RecordBytes(direction, sent)
				sp.stats.RecordBytes(uint64(sent))

				if i > 0 && result.Delay > 0 {
					select {
					case <-time.After(result.Delay):
					case <-ctx.Done():
						return
					}
				}
			}
		}

		if err != nil {
			if err != io.EOF {
				if sp.config.EnableLogging {
					log.Printf("[StreamProxy][%s] Read error: %v", conn.ID[:8], err)
				}
			}
			return
		}
	}
}

// proxyFromStream proxies from conduit.Stream to conduit.Stream
func (sp *StreamProxy) proxyFromStream(
	ctx context.Context,
	conn *Connection,
	src conduit.Stream,
	dst conduit.Stream,
	direction Direction,
) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Receive from source using Trident
		chunk, err := src.Recv(ctx, &conduit.RecvOptions{
			MaxBytes: sp.config.BufferSize,
		})

		if err != nil {
			if err != io.EOF && err != context.Canceled {
				if sp.config.EnableLogging {
					log.Printf("[StreamProxy][%s] Recv error: %v", conn.ID[:8], err)
				}
			}
			return
		}

		if chunk.Data == nil {
			continue
		}

		payload := chunk.Data.Bytes()
		n := len(payload)

		if n > 0 {
			conn.UpdateActivity()

			// Process through interception engine
			tc := &TrafficContext{
				Conn:      conn,
				Direction: direction,
				Payload:   payload,
				Size:      n,
				Metadata:  &chunk.MD,
			}

			result, procErr := sp.processor.Process(ctx, tc)
			if procErr != nil {
				chunk.Data.Release()
				if sp.config.EnableLogging {
					log.Printf("[StreamProxy][%s] Processing error: %v", conn.ID[:8], procErr)
				}
				return
			}

			// Handle disconnect action
			if result.Disconnect {
				chunk.Data.Release()
				if sp.config.EnableLogging {
					log.Printf("[StreamProxy][%s] Disconnect triggered by rule", conn.ID[:8])
				}
				return
			}

			// Handle delay action
			if result.Delay > 0 {
				select {
				case <-time.After(result.Delay):
				case <-ctx.Done():
					chunk.Data.Release()
					return
				}
			}

			// Handle drop action
			if result.Drop {
				chunk.Data.Release()
				if sp.config.EnableLogging {
					log.Printf("[StreamProxy][%s] Packet dropped (%d bytes)", conn.ID[:8], n)
				}
				continue
			}

			// Send to destination
			sendPayload := result.ModifiedPayload
			if sendPayload == nil {
				sendPayload = payload
			}

			// Handle duplicate action
			sendCount := 1
			if result.Duplicate > 0 {
				sendCount = result.Duplicate + 1
			}

			for i := 0; i < sendCount; i++ {
				sent, _, sendErr := dst.Send(ctx, sendPayload, nil, nil)
				if sendErr != nil {
					if sp.config.EnableLogging {
						log.Printf("[StreamProxy][%s] Send error: %v", conn.ID[:8], sendErr)
					}
					chunk.Data.Release()
					return
				}

				conn.Stats.RecordBytes(direction, sent)
				sp.stats.RecordBytes(uint64(sent))

				if i > 0 && result.Delay > 0 {
					select {
					case <-time.After(result.Delay):
					case <-ctx.Done():
						chunk.Data.Release()
						return
					}
				}
			}
		}

		chunk.Data.Release()
	}
}

// cloneConduit creates a new instance of the conduit for each connection
// This is a simplified version - in practice, you'd need to recreate the conduit
// with the same configuration but as a new instance
func (sp *StreamProxy) cloneConduit() conduit.Conduit[conduit.Stream] {
	// Note: This is a placeholder. In the actual implementation, you would
	// need to reconstruct the conduit based on the original configuration.
	// For now, we assume the conduit can be reused or cloned properly.
	// This might require storing the conduit factory/builder instead.
	return sp.conduit
}

// generateConnectionID generates a unique connection identifier
func generateConnectionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// GetConnection retrieves a connection by ID
func (sp *StreamProxy) GetConnection(id string) (*Connection, bool) {
	val, ok := sp.connections.Load(id)
	if !ok {
		return nil, false
	}
	return val.(*Connection), true
}

// GetAllConnections returns all active connections
func (sp *StreamProxy) GetAllConnections() []*Connection {
	var conns []*Connection
	sp.connections.Range(func(key, value interface{}) bool {
		conns = append(conns, value.(*Connection))
		return true
	})
	return conns
}
