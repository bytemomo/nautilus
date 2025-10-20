package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"bytemomo/siren/intercept"
	"bytemomo/siren/recorder"
	"bytemomo/trident/conduit"
)

// DatagramProxy handles UDP/DTLS datagram-based connections
type DatagramProxy struct {
	config    *ProxyConfig
	conn      net.PacketConn
	conduit   conduit.Conduit[conduit.Datagram]
	processor *TrafficProcessor
	stats     *ProxyStats

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	sessions sync.Map // map[string]*DatagramSession
	mu       sync.RWMutex
	running  bool
}

// DatagramSession represents a UDP "session" (pseudo-connection)
type DatagramSession struct {
	ID            string
	ClientAddr    net.Addr
	ServerAddr    net.Addr
	Stats         *ConnectionStats
	StartTime     time.Time
	LastActivity  time.Time
	State         ConnectionState
	mu            sync.RWMutex
}

// NewDatagramProxy creates a new datagram-based proxy
func NewDatagramProxy(
	config *ProxyConfig,
	conn net.PacketConn,
	conduit conduit.Conduit[conduit.Datagram],
	engine *intercept.Engine,
	rec *recorder.Recorder,
) *DatagramProxy {
	stats := NewProxyStats()
	return &DatagramProxy{
		config:    config,
		conn:      conn,
		conduit:   conduit,
		processor: NewTrafficProcessor(engine, rec, stats),
		stats:     stats,
	}
}

// Start begins accepting datagrams and proxying traffic
func (dp *DatagramProxy) Start(ctx context.Context) error {
	dp.mu.Lock()
	if dp.running {
		dp.mu.Unlock()
		return fmt.Errorf("proxy already running")
	}
	dp.running = true
	dp.ctx, dp.cancel = context.WithCancel(ctx)
	dp.mu.Unlock()

	if dp.config.EnableLogging {
		log.Printf("[DatagramProxy] Starting on %s -> %s", dp.conn.LocalAddr(), dp.config.TargetAddr)
	}

	// Dial server conduit once
	dialCtx, dialCancel := context.WithTimeout(dp.ctx, 10*time.Second)
	defer dialCancel()

	if err := dp.conduit.Dial(dialCtx); err != nil {
		return fmt.Errorf("failed to dial server: %w", err)
	}

	dp.wg.Add(2)
	go dp.receiveFromClients()
	go dp.receiveFromServer()

	return nil
}

// Stop gracefully shuts down the proxy
func (dp *DatagramProxy) Stop() error {
	dp.mu.Lock()
	if !dp.running {
		dp.mu.Unlock()
		return nil
	}
	dp.running = false
	dp.mu.Unlock()

	if dp.config.EnableLogging {
		log.Printf("[DatagramProxy] Stopping...")
	}

	// Close connections
	if err := dp.conn.Close(); err != nil {
		log.Printf("[DatagramProxy] Error closing listener: %v", err)
	}

	if err := dp.conduit.Close(); err != nil {
		log.Printf("[DatagramProxy] Error closing conduit: %v", err)
	}

	// Cancel context
	dp.cancel()

	// Wait for goroutines
	dp.wg.Wait()

	if dp.config.EnableLogging {
		log.Printf("[DatagramProxy] Stopped")
	}

	return nil
}

// Stats returns current proxy statistics
func (dp *DatagramProxy) Stats() *ProxyStats {
	return dp.stats
}

// receiveFromClients receives datagrams from clients and forwards to server
func (dp *DatagramProxy) receiveFromClients() {
	defer dp.wg.Done()

	buffer := make([]byte, dp.config.BufferSize)

	for {
		select {
		case <-dp.ctx.Done():
			return
		default:
		}

		// Read from client
		n, clientAddr, err := dp.conn.ReadFrom(buffer)
		if err != nil {
			select {
			case <-dp.ctx.Done():
				return
			default:
				if dp.config.EnableLogging {
					log.Printf("[DatagramProxy] Read error from client: %v", err)
				}
				continue
			}
		}

		if n == 0 {
			continue
		}

		// Get or create session
		session := dp.getOrCreateSession(clientAddr)
		session.UpdateActivity()

		// Process through interception engine
		tc := &TrafficContext{
			Conn:      dp.sessionToConnection(session),
			Direction: ClientToServer,
			Payload:   buffer[:n],
			Size:      n,
		}

		result, err := dp.processor.Process(dp.ctx, tc)
		if err != nil {
			if dp.config.EnableLogging {
				log.Printf("[DatagramProxy][%s] Processing error: %v", session.ID[:8], err)
			}
			continue
		}

		// Handle disconnect action
		if result.Disconnect {
			if dp.config.EnableLogging {
				log.Printf("[DatagramProxy][%s] Disconnect triggered by rule", session.ID[:8])
			}
			dp.removeSession(session.ID)
			continue
		}

		// Handle delay action
		if result.Delay > 0 {
			select {
			case <-time.After(result.Delay):
			case <-dp.ctx.Done():
				return
			}
		}

		// Handle drop action
		if result.Drop {
			if dp.config.EnableLogging {
				log.Printf("[DatagramProxy][%s] Packet dropped (%d bytes)", session.ID[:8], n)
			}
			continue
		}

		// Send to server
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
			if err := dp.sendToServer(session, payload); err != nil {
				if dp.config.EnableLogging {
					log.Printf("[DatagramProxy][%s] Send to server error: %v", session.ID[:8], err)
				}
				break
			}

			session.Stats.RecordBytes(ClientToServer, len(payload))
			dp.stats.RecordBytes(uint64(len(payload)))

			if i > 0 && result.Delay > 0 {
				select {
				case <-time.After(result.Delay):
				case <-dp.ctx.Done():
					return
				}
			}
		}
	}
}

// receiveFromServer receives datagrams from server and forwards to clients
func (dp *DatagramProxy) receiveFromServer() {
	defer dp.wg.Done()

	datagram := dp.conduit.Underlying()

	for {
		select {
		case <-dp.ctx.Done():
			return
		default:
		}

		// Receive from server using Trident
		msg, err := datagram.Recv(dp.ctx, &conduit.RecvOptions{
			MaxBytes: dp.config.BufferSize,
		})

		if err != nil {
			select {
			case <-dp.ctx.Done():
				return
			default:
				if dp.config.EnableLogging {
					log.Printf("[DatagramProxy] Recv error from server: %v", err)
				}
				continue
			}
		}

		if msg.Data == nil {
			continue
		}

		payload := msg.Data.Bytes()
		n := len(payload)

		if n == 0 {
			msg.Data.Release()
			continue
		}

		// Find session by server address (simplified - in reality you'd need better session tracking)
		// For UDP, we need to track which client initiated the connection
		// This is a simplified implementation
		var targetSession *DatagramSession
		dp.sessions.Range(func(key, value interface{}) bool {
			session := value.(*DatagramSession)
			// In a real implementation, you'd match based on NAT table or session tracking
			targetSession = session
			return false // Take first session for now
		})

		if targetSession == nil {
			msg.Data.Release()
			if dp.config.EnableLogging {
				log.Printf("[DatagramProxy] No session found for server response")
			}
			continue
		}

		targetSession.UpdateActivity()

		// Process through interception engine
		tc := &TrafficContext{
			Conn:      dp.sessionToConnection(targetSession),
			Direction: ServerToClient,
			Payload:   payload,
			Size:      n,
			Metadata:  &msg.MD,
		}

		result, err := dp.processor.Process(dp.ctx, tc)
		if err != nil {
			msg.Data.Release()
			if dp.config.EnableLogging {
				log.Printf("[DatagramProxy][%s] Processing error: %v", targetSession.ID[:8], err)
			}
			continue
		}

		// Handle disconnect action
		if result.Disconnect {
			msg.Data.Release()
			if dp.config.EnableLogging {
				log.Printf("[DatagramProxy][%s] Disconnect triggered by rule", targetSession.ID[:8])
			}
			dp.removeSession(targetSession.ID)
			continue
		}

		// Handle delay action
		if result.Delay > 0 {
			select {
			case <-time.After(result.Delay):
			case <-dp.ctx.Done():
				msg.Data.Release()
				return
			}
		}

		// Handle drop action
		if result.Drop {
			msg.Data.Release()
			if dp.config.EnableLogging {
				log.Printf("[DatagramProxy][%s] Packet dropped (%d bytes)", targetSession.ID[:8], n)
			}
			continue
		}

		// Send to client
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
			sent, err := dp.conn.WriteTo(sendPayload, targetSession.ClientAddr)
			if err != nil {
				if dp.config.EnableLogging {
					log.Printf("[DatagramProxy][%s] Send to client error: %v", targetSession.ID[:8], err)
				}
				break
			}

			targetSession.Stats.RecordBytes(ServerToClient, sent)
			dp.stats.RecordBytes(uint64(sent))

			if i > 0 && result.Delay > 0 {
				select {
				case <-time.After(result.Delay):
				case <-dp.ctx.Done():
					msg.Data.Release()
					return
				}
			}
		}

		msg.Data.Release()
	}
}

// sendToServer sends a datagram to the server using Trident
func (dp *DatagramProxy) sendToServer(session *DatagramSession, payload []byte) error {
	datagram := dp.conduit.Underlying()

	// Get buffer from pool
	buf := conduit.GetBuf(len(payload))
	copy(buf.Bytes(), payload)

	msg := &conduit.DatagramMsg{
		Data: buf,
		Dst:  datagram.RemoteAddr(),
	}

	_, _, err := datagram.Send(dp.ctx, msg, nil)
	return err
}

// getOrCreateSession gets an existing session or creates a new one
func (dp *DatagramProxy) getOrCreateSession(clientAddr net.Addr) *DatagramSession {
	sessionKey := clientAddr.String()

	// Try to load existing session
	if val, ok := dp.sessions.Load(sessionKey); ok {
		return val.(*DatagramSession)
	}

	// Create new session
	sessionID := generateDatagramSessionID()
	now := time.Now()

	session := &DatagramSession{
		ID:           sessionID,
		ClientAddr:   clientAddr,
		ServerAddr:   nil, // Set when we know it
		Stats:        &ConnectionStats{StartTime: now},
		StartTime:    now,
		LastActivity: now,
		State:        StateEstablished,
	}

	// Try to store it
	actual, loaded := dp.sessions.LoadOrStore(sessionKey, session)
	if loaded {
		return actual.(*DatagramSession)
	}

	dp.stats.AddConnection()

	if dp.config.EnableLogging {
		log.Printf("[DatagramProxy][%s] New session from %s", sessionID[:8], clientAddr)
	}

	return session
}

// removeSession removes a session
func (dp *DatagramProxy) removeSession(sessionID string) {
	dp.sessions.Range(func(key, value interface{}) bool {
		session := value.(*DatagramSession)
		if session.ID == sessionID {
			dp.sessions.Delete(key)
			dp.stats.RemoveConnection()

			if dp.config.EnableLogging {
				log.Printf("[DatagramProxy][%s] Session closed. Duration: %v, C->S: %d bytes, S->C: %d bytes",
					sessionID[:8],
					time.Since(session.StartTime),
					session.Stats.BytesClientServer,
					session.Stats.BytesServerClient,
				)
			}
			return false
		}
		return true
	})
}

// sessionToConnection converts a DatagramSession to a Connection for compatibility
func (dp *DatagramProxy) sessionToConnection(session *DatagramSession) *Connection {
	return &Connection{
		ID:           session.ID,
		ClientAddr:   session.ClientAddr,
		ServerAddr:   session.ServerAddr,
		Stats:        session.Stats,
		StartTime:    session.StartTime,
		LastActivity: session.LastActivity,
		Protocol:     "datagram",
		State:        session.State,
	}
}

// UpdateActivity updates the last activity time
func (s *DatagramSession) UpdateActivity() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastActivity = time.Now()
}

// generateDatagramSessionID generates a unique session identifier
func generateDatagramSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// GetAllSessions returns all active sessions
func (dp *DatagramProxy) GetAllSessions() []*DatagramSession {
	var sessions []*DatagramSession
	dp.sessions.Range(func(key, value interface{}) bool {
		sessions = append(sessions, value.(*DatagramSession))
		return true
	})
	return sessions
}
