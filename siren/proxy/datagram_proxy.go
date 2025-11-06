package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"sync"
	"time"

	"bytemomo/siren/intercept"
	"bytemomo/siren/pkg/core"
	"bytemomo/siren/pkg/manipulator"
	"bytemomo/siren/pkg/sirenerr"
	"bytemomo/siren/recorder"
	"bytemomo/trident/conduit"

	"github.com/sirupsen/logrus"
)

// DatagramProxy handles UDP/DTLS datagram-based connections
type DatagramProxy struct {
	config    *ProxyConfig
	conn      net.PacketConn
	conduit   conduit.Conduit[conduit.Datagram]
	processor *TrafficProcessor
	stats     *ProxyStats
	log       *logrus.Entry

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	sessions sync.Map // map[string]*DatagramSession
	mu       sync.RWMutex
	running  bool
}

// DatagramSession represents a UDP "session" (pseudo-connection)
type DatagramSession struct {
	ID           string
	ClientAddr   net.Addr
	ServerAddr   net.Addr
	Stats        *core.ConnectionStats
	StartTime    time.Time
	LastActivity time.Time
	State        core.ConnectionState
	mu           sync.RWMutex
}

// NewDatagramProxy creates a new datagram-based proxy
func NewDatagramProxy(
	config *ProxyConfig,
	conn net.PacketConn,
	conduit conduit.Conduit[conduit.Datagram],
	engine *intercept.Engine,
	rec *recorder.Recorder,
	log *logrus.Entry,
	manipulators []manipulator.Manipulator,
) *DatagramProxy {
	stats := NewProxyStats()
	return &DatagramProxy{
		config:    config,
		conn:      conn,
		conduit:   conduit,
		processor: NewTrafficProcessor(engine, rec, stats, log, manipulators),
		stats:     stats,
		log:       log,
	}
}

// Start begins accepting datagrams and proxying traffic
func (dp *DatagramProxy) Start(ctx context.Context) error {
	op := "proxy.DatagramProxy.Start"
	dp.mu.Lock()
	if dp.running {
		dp.mu.Unlock()
		return sirenerr.E(op, "proxy already running", 0, nil)
	}
	dp.running = true
	dp.ctx, dp.cancel = context.WithCancel(ctx)
	dp.mu.Unlock()

	dp.log.Infof("Starting on %s -> %s", dp.conn.LocalAddr(), dp.config.TargetAddr)

	dialCtx, dialCancel := context.WithTimeout(dp.ctx, 10*time.Second)
	defer dialCancel()

	if err := dp.conduit.Dial(dialCtx); err != nil {
		return sirenerr.E(op, "failed to dial server", 0, err)
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

	dp.log.Info("Stopping...")

	if err := dp.conn.Close(); err != nil {
		dp.log.Errorf("Error closing listener: %v", err)
	}

	if err := dp.conduit.Close(); err != nil {
		dp.log.Errorf("Error closing conduit: %v", err)
	}

	dp.cancel()
	dp.wg.Wait()

	dp.log.Info("Stopped")

	return nil
}

// Stats returns current proxy statistics
func (dp *DatagramProxy) Stats() *ProxyStats {
	return dp.stats
}

func (dp *DatagramProxy) receiveFromClients() {
	defer dp.wg.Done()

	buffer := make([]byte, dp.config.BufferSize)

	for {
		select {
		case <-dp.ctx.Done():
			return
		default:
		}

		n, clientAddr, err := dp.conn.ReadFrom(buffer)
		if err != nil {
			select {
			case <-dp.ctx.Done():
				return
			default:
				dp.log.Errorf("Read error from client: %v", err)
				continue
			}
		}

		if n == 0 {
			continue
		}

		session := dp.getOrCreateSession(clientAddr)
		session.UpdateActivity()

		tc := &core.TrafficContext{
			Conn:      dp.sessionToConnection(session),
			Direction: core.ClientToServer,
			Payload:   buffer[:n],
			Size:      n,
		}

		result, err := dp.processor.Process(dp.ctx, tc)
		if err != nil {
			dp.log.WithField("sessionID", session.ID[:8]).Errorf("Processing error: %v", err)
			continue
		}

		if result.Disconnect {
			dp.log.WithField("sessionID", session.ID[:8]).Info("Disconnect triggered by rule")
			dp.removeSession(session.ID)
			continue
		}

		if result.Delay > 0 {
			select {
			case <-time.After(result.Delay):
			case <-dp.ctx.Done():
				return
			}
		}

		if result.Drop {
			dp.log.WithField("sessionID", session.ID[:8]).Infof("Packet dropped (%d bytes)", n)
			continue
		}

		payload := result.ModifiedPayload
		if payload == nil {
			payload = buffer[:n]
		}

		sendCount := 1
		if result.Duplicate > 0 {
			sendCount = result.Duplicate + 1
		}

		for i := 0; i < sendCount; i++ {
			if err := dp.sendToServer(session, payload); err != nil {
				dp.log.WithField("sessionID", session.ID[:8]).Errorf("Send to server error: %v", err)
				break
			}

			session.Stats.RecordBytes(core.ClientToServer, len(payload))
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

func (dp *DatagramProxy) receiveFromServer() {
	defer dp.wg.Done()

	datagram := dp.conduit.Underlying()

	for {
		select {
		case <-dp.ctx.Done():
			return
		default:
		}

		msg, err := datagram.Recv(dp.ctx, &conduit.RecvOptions{
			MaxBytes: dp.config.BufferSize,
		})

		if err != nil {
			select {
			case <-dp.ctx.Done():
				return
			default:
				dp.log.Errorf("Recv error from server: %v", err)
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

		var targetSession *DatagramSession
		dp.sessions.Range(func(key, value interface{}) bool {
			session := value.(*DatagramSession)
			targetSession = session
			return false
		})

		if targetSession == nil {
			msg.Data.Release()
			dp.log.Warn("No session found for server response")
			continue
		}

		targetSession.UpdateActivity()

		tc := &core.TrafficContext{
			Conn:      dp.sessionToConnection(targetSession),
			Direction: core.ServerToClient,
			Payload:   payload,
			Size:      n,
			Metadata:  &msg.MD,
		}

		result, err := dp.processor.Process(dp.ctx, tc)
		if err != nil {
			msg.Data.Release()
			dp.log.WithField("sessionID", targetSession.ID[:8]).Errorf("Processing error: %v", err)
			continue
		}

		if result.Disconnect {
			msg.Data.Release()
			dp.log.WithField("sessionID", targetSession.ID[:8]).Info("Disconnect triggered by rule")
			dp.removeSession(targetSession.ID)
			continue
		}

		if result.Delay > 0 {
			select {
			case <-time.After(result.Delay):
			case <-dp.ctx.Done():
				msg.Data.Release()
				return
			}
		}

		if result.Drop {
			msg.Data.Release()
			dp.log.WithField("sessionID", targetSession.ID[:8]).Infof("Packet dropped (%d bytes)", n)
			continue
		}

		sendPayload := result.ModifiedPayload
		if sendPayload == nil {
			sendPayload = payload
		}

		sendCount := 1
		if result.Duplicate > 0 {
			sendCount = result.Duplicate + 1
		}

		for i := 0; i < sendCount; i++ {
			sent, err := dp.conn.WriteTo(sendPayload, targetSession.ClientAddr)
			if err != nil {
				dp.log.WithField("sessionID", targetSession.ID[:8]).Errorf("Send to client error: %v", err)
				break
			}

			targetSession.Stats.RecordBytes(core.ServerToClient, sent)
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

func (dp *DatagramProxy) sendToServer(session *DatagramSession, payload []byte) error {
	datagram := dp.conduit.Underlying()

	buf := conduit.GetBuf(len(payload))
	copy(buf.Bytes(), payload)

	msg := &conduit.DatagramMsg{
		Data: buf,
		Dst:  datagram.RemoteAddr(),
	}

	_, _, err := datagram.Send(dp.ctx, msg, nil)
	return err
}

func (dp *DatagramProxy) getOrCreateSession(clientAddr net.Addr) *DatagramSession {
	sessionKey := clientAddr.String()

	if val, ok := dp.sessions.Load(sessionKey); ok {
		return val.(*DatagramSession)
	}

	sessionID := generateDatagramSessionID()
	now := time.Now()

	session := &DatagramSession{
		ID:           sessionID,
		ClientAddr:   clientAddr,
		ServerAddr:   nil,
		Stats:        &core.ConnectionStats{StartTime: now},
		StartTime:    now,
		LastActivity: now,
		State:        core.StateEstablished,
	}

	actual, loaded := dp.sessions.LoadOrStore(sessionKey, session)
	if loaded {
		return actual.(*DatagramSession)
	}

	dp.stats.AddConnection()
	dp.log.WithFields(logrus.Fields{
		"sessionID": sessionID[:8],
		"client_ip": clientAddr,
	}).Info("New session")

	return session
}

func (dp *DatagramProxy) removeSession(sessionID string) {
	dp.sessions.Range(func(key, value interface{}) bool {
		session := value.(*DatagramSession)
		if session.ID == sessionID {
			dp.sessions.Delete(key)
			dp.stats.RemoveConnection()

			dp.log.WithFields(logrus.Fields{
				"sessionID": sessionID[:8],
				"duration":  time.Since(session.StartTime),
				"c_to_s":    session.Stats.BytesClientServer,
				"s_to_c":    session.Stats.BytesServerClient,
			}).Info("Session closed")
			return false
		}
		return true
	})
}

func (dp *DatagramProxy) sessionToConnection(session *DatagramSession) *core.Connection {
	return &core.Connection{
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

func (s *DatagramSession) UpdateActivity() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastActivity = time.Now()
}

func generateDatagramSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (dp *DatagramProxy) GetAllSessions() []*DatagramSession {
	var sessions []*DatagramSession
	dp.sessions.Range(func(key, value interface{}) bool {
		sessions = append(sessions, value.(*DatagramSession))
		return true
	})
	return sessions
}
