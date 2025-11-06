package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
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

// StreamProxy handles TCP/TLS stream-based connections
type StreamProxy struct {
	config    *ProxyConfig
	listener  net.Listener
	conduit   conduit.Conduit[conduit.Stream]
	processor *TrafficProcessor
	stats     *ProxyStats
	log       *logrus.Entry

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	connections sync.Map
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
	log *logrus.Entry,
	manipulators []manipulator.Manipulator,
) *StreamProxy {
	stats := NewProxyStats()
	return &StreamProxy{
		config:    config,
		listener:  listener,
		conduit:   conduit,
		processor: NewTrafficProcessor(engine, rec, stats, log, manipulators),
		stats:     stats,
		log:       log,
	}
}

// Start begins accepting connections and proxying traffic
func (sp *StreamProxy) Start(ctx context.Context) error {
	op := "proxy.StreamProxy.Start"
	sp.mu.Lock()
	if sp.running {
		sp.mu.Unlock()
		return sirenerr.E(op, "proxy already running", 0, nil)
	}
	sp.running = true
	sp.ctx, sp.cancel = context.WithCancel(ctx)
	sp.mu.Unlock()

	sp.log.Infof("Starting on %s -> %s", sp.listener.Addr(), sp.config.TargetAddr)

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

	sp.log.Info("Stopping...")

	if err := sp.listener.Close(); err != nil {
		sp.log.Errorf("Error closing listener: %v", err)
	}

	sp.cancel()
	sp.wg.Wait()

	sp.log.Info("Stopped")

	return nil
}

// Stats returns current proxy statistics
func (sp *StreamProxy) Stats() *ProxyStats {
	return sp.stats
}

func (sp *StreamProxy) acceptLoop() {
	defer sp.wg.Done()

	for {
		clientConn, err := sp.listener.Accept()
		if err != nil {
			select {
			case <-sp.ctx.Done():
				return
			default:
				sp.log.Errorf("Accept error: %v", err)
				continue
			}
		}

		if sp.stats.ActiveConnections >= sp.config.MaxConnections {
			sp.log.Warnf("Connection limit reached, rejecting %s", clientConn.RemoteAddr())
			clientConn.Close()
			continue
		}

		sp.wg.Add(1)
		go sp.handleConnection(clientConn)
	}
}

func (sp *StreamProxy) handleConnection(clientConn net.Conn) {
	defer sp.wg.Done()

	connID := generateConnectionID()
	connLog := sp.log.WithField("connID", connID[:8])

	conn := NewConnection(
		connID,
		clientConn.RemoteAddr(),
		nil, // Will be set after dialing server
		"stream",
	)

	sp.connections.Store(connID, conn)
	sp.stats.AddConnection()

	defer func() {
		conn.State = core.StateClosed
		conn.Stats.EndTime = time.Now()
		sp.connections.Delete(connID)
		sp.stats.RemoveConnection()
		clientConn.Close()

		connLog.WithFields(logrus.Fields{
			"duration":   conn.Stats.Duration(),
			"client_ip":  conn.ClientAddr,
			"server_ip":  conn.ServerAddr,
			"c_to_s":     conn.Stats.BytesClientServer,
			"s_to_c":     conn.Stats.BytesServerClient,
			"dropped":    conn.Stats.Dropped,
			"modified":   conn.Stats.Modified,
		}).Info("Connection closed")
	}()

	if sp.config.ConnectionTimeout > 0 {
		clientConn.SetDeadline(time.Now().Add(sp.config.ConnectionTimeout))
	}

	serverConduit := sp.cloneConduit()

	dialCtx, dialCancel := context.WithTimeout(sp.ctx, 10*time.Second)
	defer dialCancel()

	if err := serverConduit.Dial(dialCtx); err != nil {
		connLog.Errorf("Failed to dial server: %v", err)
		return
	}

	serverStream := serverConduit.Underlying()
	conn.ServerAddr = serverStream.RemoteAddr()
	conn.State = core.StateEstablished

	defer serverConduit.Close()

	connLog.WithFields(logrus.Fields{
		"client_ip":  clientConn.RemoteAddr(),
		"server_ip":  serverStream.RemoteAddr(),
		"stack":      serverConduit.Stack(),
	}).Info("Connection established")


	connCtx, connCancel := context.WithCancel(sp.ctx)
	defer connCancel()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		sp.proxyFromNetConn(connCtx, conn, clientConn, serverStream, core.ClientToServer, connLog)
	}()

	go func() {
		defer wg.Done()
		sp.proxyFromStream(connCtx, conn, serverStream, clientConn, core.ServerToClient, connLog)
	}()

	wg.Wait()
}

func (sp *StreamProxy) proxyFromNetConn(
	ctx context.Context,
	conn *core.Connection,
	src net.Conn,
	dst conduit.Stream,
	direction core.Direction,
	log *logrus.Entry,
) {
	buffer := make([]byte, sp.config.BufferSize)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := src.Read(buffer)
		if n > 0 {
			conn.LastActivity = time.Now()

			tc := &core.TrafficContext{
				Conn:      conn,
				Direction: direction,
				Payload:   buffer[:n],
				Size:      n,
			}

			result, procErr := sp.processor.Process(ctx, tc)
			if procErr != nil {
				log.Errorf("Processing error: %v", procErr)
				return
			}

			if result.Disconnect {
				log.Info("Disconnect triggered by rule")
				return
			}

			if result.Delay > 0 {
				select {
				case <-time.After(result.Delay):
				case <-ctx.Done():
					return
				}
			}

			if result.Drop {
				log.Infof("Packet dropped (%d bytes)", n)
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
				sent, _, sendErr := dst.Send(ctx, payload, nil, nil)
				if sendErr != nil {
					log.Errorf("Send error: %v", sendErr)
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
				log.Errorf("Read error: %v", err)
			}
			return
		}
	}
}

func (sp *StreamProxy) proxyFromStream(
	ctx context.Context,
	conn *core.Connection,
	src conduit.Stream,
	dst net.Conn,
	direction core.Direction,
	log *logrus.Entry,
) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		chunk, err := src.Recv(ctx, &conduit.RecvOptions{
			MaxBytes: sp.config.BufferSize,
		})

		if err != nil {
			if err != io.EOF && err != context.Canceled {
				log.Errorf("Recv error: %v", err)
			}
			return
		}

		if chunk.Data == nil {
			continue
		}

		payload := chunk.Data.Bytes()
		n := len(payload)

		if n > 0 {
			conn.LastActivity = time.Now()

			tc := &core.TrafficContext{
				Conn:      conn,
				Direction: direction,
				Payload:   payload,
				Size:      n,
				Metadata:  &chunk.MD,
			}

			result, procErr := sp.processor.Process(ctx, tc)
			if procErr != nil {
				chunk.Data.Release()
				log.Errorf("Processing error: %v", procErr)
				return
			}

			if result.Disconnect {
				chunk.Data.Release()
				log.Info("Disconnect triggered by rule")
				return
			}

			if result.Delay > 0 {
				select {
				case <-time.After(result.Delay):
				case <-ctx.Done():
					chunk.Data.Release()
					return
				}
			}

			if result.Drop {
				chunk.Data.Release()
				log.Infof("Packet dropped (%d bytes)", n)
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
				sent, sendErr := dst.Write(sendPayload)
				if sendErr != nil {
					log.Errorf("Write error: %v", sendErr)
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

func (sp *StreamProxy) cloneConduit() conduit.Conduit[conduit.Stream] {
	return sp.conduit
}

func generateConnectionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (sp *StreamProxy) GetConnection(id string) (*core.Connection, bool) {
	val, ok := sp.connections.Load(id)
	if !ok {
		return nil, false
	}
	return val.(*core.Connection), true
}

func (sp *StreamProxy) GetAllConnections() []*core.Connection {
	var conns []*core.Connection
	sp.connections.Range(func(key, value interface{}) bool {
		conns = append(conns, value.(*core.Connection))
		return true
	})
	return conns
}
