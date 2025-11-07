package ebpf

import (
	"context"
	"fmt"
	"net"
	"time"

	"bytemomo/siren/internal/core"
	"bytemomo/siren/internal/intercept"
	"bytemomo/siren/internal/proxy"

	"github.com/sirupsen/logrus"
)

// Runtime wires the eBPF dataplane with the rule/manipulation pipeline.
type Runtime struct {
	manager      *Manager
	processor    *proxy.TrafficProcessor
	log          *logrus.Entry
	dropDuration time.Duration
}

// RuntimeConfig configures the Runtime behavior.
type RuntimeConfig struct {
	DropDuration time.Duration
}

// NewRuntime creates a Runtime instance.
func NewRuntime(mgr *Manager, processor *proxy.TrafficProcessor, log *logrus.Entry, cfg RuntimeConfig) *Runtime {
	if cfg.DropDuration <= 0 {
		cfg.DropDuration = 5 * time.Second
	}
	return &Runtime{
		manager:      mgr,
		processor:    processor,
		log:          log,
		dropDuration: cfg.DropDuration,
	}
}

// Run starts consuming events from the eBPF program until the context is cancelled.
func (r *Runtime) Run(ctx context.Context) error {
	return r.manager.Read(ctx, func(evt *PacketEvent) {
		r.handleEvent(ctx, evt)
	})
}

func (r *Runtime) handleEvent(ctx context.Context, evt *PacketEvent) {
	payload := evt.Capture
	if int(evt.PayloadOffset) <= len(evt.Capture) {
		payload = evt.Capture[evt.PayloadOffset:]
	} else {
		payload = nil
	}

	conn := &core.Connection{
		ID:         GenerateFlowID(),
		Protocol:   protocolName(evt),
		State:      core.StateActive,
		StartTime:  evt.Timestamp,
		Stats:      &core.ConnectionStats{StartTime: evt.Timestamp},
		ClientAddr: buildAddr(evt.SrcIP, evt.SrcPort, evt.SrcMAC),
		ServerAddr: buildAddr(evt.DstIP, evt.DstPort, evt.DstMAC),
	}

	direction := convertDirection(evt.Direction)
	conn.Stats.RecordBytes(direction, len(payload))

	tc := &core.TrafficContext{
		Conn:      conn,
		Direction: direction,
		Payload:   payload,
		Size:      len(payload),
		Frame:     append([]byte(nil), evt.Capture...),
	}

	result, err := r.processor.Process(ctx, tc)
	if err != nil {
		r.log.WithError(err).Warn("processing pipeline failed")
		return
	}

	r.enforceResult(evt, result)
}

func (r *Runtime) enforceResult(evt *PacketEvent, result *core.ProcessingResult) {
	if result == nil {
		return
	}

	if result.Drop {
		duration := r.dropDuration
		if result.Metadata != nil {
			if raw, ok := result.Metadata["drop_duration"].(string); ok {
				if parsed, err := time.ParseDuration(raw); err == nil {
					duration = parsed
				}
			}
		}

		if err := r.manager.ApplyAction(FlowKeyFromEvent(evt), FlowAction{
			Type:     FlowActionDrop,
			Duration: duration,
		}); err != nil {
			r.log.WithError(err).Warn("failed to program drop action")
		} else {
			r.log.WithFields(logrus.Fields{
				"src":      endpointString(evt.SrcIP, evt.SrcPort, evt.SrcMAC),
				"dst":      endpointString(evt.DstIP, evt.DstPort, evt.DstMAC),
				"duration": duration,
			}).Info("flow dropped via eBPF")
		}
		return
	}

	switch result.Action {
	case intercept.ActionPass, intercept.ActionLog, intercept.ActionDrop:
		return
	default:
		// Delay/duplicate/modification actions would require a TC program or user-space responder.
		r.log.WithFields(logrus.Fields{
			"action": result.Action.String(),
		}).Debug("action not supported in eBPF mode")
	}
}

func convertDirection(dir FlowDirection) core.Direction {
	if dir == FlowDirectionIngress {
		return core.ClientToServer
	}
	return core.ServerToClient
}

func buildAddr(ip net.IP, port uint16, mac net.HardwareAddr) net.Addr {
	if ip != nil && !ip.Equal(net.IPv4zero) && len(ip) != 0 {
		return &net.TCPAddr{IP: append(net.IP(nil), ip...), Port: int(port)}
	}
	if len(mac) == 6 {
		return linkAddr{MAC: append(net.HardwareAddr(nil), mac...)}
	}
	return nil
}

func protocolName(evt *PacketEvent) string {
	if evt.EtherType == etherTypeEtherCAT {
		return "ethercat"
	}
	switch evt.Proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return fmt.Sprintf("proto-%d", evt.Proto)
	}
}

func endpointString(ip net.IP, port uint16, mac net.HardwareAddr) string {
	if ip != nil && !ip.Equal(net.IPv4zero) && len(ip) > 0 {
		return fmt.Sprintf("%s:%d", ip, port)
	}
	if len(mac) == 6 {
		return mac.String()
	}
	return "unknown"
}

type linkAddr struct {
	MAC net.HardwareAddr
}

func (l linkAddr) Network() string {
	return "ether"
}

func (l linkAddr) String() string {
	return l.MAC.String()
}
