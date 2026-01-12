package adapter

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/native"
	"bytemomo/kraken/internal/runner/contextkeys"
	"bytemomo/kraken/internal/transport"
	cnd "bytemomo/trident/conduit"
	"bytemomo/trident/conduit/datalink"
)

// NativeBuiltinAdapter executes Go-native modules compiled into the binary.
type NativeBuiltinAdapter struct{}

// NewNativeBuiltinAdapter creates a new adapter.
func NewNativeBuiltinAdapter() *NativeBuiltinAdapter {
	return &NativeBuiltinAdapter{}
}

// Supports returns true if the module references a builtin implementation.
func (n *NativeBuiltinAdapter) Supports(m *domain.Module) bool {
	return m != nil &&
		m.Type == domain.Native &&
		m.ExecConfig.ABI == nil &&
		m.ExecConfig.GRPC == nil &&
		m.ExecConfig.CLI == nil
}

// Run runs the builtin module function.
func (n *NativeBuiltinAdapter) Run(ctx context.Context, m *domain.Module, params map[string]any, t domain.Target, timeout time.Duration) (domain.RunResult, error) {
	desc, ok := native.Lookup(m.ModuleID)
	if !ok {
		// Try stripping conduit template suffix (e.g., "mqtt-dict-attack-tcp" -> "mqtt-dict-attack")
		baseID := stripTemplateSuffix(m.ModuleID)
		if baseID != m.ModuleID {
			desc, ok = native.Lookup(baseID)
		}
		if !ok {
			return domain.RunResult{Target: t}, fmt.Errorf("unknown builtin module %q", m.ModuleID)
		}
	}
	fn := desc.Run

	resources, err := n.buildResources(ctx, t, desc.Kind, desc.Stack)
	if err != nil {
		return domain.RunResult{Target: t}, err
	}

	return fn(ctx, m, t, resources, params, timeout)
}

func (n *NativeBuiltinAdapter) buildResources(ctx context.Context, target domain.Target, kind cnd.Kind, stack []domain.LayerHint) (native.Resources, error) {
	var res native.Resources
	if kind == 0 {
		return res, nil
	}

	dialOpts := n.dialOptionsFromContext(ctx)

	switch target.Kind() {
	case domain.TargetKindNetwork:
		return n.buildNetworkResources(target.(domain.HostPort), kind, stack, dialOpts)
	case domain.TargetKindEtherCAT:
		return n.buildEtherCATResources(target.(domain.EtherCATSlave), kind, dialOpts)
	default:
		return res, fmt.Errorf("unsupported target kind: %s", target.Kind())
	}
}

func (n *NativeBuiltinAdapter) dialOptionsFromContext(ctx context.Context) transport.DialOptions {
	if v := ctx.Value(contextkeys.ConnectionDefaults); v != nil {
		if defaults, ok := v.(*domain.ConnectionDefaults); ok {
			return transport.DialOptionsFromDefaults(defaults)
		}
	}
	return transport.DefaultDialOptions()
}

func (n *NativeBuiltinAdapter) buildNetworkResources(hp domain.HostPort, kind cnd.Kind, stack []domain.LayerHint, dialOpts transport.DialOptions) (native.Resources, error) {
	var res native.Resources
	addr := fmt.Sprintf("%s:%d", hp.Host, hp.Port)

	switch kind {
	case cnd.KindStream:
		layerStack := stack
		opts := dialOpts
		res.StreamFactory = func(ctx context.Context) (interface{}, func(), error) {
			conduit, err := transport.BuildStreamConduit(addr, layerStack)
			if err != nil {
				return nil, nil, err
			}
			if err := transport.DialWithRetry(ctx, conduit, opts); err != nil {
				conduit.Close()
				return nil, nil, err
			}
			return conduit.Underlying(), func() { conduit.Close() }, nil
		}
	case cnd.KindDatagram:
		layerStack := stack
		opts := dialOpts
		res.DatagramFactory = func(ctx context.Context) (interface{}, func(), error) {
			conduit, err := transport.BuildDatagramConduit(addr, layerStack)
			if err != nil {
				return nil, nil, err
			}
			if err := transport.DialWithRetry(ctx, conduit, opts); err != nil {
				conduit.Close()
				return nil, nil, err
			}
			return conduit.Underlying(), func() { conduit.Close() }, nil
		}
	default:
		return res, fmt.Errorf("unsupported conduit kind %d for network target", kind)
	}

	return res, nil
}

// stripTemplateSuffix removes conduit template suffixes like "-tcp" or "-tls" from module IDs.
func stripTemplateSuffix(id string) string {
	suffixes := []string{"-tcp", "-tls", "-dtls", "-udp"}
	for _, suffix := range suffixes {
		if strings.HasSuffix(id, suffix) {
			return strings.TrimSuffix(id, suffix)
		}
	}
	return id
}

func (n *NativeBuiltinAdapter) buildEtherCATResources(slave domain.EtherCATSlave, kind cnd.Kind, dialOpts transport.DialOptions) (native.Resources, error) {
	var res native.Resources

	if kind != cnd.KindFrame {
		return res, fmt.Errorf("EtherCAT targets require KindFrame conduit, got %d", kind)
	}

	iface := slave.Interface
	broadcast := net.HardwareAddr([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	opts := dialOpts

	res.FrameFactory = func(ctx context.Context) (interface{}, func(), error) {
		conduit := datalink.Ethernet(iface, broadcast, datalink.EtherTypeEtherCAT)
		if err := transport.DialWithRetry(ctx, conduit, opts); err != nil {
			conduit.Close()
			return nil, nil, err
		}
		return conduit.Underlying(), func() { conduit.Close() }, nil
	}

	return res, nil
}
