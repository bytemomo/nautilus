package adapter

import (
	"context"
	"fmt"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/native"
	"bytemomo/kraken/internal/transport"
	cnd "bytemomo/trident/conduit"
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
func (n *NativeBuiltinAdapter) Run(ctx context.Context, m *domain.Module, params map[string]any, t domain.HostPort, timeout time.Duration) (domain.RunResult, error) {
	fn, ok := native.Lookup(m.ModuleID)
	if !ok {
		return domain.RunResult{Target: t}, fmt.Errorf("unknown builtin module %q", m.ModuleID)
	}

	merged := make(map[string]any)
	for k, v := range m.ExecConfig.Params {
		merged[k] = v
	}
	for k, v := range params {
		merged[k] = v
	}

	resources, err := n.buildResources(t, m.ExecConfig.Conduit.Kind, m.ExecConfig.Conduit.Stack)
	if err != nil {
		return domain.RunResult{Target: t}, err
	}

	return fn(ctx, m, t, resources, merged, timeout)
}

func (n *NativeBuiltinAdapter) buildResources(target domain.HostPort, kind cnd.Kind, stack []domain.LayerHint) (native.Resources, error) {
	var res native.Resources
	if stack == nil || kind == 0 {
		return res, nil
	}

	addr := fmt.Sprintf("%s:%d", target.Host, target.Port)
	switch kind {
	case cnd.KindStream:
		stack := stack
		res.StreamFactory = func(ctx context.Context) (interface{}, func(), error) {
			conduit, err := transport.BuildStreamConduit(addr, stack)
			if err != nil {
				return nil, nil, err
			}
			if err := conduit.Dial(ctx); err != nil {
				conduit.Close()
				return nil, nil, err
			}
			return conduit.Underlying(), func() { conduit.Close() }, nil
		}
	case cnd.KindDatagram:
		return res, fmt.Errorf("builtin datagram conduits not supported yet")
	default:
		return res, fmt.Errorf("unsupported conduit kind %d for builtin module", kind)
	}

	return res, nil
}
