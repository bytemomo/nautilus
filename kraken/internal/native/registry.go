package native

import (
	"context"
	"time"

	"bytemomo/kraken/internal/domain"
)

// StreamFactory creates a new conduit handle for a module along with a cleanup func.
type StreamFactory func(ctx context.Context) (interface{}, func(), error)

// Resources exposes helpers available to native builtin modules.
type Resources struct {
	StreamFactory StreamFactory
}

// ModuleFunc is the signature implemented by builtin Go modules.
type ModuleFunc func(ctx context.Context, mod *domain.Module, target domain.HostPort, res Resources, params map[string]any, timeout time.Duration) (domain.RunResult, error)

var registry = map[string]ModuleFunc{}

// Register stores the module implementation under the provided ID.
func Register(id string, fn ModuleFunc) {
	if id == "" || fn == nil {
		return
	}
	registry[id] = fn
}

// Lookup returns the registered module implementation.
func Lookup(id string) (ModuleFunc, bool) {
	fn, ok := registry[id]
	return fn, ok
}
