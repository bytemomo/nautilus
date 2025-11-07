package manipulator

import (
	"context"
	"fmt"
	"sync"

	"bytemomo/siren/internal/core"
)

// Manipulator transforms traffic after rule evaluation.
type Manipulator interface {
	Name() string
	Configure(map[string]interface{}) error
	Process(context.Context, *core.TrafficContext, *core.ProcessingResult) (*core.ProcessingResult, error)
}

var (
	registryMu sync.RWMutex
	registry   = map[string]func() Manipulator{}
)

// Register exposes a manipulator constructor under the provided name.
func Register(name string, ctor func() Manipulator) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[name] = ctor
}

// Get returns a configured manipulator instance.
func Get(name string) (Manipulator, error) {
	registryMu.RLock()
	ctor, ok := registry[name]
	registryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("manipulator %s not registered", name)
	}
	return ctor(), nil
}
