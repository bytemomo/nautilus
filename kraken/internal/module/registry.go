package module

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Registry manages a collection of module definitions
type Registry struct {
	modules map[string]*Module
}

// NewRegistry creates a new empty module registry
func NewRegistry() *Registry {
	return &Registry{
		modules: make(map[string]*Module),
	}
}

// Register adds a module to the registry
func (r *Registry) Register(m *Module) error {
	if m.ModuleID == "" {
		return fmt.Errorf("module ID is required")
	}
	if err := m.Validate(); err != nil {
		return fmt.Errorf("invalid module %q: %w", m.ModuleID, err)
	}
	r.modules[m.ModuleID] = m
	return nil
}

// Get retrieves a module by ID
func (r *Registry) Get(id string) (*Module, bool) {
	m, ok := r.modules[id]
	return m, ok
}

// LoadFromDirectory loads all module definitions from a directory
// Supports .yaml and .yml files
func (r *Registry) LoadFromDirectory(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("failed to read modules directory %q: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		ext := filepath.Ext(name)
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		path := filepath.Join(dir, name)
		if err := r.LoadFromFile(path); err != nil {
			return fmt.Errorf("failed to load module from %q: %w", path, err)
		}
	}

	return nil
}

// LoadFromFile loads a module definition from a YAML file
func (r *Registry) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var m Module
	if err := yaml.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("failed to parse module YAML: %w", err)
	}

	return r.Register(&m)
}

// Validate validates a module definition
func (m *Module) Validate() error {
	if m.ModuleID == "" {
		return fmt.Errorf("module ID is required")
	}

	// Check that exactly one execution type is configured
	// Note: Conduit is transport configuration, not an execution type
	hasABI := m.ExecConfig.ABI != nil
	hasGRPC := m.ExecConfig.GRPC != nil
	hasCLI := m.ExecConfig.CLI != nil

	count := 0
	if hasABI {
		count++
	}
	if hasGRPC {
		count++
	}
	if hasCLI {
		count++
	}

	if count == 0 {
		return fmt.Errorf("module must specify one execution type (abi, grpc, or cli)")
	}
	if count > 1 {
		return fmt.Errorf("module can only specify one execution type")
	}

	// Validate ABI config
	// ABI supports both V1 and V2
	if hasABI {
		if m.ExecConfig.ABI.LibraryPath == "" {
			return fmt.Errorf("abi.library_path is required")
		}
		if m.ExecConfig.ABI.Symbol == "" {
			return fmt.Errorf("abi.symbol is required")
		}
		if m.Type != Native && m.Type != Lib {
			return fmt.Errorf("abi execution requires type 'native' or 'lib'")
		}
		// ABI works with both V1 and V2 - no version restriction
	}

	// Validate GRPC config
	// gRPC only supports V2
	if hasGRPC {
		if m.ExecConfig.GRPC.ServerAddr == "" {
			return fmt.Errorf("grpc.server_addr is required")
		}
		if m.Type != Grpc {
			return fmt.Errorf("grpc execution requires type 'grpc'")
		}
		if m.Version != ModuleV2 {
			return fmt.Errorf("grpc execution only supports API version v2 (api: 1)")
		}
	}

	// Validate CLI config
	// CLI only supports V1
	if hasCLI {
		if m.ExecConfig.CLI.Path == "" {
			return fmt.Errorf("cli.path is required")
		}
		if m.Version != ModuleV1 {
			return fmt.Errorf("cli execution only supports API version v1 (api: 0)")
		}
	}

	// Validate Conduit config (if present)
	// Conduit is optional and only used in V2 execution
	// For V1 modules with conduit config, it will be ignored (allows transition)
	if m.ExecConfig.Conduit != nil {
		if m.ExecConfig.Conduit.Kind == 0 {
			return fmt.Errorf("conduit.kind is required when conduit is specified")
		}
		// Conduit is only meaningful for V2, but we allow it in V1 for transition
		// (it will simply be ignored by V1 executors)
	}

	return nil
}

// Clone creates a deep copy of the module with optional param overrides
func (m *Module) Clone(paramOverrides map[string]any) *Module {
	clone := &Module{
		ModuleID:     m.ModuleID,
		RequiredTags: append([]string{}, m.RequiredTags...),
		MaxDuration:  m.MaxDuration,
		Type:         m.Type,
		Version:      m.Version,
	}

	// Copy exec config
	clone.ExecConfig = m.ExecConfig

	// Merge params
	clone.ExecConfig.Params = make(map[string]any)
	for k, v := range m.ExecConfig.Params {
		clone.ExecConfig.Params[k] = v
	}
	for k, v := range paramOverrides {
		clone.ExecConfig.Params[k] = v
	}

	return clone
}

// List returns all registered module IDs
func (r *Registry) List() []string {
	ids := make([]string, 0, len(r.modules))
	for id := range r.modules {
		ids = append(ids, id)
	}
	return ids
}

// Count returns the number of registered modules
func (r *Registry) Count() int {
	return len(r.modules)
}
