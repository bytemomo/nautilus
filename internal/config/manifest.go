package config

import (
	"fmt"
	"time"
)

// Manifest represents an extension manifest configuration
type Manifest struct {
	Name         string            `yaml:"name" json:"name"`
	Version      string            `yaml:"version" json:"version"`
	Description  string            `yaml:"description,omitempty" json:"description,omitempty"`
	Author       string            `yaml:"author,omitempty" json:"author,omitempty"`
	License      string            `yaml:"license,omitempty" json:"license,omitempty"`
	Homepage     string            `yaml:"homepage,omitempty" json:"homepage,omitempty"`
	Interface    InterfaceSpec     `yaml:"interface" json:"interface"`
	Backend      BackendSpec       `yaml:"backend" json:"backend"`
	Dependencies []Dependency      `yaml:"dependencies,omitempty" json:"dependencies,omitempty"`
	Parameters   []Parameter       `yaml:"parameters,omitempty" json:"parameters,omitempty"`
	Capabilities []string          `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
	Tags         map[string]string `yaml:"tags,omitempty" json:"tags,omitempty"`
	Metadata     map[string]any    `yaml:"metadata,omitempty" json:"metadata,omitempty"`
}

// InterfaceSpec defines the extension interface type and version
type InterfaceSpec struct {
	Type    string `yaml:"type" json:"type"`       // protocol, mutator, executor, inspector
	Version string `yaml:"version" json:"version"` // interface version (e.g., "1.0", "2.1")
}

// BackendSpec defines the extension backend configuration
type BackendSpec struct {
	Type   string        `yaml:"type" json:"type"` // grpc, cshared
	Config BackendConfig `yaml:"config,omitempty" json:"config,omitempty"`
}

// BackendConfig contains backend-specific configuration
type BackendConfig struct {
	// gRPC backend configuration
	GRPC *GRPCConfig `yaml:"grpc,omitempty" json:"grpc,omitempty"`

	// C shared library backend configuration
	CShared *CSharedConfig `yaml:"cshared,omitempty" json:"cshared,omitempty"`
}

// GRPCConfig defines gRPC backend configuration
type GRPCConfig struct {
	Address     string        `yaml:"address,omitempty" json:"address,omitempty"`
	Port        int           `yaml:"port,omitempty" json:"port,omitempty"`
	TLS         bool          `yaml:"tls,omitempty" json:"tls,omitempty"`
	CertFile    string        `yaml:"cert_file,omitempty" json:"cert_file,omitempty"`
	KeyFile     string        `yaml:"key_file,omitempty" json:"key_file,omitempty"`
	CAFile      string        `yaml:"ca_file,omitempty" json:"ca_file,omitempty"`
	Timeout     time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	MaxRecvSize int           `yaml:"max_recv_size,omitempty" json:"max_recv_size,omitempty"`
	MaxSendSize int           `yaml:"max_send_size,omitempty" json:"max_send_size,omitempty"`
	Reflection  bool          `yaml:"reflection,omitempty" json:"reflection,omitempty"`
}

// CSharedConfig defines C shared library backend configuration
type CSharedConfig struct {
	LibraryPath  string            `yaml:"library_path" json:"library_path"`
	InitFunc     string            `yaml:"init_func,omitempty" json:"init_func,omitempty"`
	CleanupFunc  string            `yaml:"cleanup_func,omitempty" json:"cleanup_func,omitempty"`
	EntryPoints  map[string]string `yaml:"entry_points,omitempty" json:"entry_points,omitempty"`
	Environment  map[string]string `yaml:"environment,omitempty" json:"environment,omitempty"`
	PreloadLibs  []string          `yaml:"preload_libs,omitempty" json:"preload_libs,omitempty"`
	SymbolPrefix string            `yaml:"symbol_prefix,omitempty" json:"symbol_prefix,omitempty"`
}

// Dependency defines an extension dependency
type Dependency struct {
	Name        string `yaml:"name" json:"name"`
	Version     string `yaml:"version,omitempty" json:"version,omitempty"`
	Type        string `yaml:"type,omitempty" json:"type,omitempty"` // system, extension, library
	Optional    bool   `yaml:"optional,omitempty" json:"optional,omitempty"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// Parameter defines a configurable parameter for the extension
type Parameter struct {
	Name        string         `yaml:"name" json:"name"`
	Type        string         `yaml:"type" json:"type"` // string, int, bool, float, array, object
	Description string         `yaml:"description,omitempty" json:"description,omitempty"`
	Required    bool           `yaml:"required,omitempty" json:"required,omitempty"`
	Default     any            `yaml:"default,omitempty" json:"default,omitempty"`
	ValidValues []any          `yaml:"valid_values,omitempty" json:"valid_values,omitempty"`
	MinValue    *float64       `yaml:"min_value,omitempty" json:"min_value,omitempty"`
	MaxValue    *float64       `yaml:"max_value,omitempty" json:"max_value,omitempty"`
	MinLength   *int           `yaml:"min_length,omitempty" json:"min_length,omitempty"`
	MaxLength   *int           `yaml:"max_length,omitempty" json:"max_length,omitempty"`
	Pattern     string         `yaml:"pattern,omitempty" json:"pattern,omitempty"`
	Constraints []string       `yaml:"constraints,omitempty" json:"constraints,omitempty"`
	Examples    []any          `yaml:"examples,omitempty" json:"examples,omitempty"`
	Sensitive   bool           `yaml:"sensitive,omitempty" json:"sensitive,omitempty"`
	Deprecated  bool           `yaml:"deprecated,omitempty" json:"deprecated,omitempty"`
	Since       string         `yaml:"since,omitempty" json:"since,omitempty"`
	Tags        []string       `yaml:"tags,omitempty" json:"tags,omitempty"`
	Metadata    map[string]any `yaml:"metadata,omitempty" json:"metadata,omitempty"`
}

// Validate performs basic validation on the manifest
func (m *Manifest) Validate() error {
	if m.Name == "" {
		return ErrInvalidManifest("manifest name is required")
	}

	if m.Version == "" {
		return ErrInvalidManifest("manifest version is required")
	}

	if err := m.Interface.Validate(); err != nil {
		return ErrInvalidManifest("invalid interface specification: " + err.Error())
	}

	if err := m.Backend.Validate(); err != nil {
		return ErrInvalidManifest("invalid backend specification: " + err.Error())
	}

	// Validate parameters
	for i, param := range m.Parameters {
		if err := param.Validate(); err != nil {
			return ErrInvalidManifest("invalid parameter %d (%s): %s", i, param.Name, err.Error())
		}
	}

	// Validate dependencies
	for i, dep := range m.Dependencies {
		if err := dep.Validate(); err != nil {
			return ErrInvalidManifest("invalid dependency %d (%s): %s", i, dep.Name, err.Error())
		}
	}

	return nil
}

// Validate performs validation on the interface specification
func (i *InterfaceSpec) Validate() error {
	if i.Type == "" {
		return ErrInvalidInterface("interface type is required")
	}

	validTypes := []string{"protocol", "mutator", "executor", "inspector"}
	valid := false
	for _, validType := range validTypes {
		if i.Type == validType {
			valid = true
			break
		}
	}

	if !valid {
		return ErrInvalidInterface("interface type must be one of: protocol, mutator, executor, inspector")
	}

	if i.Version == "" {
		return ErrInvalidInterface("interface version is required")
	}

	return nil
}

// Validate performs validation on the backend specification
func (b *BackendSpec) Validate() error {
	if b.Type == "" {
		return ErrInvalidBackend("backend type is required")
	}

	switch b.Type {
	case "grpc":
		if b.Config.GRPC == nil {
			return ErrInvalidBackend("gRPC backend requires gRPC configuration")
		}
		return b.Config.GRPC.Validate()
	case "cshared":
		if b.Config.CShared == nil {
			return ErrInvalidBackend("C shared library backend requires cshared configuration")
		}
		return b.Config.CShared.Validate()
	default:
		return ErrInvalidBackend("backend type must be 'grpc' or 'cshared'")
	}
}

// Validate performs validation on gRPC configuration
func (g *GRPCConfig) Validate() error {
	if g.Port != 0 && (g.Port < 1 || g.Port > 65535) {
		return ErrInvalidBackend("gRPC port must be between 1 and 65535")
	}

	if g.TLS {
		if g.CertFile == "" || g.KeyFile == "" {
			return ErrInvalidBackend("TLS enabled but cert_file or key_file not specified")
		}
	}

	return nil
}

// Validate performs validation on C shared library configuration
func (c *CSharedConfig) Validate() error {
	if c.LibraryPath == "" {
		return ErrInvalidBackend("library_path is required for C shared library backend")
	}

	return nil
}

// Validate performs validation on a parameter
func (p *Parameter) Validate() error {
	if p.Name == "" {
		return ErrInvalidParameter("parameter name is required")
	}

	if p.Type == "" {
		return ErrInvalidParameter("parameter type is required")
	}

	validTypes := []string{"string", "int", "bool", "float", "array", "object"}
	valid := false
	for _, validType := range validTypes {
		if p.Type == validType {
			valid = true
			break
		}
	}

	if !valid {
		return ErrInvalidParameter("parameter type must be one of: string, int, bool, float, array, object")
	}

	// Validate numeric constraints
	if p.Type == "int" || p.Type == "float" {
		if p.MinValue != nil && p.MaxValue != nil && *p.MinValue > *p.MaxValue {
			return ErrInvalidParameter("min_value cannot be greater than max_value")
		}
	}

	// Validate string constraints
	if p.Type == "string" || p.Type == "array" {
		if p.MinLength != nil && p.MaxLength != nil && *p.MinLength > *p.MaxLength {
			return ErrInvalidParameter("min_length cannot be greater than max_length")
		}
	}

	return nil
}

// Validate performs validation on a dependency
func (d *Dependency) Validate() error {
	if d.Name == "" {
		return ErrInvalidDependency("dependency name is required")
	}

	if d.Type != "" {
		validTypes := []string{"system", "extension", "library"}
		valid := false
		for _, validType := range validTypes {
			if d.Type == validType {
				valid = true
				break
			}
		}

		if !valid {
			return ErrInvalidDependency("dependency type must be one of: system, extension, library")
		}
	}

	return nil
}

// GetParameter returns a parameter by name
func (m *Manifest) GetParameter(name string) (*Parameter, bool) {
	for i, param := range m.Parameters {
		if param.Name == name {
			return &m.Parameters[i], true
		}
	}
	return nil, false
}

// GetRequiredParameters returns all required parameters
func (m *Manifest) GetRequiredParameters() []Parameter {
	var required []Parameter
	for _, param := range m.Parameters {
		if param.Required {
			required = append(required, param)
		}
	}
	return required
}

// GetDependency returns a dependency by name
func (m *Manifest) GetDependency(name string) (*Dependency, bool) {
	for i, dep := range m.Dependencies {
		if dep.Name == name {
			return &m.Dependencies[i], true
		}
	}
	return nil, false
}

// GetRequiredDependencies returns all non-optional dependencies
func (m *Manifest) GetRequiredDependencies() []Dependency {
	var required []Dependency
	for _, dep := range m.Dependencies {
		if !dep.Optional {
			required = append(required, dep)
		}
	}
	return required
}

// IsGRPC returns true if this is a gRPC backend extension
func (m *Manifest) IsGRPC() bool {
	return m.Backend.Type == "grpc"
}

// IsCShared returns true if this is a C shared library backend extension
func (m *Manifest) IsCShared() bool {
	return m.Backend.Type == "cshared"
}

// GetInterfaceType returns the extension interface type
func (m *Manifest) GetInterfaceType() string {
	return m.Interface.Type
}

// HasCapability returns true if the extension has the specified capability
func (m *Manifest) HasCapability(capability string) bool {
	for _, cap := range m.Capabilities {
		if cap == capability {
			return true
		}
	}
	return false
}

// Error types for manifest validation
func ErrInvalidManifest(msg string, args ...any) error {
	if len(args) > 0 {
		return ConfigError{Type: "invalid_manifest", Message: fmt.Sprintf(msg, args...)}
	}
	return ConfigError{Type: "invalid_manifest", Message: msg}
}

func ErrInvalidInterface(msg string) error {
	return ConfigError{Type: "invalid_interface", Message: msg}
}

func ErrInvalidBackend(msg string) error {
	return ConfigError{Type: "invalid_backend", Message: msg}
}

func ErrInvalidParameter(msg string) error {
	return ConfigError{Type: "invalid_parameter", Message: msg}
}

func ErrInvalidDependency(msg string) error {
	return ConfigError{Type: "invalid_dependency", Message: msg}
}
