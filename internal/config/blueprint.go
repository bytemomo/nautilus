package config

import (
	"fmt"
	"time"
)

// Blueprint represents a Docker topology blueprint
type Blueprint struct {
	Name        string             `yaml:"name" json:"name"`
	Version     string             `yaml:"version,omitempty" json:"version,omitempty"`
	Description string             `yaml:"description,omitempty" json:"description,omitempty"`
	Networks    map[string]Network `yaml:"networks,omitempty" json:"networks,omitempty"`
	Volumes     map[string]Volume  `yaml:"volumes,omitempty" json:"volumes,omitempty"`
	Services    map[string]Service `yaml:"services" json:"services"`
	Secrets     map[string]Secret  `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	Configs     map[string]Config  `yaml:"configs,omitempty" json:"configs,omitempty"`
	Extensions  map[string]any     `yaml:"extensions,omitempty" json:"extensions,omitempty"`
	Metadata    map[string]any     `yaml:"metadata,omitempty" json:"metadata,omitempty"`
}

// Network defines a Docker network configuration
type Network struct {
	Driver     string            `yaml:"driver,omitempty" json:"driver,omitempty"`
	DriverOpts map[string]string `yaml:"driver_opts,omitempty" json:"driver_opts,omitempty"`
	Attachable bool              `yaml:"attachable,omitempty" json:"attachable,omitempty"`
	Internal   bool              `yaml:"internal,omitempty" json:"internal,omitempty"`
	IPAM       *IPAM             `yaml:"ipam,omitempty" json:"ipam,omitempty"`
	External   *External         `yaml:"external,omitempty" json:"external,omitempty"`
	Labels     map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// IPAM defines IP Address Management configuration
type IPAM struct {
	Driver  string            `yaml:"driver,omitempty" json:"driver,omitempty"`
	Config  []IPAMConfig      `yaml:"config,omitempty" json:"config,omitempty"`
	Options map[string]string `yaml:"options,omitempty" json:"options,omitempty"`
}

// IPAMConfig defines IPAM configuration options
type IPAMConfig struct {
	Subnet     string            `yaml:"subnet,omitempty" json:"subnet,omitempty"`
	IPRange    string            `yaml:"ip_range,omitempty" json:"ip_range,omitempty"`
	Gateway    string            `yaml:"gateway,omitempty" json:"gateway,omitempty"`
	AuxAddress map[string]string `yaml:"aux_addresses,omitempty" json:"aux_addresses,omitempty"`
}

// Volume defines a Docker volume configuration
type Volume struct {
	Driver     string            `yaml:"driver,omitempty" json:"driver,omitempty"`
	DriverOpts map[string]string `yaml:"driver_opts,omitempty" json:"driver_opts,omitempty"`
	External   *External         `yaml:"external,omitempty" json:"external,omitempty"`
	Labels     map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// External defines external resource references
type External struct {
	Name string `yaml:"name,omitempty" json:"name,omitempty"`
}

// Service defines a Docker service/container configuration
type Service struct {
	Image         string                 `yaml:"image,omitempty" json:"image,omitempty"`
	Build         *Build                 `yaml:"build,omitempty" json:"build,omitempty"`
	ContainerName string                 `yaml:"container_name,omitempty" json:"container_name,omitempty"`
	Command       []string               `yaml:"command,omitempty" json:"command,omitempty"`
	Entrypoint    []string               `yaml:"entrypoint,omitempty" json:"entrypoint,omitempty"`
	Environment   map[string]string      `yaml:"environment,omitempty" json:"environment,omitempty"`
	Ports         []Port                 `yaml:"ports,omitempty" json:"ports,omitempty"`
	Volumes       []VolumeMount          `yaml:"volumes,omitempty" json:"volumes,omitempty"`
	Networks      []string               `yaml:"networks,omitempty" json:"networks,omitempty"`
	NetworksMap   map[string]NetworkConn `yaml:"networks_map,omitempty" json:"networks_map,omitempty"`
	DependsOn     []string               `yaml:"depends_on,omitempty" json:"depends_on,omitempty"`
	Restart       string                 `yaml:"restart,omitempty" json:"restart,omitempty"`
	HealthCheck   *HealthCheck           `yaml:"healthcheck,omitempty" json:"healthcheck,omitempty"`
	Labels        map[string]string      `yaml:"labels,omitempty" json:"labels,omitempty"`
	Expose        []string               `yaml:"expose,omitempty" json:"expose,omitempty"`
	WorkingDir    string                 `yaml:"working_dir,omitempty" json:"working_dir,omitempty"`
	User          string                 `yaml:"user,omitempty" json:"user,omitempty"`
	Privileged    bool                   `yaml:"privileged,omitempty" json:"privileged,omitempty"`
	CapAdd        []string               `yaml:"cap_add,omitempty" json:"cap_add,omitempty"`
	CapDrop       []string               `yaml:"cap_drop,omitempty" json:"cap_drop,omitempty"`
	SecurityOpt   []string               `yaml:"security_opt,omitempty" json:"security_opt,omitempty"`
	ReadOnly      bool                   `yaml:"read_only,omitempty" json:"read_only,omitempty"`
	ShmSize       string                 `yaml:"shm_size,omitempty" json:"shm_size,omitempty"`
	Stdin         bool                   `yaml:"stdin_open,omitempty" json:"stdin_open,omitempty"`
	Tty           bool                   `yaml:"tty,omitempty" json:"tty,omitempty"`

	// ORCA-specific extensions
	OrcaTarget   *OrcaTarget       `yaml:"orca_target,omitempty" json:"orca_target,omitempty"`
	OrcaProbes   []OrcaProbe       `yaml:"orca_probes,omitempty" json:"orca_probes,omitempty"`
	OrcaTags     map[string]string `yaml:"orca_tags,omitempty" json:"orca_tags,omitempty"`
	OrcaMetadata map[string]any    `yaml:"orca_metadata,omitempty" json:"orca_metadata,omitempty"`
}

// Build defines Docker build configuration
type Build struct {
	Context    string            `yaml:"context,omitempty" json:"context,omitempty"`
	Dockerfile string            `yaml:"dockerfile,omitempty" json:"dockerfile,omitempty"`
	Args       map[string]string `yaml:"args,omitempty" json:"args,omitempty"`
	Target     string            `yaml:"target,omitempty" json:"target,omitempty"`
	Labels     map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// Port defines port mapping configuration
type Port struct {
	Published int    `yaml:"published,omitempty" json:"published,omitempty"`
	Target    int    `yaml:"target" json:"target"`
	Protocol  string `yaml:"protocol,omitempty" json:"protocol,omitempty"`
	Mode      string `yaml:"mode,omitempty" json:"mode,omitempty"`
}

// VolumeMount defines volume mount configuration
type VolumeMount struct {
	Type     string         `yaml:"type,omitempty" json:"type,omitempty"`
	Source   string         `yaml:"source,omitempty" json:"source,omitempty"`
	Target   string         `yaml:"target" json:"target"`
	ReadOnly bool           `yaml:"read_only,omitempty" json:"read_only,omitempty"`
	Bind     *Bind          `yaml:"bind,omitempty" json:"bind,omitempty"`
	Volume   *VolumeOptions `yaml:"volume,omitempty" json:"volume,omitempty"`
}

// Bind defines bind mount options
type Bind struct {
	Propagation string `yaml:"propagation,omitempty" json:"propagation,omitempty"`
}

// VolumeOptions defines volume mount options
type VolumeOptions struct {
	NoCopy bool `yaml:"nocopy,omitempty" json:"nocopy,omitempty"`
}

// NetworkConn defines network connection configuration
type NetworkConn struct {
	Aliases  []string `yaml:"aliases,omitempty" json:"aliases,omitempty"`
	IPV4Addr string   `yaml:"ipv4_address,omitempty" json:"ipv4_address,omitempty"`
	IPV6Addr string   `yaml:"ipv6_address,omitempty" json:"ipv6_address,omitempty"`
	Priority int      `yaml:"priority,omitempty" json:"priority,omitempty"`
}

// HealthCheck defines health check configuration
type HealthCheck struct {
	Test        []string      `yaml:"test,omitempty" json:"test,omitempty"`
	Interval    time.Duration `yaml:"interval,omitempty" json:"interval,omitempty"`
	Timeout     time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	StartPeriod time.Duration `yaml:"start_period,omitempty" json:"start_period,omitempty"`
	Retries     int           `yaml:"retries,omitempty" json:"retries,omitempty"`
	Disable     bool          `yaml:"disable,omitempty" json:"disable,omitempty"`
}

// Secret defines Docker secret configuration
type Secret struct {
	File     string            `yaml:"file,omitempty" json:"file,omitempty"`
	External *External         `yaml:"external,omitempty" json:"external,omitempty"`
	Labels   map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// Config defines Docker config configuration
type Config struct {
	File     string            `yaml:"file,omitempty" json:"file,omitempty"`
	External *External         `yaml:"external,omitempty" json:"external,omitempty"`
	Labels   map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// OrcaTarget defines ORCA-specific target configuration
type OrcaTarget struct {
	Enabled  bool              `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Protocol string            `yaml:"protocol,omitempty" json:"protocol,omitempty"`
	Ports    []int             `yaml:"ports,omitempty" json:"ports,omitempty"`
	Tags     map[string]string `yaml:"tags,omitempty" json:"tags,omitempty"`
	Priority int               `yaml:"priority,omitempty" json:"priority,omitempty"`
	WaitFor  []string          `yaml:"wait_for,omitempty" json:"wait_for,omitempty"`
}

// OrcaProbe defines ORCA-specific readiness probes
type OrcaProbe struct {
	Type             string        `yaml:"type" json:"type"` // tcp, http, command
	Port             int           `yaml:"port,omitempty" json:"port,omitempty"`
	Path             string        `yaml:"path,omitempty" json:"path,omitempty"`
	Command          []string      `yaml:"command,omitempty" json:"command,omitempty"`
	InitialDelay     time.Duration `yaml:"initial_delay,omitempty" json:"initial_delay,omitempty"`
	Interval         time.Duration `yaml:"interval,omitempty" json:"interval,omitempty"`
	Timeout          time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	SuccessThreshold int           `yaml:"success_threshold,omitempty" json:"success_threshold,omitempty"`
	FailureThreshold int           `yaml:"failure_threshold,omitempty" json:"failure_threshold,omitempty"`
}

// Validate performs basic validation on the blueprint
func (b *Blueprint) Validate() error {
	if b.Name == "" {
		return ErrInvalidBlueprint("blueprint name is required")
	}

	if len(b.Services) == 0 {
		return ErrInvalidBlueprint("blueprint must define at least one service")
	}

	// Validate services
	for name, service := range b.Services {
		if err := service.Validate(name); err != nil {
			return ErrInvalidService(name, err.Error())
		}
	}

	// Validate network references
	for serviceName, service := range b.Services {
		for _, network := range service.Networks {
			if _, exists := b.Networks[network]; !exists {
				return ErrInvalidService(serviceName, "references undefined network: "+network)
			}
		}
	}

	return nil
}

// Validate performs basic validation on a service
func (s *Service) Validate(name string) error {
	if s.Image == "" && s.Build == nil {
		return ErrInvalidService(name, "service must specify either image or build configuration")
	}

	// Validate port configurations
	for i, port := range s.Ports {
		if port.Target <= 0 || port.Target > 65535 {
			return ErrInvalidService(name, fmt.Sprintf("invalid target port in port configuration %d", i))
		}
		if port.Published < 0 || port.Published > 65535 {
			return ErrInvalidService(name, fmt.Sprintf("invalid published port in port configuration %d", i))
		}
	}

	// Validate health check
	if s.HealthCheck != nil {
		if len(s.HealthCheck.Test) == 0 {
			return ErrInvalidService(name, "health check must specify test command")
		}
	}

	return nil
}

// GetTargetServices returns services that are configured as ORCA targets
func (b *Blueprint) GetTargetServices() map[string]Service {
	targets := make(map[string]Service)
	for name, service := range b.Services {
		if service.OrcaTarget != nil && service.OrcaTarget.Enabled {
			targets[name] = service
		}
	}
	return targets
}

// GetServiceDependencies returns the dependency graph of services
func (b *Blueprint) GetServiceDependencies() map[string][]string {
	deps := make(map[string][]string)
	for name, service := range b.Services {
		deps[name] = service.DependsOn
	}
	return deps
}

// Error types for blueprint validation
func ErrInvalidBlueprint(msg string) error {
	return ConfigError{Type: "invalid_blueprint", Message: msg}
}

func ErrInvalidService(serviceName, msg string) error {
	return ConfigError{Type: "invalid_service", Message: "service '" + serviceName + "': " + msg}
}
