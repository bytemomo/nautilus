package domain

import "time"

// ServiceDetectType is the type of service detection to perform.
type ServiceDetectType string

const (
	// VersionAll performs a comprehensive service detection.
	VersionAll ServiceDetectType = "ALL"
	// VersionLight performs a light service detection.
	VersionLight ServiceDetectType = "LIGHT"
)

// ServiceDetect is the configuration for service detection.
type ServiceDetect struct {
	Enabled bool              `yaml:"enabled,omitempty"`
	Version ServiceDetectType `yaml:"version,omitempty"`
}

// ScannerConfig is the configuration for the scanner.
type ScannerConfig struct {
	Interface string `yaml:"iface,omitempty"`

	SkipHostDiscovery bool `yaml:"skip_host_discovery,omitempty"` // -Pn

	EnableUDP bool     `yaml:"enable_udp,omitempty"`
	Ports     []string `yaml:"ports,omitempty"`
	OpenOnly  bool     `yaml:"open_only,omitempty"`

	ServiceDetect ServiceDetect `yaml:"service_detect,omitempty"`

	MinRate int           `yaml:"min_rate,omitempty"`
	Timing  string        `yaml:"timing,omitempty"`
	Timeout time.Duration `yaml:"timeout,omitempty"`
}
