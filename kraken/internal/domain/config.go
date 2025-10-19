package domain

import "time"

type CLIConfig struct {
	Path string `yaml:"path"`
	// Mode string `yaml:"mode"`

	// TODO: Reverse tunneling?
	// SshReverseTunneling bool   `yaml:"rev_tunnel"`
	// TargetTunnel        string `yaml:"target_tunnel"`
	// LoginUser           string `yaml:"login_user"`
	// KeyPath             string `yaml:"key_path"`

	// TODO: Run on another host/dockerized
}

type ABIConfig struct {
	LibraryPath string `yaml:"library"`
	Symbol      string `yaml:"symbol"`
}

type GRPCConfig struct {
	Server string `yaml:"server"`
}

type ExecConfig struct {
	ABI       *ABIConfig     `yaml:"abi,omitempty"`
	GRPC      *GRPCConfig    `yaml:"grpc,omitempty"`
	CLI       *CLIConfig     `yaml:"cli,omitempty"`
	Transport string         `yaml:"transport,omitempty"`
	Params    map[string]any `yaml:"params,omitempty"`
}

type RunnerConfig struct {
	GlobalTimeout time.Duration `yaml:"global_timeout,omitempty"`
	MaxTargets    int           `yaml:"max_parallel_targets,omitempty"`
}

type ServiceDetectType string

const (
	VersionAll   ServiceDetectType = "ALL"
	VersionLight ServiceDetectType = "LIGHT"
)

type ServiceDetect struct {
	Enabled bool              `yaml:"enabled,omitempty"`
	Version ServiceDetectType `yaml:"version,omitempty"`
}

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
