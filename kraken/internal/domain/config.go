package domain

import (
	"fmt"
	"time"
)

type CLIConfig struct {
	Executable string `yaml:exec`
	Command    string `yaml:"command"`
	// Mode string `yaml:"mode"`

	// TODO: Reverse tunneling to run it on remote host ?
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
	MaxTargets int `yaml:"max_parallel_targets,omitempty"`

	ResultDirectory string
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

func (e ExecConfig) Validate() error {
	hasABI := e.ABI != nil
	hasGRPC := e.GRPC != nil
	hasCLI := e.CLI != nil

	if !(hasABI || hasCLI || hasGRPC) {
		return fmt.Errorf("exec config: one of abi, grpc or cli must be set")
	}

	if e.ABI != nil {
		if e.ABI.LibraryPath == "" {
			return fmt.Errorf("exec.abi.library is required")
		}
	}
	if e.GRPC != nil {
		if e.GRPC.Server == "" {
			return fmt.Errorf("exec.grpc.server is required")
		}
	}
	if e.CLI != nil {
		if e.CLI.Command == "" {
			return fmt.Errorf("exec.abi.library is required")
		}
	}

	return nil
}
