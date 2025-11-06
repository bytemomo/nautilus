package config

import (
	"fmt"
	"os"
	"time"

	"bytemomo/siren/intercept"

	"gopkg.in/yaml.v3"
)

// Config represents the complete Siren configuration
type Config struct {
	Name         string               `yaml:"name" json:"name"`
	Description  string               `yaml:"description,omitempty" json:"description,omitempty"`
	Ebpf         *EbpfConfig          `yaml:"ebpf,omitempty" json:"ebpf,omitempty"`
	Rules        []*intercept.Rule    `yaml:"rules,omitempty" json:"rules,omitempty"`
	Manipulators []*ManipulatorConfig `yaml:"manipulators,omitempty" json:"manipulators,omitempty"`
	Recording    *RecordingConfig     `yaml:"recording,omitempty" json:"recording,omitempty"`
}

// ManipulatorConfig configures a single manipulator.
type ManipulatorConfig struct {
	Name   string                 `yaml:"name" json:"name"`
	Params map[string]interface{} `yaml:"params,omitempty" json:"params,omitempty"`
}

// RecordingConfig configures traffic recording
type RecordingConfig struct {
	Enabled        bool   `yaml:"enabled" json:"enabled"`
	Output         string `yaml:"output" json:"output"`
	Format         string `yaml:"format,omitempty" json:"format,omitempty"`
	IncludePayload bool   `yaml:"include_payload,omitempty" json:"include_payload,omitempty"`
	MaxFileSize    string `yaml:"max_file_size,omitempty" json:"max_file_size,omitempty"`
	FlushInterval  string `yaml:"flush_interval,omitempty" json:"flush_interval,omitempty"`
}

// EbpfConfig controls eBPF mode.
type EbpfConfig struct {
	Interface          string   `yaml:"interface" json:"interface"`
	DropActionDuration string   `yaml:"drop_action_duration,omitempty" json:"drop_action_duration,omitempty"`
	Targets            []string `yaml:"targets,omitempty" json:"targets,omitempty"`
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &config, nil
}

// SaveConfig saves configuration to a YAML file
func SaveConfig(config *Config, path string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.Ebpf == nil {
		return fmt.Errorf("ebpf configuration is required")
	}
	if c.Ebpf.Interface == "" {
		return fmt.Errorf("ebpf.interface is required")
	}

	if len(c.Rules) > 0 {
		for i, rule := range c.Rules {
			if rule.Match == nil {
				return fmt.Errorf("rule %d has no match criteria", i)
			}
			if rule.Action == nil {
				return fmt.Errorf("rule %d has no action", i)
			}
			if err := rule.Match.Compile(); err != nil {
				return fmt.Errorf("rule %d match compilation failed: %w", i, err)
			}
			if err := rule.Action.Compile(); err != nil {
				return fmt.Errorf("rule %d action compilation failed: %w", i, err)
			}
		}
	}

	return nil
}

// GetFlushInterval returns the parsed flush interval
func (r *RecordingConfig) GetFlushInterval() time.Duration {
	if r.FlushInterval == "" {
		return 5 * time.Second
	}
	d, err := time.ParseDuration(r.FlushInterval)
	if err != nil {
		return 5 * time.Second
	}
	return d
}

// GetMaxFileSize returns the parsed max file size in bytes
func (r *RecordingConfig) GetMaxFileSize() int64 {
	if r.MaxFileSize == "" {
		return 100 * 1024 * 1024
	}

	var num int64
	var unit string
	fmt.Sscanf(r.MaxFileSize, "%d%s", &num, &unit)

	switch unit {
	case "KB", "K":
		return num * 1024
	case "MB", "M":
		return num * 1024 * 1024
	case "GB", "G":
		return num * 1024 * 1024 * 1024
	default:
		return num
	}
}

// GetDropDuration returns the parsed duration for flow drops.
func (e *EbpfConfig) GetDropDuration() time.Duration {
	if e == nil || e.DropActionDuration == "" {
		return 10 * time.Second
	}
	d, err := time.ParseDuration(e.DropActionDuration)
	if err != nil {
		return 10 * time.Second
	}
	return d
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Name:        "Default Siren Config",
		Description: "Default configuration",
		Ebpf: &EbpfConfig{
			Interface:          "eth0",
			DropActionDuration: "5s",
		},
		Rules: make([]*intercept.Rule, 0),
		Recording: &RecordingConfig{
			Enabled:        false,
			Output:         "captures/traffic.pcap",
			Format:         "pcap",
			IncludePayload: true,
			MaxFileSize:    "100MB",
			FlushInterval:  "5s",
		},
	}
}
