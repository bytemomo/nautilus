package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"bytemomo/siren/intercept"

	"github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v3"
)

// Config represents the complete Siren configuration with validation tags.
type Config struct {
	Name         string               `yaml:"name" validate:"required"`
	Description  string               `yaml:"description,omitempty"`
	Ebpf         *EbpfConfig          `yaml:"ebpf" validate:"required"`
	Rules        []*intercept.Rule    `yaml:"rules,omitempty" validate:"dive"`
	Manipulators []*ManipulatorConfig `yaml:"manipulators,omitempty" validate:"dive"`
	Recording    *RecordingConfig     `yaml:"recording,omitempty"`
}

// ManipulatorConfig configures a single manipulator.
type ManipulatorConfig struct {
	Name   string                 `yaml:"name" validate:"required"`
	Params map[string]interface{} `yaml:"params,omitempty"`
}

// RecordingConfig configures traffic recording.
type RecordingConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Output         string `yaml:"output" validate:"required_if=Enabled true"`
	Format         string `yaml:"format,omitempty" validate:"omitempty,oneof=pcap json"`
	IncludePayload bool   `yaml:"include_payload,omitempty"`
	MaxFileSize    string `yaml:"max_file_size,omitempty" validate:"omitempty,file_size"`
	FlushInterval  string `yaml:"flush_interval,omitempty" validate:"omitempty,duration"`
}

// EbpfConfig controls eBPF mode.
type EbpfConfig struct {
	Interface          string   `yaml:"interface" validate:"required"`
	DropActionDuration string   `yaml:"drop_action_duration,omitempty" validate:"omitempty,duration"`
	Targets            []string `yaml:"targets,omitempty"`
}

// LoadConfig loads configuration from a YAML file, applies defaults, and validates it.
func LoadConfig(path string) (*Config, error) {
	config := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// It's okay if the file doesn't exist, we'll use the default config.
			// The validation step will catch any missing required fields (like interface).
			return config, config.Validate()
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config YAML: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// SaveConfig saves configuration to a YAML file.
func SaveConfig(config *Config, path string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config to YAML: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// Validate checks the configuration for correctness and compiles necessary fields.
func (c *Config) Validate() error {
	validator := NewValidator()
	if err := validator.Struct(c); err != nil {
		return err
	}

	// Compile rules after basic validation
	for i, rule := range c.Rules {
		if err := rule.Action.Compile(); err != nil {
			return fmt.Errorf("rule #%d (%s) action is invalid: %w", i+1, rule.Name, err)
		}
	}
	return nil
}

// GetFlushInterval parses the flush interval string and returns a time.Duration.
func (r *RecordingConfig) GetFlushInterval() (time.Duration, error) {
	if r.FlushInterval == "" {
		return 5 * time.Second, nil
	}
	return time.ParseDuration(r.FlushInterval)
}

// GetMaxFileSize parses the max file size string (e.g., "100MB") and returns the size in bytes.
func (r *RecordingConfig) GetMaxFileSize() (int64, error) {
	if r.MaxFileSize == "" {
		return 100 * 1024 * 1024, nil // 100MB default
	}
	return parseFileSize(r.MaxFileSize)
}

// GetDropDuration parses the duration for flow drops.
func (e *EbpfConfig) GetDropDuration() (time.Duration, error) {
	if e == nil || e.DropActionDuration == "" {
		return 10 * time.Second, nil
	}
	return time.ParseDuration(e.DropActionDuration)
}

// DefaultConfig returns a default configuration.
func DefaultConfig() *Config {
	return &Config{
		Name:        "Default Siren Config",
		Description: "Default configuration",
		Ebpf: &EbpfConfig{
			Interface:          "", // No safe default for interface
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

// NewValidator creates a new validator instance with custom validation functions.
func NewValidator() *validator.Validate {
	v := validator.New()
	v.RegisterValidation("duration", validateDuration)
	v.RegisterValidation("file_size", validateFileSize)
	return v
}

func validateDuration(fl validator.FieldLevel) bool {
	_, err := time.ParseDuration(fl.Field().String())
	return err == nil
}

func validateFileSize(fl validator.FieldLevel) bool {
	_, err := parseFileSize(fl.Field().String())
	return err == nil
}

func parseFileSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0, fmt.Errorf("file size cannot be empty")
	}

	type suffixDef struct {
		suffix     string
		multiplier int64
	}

	// Check longer suffixes first so "MB" does not get matched by the plain "B".
	suffixes := []suffixDef{
		{"GB", 1024 * 1024 * 1024},
		{"G", 1024 * 1024 * 1024},
		{"MB", 1024 * 1024},
		{"M", 1024 * 1024},
		{"KB", 1024},
		{"K", 1024},
		{"B", 1},
	}

	for _, def := range suffixes {
		if strings.HasSuffix(s, def.suffix) {
			numStr := strings.TrimSpace(strings.TrimSuffix(s, def.suffix))
			if numStr == "" {
				return 0, fmt.Errorf("missing number in file size: %q", s)
			}
			num, err := strconv.ParseInt(numStr, 10, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid number in file size %q: %w", s, err)
			}
			return num * def.multiplier, nil
		}
	}

	num, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid file size format: %q", s)
	}
	return num, nil
}
