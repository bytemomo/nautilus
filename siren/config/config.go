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
	Name        string       `yaml:"name" json:"name"`
	Description string       `yaml:"description,omitempty" json:"description,omitempty"`
	Proxy       *ProxyConfig `yaml:"proxy" json:"proxy"`
	Rules       []*intercept.Rule `yaml:"rules,omitempty" json:"rules,omitempty"`
	Recording   *RecordingConfig  `yaml:"recording,omitempty" json:"recording,omitempty"`
	Spoof       *SpoofConfig      `yaml:"spoof,omitempty" json:"spoof,omitempty"`
	API         *APIConfig        `yaml:"api,omitempty" json:"api,omitempty"`
}

// ProxyConfig configures the proxy behavior
type ProxyConfig struct {
	Listen            string        `yaml:"listen" json:"listen"`
	Target            string        `yaml:"target" json:"target"`
	Protocol          string        `yaml:"protocol" json:"protocol"` // tcp, tls, udp, dtls
	MaxConnections    int           `yaml:"max_connections,omitempty" json:"max_connections,omitempty"`
	ConnectionTimeout string        `yaml:"connection_timeout,omitempty" json:"connection_timeout,omitempty"`
	BufferSize        int           `yaml:"buffer_size,omitempty" json:"buffer_size,omitempty"`
	EnableLogging     bool          `yaml:"enable_logging,omitempty" json:"enable_logging,omitempty"`
	Conduit           *ConduitConfig `yaml:"conduit,omitempty" json:"conduit,omitempty"`
	TLS               *TLSConfig     `yaml:"tls,omitempty" json:"tls,omitempty"`
}

// ConduitConfig configures the Trident conduit stack
type ConduitConfig struct {
	Kind  int            `yaml:"kind" json:"kind"` // 1=Stream, 2=Datagram
	Stack []*LayerConfig `yaml:"stack" json:"stack"`
}

// LayerConfig configures a single layer in the conduit stack
type LayerConfig struct {
	Name   string                 `yaml:"name" json:"name"` // tcp, tls, udp, dtls, etc.
	Params map[string]interface{} `yaml:"params,omitempty" json:"params,omitempty"`
}

// TLSConfig configures TLS settings
type TLSConfig struct {
	CertFile       string `yaml:"cert_file,omitempty" json:"cert_file,omitempty"`
	KeyFile        string `yaml:"key_file,omitempty" json:"key_file,omitempty"`
	CACertFile     string `yaml:"ca_cert_file,omitempty" json:"ca_cert_file,omitempty"`
	CAKeyFile      string `yaml:"ca_key_file,omitempty" json:"ca_key_file,omitempty"`
	ServerName     string `yaml:"server_name,omitempty" json:"server_name,omitempty"`
	SkipVerify     bool   `yaml:"skip_verify,omitempty" json:"skip_verify,omitempty"`
	MinVersion     string `yaml:"min_version,omitempty" json:"min_version,omitempty"`
	MaxVersion     string `yaml:"max_version,omitempty" json:"max_version,omitempty"`
}

// RecordingConfig configures traffic recording
type RecordingConfig struct {
	Enabled        bool   `yaml:"enabled" json:"enabled"`
	Output         string `yaml:"output" json:"output"`
	Format         string `yaml:"format,omitempty" json:"format,omitempty"` // json, pcap, raw
	IncludePayload bool   `yaml:"include_payload,omitempty" json:"include_payload,omitempty"`
	MaxFileSize    string `yaml:"max_file_size,omitempty" json:"max_file_size,omitempty"` // e.g., "100MB"
	FlushInterval  string `yaml:"flush_interval,omitempty" json:"flush_interval,omitempty"` // e.g., "5s"
}

// SpoofConfig configures network spoofing
type SpoofConfig struct {
	ARP *ARPSpoofConfig `yaml:"arp,omitempty" json:"arp,omitempty"`
	DNS *DNSSpoofConfig `yaml:"dns,omitempty" json:"dns,omitempty"`
}

// ARPSpoofConfig configures ARP spoofing
type ARPSpoofConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	Interface string `yaml:"interface" json:"interface"`
	Target    string `yaml:"target" json:"target"`     // Target IP to spoof
	Gateway   string `yaml:"gateway" json:"gateway"`   // Gateway IP
}

// DNSSpoofConfig configures DNS spoofing
type DNSSpoofConfig struct {
	Enabled   bool              `yaml:"enabled" json:"enabled"`
	Listen    string            `yaml:"listen" json:"listen"`
	Upstream  string            `yaml:"upstream" json:"upstream"`
	Overrides map[string]string `yaml:"overrides,omitempty" json:"overrides,omitempty"` // domain -> IP
}

// APIConfig configures the REST API
type APIConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Listen  string `yaml:"listen" json:"listen"`
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

	// Validate configuration
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
	if c.Proxy == nil {
		return fmt.Errorf("proxy configuration is required")
	}

	if c.Proxy.Listen == "" {
		return fmt.Errorf("proxy.listen is required")
	}

	if c.Proxy.Target == "" {
		return fmt.Errorf("proxy.target is required")
	}

	if c.Proxy.Protocol == "" {
		c.Proxy.Protocol = "tcp" // Default to TCP
	}

	// Validate protocol
	switch c.Proxy.Protocol {
	case "tcp", "tls", "udp", "dtls":
		// Valid protocols
	default:
		return fmt.Errorf("invalid protocol: %s (must be tcp, tls, udp, or dtls)", c.Proxy.Protocol)
	}

	// Set defaults
	if c.Proxy.MaxConnections == 0 {
		c.Proxy.MaxConnections = 1000
	}

	if c.Proxy.BufferSize == 0 {
		c.Proxy.BufferSize = 32 * 1024 // 32KB
	}

	// Compile rules if present
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

// GetConnectionTimeout returns the parsed connection timeout
func (p *ProxyConfig) GetConnectionTimeout() time.Duration {
	if p.ConnectionTimeout == "" {
		return 30 * time.Second // Default
	}
	d, err := time.ParseDuration(p.ConnectionTimeout)
	if err != nil {
		return 30 * time.Second // Default on error
	}
	return d
}

// GetFlushInterval returns the parsed flush interval
func (r *RecordingConfig) GetFlushInterval() time.Duration {
	if r.FlushInterval == "" {
		return 5 * time.Second // Default
	}
	d, err := time.ParseDuration(r.FlushInterval)
	if err != nil {
		return 5 * time.Second // Default on error
	}
	return d
}

// GetMaxFileSize returns the parsed max file size in bytes
func (r *RecordingConfig) GetMaxFileSize() int64 {
	if r.MaxFileSize == "" {
		return 100 * 1024 * 1024 // Default 100MB
	}

	// Parse size string (e.g., "100MB", "1GB")
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
		return num // Assume bytes
	}
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Name:        "Default Siren Config",
		Description: "Default configuration",
		Proxy: &ProxyConfig{
			Listen:            ":8080",
			Target:            "localhost:80",
			Protocol:          "tcp",
			MaxConnections:    1000,
			ConnectionTimeout: "30s",
			BufferSize:        32768,
			EnableLogging:     true,
		},
		Rules: []*intercept.Rule{},
		Recording: &RecordingConfig{
			Enabled:        false,
			Output:         "captures/traffic.json",
			Format:         "json",
			IncludePayload: true,
			MaxFileSize:    "100MB",
			FlushInterval:  "5s",
		},
	}
}
