package domain

import "time"

type HostPort struct {
	Host string
	Port uint16
}

type Tag string

type ClassifiedTarget struct {
	Target HostPort
	Tags   []Tag
}

type Campaign struct {
	ID                 string         `yaml:"id"`
	Name               string         `yaml:"name"`
	Version            string         `yaml:"version"`
	Scanner            *ScannerConfig `yaml:"scanner,omitempty"`
	Steps              []CampaignStep `yaml:"steps"`
	AttackTreesDefPath string         `yaml:"attack_trees_def_path,omitempty"`
}

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

type ScannerConfig struct {
	SkipHostDiscovery bool `yaml:"skip_host_discovery,omitempty"` // -Pn

	EnableUDP bool     `yaml:"enable_udp,omitempty"`
	Ports     []string `yaml:"ports,omitempty"`
	OpenOnly  bool     `yaml:"open_only,omitempty"`

	ServiceDetect bool `yaml:"service_detect,omitempty"`
	VersionAll    bool `yaml:"version_all,omitempty"`
	VersionLight  bool `yaml:"version_light,omitempty"`

	MinRate int           `yaml:"min_rate,omitempty"`
	Timing  string        `yaml:"timing,omitempty"`
	Timeout time.Duration `yaml:"timeout,omitempty"`
}

type CampaignStep struct {
	PluginID     string     `yaml:"plugin_id"`
	RequiredTags []string   `yaml:"required_tags"`
	MaxDurationS int        `yaml:"max_duration_s"`
	Exec         ExecConfig `yaml:"exec"`
}

type Finding struct {
	ID          string         `json:"id"`
	PluginID    string         `json:"plugin_id"`
	Success     bool           `json:"success"`
	Title       string         `json:"title"`
	Severity    string         `json:"severity"`
	Description string         `json:"description"`
	Evidence    map[string]any `json:"evidence"`
	Tags        []Tag          `json:"tags"`
	Timestamp   int64          `json:"timestamp"`
	Target      HostPort       `json:"target"`
}

type RunResult struct {
	Target   HostPort  `json:"target"`
	Findings []Finding `json:"findings"`
	Logs     []string  `json:"logs"`
}
