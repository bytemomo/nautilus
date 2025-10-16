package domain

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
	Runner             RunnerConfig   `yaml:"runner"`
	Scanner            *ScannerConfig `yaml:"scanner,omitempty"`
	Steps              []CampaignStep `yaml:"steps"`
	AttackTreesDefPath string         `yaml:"attack_trees_def_path,omitempty"`
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
