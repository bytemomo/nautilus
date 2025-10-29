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
	Tasks              []*Module      `yaml:"tasks"`
	AttackTreesDefPath string         `yaml:"attack_trees_def_path,omitempty"`
	ModulesPath        string         `yaml:"modules_path,omitempty"`
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
