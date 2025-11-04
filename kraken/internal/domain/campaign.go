package domain

// HostPort represents a host and port combination.
type HostPort struct {
	Host string
	Port uint16
}

// Tag is a string that can be used to tag targets and findings.
type Tag string

// ClassifiedTarget is a target that has been classified with a set of tags.
type ClassifiedTarget struct {
	Target HostPort
	Tags   []Tag
}

// Campaign is a collection of modules that are run against a set of targets.
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

// RunResult is the result of a module run against a target.
type RunResult struct {
	Target   HostPort  `json:"target"`
	Findings []Finding `json:"findings"`
	Logs     []string  `json:"logs"`
}
