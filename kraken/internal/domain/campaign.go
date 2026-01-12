package domain

import "fmt"

// HostPort represents a host and port combination.
type HostPort struct {
	Host string
	Port uint16
}

// Tag is a string that can be used to tag targets and findings.
type Tag string

// ClassifiedTarget is a target that has been classified with a set of tags.
type ClassifiedTarget struct {
	Target Target
	Tags   []Tag
}

// CampaignType identifies the orchestration style.
type CampaignType string

const (
	CampaignNetwork CampaignType = "network"
	CampaignFuzz CampaignType = "fuzz"
)

// Campaign is a collection of modules that are run against a set of targets.
type Campaign struct {
	ID                 string             `yaml:"id"`
	Name               string             `yaml:"name"`
	Version            string             `yaml:"version"`
	Type               CampaignType       `yaml:"type,omitempty"`
	Policy             Policy             `yaml:"policy,omitempty"`
	Scanners           []*ScannerConfig   `yaml:"scanners,omitempty"`
	ConduitTemplates   []*ConduitTemplate `yaml:"conduit_templates,omitempty"`
	Tasks              []*Module          `yaml:"tasks"`
	AttackTreesDefPath string             `yaml:"attack_trees_def_path,omitempty"`
	ModulesPath        string             `yaml:"modules_path,omitempty"`
}

// EffectivePolicy returns the policy with defaults applied.
func (c *Campaign) EffectivePolicy() Policy {
	defaults := DefaultPolicy()
	return c.Policy.Merge(defaults)
}

// EffectiveScanners returns the list of scanner configs, handling legacy single scanner.
func (c *Campaign) EffectiveScanners() []*ScannerConfig {
	if len(c.Scanners) > 0 {
		return c.Scanners
	}
	return nil
}

// EffectiveType returns the campaign type, defaulting to the network flow.
func (c *Campaign) EffectiveType() CampaignType {
	if c == nil || c.Type == "" {
		return CampaignNetwork
	}
	return c.Type
}

// Validate checks that the campaign type is supported.
func (ct CampaignType) Validate() error {
	switch ct {
	case "", CampaignNetwork, CampaignFuzz:
		return nil
	default:
		return fmt.Errorf("invalid campaign type: %s", ct)
	}
}

// RunResult is the result of a module run against a target.
type RunResult struct {
	Target   Target    `json:"target"`
	Findings []Finding `json:"findings"`
	Logs     []string  `json:"logs"`
}
