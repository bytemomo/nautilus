package yamlconfig

import (
	"fmt"

	"bytemomo/kraken/internal/domain"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// LoadCampaignWithModules loads a campaign with modules directly in steps
func LoadCampaignWithModules(campaignPath string) (*domain.Campaign, error) {

	// Read campaign file
	data, err := os.ReadFile(campaignPath)
	if err != nil {
		return nil, err
	}

	// Parse campaign structure to get modules_path first
	var campaignMeta struct {
		ModulesPath string `yaml:"modules_path"`
	}
	if err := yaml.Unmarshal(data, &campaignMeta); err != nil {
		return nil, fmt.Errorf("failed to parse campaign metadata: %w", err)
	}

	// Load modules from registry if path specified
	if campaignMeta.ModulesPath != "" {
		modulesDir := campaignMeta.ModulesPath
		// If relative path, resolve relative to campaign file
		if !filepath.IsAbs(modulesDir) {
			campaignDir := filepath.Dir(campaignPath)
			modulesDir = filepath.Join(campaignDir, modulesDir)
		}
	}

	// Now parse the full campaign with modules resolved
	var campaign domain.Campaign
	if err := yaml.Unmarshal(data, &campaign); err != nil {
		return nil, fmt.Errorf("failed to parse campaign: %w", err)
	}

	// Validate all modules
	for i, mod := range campaign.Tasks {
		if mod == nil {
			return nil, fmt.Errorf("step %d is nil", i)
		}
		if err := mod.Validate(); err != nil {
			return nil, fmt.Errorf("invalid module at step %d: %w", i, err)
		}
	}

	return &campaign, nil
}

// LoadCampaign loads a campaign without module resolution (legacy)
func LoadCampaign(path string) (*domain.Campaign, error) {
	campaign, err := LoadCampaignWithModules(path)
	return campaign, err
}

func LoadAttackTrees(path string) ([]*domain.AttackNode, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var trees []*domain.AttackNode
	if err := yaml.Unmarshal(b, &trees); err != nil {
		return nil, err
	}
	return trees, nil
}
