package yamlconfig

import (
	"fmt"

	"bytemomo/kraken/internal/domain"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func LoadCampaignWithModules(campaignPath string) (*domain.Campaign, error) {
	data, err := os.ReadFile(campaignPath)
	if err != nil {
		return nil, err
	}

	var campaignMeta struct {
		ModulesPath string `yaml:"modules_path"`
	}
	if err := yaml.Unmarshal(data, &campaignMeta); err != nil {
		return nil, fmt.Errorf("failed to parse campaign metadata: %w", err)
	}

	if campaignMeta.ModulesPath != "" {
		modulesDir := campaignMeta.ModulesPath
		if !filepath.IsAbs(modulesDir) {
			campaignDir := filepath.Dir(campaignPath)
			modulesDir = filepath.Join(campaignDir, modulesDir)
		}
	}

	var campaign domain.Campaign
	if err := yaml.Unmarshal(data, &campaign); err != nil {
		return nil, fmt.Errorf("failed to parse campaign: %w", err)
	}

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
