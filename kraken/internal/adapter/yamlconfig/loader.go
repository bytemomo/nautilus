package yamlconfig

import (
	"fmt"
	"os"
	"path/filepath"

	"bytemomo/kraken/internal/domain"

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

	if err := campaign.Type.Validate(); err != nil {
		return nil, err
	}
	if campaign.Type == "" {
		campaign.Type = domain.CampaignNetwork
	}

	campaignDir := filepath.Dir(campaignPath)
	if !filepath.IsAbs(campaignDir) {
		absDir, err := filepath.Abs(campaignDir)
		if err != nil {
			return nil, fmt.Errorf("resolving campaign directory: %w", err)
		}
		campaignDir = absDir
	}
	for i, mod := range campaign.Tasks {
		if mod == nil {
			return nil, fmt.Errorf("step %d is nil", i)
		}
		resolveModulePaths(mod, campaignDir)
		if err := mod.Validate(); err != nil {
			return nil, fmt.Errorf("invalid module at step %d: %w", i, err)
		}
	}

	return &campaign, nil
}

func resolveModulePaths(mod *domain.Module, baseDir string) {
	if mod == nil || baseDir == "" {
		return
	}
	if mod.ExecConfig.Docker == nil {
		return
	}
	for i := range mod.ExecConfig.Docker.Mounts {
		hp := mod.ExecConfig.Docker.Mounts[i].HostPath
		if hp == "" || filepath.IsAbs(hp) {
			continue
		}
		mod.ExecConfig.Docker.Mounts[i].HostPath = filepath.Clean(filepath.Join(baseDir, hp))
	}
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
