package yamlconfig

import (
	"bytemomo/kraken/internal/domain"
	"os"

	"gopkg.in/yaml.v3"
)

func LoadCampaign(path string) (*domain.Campaign, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c domain.Campaign
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}

	for _, step := range c.Steps {
		if err := step.Exec.Validate(); err != nil {
			return nil, err
		}
	}
	return &c, nil
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
