package yamlconfig

import (
	"bytemomo/orca/internal/domain"
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
	return &c, nil
}
