package yamlconfig

import (
	"fmt"
	"os"
	"path/filepath"

	"bytemomo/kraken/internal/domain"
	cnd "bytemomo/trident/conduit"

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

	// Build template map for expansion
	templateMap := make(map[string]*domain.ConduitTemplate)
	for _, tmpl := range campaign.ConduitTemplates {
		if tmpl.Name == "" {
			return nil, fmt.Errorf("conduit template missing name")
		}
		if _, exists := templateMap[tmpl.Name]; exists {
			return nil, fmt.Errorf("duplicate conduit template: %s", tmpl.Name)
		}
		templateMap[tmpl.Name] = tmpl
	}

	// Expand tasks that use conduit_templates
	expandedTasks := make([]*domain.Module, 0, len(campaign.Tasks))
	for i, mod := range campaign.Tasks {
		if mod == nil {
			return nil, fmt.Errorf("step %d is nil", i)
		}

		if len(mod.ExecConfig.ConduitTemplates) == 0 {
			// No templates - keep task as-is
			resolveModulePaths(mod, campaignDir)
			if err := mod.Validate(); err != nil {
				return nil, fmt.Errorf("invalid module at step %d: %w", i, err)
			}
			expandedTasks = append(expandedTasks, mod)
			continue
		}

		// Expand into multiple tasks, one per template
		for _, tmplName := range mod.ExecConfig.ConduitTemplates {
			tmpl, ok := templateMap[tmplName]
			if !ok {
				return nil, fmt.Errorf("step %d references unknown conduit template: %s", i, tmplName)
			}

			expanded := cloneModuleWithTemplate(mod, tmpl)
			resolveModulePaths(expanded, campaignDir)
			if err := expanded.Validate(); err != nil {
				return nil, fmt.Errorf("invalid expanded module %s (template %s): %w", expanded.ModuleID, tmplName, err)
			}
			expandedTasks = append(expandedTasks, expanded)
		}
	}
	campaign.Tasks = expandedTasks

	return &campaign, nil
}

// cloneModuleWithTemplate creates a copy of the module with the conduit from the template.
func cloneModuleWithTemplate(mod *domain.Module, tmpl *domain.ConduitTemplate) *domain.Module {
	clone := *mod
	clone.ModuleID = mod.ModuleID + "-" + tmpl.Name
	clone.ExecConfig.ConduitTemplates = nil // Clear to avoid re-expansion

	// Merge template's required_tags with module's
	if len(tmpl.RequiredTags) > 0 {
		merged := make([]string, 0, len(mod.RequiredTags)+len(tmpl.RequiredTags))
		merged = append(merged, mod.RequiredTags...)
		for _, tag := range tmpl.RequiredTags {
			if !containsString(merged, tag) {
				merged = append(merged, tag)
			}
		}
		clone.RequiredTags = merged
	}

	// Deep copy the ExecConfig and set conduit from template
	clone.ExecConfig.Conduit = &struct {
		Kind  cnd.Kind           `yaml:"kind"`
		Stack []domain.LayerHint `yaml:"stack,omitempty"`
	}{
		Kind:  tmpl.Kind,
		Stack: tmpl.Stack,
	}

	return &clone
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
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
	if err != nil {
		return nil, err
	}

	// Validate safety policy
	if err := ValidatePolicy(campaign); err != nil {
		return nil, err
	}

	return campaign, nil
}

// ValidatePolicy checks campaign policy constraints for OT safety.
func ValidatePolicy(campaign *domain.Campaign) error {
	policy := campaign.EffectivePolicy()

	for _, task := range campaign.Tasks {
		// Check aggressive tasks
		if task.Aggressive && !policy.Safety.AllowAggressive {
			return fmt.Errorf(
				"task %q is marked aggressive but policy.safety.allow_aggressive is false; "+
					"set allow_aggressive: true to permit disruptive operations",
				task.ModuleID,
			)
		}

		// Check max_duration requirement
		if policy.Safety.RequiresMaxDuration() && task.MaxDuration == 0 {
			return fmt.Errorf(
				"task %q missing max_duration; all tasks must specify a timeout "+
					"(or set policy.safety.require_max_duration: false)",
				task.ModuleID,
			)
		}
	}

	return nil
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
