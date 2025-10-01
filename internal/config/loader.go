package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Loader provides functionality to load and validate configuration files
type Loader struct {
	basePath string
}

// NewLoader creates a new configuration loader with the specified base path
func NewLoader(basePath string) *Loader {
	if basePath == "" {
		basePath = "."
	}
	return &Loader{
		basePath: basePath,
	}
}

// LoadCampaign loads and validates a campaign configuration from the specified path
func (l *Loader) LoadCampaign(path string) (*Campaign, error) {
	fullPath := l.resolvePath(path)

	data, err := l.readFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read campaign file %s: %w", fullPath, err)
	}

	// Expand environment variables
	data = l.expandEnvVars(data)

	var campaign Campaign
	if err := yaml.Unmarshal(data, &campaign); err != nil {
		return nil, fmt.Errorf("failed to parse campaign file %s: %w", fullPath, err)
	}

	// Set default values
	l.setCampaignDefaults(&campaign)

	// Validate the campaign
	if err := campaign.Validate(); err != nil {
		return nil, fmt.Errorf("campaign validation failed for %s: %w", fullPath, err)
	}

	return &campaign, nil
}

// LoadBlueprint loads and validates a blueprint configuration from the specified path
func (l *Loader) LoadBlueprint(path string) (*Blueprint, error) {
	if path == "" {
		return nil, nil // Blueprint is optional
	}

	fullPath := l.resolvePath(path)

	data, err := l.readFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read blueprint file %s: %w", fullPath, err)
	}

	// Expand environment variables
	data = l.expandEnvVars(data)

	var blueprint Blueprint
	if err := yaml.Unmarshal(data, &blueprint); err != nil {
		return nil, fmt.Errorf("failed to parse blueprint file %s: %w", fullPath, err)
	}

	// Set default values
	l.setBlueprintDefaults(&blueprint)

	// Validate the blueprint
	if err := blueprint.Validate(); err != nil {
		return nil, fmt.Errorf("blueprint validation failed for %s: %w", fullPath, err)
	}

	return &blueprint, nil
}

// LoadManifest loads and validates a manifest configuration from the specified path
func (l *Loader) LoadManifest(path string) (*Manifest, error) {
	fullPath := l.resolvePath(path)

	data, err := l.readFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest file %s: %w", fullPath, err)
	}

	// Expand environment variables
	data = l.expandEnvVars(data)

	var manifest Manifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest file %s: %w", fullPath, err)
	}

	// Set default values
	l.setManifestDefaults(&manifest)

	// Validate the manifest
	if err := manifest.Validate(); err != nil {
		return nil, fmt.Errorf("manifest validation failed for %s: %w", fullPath, err)
	}

	return &manifest, nil
}

// LoadManifests loads multiple manifest files from the specified paths
func (l *Loader) LoadManifests(paths []string) (map[string]*Manifest, error) {
	manifests := make(map[string]*Manifest)

	for _, path := range paths {
		manifest, err := l.LoadManifest(path)
		if err != nil {
			return nil, err
		}
		manifests[path] = manifest
	}

	return manifests, nil
}

// FindCampaigns searches for campaign files in the specified directory
func (l *Loader) FindCampaigns(dir string) ([]string, error) {
	searchDir := l.resolvePath(dir)
	return l.findFilesByPattern(searchDir, "*.yaml", "*.yml")
}

// FindBlueprints searches for blueprint files in the specified directory
func (l *Loader) FindBlueprints(dir string) ([]string, error) {
	searchDir := l.resolvePath(dir)
	return l.findFilesByPattern(searchDir, "*.yaml", "*.yml")
}

// FindManifests searches for manifest files in the specified directory and subdirectories
func (l *Loader) FindManifests(dir string) ([]string, error) {
	searchDir := l.resolvePath(dir)
	var manifests []string

	err := filepath.Walk(searchDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), "manifest.yaml") {
			manifests = append(manifests, path)
		}

		return nil
	})

	return manifests, err
}

// ValidateConfiguration performs cross-validation between campaign, blueprint, and manifests
func (l *Loader) ValidateConfiguration(campaign *Campaign, blueprint *Blueprint, manifests map[string]*Manifest) error {
	// Validate blueprint reference
	if campaign.DockerBlueprint != "" && blueprint == nil {
		return fmt.Errorf("campaign references blueprint %s but it was not loaded", campaign.DockerBlueprint)
	}

	// Validate manifest references in steps
	for _, step := range campaign.Steps {
		manifest, exists := manifests[step.Implementation.Manifest]
		if !exists {
			return fmt.Errorf("step %s references undefined manifest: %s", step.ID, step.Implementation.Manifest)
		}

		// Validate backend consistency
		if step.Implementation.Backend != manifest.Backend.Type {
			return fmt.Errorf("step %s backend mismatch: step specifies %s but manifest specifies %s",
				step.ID, step.Implementation.Backend, manifest.Backend.Type)
		}

		// Validate required parameters
		requiredParams := manifest.GetRequiredParameters()
		for _, param := range requiredParams {
			if _, exists := step.Parameters[param.Name]; !exists {
				return fmt.Errorf("step %s missing required parameter: %s", step.ID, param.Name)
			}
		}
	}

	return nil
}

// resolvePath resolves a path relative to the loader's base path
func (l *Loader) resolvePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(l.basePath, path)
}

// readFile reads a file and returns its contents
func (l *Loader) readFile(path string) ([]byte, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("file does not exist: %s", path)
	}

	return os.ReadFile(path)
}

// expandEnvVars expands environment variables in the configuration data
func (l *Loader) expandEnvVars(data []byte) []byte {
	content := string(data)
	return []byte(os.ExpandEnv(content))
}

// findFilesByPattern searches for files matching the given patterns
func (l *Loader) findFilesByPattern(dir string, patterns ...string) ([]string, error) {
	var files []string

	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			return nil, err
		}
		files = append(files, matches...)
	}

	return files, nil
}

// setCampaignDefaults sets default values for campaign configuration
func (l *Loader) setCampaignDefaults(campaign *Campaign) {
	if campaign.Mode == "" {
		campaign.Mode = "live"
	}

	if campaign.Runtime.Concurrency == 0 {
		campaign.Runtime.Concurrency = 1
	}

	if campaign.Runtime.DurationSeconds == 0 {
		campaign.Runtime.DurationSeconds = 3600 // 1 hour
	}

	if campaign.Runtime.OutDir == "" {
		campaign.Runtime.OutDir = "results"
	}

	// Set step defaults
	for i := range campaign.Steps {
		step := &campaign.Steps[i]
		if !l.stepEnabledExplicitlySet(step) {
			step.Enabled = true
		}
	}
}

// setBlueprintDefaults sets default values for blueprint configuration
func (l *Loader) setBlueprintDefaults(blueprint *Blueprint) {
	if blueprint.Version == "" {
		blueprint.Version = "1.0"
	}

	// Set default network driver
	for name, network := range blueprint.Networks {
		if network.Driver == "" {
			network.Driver = "bridge"
			blueprint.Networks[name] = network
		}
	}

	// Set default service configurations
	for name, service := range blueprint.Services {
		if service.Restart == "" {
			service.Restart = "unless-stopped"
		}
		blueprint.Services[name] = service
	}
}

// setManifestDefaults sets default values for manifest configuration
func (l *Loader) setManifestDefaults(manifest *Manifest) {
	if manifest.Interface.Version == "" {
		manifest.Interface.Version = "1.0"
	}

	// Set gRPC defaults
	if manifest.Backend.Type == "grpc" && manifest.Backend.Config.GRPC != nil {
		grpc := manifest.Backend.Config.GRPC
		if grpc.Port == 0 {
			grpc.Port = 50051
		}
		if grpc.Timeout == 0 {
			grpc.Timeout = 30000000000 // 30 seconds in nanoseconds
		}
	}

	// Set parameter defaults
	for i := range manifest.Parameters {
		param := &manifest.Parameters[i]
		if param.Type == "" {
			param.Type = "string"
		}
	}
}

// stepEnabledExplicitlySet checks if the enabled field was explicitly set
// This is a simplified check - in a real implementation you might use a custom unmarshaler
func (l *Loader) stepEnabledExplicitlySet(step *Step) bool {
	// For now, we assume if it's false, it was explicitly set
	// A more sophisticated approach would track which fields were set during unmarshaling
	return !step.Enabled
}

// LoaderError represents a configuration loading error
type LoaderError struct {
	Type    string
	Path    string
	Message string
	Cause   error
}

func (e LoaderError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s error for %s: %s (caused by: %v)", e.Type, e.Path, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s error for %s: %s", e.Type, e.Path, e.Message)
}

func (e LoaderError) Unwrap() error {
	return e.Cause
}

// Helper functions for creating specific errors
func NewCampaignLoadError(path, message string, cause error) error {
	return LoaderError{
		Type:    "campaign",
		Path:    path,
		Message: message,
		Cause:   cause,
	}
}

func NewBlueprintLoadError(path, message string, cause error) error {
	return LoaderError{
		Type:    "blueprint",
		Path:    path,
		Message: message,
		Cause:   cause,
	}
}

func NewManifestLoadError(path, message string, cause error) error {
	return LoaderError{
		Type:    "manifest",
		Path:    path,
		Message: message,
		Cause:   cause,
	}
}
