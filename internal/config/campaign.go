package config

import (
	"time"
)

// Campaign represents a complete assessment campaign configuration
type Campaign struct {
	Name            string         `yaml:"name" json:"name"`
	Description     string         `yaml:"description,omitempty" json:"description,omitempty"`
	Scope           Scope          `yaml:"scope" json:"scope"`
	Mode            string         `yaml:"mode" json:"mode"` // live, docker, mixed
	DockerBlueprint string         `yaml:"docker_blueprint,omitempty" json:"docker_blueprint,omitempty"`
	Runtime         RuntimeOpts    `yaml:"runtime" json:"runtime"`
	Steps           []Step         `yaml:"steps" json:"steps"`
	Metadata        map[string]any `yaml:"metadata,omitempty" json:"metadata,omitempty"`
}

// Scope defines the assessment scope
type Scope struct {
	Type  string `yaml:"type" json:"type"`   // subnet, host, list, file
	Value string `yaml:"value" json:"value"` // CIDR, IP, comma-separated, file path
}

// RuntimeOpts contains runtime configuration options
type RuntimeOpts struct {
	OutDir          string         `yaml:"out_dir" json:"out_dir"`
	RunID           string         `yaml:"run_id,omitempty" json:"run_id,omitempty"`
	Concurrency     int            `yaml:"concurrency" json:"concurrency"`
	DurationSeconds int            `yaml:"duration_seconds" json:"duration_seconds"`
	TimeoutSeconds  int            `yaml:"timeout_seconds,omitempty" json:"timeout_seconds,omitempty"`
	Safety          SafetyOpts     `yaml:"safety" json:"safety"`
	Scheduling      ScheduleOpts   `yaml:"scheduling,omitempty" json:"scheduling,omitempty"`
	Logging         LoggingOpts    `yaml:"logging,omitempty" json:"logging,omitempty"`
	Metadata        map[string]any `yaml:"metadata,omitempty" json:"metadata,omitempty"`
}

// SafetyOpts defines safety constraints for the assessment
type SafetyOpts struct {
	ReadOnly       bool     `yaml:"read_only" json:"read_only"`
	NonDestructive bool     `yaml:"non_destructive" json:"non_destructive"`
	DryRun         bool     `yaml:"dry_run" json:"dry_run"`
	AllowedPorts   []int    `yaml:"allowed_ports,omitempty" json:"allowed_ports,omitempty"`
	ForbiddenPorts []int    `yaml:"forbidden_ports,omitempty" json:"forbidden_ports,omitempty"`
	AllowedHosts   []string `yaml:"allowed_hosts,omitempty" json:"allowed_hosts,omitempty"`
	ForbiddenHosts []string `yaml:"forbidden_hosts,omitempty" json:"forbidden_hosts,omitempty"`
	MaxConnections int      `yaml:"max_connections,omitempty" json:"max_connections,omitempty"`
	RateLimitRPS   int      `yaml:"rate_limit_rps,omitempty" json:"rate_limit_rps,omitempty"`
}

// ScheduleOpts defines scheduling and retry policies
type ScheduleOpts struct {
	MaxRetries        int           `yaml:"max_retries,omitempty" json:"max_retries,omitempty"`
	RetryDelay        time.Duration `yaml:"retry_delay,omitempty" json:"retry_delay,omitempty"`
	JobTimeoutSeconds int           `yaml:"job_timeout_seconds,omitempty" json:"job_timeout_seconds,omitempty"`
	Priority          string        `yaml:"priority,omitempty" json:"priority,omitempty"` // high, normal, low
	DependsOn         []string      `yaml:"depends_on,omitempty" json:"depends_on,omitempty"`
}

// LoggingOpts defines logging configuration
type LoggingOpts struct {
	Level      string `yaml:"level,omitempty" json:"level,omitempty"`   // debug, info, warn, error
	Format     string `yaml:"format,omitempty" json:"format,omitempty"` // json, text
	EnableFile bool   `yaml:"enable_file,omitempty" json:"enable_file,omitempty"`
	Verbose    bool   `yaml:"verbose,omitempty" json:"verbose,omitempty"`
}

// Step represents a single assessment step in a campaign
type Step struct {
	ID             string            `yaml:"id" json:"id"`
	Kind           string            `yaml:"kind" json:"kind"` // check, attack, compliance
	Name           string            `yaml:"name" json:"name"`
	Description    string            `yaml:"description,omitempty" json:"description,omitempty"`
	Selector       Selector          `yaml:"selector" json:"selector"`
	Implementation Implementation    `yaml:"implementation" json:"implementation"`
	Parameters     map[string]any    `yaml:"params,omitempty" json:"parameters,omitempty"`
	Policy         Policy            `yaml:"policy,omitempty" json:"policy,omitempty"`
	Schedule       ScheduleOpts      `yaml:"schedule,omitempty" json:"schedule,omitempty"`
	Enabled        bool              `yaml:"enabled,omitempty" json:"enabled"`
	Tags           map[string]string `yaml:"tags,omitempty" json:"tags,omitempty"`
	Metadata       map[string]any    `yaml:"metadata,omitempty" json:"metadata,omitempty"`
}

// Selector defines how to select targets for a step
type Selector struct {
	Ports        []int             `yaml:"ports,omitempty" json:"ports,omitempty"`
	Protocols    []string          `yaml:"protocols,omitempty" json:"protocols,omitempty"`
	ProtoGuesses []string          `yaml:"proto_guesses,omitempty" json:"proto_guesses,omitempty"`
	Services     []string          `yaml:"services,omitempty" json:"services,omitempty"`
	Hostnames    []string          `yaml:"hostnames,omitempty" json:"hostnames,omitempty"`
	IPRanges     []string          `yaml:"ip_ranges,omitempty" json:"ip_ranges,omitempty"`
	Tags         map[string]string `yaml:"tags,omitempty" json:"tags,omitempty"`
	Expression   string            `yaml:"expression,omitempty" json:"expression,omitempty"` // CEL expression
	Exclude      *Selector         `yaml:"exclude,omitempty" json:"exclude,omitempty"`
}

// Implementation defines how a step is executed
type Implementation struct {
	Manifest string         `yaml:"manifest" json:"manifest"`
	Backend  string         `yaml:"backend" json:"backend"` // grpc, cshared
	Config   map[string]any `yaml:"config,omitempty" json:"config,omitempty"`
}

// Policy defines outcome policies for a step
type Policy struct {
	SeverityIfFail   string            `yaml:"severity_if_fail,omitempty" json:"severity_if_fail,omitempty"`
	SeverityIfPass   string            `yaml:"severity_if_pass,omitempty" json:"severity_if_pass,omitempty"`
	FailureAction    string            `yaml:"failure_action,omitempty" json:"failure_action,omitempty"` // continue, abort, skip_dependent
	RequiredFindings int               `yaml:"required_findings,omitempty" json:"required_findings,omitempty"`
	MaxFindings      int               `yaml:"max_findings,omitempty" json:"max_findings,omitempty"`
	Tags             map[string]string `yaml:"tags,omitempty" json:"tags,omitempty"`
	CustomRules      []PolicyRule      `yaml:"custom_rules,omitempty" json:"custom_rules,omitempty"`
}

// PolicyRule defines a custom policy rule
type PolicyRule struct {
	Name      string         `yaml:"name" json:"name"`
	Condition string         `yaml:"condition" json:"condition"` // CEL expression
	Severity  string         `yaml:"severity" json:"severity"`
	Message   string         `yaml:"message" json:"message"`
	Action    string         `yaml:"action,omitempty" json:"action,omitempty"`
	Metadata  map[string]any `yaml:"metadata,omitempty" json:"metadata,omitempty"`
}

// Validate performs basic validation on the campaign configuration
func (c *Campaign) Validate() error {
	if c.Name == "" {
		return ErrInvalidCampaign("campaign name is required")
	}

	if c.Scope.Type == "" || c.Scope.Value == "" {
		return ErrInvalidCampaign("campaign scope type and value are required")
	}

	if len(c.Steps) == 0 {
		return ErrInvalidCampaign("campaign must have at least one step")
	}

	if c.Runtime.Concurrency <= 0 {
		c.Runtime.Concurrency = 1
	}

	if c.Runtime.DurationSeconds <= 0 {
		c.Runtime.DurationSeconds = 3600 // Default 1 hour
	}

	// Validate each step
	for i, step := range c.Steps {
		if err := step.Validate(); err != nil {
			return ErrInvalidStep(step.ID, err.Error())
		}

		// Set enabled to true by default
		if i == 0 || !stepHasEnabledField(&step) {
			c.Steps[i].Enabled = true
		}
	}

	return nil
}

// Validate performs basic validation on a step
func (s *Step) Validate() error {
	if s.ID == "" {
		return ErrInvalidStep("", "step ID is required")
	}

	if s.Kind == "" {
		return ErrInvalidStep(s.ID, "step kind is required")
	}

	if s.Kind != "check" && s.Kind != "attack" && s.Kind != "compliance" {
		return ErrInvalidStep(s.ID, "step kind must be 'check', 'attack', or 'compliance'")
	}

	if s.Name == "" {
		return ErrInvalidStep(s.ID, "step name is required")
	}

	if s.Implementation.Manifest == "" {
		return ErrInvalidStep(s.ID, "step implementation manifest is required")
	}

	if s.Implementation.Backend == "" {
		return ErrInvalidStep(s.ID, "step implementation backend is required")
	}

	if s.Implementation.Backend != "grpc" && s.Implementation.Backend != "cshared" {
		return ErrInvalidStep(s.ID, "step implementation backend must be 'grpc' or 'cshared'")
	}

	return nil
}

// GetMode returns the campaign mode, defaulting to "live"
func (c *Campaign) GetMode() string {
	if c.Mode == "" {
		return "live"
	}
	return c.Mode
}

// GetRunID returns the run ID, generating one if not set
func (r *RuntimeOpts) GetRunID() string {
	if r.RunID == "" {
		return generateRunID()
	}
	return r.RunID
}

// IsReadOnlyMode returns true if the campaign is in read-only mode
func (c *Campaign) IsReadOnlyMode() bool {
	return c.Runtime.Safety.ReadOnly
}

// IsDryRun returns true if this is a dry run
func (c *Campaign) IsDryRun() bool {
	return c.Runtime.Safety.DryRun
}

// GetEnabledSteps returns only the enabled steps
func (c *Campaign) GetEnabledSteps() []Step {
	var enabled []Step
	for _, step := range c.Steps {
		if step.Enabled {
			enabled = append(enabled, step)
		}
	}
	return enabled
}

// Helper functions
func stepHasEnabledField(step *Step) bool {
	// This is a placeholder - in real implementation, you'd check if the field was explicitly set
	// For now, we'll assume it's always explicitly set if it's false
	return !step.Enabled
}

func generateRunID() string {
	// Generate a timestamp-based run ID
	return time.Now().Format("20060102_150405")
}

// Error types
type ConfigError struct {
	Type    string
	Message string
}

func (e ConfigError) Error() string {
	return e.Message
}

func ErrInvalidCampaign(msg string) error {
	return ConfigError{Type: "invalid_campaign", Message: msg}
}

func ErrInvalidStep(stepID, msg string) error {
	if stepID != "" {
		msg = "step '" + stepID + "': " + msg
	}
	return ConfigError{Type: "invalid_step", Message: msg}
}
