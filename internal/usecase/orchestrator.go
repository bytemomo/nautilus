package usecase

import (
	"context"
	"fmt"
	"time"

	"bytemomo/orca/internal/config"
	"bytemomo/orca/internal/entity"
	"bytemomo/orca/internal/pipeline/assessor"
	"bytemomo/orca/internal/pipeline/classifier"
	"bytemomo/orca/internal/pipeline/planner"
	"bytemomo/orca/internal/pipeline/scanner"
)

// Orchestrator defines the main orchestration interface
type Orchestrator interface {
	// Execute runs a complete assessment campaign
	Execute(ctx context.Context, campaign *config.Campaign) (*OrchestrationResult, error)

	// ExecuteWithBlueprint runs a campaign with an optional Docker blueprint
	ExecuteWithBlueprint(ctx context.Context, campaign *config.Campaign, blueprint *config.Blueprint) (*OrchestrationResult, error)

	// ValidateCampaign validates a campaign before execution
	ValidateCampaign(campaign *config.Campaign) error

	// GetStatus returns the current orchestration status
	GetStatus() OrchestrationStatus
}

// Reporter defines the interface for generating assessment reports
type Reporter interface {
	// GenerateReport creates a complete assessment report
	GenerateReport(ctx context.Context, result *OrchestrationResult, campaign *config.Campaign) (*entity.Report, error)
}

// OrchestrationResult contains the complete results of a campaign execution
type OrchestrationResult struct {
	CampaignName      string                           `json:"campaign_name"`
	RunID             string                           `json:"run_id"`
	Mode              string                           `json:"mode"`
	StartTime         time.Time                        `json:"start_time"`
	EndTime           time.Time                        `json:"end_time"`
	Duration          time.Duration                    `json:"duration"`
	Status            string                           `json:"status"` // completed, failed, cancelled
	ScanResult        *scanner.ScanResult              `json:"scan_result,omitempty"`
	Classification    *classifier.ClassificationResult `json:"classification,omitempty"`
	Plan              *planner.AssessmentPlan          `json:"plan,omitempty"`
	AssessmentResults []entity.JobResult               `json:"assessment_results,omitempty"`
	Report            *entity.Report                   `json:"report,omitempty"`
	Errors            []string                         `json:"errors,omitempty"`
	Metadata          map[string]any                   `json:"metadata,omitempty"`
}

// OrchestrationStatus represents the current status of orchestration
type OrchestrationStatus struct {
	Phase       string        `json:"phase"`    // idle, scanning, classifying, planning, assessing, reporting
	Progress    float64       `json:"progress"` // 0.0 to 1.0
	CurrentJob  string        `json:"current_job,omitempty"`
	StartTime   time.Time     `json:"start_time"`
	ElapsedTime time.Duration `json:"elapsed_time"`
	Message     string        `json:"message,omitempty"`
}

// AssessmentOrchestrator coordinates the complete assessment pipeline
type AssessmentOrchestrator struct {
	scanner     scanner.Scanner
	classifier  classifier.Classifier
	planner     planner.Planner
	assessor    assessor.Assessor
	reporter    Reporter
	provisioner Provisioner
	config      OrchestratorConfig
	status      OrchestrationStatus
}

// OrchestratorConfig contains orchestrator configuration
type OrchestratorConfig struct {
	EnableProvisioning   bool          `yaml:"enable_provisioning" json:"enable_provisioning"`
	CleanupOnFailure     bool          `yaml:"cleanup_on_failure" json:"cleanup_on_failure"`
	StatusUpdateInterval time.Duration `yaml:"status_update_interval" json:"status_update_interval"`
	MaxExecutionTime     time.Duration `yaml:"max_execution_time" json:"max_execution_time"`
	ContinueOnError      bool          `yaml:"continue_on_error" json:"continue_on_error"`
	ValidateInputs       bool          `yaml:"validate_inputs" json:"validate_inputs"`
}

// NewAssessmentOrchestrator creates a new assessment orchestrator
func NewAssessmentOrchestrator(
	scanner scanner.Scanner,
	classifier classifier.Classifier,
	planner planner.Planner,
	assessor assessor.Assessor,
	reporter Reporter,
	provisioner Provisioner,
	config OrchestratorConfig,
) *AssessmentOrchestrator {
	return &AssessmentOrchestrator{
		scanner:     scanner,
		classifier:  classifier,
		planner:     planner,
		assessor:    assessor,
		reporter:    reporter,
		provisioner: provisioner,
		config:      config,
		status: OrchestrationStatus{
			Phase: "idle",
		},
	}
}

// Execute runs a complete assessment campaign
func (o *AssessmentOrchestrator) Execute(ctx context.Context, campaign *config.Campaign) (*OrchestrationResult, error) {
	return o.ExecuteWithBlueprint(ctx, campaign, nil)
}

// ExecuteWithBlueprint runs a campaign with an optional Docker blueprint
func (o *AssessmentOrchestrator) ExecuteWithBlueprint(ctx context.Context, campaign *config.Campaign, blueprint *config.Blueprint) (*OrchestrationResult, error) {
	startTime := time.Now()
	runID := campaign.Runtime.GetRunID()

	result := &OrchestrationResult{
		CampaignName: campaign.Name,
		RunID:        runID,
		Mode:         campaign.GetMode(),
		StartTime:    startTime,
		Status:       "running",
		Metadata: map[string]any{
			"campaign_mode": campaign.GetMode(),
			"dry_run":       campaign.IsDryRun(),
			"read_only":     campaign.IsReadOnlyMode(),
		},
	}

	// Update status
	o.updateStatus("initializing", 0.0, "Starting campaign execution")

	// Validate campaign if configured
	if o.config.ValidateInputs {
		if err := o.ValidateCampaign(campaign); err != nil {
			result.Status = "failed"
			result.Errors = append(result.Errors, fmt.Sprintf("Campaign validation failed: %v", err))
			return result, fmt.Errorf("campaign validation failed: %w", err)
		}
	}

	// Set execution timeout
	if o.config.MaxExecutionTime > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.config.MaxExecutionTime)
		defer cancel()
	}

	// Phase 1: Provisioning (if needed)
	var resolvedTargets []entity.ResolvedTarget
	if campaign.GetMode() != "live" && o.provisioner != nil {
		o.updateStatus("provisioning", 0.1, "Setting up infrastructure")

		targets, err := o.executeProvisioning(ctx, campaign, blueprint)
		if err != nil {
			result.Status = "failed"
			result.Errors = append(result.Errors, fmt.Sprintf("Provisioning failed: %v", err))
			if !o.config.ContinueOnError {
				return result, fmt.Errorf("provisioning failed: %w", err)
			}
		} else {
			resolvedTargets = targets
		}
	}

	// Phase 2: Scanning
	o.updateStatus("scanning", 0.2, "Discovering hosts and services")

	scanResult, err := o.executeScanning(ctx, campaign)
	if err != nil {
		result.Status = "failed"
		result.Errors = append(result.Errors, fmt.Sprintf("Scanning failed: %v", err))
		if !o.config.ContinueOnError {
			return result, fmt.Errorf("scanning failed: %w", err)
		}
	} else {
		result.ScanResult = scanResult
	}

	// Merge resolved targets with scan targets
	allTargets := o.mergeTargets(resolvedTargets, scanResult)

	// Phase 3: Classification
	o.updateStatus("classifying", 0.4, "Mapping targets to assessment steps")

	classification, err := o.executeClassification(ctx, allTargets, campaign)
	if err != nil {
		result.Status = "failed"
		result.Errors = append(result.Errors, fmt.Sprintf("Classification failed: %v", err))
		if !o.config.ContinueOnError {
			return result, fmt.Errorf("classification failed: %w", err)
		}
	} else {
		result.Classification = classification
	}

	// Phase 4: Planning
	o.updateStatus("planning", 0.5, "Creating assessment execution plan")

	plan, err := o.executePlanning(ctx, classification, campaign)
	if err != nil {
		result.Status = "failed"
		result.Errors = append(result.Errors, fmt.Sprintf("Planning failed: %v", err))
		if !o.config.ContinueOnError {
			return result, fmt.Errorf("planning failed: %w", err)
		}
	} else {
		result.Plan = plan
	}

	// Phase 5: Assessment (skip if dry run)
	if !campaign.IsDryRun() {
		o.updateStatus("assessing", 0.6, "Executing assessment jobs")

		assessmentResults, err := o.executeAssessment(ctx, plan, campaign)
		if err != nil {
			result.Status = "failed"
			result.Errors = append(result.Errors, fmt.Sprintf("Assessment failed: %v", err))
			if !o.config.ContinueOnError {
				return result, fmt.Errorf("assessment failed: %w", err)
			}
		} else {
			result.AssessmentResults = assessmentResults
		}
	} else {
		o.updateStatus("skipping_assessment", 0.8, "Skipping assessment (dry run mode)")
	}

	// Phase 6: Reporting
	o.updateStatus("reporting", 0.9, "Generating assessment report")

	report, err := o.executeReporting(ctx, result, campaign)
	if err != nil {
		result.Status = "failed"
		result.Errors = append(result.Errors, fmt.Sprintf("Reporting failed: %v", err))
		if !o.config.ContinueOnError {
			return result, fmt.Errorf("reporting failed: %w", err)
		}
	} else {
		result.Report = report
	}

	// Finalize result
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	if len(result.Errors) == 0 {
		result.Status = "completed"
	} else if result.Status == "running" {
		result.Status = "completed_with_errors"
	}

	o.updateStatus("completed", 1.0, fmt.Sprintf("Campaign execution %s", result.Status))

	// Cleanup if needed
	if result.Status == "failed" && o.config.CleanupOnFailure {
		o.cleanup(ctx, campaign, resolvedTargets)
	}

	return result, nil
}

// ValidateCampaign validates a campaign configuration
func (o *AssessmentOrchestrator) ValidateCampaign(campaign *config.Campaign) error {
	if err := campaign.Validate(); err != nil {
		return fmt.Errorf("campaign configuration invalid: %w", err)
	}

	// Validate that required components are available
	if o.scanner == nil {
		return fmt.Errorf("scanner is required but not configured")
	}

	if o.classifier == nil {
		return fmt.Errorf("classifier is required but not configured")
	}

	if o.planner == nil {
		return fmt.Errorf("planner is required but not configured")
	}

	if !campaign.IsDryRun() && o.assessor == nil {
		return fmt.Errorf("assessor is required for non-dry-run campaigns")
	}

	if o.reporter == nil {
		return fmt.Errorf("reporter is required but not configured")
	}

	// Validate mode-specific requirements
	mode := campaign.GetMode()
	if (mode == "docker" || mode == "mixed") && o.provisioner == nil {
		return fmt.Errorf("provisioner is required for %s mode", mode)
	}

	return nil
}

// GetStatus returns the current orchestration status
func (o *AssessmentOrchestrator) GetStatus() OrchestrationStatus {
	return o.status
}

// Private methods for executing each phase

func (o *AssessmentOrchestrator) executeProvisioning(ctx context.Context, campaign *config.Campaign, blueprint *config.Blueprint) ([]entity.ResolvedTarget, error) {
	if o.provisioner == nil {
		return nil, fmt.Errorf("provisioner not available")
	}

	// This will be implemented when Docker runtime is added
	// For now, return empty slice
	return []entity.ResolvedTarget{}, nil
}

func (o *AssessmentOrchestrator) executeScanning(ctx context.Context, campaign *config.Campaign) (*scanner.ScanResult, error) {
	scope, err := scanner.ParseScope(campaign.Scope.Type, campaign.Scope.Value)
	if err != nil {
		return nil, fmt.Errorf("invalid campaign scope: %w", err)
	}

	return o.scanner.Scan(ctx, scope)
}

func (o *AssessmentOrchestrator) executeClassification(ctx context.Context, targets []entity.Target, campaign *config.Campaign) (*classifier.ClassificationResult, error) {
	steps := campaign.GetEnabledSteps()
	return o.classifier.Classify(ctx, targets, steps)
}

func (o *AssessmentOrchestrator) executePlanning(ctx context.Context, classification *classifier.ClassificationResult, campaign *config.Campaign) (*planner.AssessmentPlan, error) {
	return o.planner.Plan(ctx, classification, campaign)
}

func (o *AssessmentOrchestrator) executeAssessment(ctx context.Context, plan *planner.AssessmentPlan, campaign *config.Campaign) ([]entity.JobResult, error) {
	if o.assessor == nil {
		return nil, fmt.Errorf("assessor not available")
	}

	return o.assessor.ExecutePlan(ctx, plan, campaign)
}

func (o *AssessmentOrchestrator) executeReporting(ctx context.Context, result *OrchestrationResult, campaign *config.Campaign) (*entity.Report, error) {
	if o.reporter == nil {
		return nil, fmt.Errorf("reporter not available")
	}
	return o.reporter.GenerateReport(ctx, result, campaign)
}

func (o *AssessmentOrchestrator) mergeTargets(resolvedTargets []entity.ResolvedTarget, scanResult *scanner.ScanResult) []entity.Target {
	var allTargets []entity.Target

	// Add resolved targets (from provisioning)
	for _, resolved := range resolvedTargets {
		allTargets = append(allTargets, *resolved.Resolved)
	}

	// Add scan targets
	if scanResult != nil {
		allTargets = append(allTargets, scanResult.Targets...)
	}

	return allTargets
}

func (o *AssessmentOrchestrator) updateStatus(phase string, progress float64, message string) {
	o.status = OrchestrationStatus{
		Phase:       phase,
		Progress:    progress,
		StartTime:   o.status.StartTime,
		ElapsedTime: time.Since(o.status.StartTime),
		Message:     message,
	}
}

func (o *AssessmentOrchestrator) cleanup(ctx context.Context, campaign *config.Campaign, resolvedTargets []entity.ResolvedTarget) {
	// Cleanup provisioned resources
	if o.provisioner != nil && len(resolvedTargets) > 0 {
		// This would cleanup Docker containers/networks
		// Implementation will be added with Docker runtime
	}
}

// DefaultOrchestratorConfig returns default orchestrator configuration
func DefaultOrchestratorConfig() OrchestratorConfig {
	return OrchestratorConfig{
		EnableProvisioning:   true,
		CleanupOnFailure:     true,
		StatusUpdateInterval: 5 * time.Second,
		MaxExecutionTime:     24 * time.Hour,
		ContinueOnError:      false,
		ValidateInputs:       true,
	}
}

// OrchestrationPhase constants
const (
	PhaseIdle         = "idle"
	PhaseInitializing = "initializing"
	PhaseProvisioning = "provisioning"
	PhaseScanning     = "scanning"
	PhaseClassifying  = "classifying"
	PhasePlanning     = "planning"
	PhaseAssessing    = "assessing"
	PhaseReporting    = "reporting"
	PhaseCompleted    = "completed"
	PhaseFailed       = "failed"
	PhaseCancelled    = "cancelled"
)

// Helper function to create a basic orchestrator for testing
func NewBasicOrchestrator(scanner scanner.Scanner, classifier classifier.Classifier, planner planner.Planner, reporter Reporter) *AssessmentOrchestrator {
	return NewAssessmentOrchestrator(
		scanner,
		classifier,
		planner,
		nil, // assessor - will be implemented later
		reporter,
		nil, // provisioner - will be implemented later
		DefaultOrchestratorConfig(),
	)
}
