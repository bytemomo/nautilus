package planner

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"bytemomo/orca/internal/config"
	"bytemomo/orca/internal/entity"
	"bytemomo/orca/internal/pipeline/classifier"
)

// Planner defines the interface for creating assessment job plans
type Planner interface {
	// Plan creates an assessment plan from classification results
	Plan(ctx context.Context, result *classifier.ClassificationResult, campaign *config.Campaign) (*AssessmentPlan, error)

	// ValidatePlan validates an assessment plan for safety and feasibility
	ValidatePlan(plan *AssessmentPlan, campaign *config.Campaign) error

	// OptimizePlan optimizes job ordering and dependencies
	OptimizePlan(plan *AssessmentPlan) error
}

// AssessmentPlan contains the complete plan for assessment execution
type AssessmentPlan struct {
	ID               string                 `json:"id"`
	CampaignName     string                 `json:"campaign_name"`
	CreatedAt        time.Time              `json:"created_at"`
	Jobs             []entity.AssessmentJob `json:"jobs"`
	JobGroups        []JobGroup             `json:"job_groups"`
	Dependencies     []JobDependency        `json:"dependencies"`
	ExecutionOrder   []string               `json:"execution_order"` // Job IDs in execution order
	EstimatedRuntime time.Duration          `json:"estimated_runtime"`
	ResourceLimits   ResourceLimits         `json:"resource_limits"`
	SafetyChecks     []SafetyCheck          `json:"safety_checks"`
	Metadata         map[string]any         `json:"metadata,omitempty"`
}

// JobGroup represents a group of jobs that can be executed concurrently
type JobGroup struct {
	ID          string   `json:"id"`
	Jobs        []string `json:"jobs"`        // Job IDs
	Priority    int      `json:"priority"`    // Higher number = higher priority
	Concurrency int      `json:"concurrency"` // Max concurrent jobs in this group
	DependsOn   []string `json:"depends_on"`  // Other group IDs this group depends on
}

// JobDependency represents a dependency between jobs
type JobDependency struct {
	JobID       string `json:"job_id"`
	DependsOnID string `json:"depends_on_id"`
	Type        string `json:"type"` // hard, soft, ordering
	Reason      string `json:"reason"`
}

// ResourceLimits defines resource constraints for the plan
type ResourceLimits struct {
	MaxConcurrentJobs int           `json:"max_concurrent_jobs"`
	MaxDuration       time.Duration `json:"max_duration"`
	MaxMemoryMB       int           `json:"max_memory_mb"`
	MaxConnections    int           `json:"max_connections"`
	RateLimitRPS      int           `json:"rate_limit_rps"`
}

// SafetyCheck represents a safety validation
type SafetyCheck struct {
	Type       string         `json:"type"`   // port_check, host_check, destructive_check
	Status     string         `json:"status"` // passed, failed, warning
	Message    string         `json:"message"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	BlocksPlan bool           `json:"blocks_plan"`
	Severity   string         `json:"severity"` // low, medium, high, critical
}

// SchedulingPlanner implements job planning and scheduling
type SchedulingPlanner struct {
	config PlannerConfig
}

// PlannerConfig contains configuration for the planner
type PlannerConfig struct {
	DefaultJobTimeout  time.Duration `yaml:"default_job_timeout" json:"default_job_timeout"`
	MaxJobsPerTarget   int           `yaml:"max_jobs_per_target" json:"max_jobs_per_target"`
	EnableOptimization bool          `yaml:"enable_optimization" json:"enable_optimization"`
	SafetyValidation   bool          `yaml:"safety_validation" json:"safety_validation"`
	EstimateRuntimes   bool          `yaml:"estimate_runtimes" json:"estimate_runtimes"`
	GroupSimilarJobs   bool          `yaml:"group_similar_jobs" json:"group_similar_jobs"`
	MaxGroupSize       int           `yaml:"max_group_size" json:"max_group_size"`
	PrioritizeByRisk   bool          `yaml:"prioritize_by_risk" json:"prioritize_by_risk"`
}

// NewSchedulingPlanner creates a new scheduling planner
func NewSchedulingPlanner(config PlannerConfig) *SchedulingPlanner {
	return &SchedulingPlanner{
		config: config,
	}
}

// DefaultPlannerConfig returns default planner configuration
func DefaultPlannerConfig() PlannerConfig {
	return PlannerConfig{
		DefaultJobTimeout:  300 * time.Second, // 5 minutes
		MaxJobsPerTarget:   10,
		EnableOptimization: true,
		SafetyValidation:   true,
		EstimateRuntimes:   true,
		GroupSimilarJobs:   true,
		MaxGroupSize:       5,
		PrioritizeByRisk:   false,
	}
}

// Plan creates an assessment plan from classification results
func (p *SchedulingPlanner) Plan(ctx context.Context, result *classifier.ClassificationResult, campaign *config.Campaign) (*AssessmentPlan, error) {
	planID := fmt.Sprintf("plan_%s_%s", campaign.Name, time.Now().Format("20060102_150405"))

	plan := &AssessmentPlan{
		ID:           planID,
		CampaignName: campaign.Name,
		CreatedAt:    time.Now(),
		ResourceLimits: ResourceLimits{
			MaxConcurrentJobs: campaign.Runtime.Concurrency,
			MaxDuration:       time.Duration(campaign.Runtime.DurationSeconds) * time.Second,
			MaxConnections:    campaign.Runtime.Safety.MaxConnections,
			RateLimitRPS:      campaign.Runtime.Safety.RateLimitRPS,
		},
	}

	// Create jobs from mappings
	jobs, err := p.createJobsFromMappings(result.Mappings, campaign)
	if err != nil {
		return nil, fmt.Errorf("failed to create jobs: %w", err)
	}
	plan.Jobs = jobs

	// Perform safety validation
	if p.config.SafetyValidation {
		safetyChecks, err := p.performSafetyChecks(jobs, campaign)
		if err != nil {
			return nil, fmt.Errorf("safety validation failed: %w", err)
		}
		plan.SafetyChecks = safetyChecks

		// Check if any safety checks block the plan
		for _, check := range safetyChecks {
			if check.BlocksPlan {
				return nil, fmt.Errorf("safety check failed: %s", check.Message)
			}
		}
	}

	// Create job groups and dependencies
	if p.config.GroupSimilarJobs {
		plan.JobGroups = p.createJobGroups(jobs)
	}

	plan.Dependencies = p.createJobDependencies(jobs, campaign.Steps)

	// Create execution order
	plan.ExecutionOrder = p.createExecutionOrder(jobs, plan.Dependencies)

	// Estimate runtime
	if p.config.EstimateRuntimes {
		plan.EstimatedRuntime = p.estimateRuntime(jobs, plan.JobGroups, campaign)
	}

	// Optimize if enabled
	if p.config.EnableOptimization {
		if err := p.OptimizePlan(plan); err != nil {
			return nil, fmt.Errorf("failed to optimize plan: %w", err)
		}
	}

	return plan, nil
}

// ValidatePlan validates an assessment plan
func (p *SchedulingPlanner) ValidatePlan(plan *AssessmentPlan, campaign *config.Campaign) error {
	if len(plan.Jobs) == 0 {
		return fmt.Errorf("plan contains no jobs")
	}

	// Validate resource limits
	if plan.ResourceLimits.MaxConcurrentJobs <= 0 {
		return fmt.Errorf("max concurrent jobs must be positive")
	}

	// Validate job dependencies don't create cycles
	if err := p.validateNoCycles(plan.Dependencies); err != nil {
		return fmt.Errorf("dependency cycle detected: %w", err)
	}

	// Validate all jobs have valid configurations
	for _, job := range plan.Jobs {
		if err := p.validateJob(job, campaign); err != nil {
			return fmt.Errorf("invalid job %s: %w", job.ID, err)
		}
	}

	return nil
}

// OptimizePlan optimizes job ordering and dependencies
func (p *SchedulingPlanner) OptimizePlan(plan *AssessmentPlan) error {
	// Sort jobs by priority and estimated duration
	sort.Slice(plan.Jobs, func(i, j int) bool {
		jobI := plan.Jobs[i]
		jobJ := plan.Jobs[j]

		// First by step kind priority (checks < attacks < compliance)
		priorityI := getStepKindPriority(jobI.StepKind)
		priorityJ := getStepKindPriority(jobJ.StepKind)

		if priorityI != priorityJ {
			return priorityI < priorityJ
		}

		// Then by estimated duration (shorter first)
		return jobI.Duration < jobJ.Duration
	})

	// Re-create execution order with optimized job list
	plan.ExecutionOrder = p.createExecutionOrder(plan.Jobs, plan.Dependencies)

	// Optimize job groups
	if len(plan.JobGroups) > 0 {
		plan.JobGroups = p.optimizeJobGroups(plan.JobGroups, plan.Jobs)
	}

	return nil
}

// createJobsFromMappings creates AssessmentJob entities from target-step mappings
func (p *SchedulingPlanner) createJobsFromMappings(mappings []classifier.TargetStepMapping, campaign *config.Campaign) ([]entity.AssessmentJob, error) {
	var jobs []entity.AssessmentJob
	jobCounter := 1

	for _, mapping := range mappings {
		jobID := fmt.Sprintf("job_%d", jobCounter)

		job := entity.AssessmentJob{
			ID:                jobID,
			StepID:            mapping.Step.ID,
			Target:            &mapping.Target,
			StepName:          mapping.Step.Name,
			StepKind:          mapping.Step.Kind,
			Status:            entity.JobStatusPending,
			MaxRetries:        getMaxRetries(mapping.Step, campaign),
			ExtensionManifest: mapping.Step.Implementation.Manifest,
			ExtensionBackend:  mapping.Step.Implementation.Backend,
			Parameters:        mapping.Step.Parameters,
			Metadata: map[string]any{
				"classification_score":  mapping.Score,
				"classification_reason": mapping.Reason,
				"campaign_name":         campaign.Name,
				"target_endpoint":       mapping.Target.Endpoint,
			},
		}

		// Set job timeout
		if mapping.Step.Schedule.JobTimeoutSeconds > 0 {
			job.Duration = time.Duration(mapping.Step.Schedule.JobTimeoutSeconds) * time.Second
		} else {
			job.Duration = p.config.DefaultJobTimeout
		}

		jobs = append(jobs, job)
		jobCounter++
	}

	return jobs, nil
}

// performSafetyChecks validates jobs against safety policies
func (p *SchedulingPlanner) performSafetyChecks(jobs []entity.AssessmentJob, campaign *config.Campaign) ([]SafetyCheck, error) {
	var checks []SafetyCheck

	// Check read-only mode violations
	if campaign.Runtime.Safety.ReadOnly {
		for _, job := range jobs {
			if job.StepKind == "attack" {
				checks = append(checks, SafetyCheck{
					Type:       "read_only_violation",
					Status:     "failed",
					Message:    fmt.Sprintf("Job %s is an attack step but read-only mode is enabled", job.ID),
					BlocksPlan: true,
					Severity:   "critical",
				})
			}
		}
	}

	// Check non-destructive mode violations
	if campaign.Runtime.Safety.NonDestructive {
		destructiveKeywords := []string{"fuzz", "exploit", "brute", "crack", "overload"}
		for _, job := range jobs {
			stepNameLower := strings.ToLower(job.StepName)
			for _, keyword := range destructiveKeywords {
				if strings.Contains(stepNameLower, keyword) {
					checks = append(checks, SafetyCheck{
						Type:       "destructive_check",
						Status:     "warning",
						Message:    fmt.Sprintf("Job %s may be destructive but non-destructive mode is enabled", job.ID),
						BlocksPlan: false,
						Severity:   "medium",
					})
					break
				}
			}
		}
	}

	// Check forbidden ports
	if len(campaign.Runtime.Safety.ForbiddenPorts) > 0 {
		for _, job := range jobs {
			if job.Target != nil && job.Target.Service != nil {
				for _, forbiddenPort := range campaign.Runtime.Safety.ForbiddenPorts {
					if job.Target.Service.Port == forbiddenPort {
						checks = append(checks, SafetyCheck{
							Type:       "forbidden_port",
							Status:     "failed",
							Message:    fmt.Sprintf("Job %s targets forbidden port %d", job.ID, forbiddenPort),
							BlocksPlan: true,
							Severity:   "high",
						})
					}
				}
			}
		}
	}

	// Check allowed ports (if specified)
	if len(campaign.Runtime.Safety.AllowedPorts) > 0 {
		for _, job := range jobs {
			if job.Target != nil && job.Target.Service != nil {
				allowed := false
				for _, allowedPort := range campaign.Runtime.Safety.AllowedPorts {
					if job.Target.Service.Port == allowedPort {
						allowed = true
						break
					}
				}
				if !allowed {
					checks = append(checks, SafetyCheck{
						Type:       "port_not_allowed",
						Status:     "failed",
						Message:    fmt.Sprintf("Job %s targets port %d which is not in allowed ports list", job.ID, job.Target.Service.Port),
						BlocksPlan: true,
						Severity:   "high",
					})
				}
			}
		}
	}

	return checks, nil
}

// createJobGroups groups similar jobs together
func (p *SchedulingPlanner) createJobGroups(jobs []entity.AssessmentJob) []JobGroup {
	var groups []JobGroup
	groupCounter := 1

	// Group by step kind and similar characteristics
	kindGroups := make(map[string][]entity.AssessmentJob)

	for _, job := range jobs {
		key := fmt.Sprintf("%s_%s", job.StepKind, job.ExtensionManifest)
		kindGroups[key] = append(kindGroups[key], job)
	}

	for _, groupJobs := range kindGroups {
		if len(groupJobs) == 0 {
			continue
		}

		// Split large groups
		for i := 0; i < len(groupJobs); i += p.config.MaxGroupSize {
			end := i + p.config.MaxGroupSize
			if end > len(groupJobs) {
				end = len(groupJobs)
			}

			var jobIDs []string
			for j := i; j < end; j++ {
				jobIDs = append(jobIDs, groupJobs[j].ID)
			}

			group := JobGroup{
				ID:          fmt.Sprintf("group_%d", groupCounter),
				Jobs:        jobIDs,
				Priority:    getStepKindPriority(groupJobs[i].StepKind),
				Concurrency: min(len(jobIDs), 3), // Max 3 concurrent jobs per group
			}

			groups = append(groups, group)
			groupCounter++
		}
	}

	return groups
}

// createJobDependencies creates dependencies between jobs
func (p *SchedulingPlanner) createJobDependencies(jobs []entity.AssessmentJob, steps []config.Step) []JobDependency {
	var dependencies []JobDependency

	// Create step dependency map
	stepDeps := make(map[string][]string)
	for _, step := range steps {
		stepDeps[step.ID] = step.Schedule.DependsOn
	}

	// Create job dependencies based on step dependencies
	for _, job := range jobs {
		if deps, exists := stepDeps[job.StepID]; exists {
			for _, depStepID := range deps {
				// Find jobs with the dependent step
				for _, depJob := range jobs {
					if depJob.StepID == depStepID {
						dependencies = append(dependencies, JobDependency{
							JobID:       job.ID,
							DependsOnID: depJob.ID,
							Type:        "hard",
							Reason:      "step dependency",
						})
					}
				}
			}
		}
	}

	// Add ordering dependencies (checks before attacks)
	checkJobs := make([]entity.AssessmentJob, 0)
	attackJobs := make([]entity.AssessmentJob, 0)

	for _, job := range jobs {
		switch job.StepKind {
		case "check", "compliance":
			checkJobs = append(checkJobs, job)
		case "attack":
			attackJobs = append(attackJobs, job)
		}
	}

	// Make all attacks depend on checks for the same target
	for _, attackJob := range attackJobs {
		for _, checkJob := range checkJobs {
			if attackJob.Target != nil && checkJob.Target != nil &&
				attackJob.Target.Endpoint == checkJob.Target.Endpoint {
				dependencies = append(dependencies, JobDependency{
					JobID:       attackJob.ID,
					DependsOnID: checkJob.ID,
					Type:        "ordering",
					Reason:      "checks before attacks",
				})
			}
		}
	}

	return dependencies
}

// createExecutionOrder creates an execution order respecting dependencies
func (p *SchedulingPlanner) createExecutionOrder(jobs []entity.AssessmentJob, dependencies []JobDependency) []string {
	// Build dependency graph
	depGraph := make(map[string][]string)
	inDegree := make(map[string]int)

	// Initialize
	for _, job := range jobs {
		depGraph[job.ID] = []string{}
		inDegree[job.ID] = 0
	}

	// Build graph
	for _, dep := range dependencies {
		depGraph[dep.DependsOnID] = append(depGraph[dep.DependsOnID], dep.JobID)
		inDegree[dep.JobID]++
	}

	// Topological sort
	var queue []string
	var result []string

	// Find nodes with no dependencies
	for jobID, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, jobID)
		}
	}

	// Process queue
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		result = append(result, current)

		// Update dependents
		for _, dependent := range depGraph[current] {
			inDegree[dependent]--
			if inDegree[dependent] == 0 {
				queue = append(queue, dependent)
			}
		}
	}

	return result
}

// estimateRuntime estimates the total runtime for the plan
func (p *SchedulingPlanner) estimateRuntime(jobs []entity.AssessmentJob, groups []JobGroup, campaign *config.Campaign) time.Duration {
	if len(groups) > 0 {
		return p.estimateRuntimeWithGroups(groups, campaign)
	}

	// Simple sequential estimation
	var total time.Duration
	for _, job := range jobs {
		total += job.Duration
	}

	// Adjust for concurrency
	concurrency := campaign.Runtime.Concurrency
	if concurrency > 1 {
		total = time.Duration(float64(total) / float64(concurrency))
	}

	return total
}

// estimateRuntimeWithGroups estimates runtime considering job groups
func (p *SchedulingPlanner) estimateRuntimeWithGroups(groups []JobGroup, campaign *config.Campaign) time.Duration {
	// This is a simplified estimation
	// In practice, you'd use more sophisticated scheduling algorithms

	var totalTime time.Duration
	for _, group := range groups {
		// Assume each group takes the time of its longest job
		// divided by the group's concurrency
		groupTime := time.Duration(len(group.Jobs)) * p.config.DefaultJobTimeout
		groupTime = time.Duration(float64(groupTime) / float64(group.Concurrency))
		totalTime += groupTime
	}

	return totalTime
}

// Helper functions

func getMaxRetries(step config.Step, campaign *config.Campaign) int {
	if step.Schedule.MaxRetries > 0 {
		return step.Schedule.MaxRetries
	}
	return 2 // Default
}

func getStepKindPriority(kind string) int {
	switch kind {
	case "check":
		return 1
	case "compliance":
		return 2
	case "attack":
		return 3
	default:
		return 99
	}
}

func (p *SchedulingPlanner) validateNoCycles(dependencies []JobDependency) error {
	// Build adjacency list
	graph := make(map[string][]string)
	for _, dep := range dependencies {
		graph[dep.DependsOnID] = append(graph[dep.DependsOnID], dep.JobID)
	}

	// DFS cycle detection
	visited := make(map[string]bool)
	recStack := make(map[string]bool)

	var dfs func(string) bool
	dfs = func(node string) bool {
		visited[node] = true
		recStack[node] = true

		for _, neighbor := range graph[node] {
			if !visited[neighbor] {
				if dfs(neighbor) {
					return true
				}
			} else if recStack[neighbor] {
				return true // Cycle found
			}
		}

		recStack[node] = false
		return false
	}

	for node := range graph {
		if !visited[node] {
			if dfs(node) {
				return fmt.Errorf("cycle detected involving job %s", node)
			}
		}
	}

	return nil
}

func (p *SchedulingPlanner) validateJob(job entity.AssessmentJob, campaign *config.Campaign) error {
	if job.ID == "" {
		return fmt.Errorf("job ID is required")
	}

	if job.StepID == "" {
		return fmt.Errorf("step ID is required")
	}

	if job.Target == nil {
		return fmt.Errorf("target is required")
	}

	if job.ExtensionManifest == "" {
		return fmt.Errorf("extension manifest is required")
	}

	return nil
}

func (p *SchedulingPlanner) optimizeJobGroups(groups []JobGroup, jobs []entity.AssessmentJob) []JobGroup {
	// Sort groups by priority
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Priority < groups[j].Priority
	})

	return groups
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
