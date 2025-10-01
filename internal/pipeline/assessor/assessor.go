package assessor

import (
	"context"
	"fmt"
	"sync"
	"time"

	"bytemomo/orca/internal/config"
	"bytemomo/orca/internal/entity"
	"bytemomo/orca/internal/pipeline/planner"
)

// Assessor defines the interface for executing assessment jobs
type Assessor interface {
	// ExecutePlan executes an assessment plan
	ExecutePlan(ctx context.Context, plan *planner.AssessmentPlan, campaign *config.Campaign) ([]entity.JobResult, error)

	// ExecuteJob executes a single assessment job
	ExecuteJob(ctx context.Context, job entity.AssessmentJob) (*entity.JobResult, error)

	// ExecuteJobGroup executes a group of jobs concurrently
	ExecuteJobGroup(ctx context.Context, jobs []entity.AssessmentJob, concurrency int) ([]entity.JobResult, error)

	// GetJobStatus returns the status of a running job
	GetJobStatus(jobID string) (*entity.AssessmentJob, error)

	// CancelJob cancels a running job
	CancelJob(ctx context.Context, jobID string) error

	// GetCapabilities returns the assessor's capabilities
	GetCapabilities() AssessorCapabilities
}

// AssessorCapabilities describes what the assessor can do
type AssessorCapabilities struct {
	MaxConcurrentJobs    int      `json:"max_concurrent_jobs"`
	SupportedBackends    []string `json:"supported_backends"`
	SupportsCancellation bool     `json:"supports_cancellation"`
	SupportsRetries      bool     `json:"supports_retries"`
	SupportsTimeout      bool     `json:"supports_timeout"`
	SupportsArtifacts    bool     `json:"supports_artifacts"`
	SupportsPCAP         bool     `json:"supports_pcap"`
}

// AssessmentExecutor coordinates job execution
type AssessmentExecutor struct {
	config      AssessorConfig
	runningJobs map[string]*RunningJob
	jobsMutex   sync.RWMutex
	scheduler   JobScheduler
	collector   ArtifactCollector
}

// AssessorConfig contains configuration for the assessor
type AssessorConfig struct {
	MaxConcurrentJobs int           `yaml:"max_concurrent_jobs" json:"max_concurrent_jobs"`
	DefaultTimeout    time.Duration `yaml:"default_timeout" json:"default_timeout"`
	MaxRetries        int           `yaml:"max_retries" json:"max_retries"`
	RetryDelay        time.Duration `yaml:"retry_delay" json:"retry_delay"`
	CollectArtifacts  bool          `yaml:"collect_artifacts" json:"collect_artifacts"`
	CollectPCAP       bool          `yaml:"collect_pcap" json:"collect_pcap"`
	ArtifactPath      string        `yaml:"artifact_path" json:"artifact_path"`
	EnableLogging     bool          `yaml:"enable_logging" json:"enable_logging"`
	LogLevel          string        `yaml:"log_level" json:"log_level"`
}

// RunningJob represents a job that is currently executing
type RunningJob struct {
	Job       entity.AssessmentJob `json:"job"`
	StartTime time.Time            `json:"start_time"`
	Context   context.Context      `json:"-"`
	Cancel    context.CancelFunc   `json:"-"`
	Status    string               `json:"status"`
	Progress  float64              `json:"progress"`
}

// JobScheduler handles job scheduling and concurrency
type JobScheduler interface {
	// ScheduleJob schedules a job for execution
	ScheduleJob(ctx context.Context, job entity.AssessmentJob) error

	// GetNextJob gets the next job to execute
	GetNextJob() (*entity.AssessmentJob, error)

	// UpdateJobStatus updates a job's status
	UpdateJobStatus(jobID string, status entity.JobStatus) error

	// GetQueueSize returns the number of jobs in the queue
	GetQueueSize() int
}

// ArtifactCollector handles collection of job artifacts
type ArtifactCollector interface {
	// CollectArtifacts collects artifacts from a completed job
	CollectArtifacts(ctx context.Context, job entity.AssessmentJob, result *entity.JobResult) ([]entity.Artifact, error)

	// SaveArtifact saves an artifact to storage
	SaveArtifact(ctx context.Context, artifact entity.Artifact, data []byte) error

	// GetArtifact retrieves an artifact from storage
	GetArtifact(ctx context.Context, artifactID string) (*entity.Artifact, []byte, error)
}

// NewAssessmentExecutor creates a new assessment executor
func NewAssessmentExecutor(config AssessorConfig) *AssessmentExecutor {
	return &AssessmentExecutor{
		config:      config,
		runningJobs: make(map[string]*RunningJob),
		scheduler:   NewFIFOScheduler(),
		collector:   NewFileArtifactCollector(config.ArtifactPath),
	}
}

// DefaultAssessorConfig returns default assessor configuration
func DefaultAssessorConfig() AssessorConfig {
	return AssessorConfig{
		MaxConcurrentJobs: 10,
		DefaultTimeout:    300 * time.Second,
		MaxRetries:        3,
		RetryDelay:        30 * time.Second,
		CollectArtifacts:  true,
		CollectPCAP:       false,
		ArtifactPath:      "results",
		EnableLogging:     true,
		LogLevel:          "info",
	}
}

// ExecutePlan executes an assessment plan
func (e *AssessmentExecutor) ExecutePlan(ctx context.Context, plan *planner.AssessmentPlan, campaign *config.Campaign) ([]entity.JobResult, error) {
	if plan == nil {
		return nil, fmt.Errorf("assessment plan is nil")
	}

	if len(plan.Jobs) == 0 {
		return []entity.JobResult{}, nil
	}

	// Execute jobs according to the plan's execution order
	var results []entity.JobResult
	var errors []error

	// Group jobs by their position in execution order
	jobGroups := e.groupJobsByOrder(plan.Jobs, plan.ExecutionOrder)

	for _, jobGroup := range jobGroups {
		groupResults, err := e.ExecuteJobGroup(ctx, jobGroup, e.config.MaxConcurrentJobs)
		if err != nil {
			errors = append(errors, err)
			if !campaign.Runtime.Safety.NonDestructive {
				// Continue on error in non-destructive mode
				break
			}
		}
		results = append(results, groupResults...)
	}

	if len(errors) > 0 {
		return results, fmt.Errorf("execution completed with %d errors", len(errors))
	}

	return results, nil
}

// ExecuteJob executes a single assessment job
func (e *AssessmentExecutor) ExecuteJob(ctx context.Context, job entity.AssessmentJob) (*entity.JobResult, error) {
	// Create job context with timeout
	timeout := job.Duration
	if timeout == 0 {
		timeout = e.config.DefaultTimeout
	}

	jobCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Track running job
	runningJob := &RunningJob{
		Job:       job,
		StartTime: time.Now(),
		Context:   jobCtx,
		Cancel:    cancel,
		Status:    "running",
		Progress:  0.0,
	}

	e.jobsMutex.Lock()
	e.runningJobs[job.ID] = runningJob
	e.jobsMutex.Unlock()

	defer func() {
		e.jobsMutex.Lock()
		delete(e.runningJobs, job.ID)
		e.jobsMutex.Unlock()
	}()

	// Execute with retries
	var result *entity.JobResult
	var lastError error

	maxRetries := job.MaxRetries
	if maxRetries == 0 {
		maxRetries = e.config.MaxRetries
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Wait before retry
			select {
			case <-jobCtx.Done():
				break
			case <-time.After(e.config.RetryDelay):
			}
		}

		result, lastError = e.executeJobAttempt(jobCtx, job, attempt)
		if lastError == nil {
			break
		}

		// Check if we should retry
		if !e.shouldRetry(lastError) {
			break
		}
	}

	// If execution failed, create failure result
	if result == nil {
		result = &entity.JobResult{
			JobID:    job.ID,
			Status:   entity.JobStatusFailed,
			Error:    lastError.Error(),
			Duration: time.Since(runningJob.StartTime),
		}
	}

	// Collect artifacts if configured
	if e.config.CollectArtifacts {
		artifacts, err := e.collector.CollectArtifacts(jobCtx, job, result)
		if err != nil {
			// Log error but don't fail the job
			result.Error = fmt.Sprintf("%s; artifact collection failed: %v", result.Error, err)
		} else {
			result.Artifacts = artifacts
		}
	}

	return result, lastError
}

// ExecuteJobGroup executes a group of jobs concurrently
func (e *AssessmentExecutor) ExecuteJobGroup(ctx context.Context, jobs []entity.AssessmentJob, concurrency int) ([]entity.JobResult, error) {
	if len(jobs) == 0 {
		return []entity.JobResult{}, nil
	}

	// Limit concurrency
	if concurrency <= 0 || concurrency > e.config.MaxConcurrentJobs {
		concurrency = e.config.MaxConcurrentJobs
	}

	// Use semaphore to limit concurrent jobs
	semaphore := make(chan struct{}, concurrency)
	resultsChan := make(chan entity.JobResult, len(jobs))
	errorsChan := make(chan error, len(jobs))

	// Start workers
	var wg sync.WaitGroup
	for _, job := range jobs {
		wg.Add(1)
		go func(j entity.AssessmentJob) {
			defer wg.Done()

			// Acquire semaphore
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				errorsChan <- ctx.Err()
				return
			}

			// Execute job
			result, err := e.ExecuteJob(ctx, j)
			if err != nil {
				errorsChan <- err
			}
			if result != nil {
				resultsChan <- *result
			}
		}(job)
	}

	// Wait for completion
	wg.Wait()
	close(resultsChan)
	close(errorsChan)

	// Collect results
	var results []entity.JobResult
	for result := range resultsChan {
		results = append(results, result)
	}

	// Collect errors
	var errors []error
	for err := range errorsChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return results, fmt.Errorf("job group execution failed with %d errors", len(errors))
	}

	return results, nil
}

// GetJobStatus returns the status of a running job
func (e *AssessmentExecutor) GetJobStatus(jobID string) (*entity.AssessmentJob, error) {
	e.jobsMutex.RLock()
	defer e.jobsMutex.RUnlock()

	runningJob, exists := e.runningJobs[jobID]
	if !exists {
		return nil, fmt.Errorf("job %s not found", jobID)
	}

	job := runningJob.Job
	job.Status = entity.JobStatus(runningJob.Status)
	return &job, nil
}

// CancelJob cancels a running job
func (e *AssessmentExecutor) CancelJob(ctx context.Context, jobID string) error {
	e.jobsMutex.Lock()
	defer e.jobsMutex.Unlock()

	runningJob, exists := e.runningJobs[jobID]
	if !exists {
		return fmt.Errorf("job %s not found", jobID)
	}

	runningJob.Cancel()
	runningJob.Status = "cancelled"
	return nil
}

// GetCapabilities returns the assessor's capabilities
func (e *AssessmentExecutor) GetCapabilities() AssessorCapabilities {
	return AssessorCapabilities{
		MaxConcurrentJobs:    e.config.MaxConcurrentJobs,
		SupportedBackends:    []string{"grpc", "cshared"},
		SupportsCancellation: true,
		SupportsRetries:      true,
		SupportsTimeout:      true,
		SupportsArtifacts:    e.config.CollectArtifacts,
		SupportsPCAP:         e.config.CollectPCAP,
	}
}

// Private helper methods

func (e *AssessmentExecutor) executeJobAttempt(ctx context.Context, job entity.AssessmentJob, attempt int) (*entity.JobResult, error) {
	startTime := time.Now()

	// TODO: This is where extension execution would happen
	// For now, return a mock result

	result := &entity.JobResult{
		JobID:    job.ID,
		Status:   entity.JobStatusCompleted,
		ExitCode: 0,
		Duration: time.Since(startTime),
		Stdout:   fmt.Sprintf("Mock execution of job %s (attempt %d)", job.ID, attempt+1),
	}

	// Simulate some execution time
	time.Sleep(100 * time.Millisecond)

	return result, nil
}

func (e *AssessmentExecutor) shouldRetry(err error) bool {
	// Define which errors are retryable
	// TODO: Implement more sophisticated retry logic
	return err != nil && !isContextError(err)
}

func (e *AssessmentExecutor) groupJobsByOrder(jobs []entity.AssessmentJob, executionOrder []string) [][]entity.AssessmentJob {
	// Simple implementation: group sequential jobs
	// TODO: Implement more sophisticated grouping based on dependencies

	var groups [][]entity.AssessmentJob
	if len(jobs) == 0 {
		return groups
	}

	// For now, just create one group with all jobs
	groups = append(groups, jobs)
	return groups
}

func isContextError(err error) bool {
	return err == context.Canceled || err == context.DeadlineExceeded
}

// Simple FIFO scheduler implementation
type FIFOScheduler struct {
	jobs  []entity.AssessmentJob
	mutex sync.Mutex
}

func NewFIFOScheduler() *FIFOScheduler {
	return &FIFOScheduler{}
}

func (s *FIFOScheduler) ScheduleJob(ctx context.Context, job entity.AssessmentJob) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.jobs = append(s.jobs, job)
	return nil
}

func (s *FIFOScheduler) GetNextJob() (*entity.AssessmentJob, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if len(s.jobs) == 0 {
		return nil, fmt.Errorf("no jobs in queue")
	}

	job := s.jobs[0]
	s.jobs = s.jobs[1:]
	return &job, nil
}

func (s *FIFOScheduler) UpdateJobStatus(jobID string, status entity.JobStatus) error {
	// TODO: Implement job status tracking
	return nil
}

func (s *FIFOScheduler) GetQueueSize() int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return len(s.jobs)
}

// Simple file-based artifact collector
type FileArtifactCollector struct {
	basePath string
}

func NewFileArtifactCollector(basePath string) *FileArtifactCollector {
	return &FileArtifactCollector{basePath: basePath}
}

func (c *FileArtifactCollector) CollectArtifacts(ctx context.Context, job entity.AssessmentJob, result *entity.JobResult) ([]entity.Artifact, error) {
	// TODO: Implement artifact collection
	return []entity.Artifact{}, nil
}

func (c *FileArtifactCollector) SaveArtifact(ctx context.Context, artifact entity.Artifact, data []byte) error {
	// TODO: Implement artifact saving
	return nil
}

func (c *FileArtifactCollector) GetArtifact(ctx context.Context, artifactID string) (*entity.Artifact, []byte, error) {
	// TODO: Implement artifact retrieval
	return nil, nil, fmt.Errorf("artifact retrieval not implemented")
}
