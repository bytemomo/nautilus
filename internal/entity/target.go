package entity

import (
	"net"
	"time"
)

// Host represents a discovered network host
type Host struct {
	IP       net.IP            `json:"ip"`
	Hostname string            `json:"hostname,omitempty"`
	OS       string            `json:"os,omitempty"`
	Tags     map[string]string `json:"tags,omitempty"`
	Alive    bool              `json:"alive"`
}

// Service represents a discovered service on a host
type Service struct {
	Host        *Host             `json:"host"`
	Port        int               `json:"port"`
	Protocol    string            `json:"protocol"` // tcp, udp
	State       string            `json:"state"`    // open, closed, filtered
	ServiceName string            `json:"service_name,omitempty"`
	Version     string            `json:"version,omitempty"`
	Banner      string            `json:"banner,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}

// Target represents a canonical assessment target
type Target struct {
	ID          string            `json:"id"`
	Host        *Host             `json:"host"`
	Service     *Service          `json:"service,omitempty"`
	Protocol    string            `json:"protocol"`
	Endpoint    string            `json:"endpoint"` // host:port or container reference
	Tags        map[string]string `json:"tags,omitempty"`
	IsContainer bool              `json:"is_container"`
	Metadata    map[string]any    `json:"metadata,omitempty"`
}

// Finding represents a security finding from an assessment
type Finding struct {
	ID          string            `json:"id"`
	JobID       string            `json:"job_id"`
	TargetID    string            `json:"target_id"`
	StepID      string            `json:"step_id"`
	Type        string            `json:"type"`     // vulnerability, compliance, info, etc.
	Severity    string            `json:"severity"` // critical, high, medium, low, info
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Evidence    map[string]any    `json:"evidence,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
}

// Artifact represents a file or data artifact from an assessment
type Artifact struct {
	ID        string         `json:"id"`
	JobID     string         `json:"job_id"`
	Type      string         `json:"type"` // pcap, log, crash_input, screenshot, etc.
	Path      string         `json:"path"`
	Size      int64          `json:"size"`
	Hash      string         `json:"hash,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

// Report represents an aggregated assessment report
type Report struct {
	ID           string         `json:"id"`
	CampaignName string         `json:"campaign_name"`
	RunID        string         `json:"run_id"`
	Scope        string         `json:"scope"`
	Mode         string         `json:"mode"`
	StartedAt    time.Time      `json:"started_at"`
	CompletedAt  *time.Time     `json:"completed_at,omitempty"`
	Duration     time.Duration  `json:"duration"`
	Status       string         `json:"status"` // running, completed, failed, cancelled
	Summary      ReportSummary  `json:"summary"`
	Findings     []Finding      `json:"findings"`
	Artifacts    []Artifact     `json:"artifacts"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

// ReportSummary provides aggregate statistics for a report
type ReportSummary struct {
	TotalTargets   int `json:"total_targets"`
	TotalJobs      int `json:"total_jobs"`
	CompletedJobs  int `json:"completed_jobs"`
	FailedJobs     int `json:"failed_jobs"`
	TotalFindings  int `json:"total_findings"`
	CriticalCount  int `json:"critical_count"`
	HighCount      int `json:"high_count"`
	MediumCount    int `json:"medium_count"`
	LowCount       int `json:"low_count"`
	InfoCount      int `json:"info_count"`
	CompliancePass int `json:"compliance_pass"`
	ComplianceFail int `json:"compliance_fail"`
}

// JobStatus represents the status of an assessment job
type JobStatus string

const (
	JobStatusPending   JobStatus = "pending"
	JobStatusRunning   JobStatus = "running"
	JobStatusCompleted JobStatus = "completed"
	JobStatusFailed    JobStatus = "failed"
	JobStatusTimeout   JobStatus = "timeout"
	JobStatusCancelled JobStatus = "cancelled"
	JobStatusSkipped   JobStatus = "skipped"
)

// AssessmentJob represents a single assessment task
type AssessmentJob struct {
	ID          string         `json:"id"`
	StepID      string         `json:"step_id"`
	Target      *Target        `json:"target"`
	StepName    string         `json:"step_name"`
	StepKind    string         `json:"step_kind"` // check, attack, compliance
	Status      JobStatus      `json:"status"`
	StartedAt   *time.Time     `json:"started_at,omitempty"`
	CompletedAt *time.Time     `json:"completed_at,omitempty"`
	Duration    time.Duration  `json:"duration"`
	ExitCode    int            `json:"exit_code"`
	Error       string         `json:"error,omitempty"`
	Retry       int            `json:"retry"`
	MaxRetries  int            `json:"max_retries"`
	Findings    []Finding      `json:"findings,omitempty"`
	Artifacts   []Artifact     `json:"artifacts,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`

	// Extension execution details
	ExtensionManifest string         `json:"extension_manifest"`
	ExtensionBackend  string         `json:"extension_backend"` // grpc, cshared
	Parameters        map[string]any `json:"parameters,omitempty"`
}

// JobResult contains the outcome of a completed job
type JobResult struct {
	JobID     string        `json:"job_id"`
	Status    JobStatus     `json:"status"`
	ExitCode  int           `json:"exit_code"`
	Error     string        `json:"error,omitempty"`
	Findings  []Finding     `json:"findings,omitempty"`
	Artifacts []Artifact    `json:"artifacts,omitempty"`
	Stdout    string        `json:"stdout,omitempty"`
	Stderr    string        `json:"stderr,omitempty"`
	Duration  time.Duration `json:"duration"`
}

// ResolvedTarget represents a target that has been resolved by the provisioner
type ResolvedTarget struct {
	Original    *Target        `json:"original"`
	Resolved    *Target        `json:"resolved"`
	IsContainer bool           `json:"is_container"`
	ContainerID string         `json:"container_id,omitempty"`
	NetworkID   string         `json:"network_id,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}
