package reporter

import (
	"context"
	"fmt"
	"html/template"
	"sort"
	"time"

	"bytemomo/orca/internal/config"
	"bytemomo/orca/internal/entity"
	"bytemomo/orca/internal/usecase"
)

// Reporter defines the interface for generating assessment reports
type Reporter interface {
	// GenerateReport creates a complete assessment report
	GenerateReport(ctx context.Context, result *usecase.OrchestrationResult, campaign *config.Campaign) (*entity.Report, error)

	// GenerateJSONReport generates a JSON format report
	GenerateJSONReport(ctx context.Context, result *usecase.OrchestrationResult, campaign *config.Campaign) ([]byte, error)

	// GenerateHTMLReport generates an HTML format report
	GenerateHTMLReport(ctx context.Context, result *usecase.OrchestrationResult, campaign *config.Campaign) ([]byte, error)

	// SaveReport saves a report to the specified location
	SaveReport(ctx context.Context, report *entity.Report, outputPath string) error

	// GetReportSummary generates a summary of the assessment results
	GetReportSummary(result *usecase.OrchestrationResult) (*entity.ReportSummary, error)

	// GetCapabilities returns the reporter's capabilities
	GetCapabilities() ReporterCapabilities
}

// ReporterCapabilities describes what the reporter can do
type ReporterCapabilities struct {
	SupportedFormats  []string `json:"supported_formats"`
	SupportsHTML      bool     `json:"supports_html"`
	SupportsJSON      bool     `json:"supports_json"`
	SupportsCSV       bool     `json:"supports_csv"`
	SupportsPDF       bool     `json:"supports_pdf"`
	SupportsXML       bool     `json:"supports_xml"`
	SupportsTemplates bool     `json:"supports_templates"`
	SupportsCharts    bool     `json:"supports_charts"`
}

// AssessmentReporter implements comprehensive report generation
type AssessmentReporter struct {
	config    ReporterConfig
	templates map[string]*template.Template
}

// ReporterConfig contains configuration for the reporter
type ReporterConfig struct {
	OutputFormats     []string          `yaml:"output_formats" json:"output_formats"`
	TemplateDir       string            `yaml:"template_dir" json:"template_dir"`
	IncludeCharts     bool              `yaml:"include_charts" json:"include_charts"`
	IncludeArtifacts  bool              `yaml:"include_artifacts" json:"include_artifacts"`
	GroupByTarget     bool              `yaml:"group_by_target" json:"group_by_target"`
	GroupBySeverity   bool              `yaml:"group_by_severity" json:"group_by_severity"`
	IncludeRawOutput  bool              `yaml:"include_raw_output" json:"include_raw_output"`
	MaxFindingsPerJob int               `yaml:"max_findings_per_job" json:"max_findings_per_job"`
	Branding          BrandingConfig    `yaml:"branding" json:"branding"`
	Filters           ReportFilters     `yaml:"filters" json:"filters"`
	CustomFields      map[string]string `yaml:"custom_fields" json:"custom_fields"`
}

// BrandingConfig contains branding configuration for reports
type BrandingConfig struct {
	Organization string `yaml:"organization" json:"organization"`
	Logo         string `yaml:"logo" json:"logo"`
	Colors       struct {
		Primary   string `yaml:"primary" json:"primary"`
		Secondary string `yaml:"secondary" json:"secondary"`
		Success   string `yaml:"success" json:"success"`
		Warning   string `yaml:"warning" json:"warning"`
		Danger    string `yaml:"danger" json:"danger"`
	} `yaml:"colors" json:"colors"`
}

// ReportFilters defines what to include/exclude in reports
type ReportFilters struct {
	IncludeSeverities []string `yaml:"include_severities" json:"include_severities"`
	ExcludeSeverities []string `yaml:"exclude_severities" json:"exclude_severities"`
	IncludeStepKinds  []string `yaml:"include_step_kinds" json:"include_step_kinds"`
	ExcludeStepKinds  []string `yaml:"exclude_step_kinds" json:"exclude_step_kinds"`
	MinSeverityLevel  string   `yaml:"min_severity_level" json:"min_severity_level"`
	MaxFindings       int      `yaml:"max_findings" json:"max_findings"`
	OnlyFailures      bool     `yaml:"only_failures" json:"only_failures"`
}

// ReportData contains all data needed for report generation
type ReportData struct {
	Campaign           *config.Campaign             `json:"campaign"`
	Result             *usecase.OrchestrationResult `json:"result"`
	Summary            *entity.ReportSummary        `json:"summary"`
	FindingsByTarget   map[string][]entity.Finding  `json:"findings_by_target"`
	FindingsBySeverity map[string][]entity.Finding  `json:"findings_by_severity"`
	FindingsByStep     map[string][]entity.Finding  `json:"findings_by_step"`
	ArtifactsByJob     map[string][]entity.Artifact `json:"artifacts_by_job"`
	Statistics         ReportStatistics             `json:"statistics"`
	GeneratedAt        time.Time                    `json:"generated_at"`
	Metadata           map[string]any               `json:"metadata"`
}

// ReportStatistics provides detailed statistics about the assessment
type ReportStatistics struct {
	ExecutionTime     time.Duration   `json:"execution_time"`
	JobsTotal         int             `json:"jobs_total"`
	JobsCompleted     int             `json:"jobs_completed"`
	JobsFailed        int             `json:"jobs_failed"`
	JobsSkipped       int             `json:"jobs_skipped"`
	TargetsTotal      int             `json:"targets_total"`
	TargetsAssessed   int             `json:"targets_assessed"`
	FindingsTotal     int             `json:"findings_total"`
	ArtifactsTotal    int             `json:"artifacts_total"`
	SeverityBreakdown map[string]int  `json:"severity_breakdown"`
	StepKindBreakdown map[string]int  `json:"step_kind_breakdown"`
	TargetBreakdown   map[string]int  `json:"target_breakdown"`
	TopFindings       []TopFinding    `json:"top_findings"`
	Timeline          []TimelineEvent `json:"timeline"`
	Coverage          CoverageStats   `json:"coverage"`
}

// TopFinding represents a frequently occurring finding
type TopFinding struct {
	Title      string   `json:"title"`
	Severity   string   `json:"severity"`
	Count      int      `json:"count"`
	Percentage float64  `json:"percentage"`
	Affected   []string `json:"affected_targets"`
}

// TimelineEvent represents an event in the assessment timeline
type TimelineEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Event     string    `json:"event"`
	Details   string    `json:"details"`
	JobID     string    `json:"job_id,omitempty"`
	TargetID  string    `json:"target_id,omitempty"`
}

// CoverageStats represents assessment coverage statistics
type CoverageStats struct {
	PortsCovered    int     `json:"ports_covered"`
	PortsTotal      int     `json:"ports_total"`
	PortCoverage    float64 `json:"port_coverage"`
	ServicesCovered int     `json:"services_covered"`
	ServicesTotal   int     `json:"services_total"`
	ServiceCoverage float64 `json:"service_coverage"`
	HostsCovered    int     `json:"hosts_covered"`
	HostsTotal      int     `json:"hosts_total"`
	HostCoverage    float64 `json:"host_coverage"`
}

// NewAssessmentReporter creates a new assessment reporter
func NewAssessmentReporter(config ReporterConfig) *AssessmentReporter {
	reporter := &AssessmentReporter{
		config:    config,
		templates: make(map[string]*template.Template),
	}

	// Load templates if template directory is specified
	if config.TemplateDir != "" {
		reporter.loadTemplates()
	}

	return reporter
}

// DefaultReporterConfig returns default reporter configuration
func DefaultReporterConfig() ReporterConfig {
	return ReporterConfig{
		OutputFormats:     []string{"json", "html"},
		IncludeCharts:     true,
		IncludeArtifacts:  true,
		GroupByTarget:     true,
		GroupBySeverity:   true,
		IncludeRawOutput:  false,
		MaxFindingsPerJob: 100,
		Branding: BrandingConfig{
			Organization: "ORCA Security Assessment",
		},
		Filters: ReportFilters{
			MaxFindings: 1000,
		},
	}
}

// GenerateReport creates a complete assessment report
func (r *AssessmentReporter) GenerateReport(ctx context.Context, result *usecase.OrchestrationResult, campaign *config.Campaign) (*entity.Report, error) {
	if result == nil {
		return nil, fmt.Errorf("orchestration result is nil")
	}

	if campaign == nil {
		return nil, fmt.Errorf("campaign is nil")
	}

	// Generate report data
	reportData, err := r.prepareReportData(result, campaign)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare report data: %w", err)
	}

	// Create the report entity
	report := &entity.Report{
		ID:           fmt.Sprintf("report_%s", result.RunID),
		CampaignName: campaign.Name,
		RunID:        result.RunID,
		Scope:        campaign.Scope.Value,
		Mode:         campaign.GetMode(),
		StartedAt:    result.StartTime,
		Duration:     result.Duration,
		Status:       result.Status,
		Summary:      *reportData.Summary,
		Findings:     r.aggregateFindings(result),
		Artifacts:    r.aggregateArtifacts(result),
		Metadata: map[string]any{
			"campaign_mode":    campaign.GetMode(),
			"dry_run":          campaign.IsDryRun(),
			"read_only":        campaign.IsReadOnlyMode(),
			"total_steps":      len(campaign.Steps),
			"enabled_steps":    len(campaign.GetEnabledSteps()),
			"report_generated": reportData.GeneratedAt,
		},
	}

	if result.EndTime != (time.Time{}) {
		report.CompletedAt = &result.EndTime
	}

	return report, nil
}

// GenerateJSONReport generates a JSON format report
func (r *AssessmentReporter) GenerateJSONReport(ctx context.Context, result *usecase.OrchestrationResult, campaign *config.Campaign) ([]byte, error) {
	report, err := r.GenerateReport(ctx, result, campaign)
	if err != nil {
		return nil, err
	}

	// TODO: Implement JSON marshaling
	// For now, return a placeholder
	jsonData := fmt.Sprintf(`{
		"report_id": "%s",
		"campaign_name": "%s",
		"run_id": "%s",
		"status": "%s",
		"generated_at": "%s",
		"summary": {
			"total_findings": %d,
			"total_targets": %d
		}
	}`, report.ID, report.CampaignName, report.RunID, report.Status,
		time.Now().Format(time.RFC3339), report.Summary.TotalFindings, report.Summary.TotalTargets)

	return []byte(jsonData), nil
}

// GenerateHTMLReport generates an HTML format report
func (r *AssessmentReporter) GenerateHTMLReport(ctx context.Context, result *usecase.OrchestrationResult, campaign *config.Campaign) ([]byte, error) {
	reportData, err := r.prepareReportData(result, campaign)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare report data: %w", err)
	}

	// Use template if available, otherwise generate basic HTML
	if tmpl, exists := r.templates["report"]; exists {
		// TODO: Execute template with report data
		_ = tmpl
	}

	// Generate basic HTML report
	html := r.generateBasicHTMLReport(reportData)
	return []byte(html), nil
}

// SaveReport saves a report to the specified location
func (r *AssessmentReporter) SaveReport(ctx context.Context, report *entity.Report, outputPath string) error {
	// TODO: Implement file saving
	return fmt.Errorf("report saving not implemented")
}

// GetReportSummary generates a summary of the assessment results
func (r *AssessmentReporter) GetReportSummary(result *usecase.OrchestrationResult) (*entity.ReportSummary, error) {
	summary := &entity.ReportSummary{}

	// Count targets
	if result.ScanResult != nil {
		summary.TotalTargets = len(result.ScanResult.Targets)
	}

	// Count jobs
	if result.Plan != nil {
		summary.TotalJobs = len(result.Plan.Jobs)
	}

	// Count completed/failed jobs
	for _, jobResult := range result.AssessmentResults {
		switch jobResult.Status {
		case entity.JobStatusCompleted:
			summary.CompletedJobs++
		case entity.JobStatusFailed:
			summary.FailedJobs++
		}
	}

	// Count findings by severity
	findings := r.aggregateFindings(result)
	summary.TotalFindings = len(findings)

	for _, finding := range findings {
		switch finding.Severity {
		case "critical":
			summary.CriticalCount++
		case "high":
			summary.HighCount++
		case "medium":
			summary.MediumCount++
		case "low":
			summary.LowCount++
		case "info":
			summary.InfoCount++
		}
	}

	return summary, nil
}

// GetCapabilities returns the reporter's capabilities
func (r *AssessmentReporter) GetCapabilities() ReporterCapabilities {
	return ReporterCapabilities{
		SupportedFormats:  r.config.OutputFormats,
		SupportsHTML:      r.supportsFormat("html"),
		SupportsJSON:      r.supportsFormat("json"),
		SupportsCSV:       r.supportsFormat("csv"),
		SupportsPDF:       r.supportsFormat("pdf"),
		SupportsXML:       r.supportsFormat("xml"),
		SupportsTemplates: r.config.TemplateDir != "",
		SupportsCharts:    r.config.IncludeCharts,
	}
}

// Private helper methods

func (r *AssessmentReporter) prepareReportData(result *usecase.OrchestrationResult, campaign *config.Campaign) (*ReportData, error) {
	summary, err := r.GetReportSummary(result)
	if err != nil {
		return nil, err
	}

	findings := r.aggregateFindings(result)
	artifacts := r.aggregateArtifacts(result)

	data := &ReportData{
		Campaign:           campaign,
		Result:             result,
		Summary:            summary,
		FindingsByTarget:   r.groupFindingsByTarget(findings),
		FindingsBySeverity: r.groupFindingsBySeverity(findings),
		FindingsByStep:     r.groupFindingsByStep(findings),
		ArtifactsByJob:     r.groupArtifactsByJob(artifacts),
		Statistics:         r.calculateStatistics(result, findings, artifacts),
		GeneratedAt:        time.Now(),
		Metadata: map[string]any{
			"generator":     "ORCA Assessment Reporter",
			"version":       "1.0",
			"report_config": r.config,
		},
	}

	return data, nil
}

func (r *AssessmentReporter) aggregateFindings(result *usecase.OrchestrationResult) []entity.Finding {
	var allFindings []entity.Finding

	for _, jobResult := range result.AssessmentResults {
		allFindings = append(allFindings, jobResult.Findings...)
	}

	// Apply filters
	filteredFindings := r.applyFilters(allFindings)

	// Sort by severity and timestamp
	sort.Slice(filteredFindings, func(i, j int) bool {
		severityOrder := map[string]int{
			"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
		}

		severityI := severityOrder[filteredFindings[i].Severity]
		severityJ := severityOrder[filteredFindings[j].Severity]

		if severityI != severityJ {
			return severityI < severityJ
		}

		return filteredFindings[i].CreatedAt.Before(filteredFindings[j].CreatedAt)
	})

	return filteredFindings
}

func (r *AssessmentReporter) aggregateArtifacts(result *usecase.OrchestrationResult) []entity.Artifact {
	var allArtifacts []entity.Artifact

	if !r.config.IncludeArtifacts {
		return allArtifacts
	}

	for _, jobResult := range result.AssessmentResults {
		allArtifacts = append(allArtifacts, jobResult.Artifacts...)
	}

	return allArtifacts
}

func (r *AssessmentReporter) groupFindingsByTarget(findings []entity.Finding) map[string][]entity.Finding {
	groups := make(map[string][]entity.Finding)
	for _, finding := range findings {
		groups[finding.TargetID] = append(groups[finding.TargetID], finding)
	}
	return groups
}

func (r *AssessmentReporter) groupFindingsBySeverity(findings []entity.Finding) map[string][]entity.Finding {
	groups := make(map[string][]entity.Finding)
	for _, finding := range findings {
		groups[finding.Severity] = append(groups[finding.Severity], finding)
	}
	return groups
}

func (r *AssessmentReporter) groupFindingsByStep(findings []entity.Finding) map[string][]entity.Finding {
	groups := make(map[string][]entity.Finding)
	for _, finding := range findings {
		groups[finding.StepID] = append(groups[finding.StepID], finding)
	}
	return groups
}

func (r *AssessmentReporter) groupArtifactsByJob(artifacts []entity.Artifact) map[string][]entity.Artifact {
	groups := make(map[string][]entity.Artifact)
	for _, artifact := range artifacts {
		groups[artifact.JobID] = append(groups[artifact.JobID], artifact)
	}
	return groups
}

func (r *AssessmentReporter) calculateStatistics(result *usecase.OrchestrationResult, findings []entity.Finding, artifacts []entity.Artifact) ReportStatistics {
	stats := ReportStatistics{
		ExecutionTime:     result.Duration,
		FindingsTotal:     len(findings),
		ArtifactsTotal:    len(artifacts),
		SeverityBreakdown: make(map[string]int),
		StepKindBreakdown: make(map[string]int),
		TargetBreakdown:   make(map[string]int),
	}

	// Count job statistics
	for _, jobResult := range result.AssessmentResults {
		stats.JobsTotal++
		switch jobResult.Status {
		case entity.JobStatusCompleted:
			stats.JobsCompleted++
		case entity.JobStatusFailed:
			stats.JobsFailed++
		case entity.JobStatusSkipped:
			stats.JobsSkipped++
		}
	}

	// Count severity breakdown
	for _, finding := range findings {
		stats.SeverityBreakdown[finding.Severity]++
		stats.TargetBreakdown[finding.TargetID]++
	}

	// Count targets
	if result.ScanResult != nil {
		stats.TargetsTotal = len(result.ScanResult.Targets)
		stats.TargetsAssessed = len(stats.TargetBreakdown)
	}

	return stats
}

func (r *AssessmentReporter) applyFilters(findings []entity.Finding) []entity.Finding {
	if !r.hasFilters() {
		return findings
	}

	var filtered []entity.Finding
	for _, finding := range findings {
		if r.shouldIncludeFinding(finding) {
			filtered = append(filtered, finding)
		}
	}

	// Limit number of findings if configured
	if r.config.Filters.MaxFindings > 0 && len(filtered) > r.config.Filters.MaxFindings {
		filtered = filtered[:r.config.Filters.MaxFindings]
	}

	return filtered
}

func (r *AssessmentReporter) hasFilters() bool {
	filters := r.config.Filters
	return len(filters.IncludeSeverities) > 0 ||
		len(filters.ExcludeSeverities) > 0 ||
		filters.MinSeverityLevel != "" ||
		filters.OnlyFailures
}

func (r *AssessmentReporter) shouldIncludeFinding(finding entity.Finding) bool {
	filters := r.config.Filters

	// Check severity inclusion
	if len(filters.IncludeSeverities) > 0 {
		included := false
		for _, sev := range filters.IncludeSeverities {
			if finding.Severity == sev {
				included = true
				break
			}
		}
		if !included {
			return false
		}
	}

	// Check severity exclusion
	for _, sev := range filters.ExcludeSeverities {
		if finding.Severity == sev {
			return false
		}
	}

	return true
}

func (r *AssessmentReporter) supportsFormat(format string) bool {
	for _, f := range r.config.OutputFormats {
		if f == format {
			return true
		}
	}
	return false
}

func (r *AssessmentReporter) loadTemplates() {
	// TODO: Load HTML templates from template directory
}

func (r *AssessmentReporter) generateBasicHTMLReport(data *ReportData) string {
	// Generate a basic HTML report
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>ORCA Security Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { border-bottom: 2px solid #333; padding-bottom: 10px; }
        .summary { background-color: #f5f5f5; padding: 15px; margin: 20px 0; }
        .finding { border-left: 4px solid #ccc; padding: 10px; margin: 10px 0; }
        .critical { border-color: #dc3545; }
        .high { border-color: #fd7e14; }
        .medium { border-color: #ffc107; }
        .low { border-color: #6c757d; }
        .info { border-color: #17a2b8; }
    </style>
</head>
<body>
    <div class="header">
        <h1>ORCA Security Assessment Report</h1>
        <h2>Campaign: %s</h2>
        <p>Generated: %s</p>
    </div>

    <div class="summary">
        <h3>Summary</h3>
        <p>Total Targets: %d</p>
        <p>Total Findings: %d</p>
        <p>Execution Time: %s</p>
        <p>Status: %s</p>
    </div>

    <h3>Findings</h3>
    <!-- Findings would be listed here -->

</body>
</html>`,
		data.Campaign.Name,
		data.GeneratedAt.Format("2006-01-02 15:04:05"),
		data.Summary.TotalTargets,
		data.Summary.TotalFindings,
		data.Result.Duration.String(),
		data.Result.Status)

	return html
}
