package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"bytemomo/orca/internal/config"
	"bytemomo/orca/internal/entity"
	"bytemomo/orca/internal/pipeline/assessor"
	"bytemomo/orca/internal/pipeline/classifier"
	"bytemomo/orca/internal/pipeline/planner"
	"bytemomo/orca/internal/pipeline/reporter"
	"bytemomo/orca/internal/pipeline/scanner"
	"bytemomo/orca/internal/usecase"
)

var (
	version = "1.0.0"
	commit  = "dev"
)

func main() {
	// Command line flags
	var (
		campaignFile  = flag.String("campaign", "", "Path to campaign YAML file (required)")
		blueprint     = flag.String("blueprint", "", "Path to Docker blueprint YAML file (optional)")
		outDir        = flag.String("out", "", "Output directory (overrides campaign setting)")
		runID         = flag.String("run-id", "", "Custom run ID (overrides campaign setting)")
		dryRun        = flag.Bool("dry-run", false, "Perform dry run without executing assessments")
		verbose       = flag.Bool("verbose", false, "Enable verbose logging")
		versionFlag   = flag.Bool("version", false, "Show version information")
		listCampaigns = flag.String("list", "", "List campaigns in directory")
	)
	flag.Parse()

	// Show version
	if *versionFlag {
		fmt.Printf("ORCA Network Assessment Orchestrator v%s (%s)\n", version, commit)
		os.Exit(0)
	}

	// List campaigns
	if *listCampaigns != "" {
		if err := listCampaignsInDir(*listCampaigns); err != nil {
			log.Fatalf("Failed to list campaigns: %v", err)
		}
		return
	}

	// Validate required arguments
	if *campaignFile == "" {
		fmt.Fprintf(os.Stderr, "Error: --campaign is required\n\n")
		flag.Usage()
		os.Exit(1)
	}

	// Set up logging
	setupLogging(*verbose)

	log.Printf("ORCA v%s starting...", version)
	log.Printf("Campaign file: %s", *campaignFile)

	ctx := context.Background()

	// Load configuration
	loader := config.NewLoader(filepath.Dir(*campaignFile))

	// Load campaign
	campaign, err := loader.LoadCampaign(filepath.Base(*campaignFile))
	if err != nil {
		log.Fatalf("Failed to load campaign: %v", err)
	}

	log.Printf("Loaded campaign: %s (mode: %s)", campaign.Name, campaign.GetMode())

	// Override runtime settings from command line
	if *outDir != "" {
		campaign.Runtime.OutDir = *outDir
	}
	if *runID != "" {
		campaign.Runtime.RunID = *runID
	}
	if *dryRun {
		campaign.Runtime.Safety.DryRun = true
	}

	// Load blueprint if specified
	var blueprintConfig *config.Blueprint
	if *blueprint != "" || campaign.DockerBlueprint != "" {
		blueprintPath := *blueprint
		if blueprintPath == "" {
			blueprintPath = campaign.DockerBlueprint
		}

		blueprintConfig, err = loader.LoadBlueprint(blueprintPath)
		if err != nil {
			log.Fatalf("Failed to load blueprint: %v", err)
		}
		log.Printf("Loaded blueprint: %s", blueprintConfig.Name)
	}

	// Load manifests referenced in steps
	manifestPaths := getManifestPaths(campaign.Steps)
	manifests, err := loader.LoadManifests(manifestPaths)
	if err != nil {
		log.Fatalf("Failed to load manifests: %v", err)
	}

	log.Printf("Loaded %d extension manifests", len(manifests))

	// Validate configuration
	if err := loader.ValidateConfiguration(campaign, blueprintConfig, manifests); err != nil {
		log.Fatalf("Configuration validation failed: %v", err)
	}

	// Create output directory
	if err := os.MkdirAll(campaign.Runtime.OutDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Set up pipeline components
	orchestrator, err := setupOrchestrator(campaign, blueprintConfig)
	if err != nil {
		log.Fatalf("Failed to setup orchestrator: %v", err)
	}

	// Execute campaign
	log.Printf("Starting campaign execution...")
	startTime := time.Now()

	result, err := orchestrator.ExecuteWithBlueprint(ctx, campaign, blueprintConfig)
	if err != nil {
		log.Fatalf("Campaign execution failed: %v", err)
	}

	executionTime := time.Since(startTime)
	log.Printf("Campaign execution completed in %s", executionTime)

	// Print summary
	printSummary(result)

	// Save results
	if err := saveResults(result, campaign); err != nil {
		log.Printf("Warning: Failed to save some results: %v", err)
	}

	log.Printf("Results saved to: %s", campaign.Runtime.OutDir)

	// Exit with appropriate code
	if result.Status == "failed" {
		os.Exit(1)
	}
	if result.Status == "completed_with_errors" {
		os.Exit(2)
	}

	log.Printf("Campaign %s completed successfully", campaign.Name)
}

func setupOrchestrator(campaign *config.Campaign, blueprint *config.Blueprint) (usecase.Orchestrator, error) {
	// Create scanner - using mock for demo
	mockScanner := scanner.NewMockScanner()

	// Add some sample hosts and services for demonstration
	sampleHosts := []entity.Host{
		{
			IP:       net.ParseIP("192.168.1.10"),
			Hostname: "web-server.local",
			OS:       "Linux",
			Alive:    true,
			Tags:     map[string]string{"role": "web"},
		},
		{
			IP:       net.ParseIP("192.168.1.20"),
			Hostname: "db-server.local",
			OS:       "Linux",
			Alive:    true,
			Tags:     map[string]string{"role": "database"},
		},
	}

	sampleServices := []entity.Service{
		{
			Host:        &sampleHosts[0],
			Port:        80,
			Protocol:    "tcp",
			State:       "open",
			ServiceName: "http",
			Banner:      "Apache/2.4.41",
			Tags:        map[string]string{"protocol": "http"},
		},
		{
			Host:        &sampleHosts[0],
			Port:        443,
			Protocol:    "tcp",
			State:       "open",
			ServiceName: "https",
			Banner:      "Apache/2.4.41 (TLS)",
			Tags:        map[string]string{"protocol": "https", "tls": "true"},
		},
		{
			Host:        &sampleHosts[1],
			Port:        3306,
			Protocol:    "tcp",
			State:       "open",
			ServiceName: "mysql",
			Banner:      "MySQL 8.0.25",
			Tags:        map[string]string{"protocol": "mysql"},
		},
	}

	mockScanner.WithHosts(sampleHosts).WithServices(sampleServices)

	// Create classifier
	classifierImpl := classifier.NewRuleBasedClassifier()

	// Create planner
	plannerImpl := planner.NewSchedulingPlanner(planner.DefaultPlannerConfig())

	// Create assessor (using mock for now since extensions aren't implemented)
	assessorImpl := assessor.NewAssessmentExecutor(assessor.DefaultAssessorConfig())

	// Create reporter
	reporterImpl := reporter.NewAssessmentReporter(reporter.DefaultReporterConfig())

	// Create provisioner (mock since Docker runtime is unimplemented)
	var provisioner usecase.Provisioner
	if campaign.GetMode() != "live" {
		provisioner = usecase.NewMockProvisioner()
	}

	// Create orchestrator
	orch := usecase.NewAssessmentOrchestrator(
		mockScanner,
		classifierImpl,
		plannerImpl,
		assessorImpl,
		reporterImpl,
		provisioner,
		usecase.DefaultOrchestratorConfig(),
	)

	return orch, nil
}

func getManifestPaths(steps []config.Step) []string {
	var paths []string
	seen := make(map[string]bool)

	for _, step := range steps {
		if !seen[step.Implementation.Manifest] {
			paths = append(paths, step.Implementation.Manifest)
			seen[step.Implementation.Manifest] = true
		}
	}

	return paths
}

func listCampaignsInDir(dir string) error {
	loader := config.NewLoader(dir)
	campaigns, err := loader.FindCampaigns(dir)
	if err != nil {
		return err
	}

	if len(campaigns) == 0 {
		fmt.Printf("No campaign files found in %s\n", dir)
		return nil
	}

	fmt.Printf("Found %d campaign(s) in %s:\n", len(campaigns), dir)
	for _, campaignPath := range campaigns {
		// Try to load basic info
		campaign, err := loader.LoadCampaign(campaignPath)
		if err != nil {
			fmt.Printf("  %-30s [ERROR: %v]\n", filepath.Base(campaignPath), err)
			continue
		}

		fmt.Printf("  %-30s %s (mode: %s, steps: %d)\n",
			filepath.Base(campaignPath),
			campaign.Name,
			campaign.GetMode(),
			len(campaign.Steps))
	}

	return nil
}

func setupLogging(verbose bool) {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if verbose {
		log.SetOutput(os.Stdout)
	} else {
		// In non-verbose mode, we could filter out debug messages
		log.SetOutput(os.Stdout)
	}
}

func printSummary(result *usecase.OrchestrationResult) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Printf("CAMPAIGN EXECUTION SUMMARY\n")
	fmt.Println(strings.Repeat("=", 60))

	fmt.Printf("Campaign: %s\n", result.CampaignName)
	fmt.Printf("Run ID: %s\n", result.RunID)
	fmt.Printf("Mode: %s\n", result.Mode)
	fmt.Printf("Status: %s\n", result.Status)
	fmt.Printf("Duration: %s\n", result.Duration)

	if result.ScanResult != nil {
		fmt.Printf("\nSCAN RESULTS:\n")
		fmt.Printf("  Hosts discovered: %d\n", len(result.ScanResult.Hosts))
		fmt.Printf("  Services discovered: %d\n", len(result.ScanResult.Services))
		fmt.Printf("  Targets identified: %d\n", len(result.ScanResult.Targets))
	}

	if result.Classification != nil {
		fmt.Printf("\nCLASSIFICATION RESULTS:\n")
		fmt.Printf("  Target-step mappings: %d\n", len(result.Classification.Mappings))
		fmt.Printf("  Unmatched targets: %d\n", len(result.Classification.UnmatchedTargets))
		fmt.Printf("  Unused steps: %d\n", len(result.Classification.UnusedSteps))
	}

	if result.Plan != nil {
		fmt.Printf("\nPLANNING RESULTS:\n")
		fmt.Printf("  Jobs planned: %d\n", len(result.Plan.Jobs))
		fmt.Printf("  Job groups: %d\n", len(result.Plan.JobGroups))
		fmt.Printf("  Estimated runtime: %s\n", result.Plan.EstimatedRuntime)
	}

	if len(result.AssessmentResults) > 0 {
		fmt.Printf("\nASSESSMENT RESULTS:\n")
		completed := 0
		failed := 0
		for _, jobResult := range result.AssessmentResults {
			switch jobResult.Status {
			case entity.JobStatusCompleted:
				completed++
			case entity.JobStatusFailed:
				failed++
			}
		}
		fmt.Printf("  Jobs executed: %d\n", len(result.AssessmentResults))
		fmt.Printf("  Jobs completed: %d\n", completed)
		fmt.Printf("  Jobs failed: %d\n", failed)
	}

	if result.Report != nil {
		fmt.Printf("\nREPORT SUMMARY:\n")
		fmt.Printf("  Total findings: %d\n", result.Report.Summary.TotalFindings)
		fmt.Printf("  Critical: %d, High: %d, Medium: %d, Low: %d, Info: %d\n",
			result.Report.Summary.CriticalCount,
			result.Report.Summary.HighCount,
			result.Report.Summary.MediumCount,
			result.Report.Summary.LowCount,
			result.Report.Summary.InfoCount)
	}

	if len(result.Errors) > 0 {
		fmt.Printf("\nERRORS:\n")
		for i, err := range result.Errors {
			if i < 5 { // Show first 5 errors
				fmt.Printf("  - %s\n", err)
			} else if i == 5 {
				fmt.Printf("  - ... and %d more errors\n", len(result.Errors)-5)
				break
			}
		}
	}

	fmt.Println(strings.Repeat("=", 60))
}

func saveResults(result *usecase.OrchestrationResult, campaign *config.Campaign) error {
	outputDir := filepath.Join(campaign.Runtime.OutDir, result.RunID)

	// Create subdirectories
	dirs := []string{
		filepath.Join(outputDir, "logs"),
		filepath.Join(outputDir, "scan"),
		filepath.Join(outputDir, "jobs"),
		filepath.Join(outputDir, "report"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// TODO: Save detailed results to files
	// - Scan results to scan/
	// - Job results to jobs/
	// - Final report to report/
	// - Logs to logs/

	// For now, just create placeholder files
	placeholderFiles := map[string]string{
		filepath.Join(outputDir, "scan", "hosts.json"):       "[]",
		filepath.Join(outputDir, "scan", "services.json"):    "[]",
		filepath.Join(outputDir, "report", "findings.json"):  "[]",
		filepath.Join(outputDir, "logs", "orchestrator.log"): fmt.Sprintf("Campaign %s executed at %s\n", result.CampaignName, result.StartTime),
	}

	for filePath, content := range placeholderFiles {
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", filePath, err)
		}
	}

	// Write a summary file
	summaryPath := filepath.Join(outputDir, "summary.txt")
	summaryContent := fmt.Sprintf(`ORCA Assessment Summary
======================

Campaign: %s
Run ID: %s
Mode: %s
Status: %s
Start Time: %s
Duration: %s

Scan Results:
- Hosts: %d
- Services: %d
- Targets: %d

Assessment:
- Jobs: %d
- Status: %s

Generated by ORCA v%s
`,
		result.CampaignName,
		result.RunID,
		result.Mode,
		result.Status,
		result.StartTime.Format("2006-01-02 15:04:05"),
		result.Duration,
		func() int {
			if result.ScanResult != nil {
				return len(result.ScanResult.Hosts)
			}
			return 0
		}(),
		func() int {
			if result.ScanResult != nil {
				return len(result.ScanResult.Services)
			}
			return 0
		}(),
		func() int {
			if result.ScanResult != nil {
				return len(result.ScanResult.Targets)
			}
			return 0
		}(),
		len(result.AssessmentResults),
		result.Status,
		version)

	return os.WriteFile(summaryPath, []byte(summaryContent), 0644)
}
