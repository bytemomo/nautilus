package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"bytemomo/kraken/internal/adapter/jsonreport"
	"bytemomo/kraken/internal/adapter/yamlconfig"
	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/runner"
	"bytemomo/kraken/internal/scanner"

	"github.com/sirupsen/logrus"
)

func main() {
	var (
		campaignPath = flag.String("campaign", "", "Path to campaign YAML (required)")
		cidrsArg     = flag.String("cidrs", "", "Comma-separated CIDRs to scan (required)")
		outDir       = flag.String("out", "./results", "Output directory")
		help         = flag.Bool("help", false, "Print program usage")
	)
	flag.Parse()

	if *campaignPath == "" || *cidrsArg == "" || *help {
		flag.Usage()
		os.Exit(2)
	}

	camp, err := yamlconfig.LoadCampaign(*campaignPath)
	if err != nil {
		logrus.Fatalf("Cannot load campaign %s\n", err)
	}

	cidrs := splitCSV(*cidrsArg)
	if len(cidrs) == 0 {
		logrus.Fatal("No CIDRs parsed!")
	}

	resultDir := fmt.Sprintf("%s/%s/%d", *outDir, camp.ID, time.Now().Unix())
	jsonReporter := jsonreport.New(resultDir)
	camp.Runner.ResultDirectory = resultDir

	// Scanner
	classifiedTargets := setupAndRunScanner(camp, cidrs)

	// Runner
	results := setupAndRunModuleRunner(camp, jsonReporter, classifiedTargets)

	// Report
	report(jsonReporter, results, camp)
}

func setupAndRunScanner(camp *domain.Campaign, cidrs []string) []domain.ClassifiedTarget {
	scannerConfig := camp.Scanner
	if scannerConfig == nil {
		scannerConfig = &domain.ScannerConfig{}
	}

	scanner := scanner.Scanner{
		Config: *scannerConfig,
	}

	scannerCtx := context.Background()
	classified, err := scanner.Execute(scannerCtx, cidrs)
	if err != nil {
		logrus.Fatalf("Failed network scanning %s\n", err)
		os.Exit(1)
	}

	return classified
}

func setupAndRunModuleRunner(camp *domain.Campaign, reporter domain.ResultRepo, classifiedTargets []domain.ClassifiedTarget) []domain.RunResult {
	executors := []runner.ModuleExecutor{
		runner.NewABIModuleAdapter(),
		runner.NewCLIModuleAdapter(),
		// runner.NewGRPCModuleAdapter(),
	}

	runner := runner.Runner{
		Executors: executors,
		Store:     reporter,
		Config:    camp.Runner,
	}

	runnerCtx := context.Background()
	results, err := runner.Execute(runnerCtx, *camp, classifiedTargets)
	if err != nil {
		logrus.Fatalf("Failed runner execution: %s", err)
	}

	return results
}

func report(reportWriter domain.ReportWriter, results []domain.RunResult, camp *domain.Campaign) {
	path, err := reportWriter.Aggregate(results)
	if err != nil {
		log.Fatalf("Cannot report results: %s\n", err)
	}

	fmt.Println("Report written to:", path)

	// Attack trees evaluation
	if camp.AttackTreesDefPath == "" {
		logrus.Info("Attack tree definition file not specified!")
	}

	trees, err := yamlconfig.LoadAttackTrees(camp.AttackTreesDefPath)
	if err != nil {
		logrus.Fatalf("Could not load attack trees path: %s", err)
	}

	if len(trees) == 0 {
		logrus.Info("No attack tree specified!")
	}

	for _, result := range results {
		for _, tree := range trees {
			if tree.Evaluate(result.Findings) {
				logrus.Infof("For target [%s:%d] attack tree is evaluated as true: %s", result.Target.Host, result.Target.Port, tree.Name)
				tree.PrintTree(fmt.Sprintf("Target: %s:%d", result.Target.Host, result.Target.Port))
				logrus.Infof("%s", tree.RenderTree())
			}
		}
	}
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
