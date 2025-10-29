package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"bytemomo/kraken/internal/adapter/jsonreport"
	"bytemomo/kraken/internal/adapter/yamlconfig"
	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/reporter"
	"bytemomo/kraken/internal/runner"
	"bytemomo/kraken/internal/scanner"

	log "github.com/sirupsen/logrus"
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
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	cidrs := splitCSV(*cidrsArg)
	if len(cidrs) == 0 {
		must(fmt.Errorf("no CIDRs parsed"))
	}

	resultDir := fmt.Sprintf("%s/%s/%d", *outDir, camp.ID, time.Now().Unix())
	jsonReporter := jsonreport.New(resultDir)
	camp.Runner.ResultDirectory = resultDir

	// Scanner
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
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}

	// Runner with module-based executors (supports both V1 and V2)
	executors := []runner.ModuleExecutor{
		runner.NewABIModuleAdapter(),
		runner.NewCLIModuleAdapter(),
		// runner.NewGRPCModuleAdapter(),
	}

	runner := runner.Runner{
		Executors: executors,
		Store:     jsonReporter,
		Config:    camp.Runner,
	}

	runnerCtx := context.Background()
	all, err := runner.Execute(runnerCtx, *camp, classified)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}

	// Report
	report := reporter.Reporter{Writer: jsonReporter}
	path, err := report.Execute(context.Background(), all)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}

	fmt.Println("Report written to:", path)

	// Attack trees
	if camp.AttackTreesDefPath == "" {
		log.Info("Attack tree definition file not specified!")
	}

	trees, err := yamlconfig.LoadAttackTrees(camp.AttackTreesDefPath)
	if err != nil {
		log.Errorf("Could not load attack trees path: %s", err)
		return
	}

	if len(trees) == 0 {
		log.Info("No attack tree specified!")
	}

	for _, result := range all {
		for _, tree := range trees {
			if tree.Evaluate(result.Findings) {
				log.Infof("For target [%s:%d] attack tree is evaluated as true: %s", result.Target.Host, result.Target.Port, tree.Name)
				tree.PrintTree(fmt.Sprintf("Target: %s:%d", result.Target.Host, result.Target.Port))
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

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}
