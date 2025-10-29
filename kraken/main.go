package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"bytemomo/kraken/internal/adapter/abiplugin"
	"bytemomo/kraken/internal/adapter/cliplugin"
	"bytemomo/kraken/internal/adapter/grpcplugin"
	"bytemomo/kraken/internal/adapter/jsonreport"
	"bytemomo/kraken/internal/adapter/yamlconfig"
	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/usecase"

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
	reporter := jsonreport.New(resultDir)
	camp.Runner.ResultDirectory = resultDir

	// Scanner
	scannerConfig := camp.Scanner
	if scannerConfig == nil {
		scannerConfig = &domain.ScannerConfig{}
	}

	scanner := usecase.ScannerUC{
		Config: *scannerConfig,
	}

	scannerCtx := context.Background()
	classified, err := scanner.Execute(scannerCtx, cidrs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}

	// Runner with module-based executors (supports both V1 and V2)
	executors := []domain.ModuleExecutor{
		abiplugin.NewModuleAdapter(), // ABI adapter supports both V1 and V2
		cliplugin.NewModuleAdapter(), // CLI adapter for V1 modules
		grpcplugin.New(),             // gRPC adapter for V2 modules with conduit config
	}

	runner := usecase.RunnerUC{
		Executors: executors,
		Store:     reporter,
		Config:    camp.Runner,
	}

	runnerCtx := context.Background()
	all, err := runner.Execute(runnerCtx, *camp, classified)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}

	// Report
	report := usecase.ReporterUC{Writer: reporter}
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
