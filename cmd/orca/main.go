package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"bytemomo/orca/internal/adapter/abiplugin"
	"bytemomo/orca/internal/adapter/cliplugin"
	"bytemomo/orca/internal/adapter/grpcplugin"
	"bytemomo/orca/internal/adapter/jsonreport"
	"bytemomo/orca/internal/adapter/yamlconfig"
	"bytemomo/orca/internal/domain"
	"bytemomo/orca/internal/usecase"

	log "github.com/sirupsen/logrus"
)

func main() {
	var (
		campaignPath = flag.String("campaign", "", "Path to campaign YAML (required)")
		cidrsArg     = flag.String("cidrs", "", "Comma-separated CIDRs to scan (required)")
		outDir       = flag.String("out", "./results", "Output directory")
		timeoutSec   = flag.Int("timeout", 20, "Per-plugin timeout seconds")
		targetsPar   = flag.Int("targets-par", 16, "Parallel targets for plugin execution")
	)
	flag.Parse()

	if *campaignPath == "" || *cidrsArg == "" {
		fmt.Fprintln(os.Stderr, "ERROR: --campaign and --cidrs are required")
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

	reporter := jsonreport.New(*outDir)

	// Scanner
	scannerConfig := camp.Scanner
	if scannerConfig == nil {
		scannerConfig = &domain.ScannerConfig{}
	}

	scanner := usecase.ScannerUC{
		EnableUDP:         scannerConfig.EnableUDP,
		ServiceDetect:     scannerConfig.ServiceDetect,
		VersionLight:      scannerConfig.VersionLight,
		VersionAll:        scannerConfig.VersionAll,
		MinRate:           scannerConfig.MinRate,
		Timing:            scannerConfig.Timing,
		CommandTimeout:    scannerConfig.Timeout,
		SkipHostDiscovery: scannerConfig.SkipHostDiscovery,
		OpenOnly:          scannerConfig.OpenOnly,
		Ports:             scannerConfig.Ports,
	}

	ctx := context.Background()
	classified, err := scanner.Execute(ctx, cidrs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}

	// Runner
	executors := []domain.PluginExecutor{
		grpcplugin.New(),
		abiplugin.New(),
		cliplugin.New(),
	}

	runner := usecase.RunnerUC{
		Executors: executors,
		Store:     reporter,
		Config: domain.RunnerConfig{
			GlobalTimeout: time.Duration(*timeoutSec) * time.Second,
			MaxTargets:    *targetsPar,
		},
	}

	all, err := runner.Execute(ctx, *camp, classified)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}

	// Report
	report := usecase.ReporterUC{Writer: reporter}
	path, err := report.Execute(ctx, all)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}

	fmt.Println("Report written to:", path)
	fmt.Println(all)

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
