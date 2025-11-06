package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"bytemomo/kraken/internal/adapter/jsonreport"
	"bytemomo/kraken/internal/adapter/logger"
	"bytemomo/kraken/internal/adapter/yamlconfig"
	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/runner"
	"bytemomo/kraken/internal/runner/adapter"
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

	logger.SetLoggerToStructured(logrus.InfoLevel, fmt.Sprintf("%s/kraken.log", *outDir))

	if err := run(*campaignPath, *cidrsArg, *outDir); err != nil {
		logrus.WithError(err).Fatal("Failed to run campaign")
	}
}

func run(campaignPath, cidrsArg, outDir string) error {
	log := logrus.WithFields(logrus.Fields{
		"campaign_path": campaignPath,
	})
	log.Info("Starting campaign")

	camp, err := yamlconfig.LoadCampaign(campaignPath)
	if err != nil {
		return fmt.Errorf("could not load campaign: %w", err)
	}
	log = log.WithField("campaign_id", camp.ID)

	cidrs := splitCSV(cidrsArg)
	if len(cidrs) == 0 {
		return errors.New("no CIDRs specified")
	}

	resultDir := fmt.Sprintf("%s/%s/%d", outDir, camp.ID, time.Now().Unix())
	jsonReporter := jsonreport.New(resultDir)
	camp.Runner.ResultDirectory = resultDir

	classifiedTargets, err := setupAndRunScanner(log, camp, cidrs)
	if err != nil {
		return err
	}

	results, err := setupAndRunModuleRunner(log, camp, jsonReporter, classifiedTargets)
	if err != nil {
		return err
	}

	return report(log, jsonReporter, results, camp)
}

func setupAndRunScanner(log *logrus.Entry, camp *domain.Campaign, cidrs []string) ([]domain.ClassifiedTarget, error) {
	log.Info("Starting scanner")
	scannerConfig := camp.Scanner
	if scannerConfig == nil {
		scannerConfig = &domain.ScannerConfig{}
	}

	s := scanner.Scanner{
		Log:    log,
		Config: *scannerConfig,
	}

	scannerCtx := context.Background()
	classified, err := s.Execute(scannerCtx, cidrs)
	if err != nil {
		return nil, fmt.Errorf("failed network scanning: %w", err)
	}

	log.WithField("target_count", len(classified)).Info("Scanner finished")
	return classified, nil
}

func setupAndRunModuleRunner(log *logrus.Entry, camp *domain.Campaign, reporter domain.ResultRepo, classifiedTargets []domain.ClassifiedTarget) ([]domain.RunResult, error) {
	log.Info("Starting module runner")
	executors := []runner.ModuleExecutor{
		adapter.NewABIModuleAdapter(),
		adapter.NewCLIModuleAdapter(),
		adapter.NewGRPCModuleAdapter(),
	}

	r := runner.Runner{
		Log:       log,
		Executors: executors,
		Store:     reporter,
		Config:    camp.Runner,
	}

	runnerCtx := context.Background()
	results, err := r.Execute(runnerCtx, *camp, classifiedTargets)
	if err != nil {
		return nil, fmt.Errorf("failed runner execution: %w", err)
	}

	log.WithField("result_count", len(results)).Info("Module runner finished")
	return results, nil
}

func report(log *logrus.Entry, reportWriter domain.ReportWriter, results []domain.RunResult, camp *domain.Campaign) error {
	log.Info("Starting reporting")
	path, err := reportWriter.Aggregate(results)
	if err != nil {
		return fmt.Errorf("cannot report results: %w", err)
	}

	log.WithField("report_path", path).Info("Report written")

	// Attack trees evaluation
	if camp.AttackTreesDefPath == "" {
		log.Info("Attack tree definition file not specified!")
		return nil
	}

	trees, err := yamlconfig.LoadAttackTrees(camp.AttackTreesDefPath)
	if err != nil {
		return fmt.Errorf("could not load attack trees path: %w", err)
	}

	if len(trees) == 0 {
		log.Info("No attack tree specified!")
		return nil
	}

	for _, result := range results {
		log := log.WithFields(logrus.Fields{
			"target_host": result.Target.Host,
			"target_port": result.Target.Port,
		})
		for _, tree := range trees {
			if tree.Evaluate(result.Findings) {
				log.WithField("attack_tree_name", tree.Name).Warning("Attack tree evaluated as true")
				// fmt.Printf("Code to render attack tree:\n%s", tree.RenderTree())
			}
		}
	}
	return nil
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
