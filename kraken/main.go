package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"bytemomo/kraken/internal/adapter/attacktreereport"
	"bytemomo/kraken/internal/adapter/jsonreport"
	"bytemomo/kraken/internal/adapter/logger"
	"bytemomo/kraken/internal/adapter/yamlconfig"
	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/modules"
	"bytemomo/kraken/internal/native"
	"bytemomo/kraken/internal/runner"
	"bytemomo/kraken/internal/runner/adapter"
	"bytemomo/kraken/internal/scanner"

	"github.com/sirupsen/logrus"
)

func main() {
	var (
		campaignPath = flag.String("campaign", "", "Path to campaign YAML (required)")
		cidrsArg     = flag.String("cidrs", "", "Comma-separated CIDRs to scan (required)")
		outDir       = flag.String("out", "./kraken-results", "Output directory")
		module_list  = flag.Bool("native-modules", false, "Print the native modules and their capabilities")
		help         = flag.Bool("help", false, "Print program usage")
	)
	flag.Parse()

	if (*campaignPath == "" || *help) && !*module_list {
		flag.Usage()
		os.Exit(2)
	}

	logger.SetLoggerToStructured(logrus.InfoLevel, fmt.Sprintf("%s/kraken.log", *outDir))

	modules.Init()
	if *module_list {
		for _, m := range native.List() {
			fmt.Printf("   - %s --- conduit kind: %d, transport stack: %s\n", m.ID, m.Descriptor.Kind, m.Descriptor.Stack)
			if m.Descriptor.Description != "" {
				fmt.Printf("        %s", m.Descriptor.Description)
			}
		}
		return
	}

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
	campType := camp.EffectiveType()

	if campType == domain.CampaignNetwork && len(splitCSV(cidrsArg)) == 0 {
		return errors.New("no CIDRs specified")
	}

	resultDir := fmt.Sprintf("%s/%s/%d", outDir, camp.ID, time.Now().Unix())
	jsonReporter := jsonreport.New(resultDir)
	attackTreeReporter := attacktreereport.New(resultDir)

	if campType == domain.CampaignFuzz {
		results, err := setupAndRunFuzzingRunner(log, camp, jsonReporter, resultDir)
		if err != nil {
			return err
		}
		return report(log, jsonReporter, attackTreeReporter, results, camp)
	}

	cidrs := splitCSV(cidrsArg)
	classifiedTargets, err := setupAndRunScanner(log, camp, cidrs)
	if err != nil {
		return err
	}

	results, err := setupAndRunModuleRunner(log, camp, jsonReporter, classifiedTargets, resultDir)
	if err != nil {
		return err
	}

	return report(log, jsonReporter, attackTreeReporter, results, camp)
}

func setupAndRunScanner(log *logrus.Entry, camp *domain.Campaign, cidrs []string) ([]domain.ClassifiedTarget, error) {
	log.Info("Starting scanners")

	configs := camp.EffectiveScanners()
	if len(configs) == 0 {
		// Default to nmap scanner with empty config
		configs = []*domain.ScannerConfig{{Type: "nmap"}}
	}

	var scanners []scanner.Scanner
	for i, cfg := range configs {
		s, err := scanner.NewScanner(log.WithField("scanner_idx", i), cfg, cidrs)
		if err != nil {
			return nil, fmt.Errorf("create scanner %d: %w", i, err)
		}
		scanners = append(scanners, s)
	}

	log.WithField("scanner_count", len(scanners)).Info("Executing scanners")
	scannerCtx := context.Background()
	classified, err := scanner.ExecuteAll(scannerCtx, scanners)
	if err != nil {
		return nil, fmt.Errorf("failed scanning: %w", err)
	}

	log.WithField("target_count", len(classified)).Info("Scanners finished")
	return classified, nil
}

func setupAndRunModuleRunner(log *logrus.Entry, camp *domain.Campaign, reporter domain.ResultRepo, classifiedTargets []domain.ClassifiedTarget, resultDir string) ([]domain.RunResult, error) {
	log.Info("Starting module runner")
	executors := newModuleExecutors()

	r := runner.Runner{
		Log:             log,
		Executors:       executors,
		Store:           reporter,
		ResultDirectory: resultDir,
	}

	runnerCtx := context.Background()
	results, err := r.Execute(runnerCtx, *camp, classifiedTargets)
	if err != nil {
		return nil, fmt.Errorf("failed runner execution: %w", err)
	}

	log.WithField("result_count", len(results)).Info("Module runner finished")
	return results, nil
}

func setupAndRunFuzzingRunner(log *logrus.Entry, camp *domain.Campaign, reporter domain.ResultRepo, resultDir string) ([]domain.RunResult, error) {
	log.Info("Starting fuzzing runner")
	executors := newModuleExecutors()

	r := runner.Runner{
		Log:             log,
		Executors:       executors,
		Store:           reporter,
		ResultDirectory: resultDir,
	}

	runnerCtx := context.Background()
	classifiedTargets := []domain.ClassifiedTarget{{
		Target: domain.HostPort{Host: camp.ID},
	}}

	results, err := r.Execute(runnerCtx, *camp, classifiedTargets)
	if err != nil {
		return nil, fmt.Errorf("failed fuzzing execution: %w", err)
	}

	log.WithField("result_count", len(results)).Info("Fuzzing runner finished")
	return results, nil
}

func newModuleExecutors() []runner.ModuleExecutor {
	return []runner.ModuleExecutor{
		adapter.NewNativeBuiltinAdapter(),
		adapter.NewABIModuleAdapter(),
		adapter.NewCLIModuleAdapter(),
		adapter.NewDockerModuleAdapter(),
		adapter.NewGRPCModuleAdapter(),
	}
}

func report(log *logrus.Entry, reportWriter domain.ReportWriter, attackTreeWriter *attacktreereport.Writer, results []domain.RunResult, camp *domain.Campaign) error {
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

	var attackTreeResults []domain.AttackTreeResult
	for _, result := range results {
		log := log.WithField("target", result.Target.String())
		for _, tree := range trees {
			// Clone the tree so each target gets its own evaluation state
			treeClone := tree.Clone()
			treeClone.Evaluate(result.Findings)
			attackTreeResults = append(attackTreeResults, domain.AttackTreeResult{
				Target: result.Target,
				Tree:   treeClone,
			})
			if treeClone.Success {
				log.WithField("attack_tree_name", treeClone.Name).Warning("Attack tree evaluated as true")
			}
		}
	}

	// Save attack trees to result directory
	if err := attackTreeWriter.Save(attackTreeResults); err != nil {
		return fmt.Errorf("cannot save attack trees: %w", err)
	}
	log.Info("Attack trees saved to result directory")

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
