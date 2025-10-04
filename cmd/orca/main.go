package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"bytemomo/orca/internal/adapter/abiplugin"
	"bytemomo/orca/internal/adapter/grpcplugin"
	"bytemomo/orca/internal/adapter/jsonreport"
	"bytemomo/orca/internal/adapter/yamlconfig"
	"bytemomo/orca/internal/domain"
	"bytemomo/orca/internal/usecase"

	nmap "github.com/Ullaakut/nmap/v3"
)

func main() {
	var (
		campaignPath = flag.String("campaign", "", "Path to campaign YAML (required)")
		cidrsArg     = flag.String("cidrs", "", "Comma-separated CIDRs to scan (required)")
		outDir       = flag.String("out", "./results", "Output directory")
		timeoutSec   = flag.Int("timeout", 20, "Per-plugin timeout seconds")
		targetsPar   = flag.Int("targets-par", 16, "Parallel targets for plugin execution")

		// Scanner knobs (example; if your scanner is elsewhere, keep this minimal)
		udp      = flag.Bool("udp", false, "Enable UDP scanning")
		minRate  = flag.Int("min-rate", 0, "nmap --min-rate")
		useT4    = flag.Bool("T4", true, "Use nmap -T4")
		useSV    = flag.Bool("sV", true, "Enable -sV service detection")
		verLight = flag.Bool("version-light", true, "Use --version-light")
		// preferSYN = flag.Bool("syn", false, "Prefer SYN scan (falls back to connect if unavailable)")
		// skipPn    = flag.Bool("Pn", false, "Skip host discovery (-Pn)")
		// verbosity = flag.Int("v", 0, "nmap verbosity (0..2)")
	)
	flag.Parse()

	if *campaignPath == "" || *cidrsArg == "" {
		fmt.Fprintln(os.Stderr, "ERROR: --campaign and --cidrs are required")
		flag.Usage()
		os.Exit(2)
	}

	camp, err := yamlconfig.LoadCampaign(*campaignPath)
	must(err)

	cidrs := splitCSV(*cidrsArg)
	if len(cidrs) == 0 {
		must(fmt.Errorf("no CIDRs parsed"))
	}

	// Adapters
	executors := []domain.PluginExecutor{
		grpcplugin.New(), // transport: "grpc"
		abiplugin.New(),  // transport: "abi"
	}
	reporter := jsonreport.New(*outDir)

	// Scanner (Nmap-based; returns []ClassifiedTarget)
	scanner := usecase.ScannerUC{
		EnableUDP:      *udp,
		ServiceDetect:  *useSV,
		VersionLight:   *verLight,
		MinRate:        *minRate,
		Timing:         ternary(*useT4, nmap.TimingAggressive, nmap.TimingNormal),
		CommandTimeout: 30 * time.Minute,
		// PreferSYN:         *preferSYN,
		// PreflightSYNCheck: true,
		// SkipHostDisc:      *skipPn,
		// Verbosity:         *verbosity,
	}

	// Runner
	runner := usecase.RunnerUC{
		Executors: executors,
		Store:     reporter,
		Config: domain.RunnerConfig{
			GlobalTimeout: time.Duration(*timeoutSec) * time.Second,
			MaxTargets:    *targetsPar,
		},
	}
	report := usecase.ReporterUC{Writer: reporter}

	ctx := context.Background()
	classified, err := scanner.Execute(ctx, cidrs) // scanner returns []ClassifiedTarget
	must(err)

	all, err := runner.Execute(ctx, *camp, classified)
	must(err)

	path, err := report.Execute(ctx, all)
	must(err)

	fmt.Println("Report written to:", path)
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

func ternary[T any](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}
