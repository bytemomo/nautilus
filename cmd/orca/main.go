package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

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
		outDir       = flag.String("out", "./output", "Output directory")
		timeoutSec   = flag.Int("timeout", 20, "Global plugin timeout (seconds)")
		targetsPar   = flag.Int("targets-par", 16, "Parallel targets for plugin execution")
		udp          = flag.Bool("udp", false, "Enable UDP scanning (slower)")
		minRate      = flag.Int("min-rate", 0, "Set nmap --min-rate (packets/sec)")
		tAggressive  = flag.Bool("T4", true, "Use nmap -T4 timing template")
		versionInfo  = flag.Bool("sV", true, "Enable service/version detection (-sV)")
		verLight     = flag.Bool("version-light", true, "Use --version-light with -sV")
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
	exec := grpcplugin.New()
	reporter := jsonreport.New(*outDir)

	// Use-cases
	scanner := usecase.ScannerUC{
		EnableUDP:      *udp,
		ServiceDetect:  *versionInfo,
		VersionLight:   *verLight,
		MinRate:        *minRate,
		Timing:         ternary(*tAggressive, nmap.TimingAggressive, nmap.TimingNormal),
		CommandTimeout: 30 * time.Minute,
	}
	runner := usecase.RunnerUC{
		Exec:  exec,
		Store: reporter,
		Config: domain.RunnerConfig{
			GlobalTimeout: time.Duration(*timeoutSec) * time.Second,
			MaxTargets:    *targetsPar,
		},
	}
	report := usecase.ReporterUC{Writer: reporter}

	// Pipeline
	ctx := context.Background()
	classified, err := scanner.Execute(ctx, cidrs)
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
