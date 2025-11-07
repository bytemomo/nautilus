package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"bytemomo/siren/internal/config"
	"bytemomo/siren/internal/ebpf"
	"bytemomo/siren/internal/intercept"
	"bytemomo/siren/internal/manipulator"
	"bytemomo/siren/internal/proxy"
	"bytemomo/siren/internal/recorder"

	"github.com/sirupsen/logrus"
)

const version = "0.2.0"

var (
	configFile  = flag.String("config", "", "Path to configuration file (required)")
	showVersion = flag.Bool("version", false, "Show version information")
	logLevel    = flag.String("loglevel", "info", "Log level (debug, info, warn, error, fatal, panic)")
)

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("Siren v%s\n", version)
		fmt.Println("Transparent eBPF-based MITM testing proxy")
		return
	}

	log := logrus.New()
	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		log.Fatalf("Invalid log level: %v", err)
	}
	log.SetLevel(level)

	if *configFile == "" {
		log.Fatal("Configuration file is required. Use: siren -config <file>")
	}

	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	printBanner(cfg)

	app, err := setupApplication(cfg, log)
	if err != nil {
		log.Fatalf("Failed to set up application: %v", err)
	}
	defer app.Cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runAndWait(ctx, cancel, app.runtime, log)
}

// application holds the state of the running application.
type application struct {
	runtime *ebpf.Runtime
	manager *ebpf.Manager
	rec     *recorder.Recorder
}

// Cleanup stops all background components.
func (a *application) Cleanup() {
	if a.rec != nil {
		a.rec.Stop()
	}
	if a.manager != nil {
		a.manager.Stop()
	}
}


func setupApplication(cfg *config.Config, log *logrus.Logger) (*application, error) {
	engine, err := buildEngine(cfg, log)
	if err != nil {
		return nil, fmt.Errorf("failed to build intercept engine: %w", err)
	}

	rec, err := buildRecorder(cfg, log)
	if err != nil {
		return nil, fmt.Errorf("failed to start recorder: %w", err)
	}

	manips, err := buildManipulators(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to configure manipulators: %w", err)
	}

	processor := proxy.NewTrafficProcessor(engine, rec, proxy.NewProxyStats(), log.WithField("component", "processor"), manips)

	targets, err := parseTargets(cfg.Ebpf)
	if err != nil {
		return nil, fmt.Errorf("failed to parse targets: %w", err)
	}

	manager, err := ebpf.NewManager(ebpf.ManagerConfig{Interface: cfg.Ebpf.Interface})
	if err != nil {
		return nil, fmt.Errorf("failed to create eBPF manager: %w", err)
	}
	if err := manager.Start(); err != nil {
		manager.Stop()
		return nil, fmt.Errorf("failed to start eBPF manager: %w", err)
	}
	if err := manager.SetTargets(targets); err != nil {
		manager.Stop()
		return nil, fmt.Errorf("failed to configure targets: %w", err)
	}

	dropDuration, err := cfg.Ebpf.GetDropDuration()
	if err != nil {
		log.Warnf("Invalid drop_action_duration: %v. Using default.", err)
		dropDuration = 10 * time.Second
	}
	runtime := ebpf.NewRuntime(manager, processor, log.WithField("component", "ebpf-runtime"), ebpf.RuntimeConfig{
		DropDuration: dropDuration,
	})

	return &application{
		runtime: runtime,
		manager: manager,
		rec:     rec,
	}, nil
}

func runAndWait(ctx context.Context, cancel context.CancelFunc, rt *ebpf.Runtime, log *logrus.Logger) {
	runtimeErr := make(chan error, 1)
	go func() {
		runtimeErr <- rt.Run(ctx)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-runtimeErr:
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Fatalf("Runtime error: %v", err)
		}
	case sig := <-sigCh:
		log.Infof("Received %s, shutting down...", sig)
		cancel()
		if err := <-runtimeErr; err != nil && !errors.Is(err, context.Canceled) {
			log.Errorf("Shutdown error: %v", err)
		}
	}
}

func buildEngine(cfg *config.Config, log *logrus.Logger) (*intercept.Engine, error) {
	if len(cfg.Rules) == 0 {
		log.Info("No interception rules loaded.")
		return nil, nil
	}
	ruleSet := &intercept.RuleSet{
		Name:        cfg.Name,
		Description: cfg.Description,
		Rules:       cfg.Rules,
	}
	engine, err := intercept.NewEngine(ruleSet, log)
	if err != nil {
		return nil, err
	}
	log.Infof("Loaded %d interception rules.", len(cfg.Rules))
	return engine, nil
}

func buildRecorder(cfg *config.Config, log *logrus.Logger) (*recorder.Recorder, error) {
	if cfg.Recording == nil || !cfg.Recording.Enabled {
		return nil, nil
	}

	flushInterval, err := cfg.Recording.GetFlushInterval()
	if err != nil {
		log.Warnf("Invalid flush_interval: %v. Using default.", err)
		flushInterval = 5 * time.Second
	}
	maxFileSize, err := cfg.Recording.GetMaxFileSize()
	if err != nil {
		log.Warnf("Invalid max_file_size: %v. Using default.", err)
		maxFileSize = 100 * 1024 * 1024
	}

	rec, err := recorder.NewRecorder(&recorder.RecorderConfig{
		OutputPath:     cfg.Recording.Output,
		Format:         cfg.Recording.Format,
		BufferSize:     1000, // Consider making this configurable
		FlushInterval:  flushInterval,
		IncludePayload: cfg.Recording.IncludePayload,
		MaxFileSize:    maxFileSize,
	})
	if err != nil {
		return nil, err
	}
	if err := rec.Start(); err != nil {
		return nil, err
	}
	log.Infof("Recording enabled: %s (%s)", cfg.Recording.Output, cfg.Recording.Format)
	return rec, nil
}

func buildManipulators(cfg *config.Config) ([]manipulator.Manipulator, error) {
	if len(cfg.Manipulators) == 0 {
		return nil, nil
	}

	var result []manipulator.Manipulator
	for _, mcfg := range cfg.Manipulators {
		m, err := manipulator.Get(mcfg.Name)
		if err != nil {
			return nil, fmt.Errorf("manipulator %s: %w", mcfg.Name, err)
		}
		if err := m.Configure(mcfg.Params); err != nil {
			return nil, fmt.Errorf("configure %s: %w", mcfg.Name, err)
		}
		result = append(result, m)
	}
	return result, nil
}


func printBanner(cfg *config.Config) {
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                 SIREN - MITM Testing Proxy                    ║")
	fmt.Printf("║                        Version %s                           ║\n", version)
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("Configuration: %s\n", cfg.Name)
	if cfg.Description != "" {
		fmt.Printf("Description:   %s\n", cfg.Description)
	}
	fmt.Printf("Interface:     %s\n", cfg.Ebpf.Interface)
	fmt.Printf("Targets:       %d (empty = all)\n", len(cfg.Ebpf.Targets))
	fmt.Printf("Rules:         %d loaded\n", len(cfg.Rules))

	if cfg.Recording != nil && cfg.Recording.Enabled {
		fmt.Printf("Recording:     %s (%s)\n", cfg.Recording.Output, cfg.Recording.Format)
	}
	fmt.Println()
	fmt.Println("Using eBPF for transparent interception")
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println("───────────────────────────────────────────────────────────────")
	fmt.Println()
}
