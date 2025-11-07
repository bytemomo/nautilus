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

	"bytemomo/siren/config"
	"bytemomo/siren/ebpf"
	"bytemomo/siren/intercept"
	"bytemomo/siren/pkg/logger"
	"bytemomo/siren/pkg/manipulator"
	"bytemomo/siren/proxy"
	"bytemomo/siren/recorder"

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

	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		logrus.Fatalf("Invalid log level: %v", err)
	}
	log := logger.New(level)

	if *configFile == "" {
		log.Fatal("Configuration file is required. Use: siren -config <file>")
	}

	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	printBanner(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine, err := buildEngine(cfg, log)
	if err != nil {
		log.Fatalf("Failed to build intercept engine: %v", err)
	}

	rec, err := buildRecorder(cfg, log)
	if err != nil {
		log.Fatalf("Failed to start recorder: %v", err)
	}
	if rec != nil {
		defer rec.Stop()
	}

	manips, err := buildManipulators(cfg)
	if err != nil {
		log.Fatalf("Failed to configure manipulators: %v", err)
	}

	stats := proxy.NewProxyStats()
	processor := proxy.NewTrafficProcessor(engine, rec, stats, log.WithField("component", "processor"), manips)

	targets, err := parseTargets(cfg.Ebpf)
	if err != nil {
		log.Fatalf("Failed to parse targets: %v", err)
	}

	mgr, err := ebpf.NewManager(ebpf.ManagerConfig{
		Interface: cfg.Ebpf.Interface,
	})
	if err != nil {
		log.Fatalf("Failed to create eBPF manager: %v", err)
	}
	if err := mgr.Start(); err != nil {
		log.Fatalf("Failed to start eBPF manager: %v", err)
	}
	defer mgr.Stop()

	if err := mgr.SetTargets(targets); err != nil {
		log.Fatalf("Failed to configure targets: %v", err)
	}

	rt := ebpf.NewRuntime(mgr, processor, log.WithField("component", "ebpf-runtime"), ebpf.RuntimeConfig{
		DropDuration: cfg.Ebpf.GetDropDuration(),
	})

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
			log.Fatalf("Runtime error: %v", err)
		}
	}
}

func buildEngine(cfg *config.Config, log *logrus.Logger) (*intercept.Engine, error) {
	if len(cfg.Rules) == 0 {
		return nil, nil
	}

	ruleSet := &intercept.RuleSet{
		Name:        cfg.Name,
		Description: cfg.Description,
		Rules:       cfg.Rules,
	}

	engine, err := intercept.NewEngine(ruleSet, &intercept.DefaultLogger{})
	if err != nil {
		return nil, err
	}

	log.Infof("Loaded %d interception rules", len(cfg.Rules))
	return engine, nil
}

func buildRecorder(cfg *config.Config, log *logrus.Logger) (*recorder.Recorder, error) {
	if cfg.Recording == nil || !cfg.Recording.Enabled {
		return nil, nil
	}

	rec, err := recorder.NewRecorder(&recorder.RecorderConfig{
		OutputPath:     cfg.Recording.Output,
		Format:         cfg.Recording.Format,
		BufferSize:     1000,
		FlushInterval:  cfg.Recording.GetFlushInterval(),
		IncludePayload: cfg.Recording.IncludePayload,
		MaxFileSize:    cfg.Recording.GetMaxFileSize(),
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

func parseTargets(cfg *config.EbpfConfig) ([]ebpf.Target, error) {
	if cfg == nil || len(cfg.Targets) == 0 {
		return nil, nil
	}

	var targets []ebpf.Target
	for i, raw := range cfg.Targets {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		tgt, err := parseTargetEntry(raw)
		if err != nil {
			return nil, fmt.Errorf("target %d: %w", i, err)
		}
		if tgt.Kind == ebpf.TargetKindAny {
			continue
		}
		targets = append(targets, tgt)
	}
	return targets, nil
}

func parseTargetEntry(raw string) (ebpf.Target, error) {
	lower := strings.ToLower(raw)
	switch {
	case strings.HasPrefix(lower, "mac:") || strings.HasPrefix(lower, "mac="):
		val := raw[strings.IndexAny(raw, ":=")+1:]
		return parseMacTarget(strings.TrimSpace(val))
	case strings.HasPrefix(lower, "ethercat:") || strings.HasPrefix(lower, "ethercat=") ||
		strings.HasPrefix(lower, "ec:") || strings.HasPrefix(lower, "ec="):
		val := raw[strings.IndexAny(raw, ":=")+1:]
		return parseEthercatTarget(strings.TrimSpace(val))
	case strings.HasPrefix(lower, "ip_port:") || strings.HasPrefix(lower, "ip_port="):
		val := raw[strings.IndexAny(raw, ":=")+1:]
		return parseIPPortTarget(strings.TrimSpace(val))
	case strings.HasPrefix(lower, "ip:") || strings.HasPrefix(lower, "ip="):
		val := raw[strings.IndexAny(raw, ":=")+1:]
		return parseIPTarget(strings.TrimSpace(val))
	default:
		if looksLikeMAC(raw) {
			return parseMacTarget(raw)
		}
		if strings.Count(raw, ":") == 1 && strings.IndexByte(raw, '[') == -1 {
			if tgt, err := parseIPPortTarget(raw); err == nil {
				return tgt, nil
			}
		}
		return parseIPTarget(raw)
	}
}

func parseIPTarget(val string) (ebpf.Target, error) {
	ip := net.ParseIP(strings.TrimSpace(val))
	if ip == nil {
		return ebpf.Target{}, fmt.Errorf("invalid IP %q", val)
	}
	v4 := ip.To4()
	if v4 == nil {
		return ebpf.Target{}, fmt.Errorf("only IPv4 targets are supported (%s)", val)
	}
	return ebpf.Target{Kind: ebpf.TargetKindIP, IP: append(net.IP(nil), v4...)}, nil
}

func parseIPPortTarget(val string) (ebpf.Target, error) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(val))
	if err != nil {
		return ebpf.Target{}, fmt.Errorf("invalid ip:port target %q", val)
	}
	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return ebpf.Target{}, fmt.Errorf("invalid port in %q: %w", val, err)
	}
	ipTarget, err := parseIPTarget(host)
	if err != nil {
		return ebpf.Target{}, err
	}
	ipTarget.Kind = ebpf.TargetKindIPPort
	ipTarget.Port = uint16(port64)
	return ipTarget, nil
}

func parseMacTarget(val string) (ebpf.Target, error) {
	mac, err := net.ParseMAC(strings.TrimSpace(val))
	if err != nil {
		return ebpf.Target{}, fmt.Errorf("invalid MAC %q", val)
	}
	if len(mac) != 6 {
		return ebpf.Target{}, fmt.Errorf("MAC %q must be 6 bytes", val)
	}
	var arr [6]byte
	copy(arr[:], mac[:6])
	return ebpf.Target{Kind: ebpf.TargetKindMAC, MAC: arr}, nil
}

func parseEthercatTarget(val string) (ebpf.Target, error) {
	id, err := strconv.ParseUint(strings.TrimSpace(val), 0, 16)
	if err != nil {
		return ebpf.Target{}, fmt.Errorf("invalid ethercat slave id %q: %w", val, err)
	}
	return ebpf.Target{Kind: ebpf.TargetKindEtherCAT, EtherCAT: uint16(id)}, nil
}

func looksLikeMAC(s string) bool {
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return false
	}
	for _, part := range parts {
		if len(part) != 2 {
			return false
		}
		if _, err := strconv.ParseUint(part, 16, 8); err != nil {
			return false
		}
	}
	return true
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
