package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"bytemomo/siren/config"
	"bytemomo/siren/intercept"
	"bytemomo/siren/pkg/logger"
	"bytemomo/siren/pkg/manipulator"
	"bytemomo/siren/pkg/sirenerr"
	"bytemomo/siren/proxy"
	"bytemomo/siren/recorder"
	"bytemomo/siren/spoof"
	"bytemomo/trident/conduit/transport"
	tlscond "bytemomo/trident/conduit/transport/tls"

	"github.com/pion/dtls/v3"
	"github.com/sirupsen/logrus"
)

const version = "0.1.0"

var (
	configFile  = flag.String("config", "", "Path to configuration file (required)")
	showVersion = flag.Bool("version", false, "Show version information")
	logLevel    = flag.String("loglevel", "info", "Log level (debug, info, warn, error, fatal, panic)")
)

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("Siren v%s\n", version)
		fmt.Println("Man-in-the-Middle Testing Proxy using Trident")
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

	log.Infof("Loaded configuration from %s", *configFile)
	printBanner(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	if cfg.Spoof != nil {
		if cfg.Spoof.ARP != nil && cfg.Spoof.ARP.Enabled {
			log.Info("[Spoof] Starting ARP spoofing...")
			_, err := startARPSpoof(ctx, cfg.Spoof.ARP, log)
			if err != nil {
				log.Fatalf("Failed to start ARP spoofing: %v", err)
			}
		}

		if cfg.Spoof.DNS != nil && cfg.Spoof.DNS.Enabled {
			log.Info("[Spoof] Starting DNS spoofing...")
			_, err := startDNSSpoof(ctx, cfg.Spoof.DNS, log)
			if err != nil {
				log.Fatalf("Failed to start DNS spoofing: %v", err)
			}
		}
	}

	go func() {
		if err := runProxy(ctx, cfg, log); err != nil {
			log.Fatalf("Proxy error: %v", err)
		}
		if err := ebpfManager.Start(); err != nil {
			log.Fatalf("Failed to start eBPF manager: %v", err)
		}
		defer ebpfManager.Stop()

		go func() {
			if err := ebpfManager.Read(ctx, func(data []byte) {
				packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
				if err := processPacket(ctx, packet, cfg.Manipulators, cfg.Ebpf.Interface); err != nil {
					log.Errorf("Failed to process packet: %v", err)
				}
			}); err != nil {
				log.Errorf("Failed to read from eBPF ring buffer: %v", err)
			}
		}()
	} else {
		// TODO: Implement non-eBPF mode
	}

	<-sigCh
	log.Info("\nShutting down gracefully...")
	cancel()

	time.Sleep(2 * time.Second)
}

func startARPSpoof(ctx context.Context, cfg *config.ARPSpoofConfig, log *logrus.Logger) (*spoof.ARPSpoofer, error) {
	op := "main.startARPSpoof"
	targetIP := net.ParseIP(cfg.Target)
	if targetIP == nil {
		return nil, sirenerr.E(op, fmt.Sprintf("invalid target IP: %s", cfg.Target), 0, nil)
	}

	gatewayIP := net.ParseIP(cfg.Gateway)
	if gatewayIP == nil {
		return nil, sirenerr.E(op, fmt.Sprintf("invalid gateway IP: %s", cfg.Gateway), 0, nil)
	}

	arpConfig := &spoof.ARPConfig{
		Interface:      cfg.Interface,
		TargetIP:       targetIP,
		GatewayIP:      gatewayIP,
		Bidirectional:  true,
		EnableLogging:  true,
		UpdateInterval: 2 * time.Second,
	}

	spoofer, err := spoof.NewARPSpoofer(arpConfig)
	if err != nil {
		return nil, sirenerr.E(op, "failed to create ARP spoofer", 0, err)
	}

	if err := spoofer.Start(ctx); err != nil {
		return nil, sirenerr.E(op, "failed to start ARP spoofer", 0, err)
	}

	log.Infof("[ARP Spoof] Active: %s <-> %s via %s", cfg.Target, cfg.Gateway, cfg.Interface)
	return spoofer, nil
}

func startDNSSpoof(ctx context.Context, cfg *config.DNSSpoofConfig, log *logrus.Logger) (*spoof.DNSSpoofer, error) {
	op := "main.startDNSSpoof"
	dnsConfig := &spoof.DNSConfig{
		ListenAddr:    cfg.Listen,
		UpstreamDNS:   cfg.Upstream,
		Overrides:     cfg.Overrides,
		TTL:           60,
		EnableLogging: true,
		Timeout:       5 * time.Second,
	}

	spoofer, err := spoof.NewDNSSpoofer(dnsConfig)
	if err != nil {
		return nil, sirenerr.E(op, "failed to create DNS spoofer", 0, err)
	}

	if err := spoofer.Start(ctx); err != nil {
		return nil, sirenerr.E(op, "failed to start DNS spoofer", 0, err)
	}

	log.Infof("[DNS Spoof] Active on %s, %d overrides configured", cfg.Listen, len(cfg.Overrides))
	return spoofer, nil
}

func runProxy(ctx context.Context, cfg *config.Config, log *logrus.Logger) error {
	op := "main.runProxy"
	var engine *intercept.Engine
	var err error

	if len(cfg.Rules) > 0 {
		ruleSet := &intercept.RuleSet{
			Name:        cfg.Name,
			Description: cfg.Description,
			Rules:       cfg.Rules,
		}

		engine, err = intercept.NewEngine(ruleSet, &intercept.DefaultLogger{})
		if err != nil {
			return sirenerr.E(op, "failed to create interception engine", 0, err)
		}
		log.Infof("Loaded %d interception rules", len(cfg.Rules))
	}

	var rec *recorder.Recorder
	if cfg.Recording != nil && cfg.Recording.Enabled {
		recConfig := &recorder.RecorderConfig{
			OutputPath:     cfg.Recording.Output,
			Format:         cfg.Recording.Format,
			BufferSize:     1000,
			FlushInterval:  cfg.Recording.GetFlushInterval(),
			IncludePayload: cfg.Recording.IncludePayload,
			MaxFileSize:    cfg.Recording.GetMaxFileSize(),
			Compress:       false,
		}

		rec, err = recorder.NewRecorder(recConfig)
		if err != nil {
			return sirenerr.E(op, "failed to create recorder", 0, err)
		}

		if err := rec.Start(); err != nil {
			return sirenerr.E(op, "failed to start recorder", 0, err)
		}
		defer rec.Stop()

		log.Infof("Recording enabled: %s (format: %s)", cfg.Recording.Output, cfg.Recording.Format)
	}

	var manipulators []manipulator.Manipulator
	if len(cfg.Manipulators) > 0 {
		for _, mcfg := range cfg.Manipulators {
			m, err := manipulator.Get(mcfg.Name)
			if err != nil {
				return sirenerr.E(op, fmt.Sprintf("failed to get manipulator: %s", mcfg.Name), 0, err)
			}
			if err := m.Configure(mcfg.Params); err != nil {
				return sirenerr.E(op, fmt.Sprintf("failed to configure manipulator: %s", mcfg.Name), 0, err)
			}
			manipulators = append(manipulators, m)
		}
		log.Infof("Loaded %d manipulators", len(manipulators))
	}

	proxyLogger := log.WithField("component", "proxy")

	switch cfg.Proxy.Protocol {
	case "tcp":
		return runTCPProxy(ctx, cfg, engine, rec, proxyLogger, manipulators)
	case "tls":
		return runTLSProxy(ctx, cfg, engine, rec, proxyLogger, manipulators)
	case "udp":
		return runUDPProxy(ctx, cfg, engine, rec, proxyLogger, manipulators)
	case "dtls":
		return runDTLSProxy(ctx, cfg, engine, rec, proxyLogger, manipulators)
	default:
		return sirenerr.E(op, fmt.Sprintf("unsupported protocol: %s", cfg.Proxy.Protocol), 0, nil)
	}
}

func runTCPProxy(ctx context.Context, cfg *config.Config, engine *intercept.Engine, rec *recorder.Recorder, log *logrus.Entry, manipulators []manipulator.Manipulator) error {
	op := "main.runTCPProxy"
	listener, err := net.Listen("tcp", cfg.Proxy.Listen)
	if err != nil {
		return sirenerr.E(op, "failed to create listener", 0, err)
	}
	defer listener.Close()

	log.Infof("TCP proxy listening on %s -> %s", cfg.Proxy.Listen, cfg.Proxy.Target)

	serverConduit := transport.TCP(cfg.Proxy.Target)

	proxyConfig := &proxy.ProxyConfig{
		ListenAddr:        cfg.Proxy.Listen,
		TargetAddr:        cfg.Proxy.Target,
		MaxConnections:    cfg.Proxy.MaxConnections,
		ConnectionTimeout: cfg.Proxy.GetConnectionTimeout(),
		BufferSize:        cfg.Proxy.BufferSize,
		EnableRecording:   cfg.Recording != nil && cfg.Recording.Enabled,
	}

	streamProxy := proxy.NewStreamProxy(proxyConfig, listener, serverConduit, engine, rec, log, manipulators)

	if err := streamProxy.Start(ctx); err != nil {
		return sirenerr.E(op, "failed to start proxy", 0, err)
	}

	<-ctx.Done()
	return streamProxy.Stop()
}

func runTLSProxy(ctx context.Context, cfg *config.Config, engine *intercept.Engine, rec *recorder.Recorder, log *logrus.Entry, manipulators []manipulator.Manipulator) error {
	op := "main.runTLSProxy"
	if cfg.Proxy.TLS == nil {
		return sirenerr.E(op, "TLS configuration required for TLS proxy", 0, nil)
	}

	var serverTLSConfig *tls.Config
	if cfg.Proxy.TLS.CertFile != "" && cfg.Proxy.TLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.Proxy.TLS.CertFile, cfg.Proxy.TLS.KeyFile)
		if err != nil {
			return sirenerr.E(op, "failed to load server certificate", 0, err)
		}
		serverTLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	} else {
		return sirenerr.E(op, "server certificate and key required for TLS interception", 0, nil)
	}

	listener, err := tls.Listen("tcp", cfg.Proxy.Listen, serverTLSConfig)
	if err != nil {
		return sirenerr.E(op, "failed to create TLS listener", 0, err)
	}
	defer listener.Close()

	log.Infof("TLS proxy listening on %s -> %s", cfg.Proxy.Listen, cfg.Proxy.Target)

	tcpConduit := transport.TCP(cfg.Proxy.Target)
	clientTLSConfig := &tls.Config{InsecureSkipVerify: cfg.Proxy.TLS.SkipVerify}
	if cfg.Proxy.TLS.ServerName != "" {
		clientTLSConfig.ServerName = cfg.Proxy.TLS.ServerName
	}
	tlsConduit := tlscond.NewTlsClient(tcpConduit, clientTLSConfig)

	proxyConfig := &proxy.ProxyConfig{
		ListenAddr:        cfg.Proxy.Listen,
		TargetAddr:        cfg.Proxy.Target,
		MaxConnections:    cfg.Proxy.MaxConnections,
		ConnectionTimeout: cfg.Proxy.GetConnectionTimeout(),
		BufferSize:        cfg.Proxy.BufferSize,
		EnableRecording:   cfg.Recording != nil && cfg.Recording.Enabled,
	}

	streamProxy := proxy.NewStreamProxy(proxyConfig, listener, tlsConduit, engine, rec, log, manipulators)

	if err := streamProxy.Start(ctx); err != nil {
		return sirenerr.E(op, "failed to start proxy", 0, err)
	}

	<-ctx.Done()
	return streamProxy.Stop()
}

func runUDPProxy(ctx context.Context, cfg *config.Config, engine *intercept.Engine, rec *recorder.Recorder, log *logrus.Entry, manipulators []manipulator.Manipulator) error {
	op := "main.runUDPProxy"
	addr, err := net.ResolveUDPAddr("udp", cfg.Proxy.Listen)
	if err != nil {
		return sirenerr.E(op, "failed to resolve listen address", 0, err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return sirenerr.E(op, "failed to create UDP listener", 0, err)
	}
	defer conn.Close()

	log.Infof("UDP proxy listening on %s -> %s", cfg.Proxy.Listen, cfg.Proxy.Target)

	serverConduit := transport.UDP(cfg.Proxy.Target)

	proxyConfig := &proxy.ProxyConfig{
		ListenAddr:        cfg.Proxy.Listen,
		TargetAddr:        cfg.Proxy.Target,
		MaxConnections:    cfg.Proxy.MaxConnections,
		ConnectionTimeout: cfg.Proxy.GetConnectionTimeout(),
		BufferSize:        cfg.Proxy.BufferSize,
		EnableRecording:   cfg.Recording != nil && cfg.Recording.Enabled,
	}

	datagramProxy := proxy.NewDatagramProxy(proxyConfig, conn, serverConduit, engine, rec, log, manipulators)

	if err := datagramProxy.Start(ctx); err != nil {
		return sirenerr.E(op, "failed to start proxy", 0, err)
	}

	<-ctx.Done()
	return datagramProxy.Stop()
}

func runDTLSProxy(ctx context.Context, cfg *config.Config, engine *intercept.Engine, rec *recorder.Recorder, log *logrus.Entry, manipulators []manipulator.Manipulator) error {
	op := "main.runDTLSProxy"
	if cfg.Proxy.DTLS == nil {
		return sirenerr.E(op, "DTLS configuration required for DTLS proxy", 0, nil)
	}

	cert, err := tls.LoadX509KeyPair(cfg.Proxy.DTLS.CertFile, cfg.Proxy.DTLS.KeyFile)
	if err != nil {
		return sirenerr.E(op, "failed to load server certificate", 0, err)
	}

	dtlsConfig := &dtls.Config{
		Certificates:         []tls.Certificate{cert},
		InsecureSkipVerify:   cfg.Proxy.DTLS.SkipVerify,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	}

	addr, err := net.ResolveUDPAddr("udp", cfg.Proxy.Listen)
	if err != nil {
		return sirenerr.E(op, "failed to resolve listen address", 0, err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return sirenerr.E(op, "failed to create dtls listener", 0, err)
	}

	log.Infof("DTLS proxy listening on %s -> %s", cfg.Proxy.Listen, cfg.Proxy.Target)

	udpConduit := transport.UDP(cfg.Proxy.Target)
	dtlsConduit := tlscond.NewDtlsClient(udpConduit, dtlsConfig)

	proxyConfig := &proxy.ProxyConfig{
		ListenAddr:        cfg.Proxy.Listen,
		TargetAddr:        cfg.Proxy.Target,
		MaxConnections:    cfg.Proxy.MaxConnections,
		ConnectionTimeout: cfg.Proxy.GetConnectionTimeout(),
		BufferSize:        cfg.Proxy.BufferSize,
		EnableRecording:   cfg.Recording != nil && cfg.Recording.Enabled,
	}

	datagramProxy := proxy.NewDatagramProxy(proxyConfig, conn, dtlsConduit, engine, rec, log, manipulators)

	if err := datagramProxy.Start(ctx); err != nil {
		return sirenerr.E(op, "failed to start proxy", 0, err)
	}

	<-ctx.Done()
	return datagramProxy.Stop()
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
	if cfg.Ebpf != nil && cfg.Ebpf.Enabled {
		fmt.Printf("Mode:          eBPF\n")
		fmt.Printf("Interface:     %s\n", cfg.Ebpf.Interface)
	} else {
		fmt.Printf("Mode:          Proxy\n")
		fmt.Printf("Protocol:      %s\n", cfg.Proxy.Protocol)
		fmt.Printf("Listen:        %s\n", cfg.Proxy.Listen)
		fmt.Printf("Target:        %s\n", cfg.Proxy.Target)
		fmt.Printf("Max Conns:     %d\n", cfg.Proxy.MaxConnections)
	}
	fmt.Printf("Rules:         %d loaded\n", len(cfg.Rules))

	if cfg.Spoof != nil {
		if cfg.Spoof.ARP != nil && cfg.Spoof.ARP.Enabled {
			fmt.Printf("ARP Spoof:     Enabled (%s: %s -> %s)\n", cfg.Spoof.ARP.Interface, cfg.Spoof.ARP.Target, cfg.Spoof.ARP.Gateway)
		}
		if cfg.Spoof.DNS != nil && cfg.Spoof.DNS.Enabled {
			fmt.Printf("DNS Spoof:     Enabled (%s, %d overrides)\n", cfg.Spoof.DNS.Listen, len(cfg.Spoof.DNS.Overrides))
		}
	}

	if cfg.Recording != nil && cfg.Recording.Enabled {
		fmt.Printf("Recording:     %s (%s)\n", cfg.Recording.Output, cfg.Recording.Format)
	}
	fmt.Println()
	if cfg.Ebpf != nil && cfg.Ebpf.Enabled {
		fmt.Println("Using eBPF for transparent interception")
	} else {
		fmt.Println("Using Trident for transport abstraction")
	}
	fmt.Println()
	if cfg.Spoof != nil && (cfg.Spoof.ARP != nil && cfg.Spoof.ARP.Enabled || cfg.Spoof.DNS != nil && cfg.Spoof.DNS.Enabled) {
		fmt.Println("⚠️  WARNING: Spoofing enabled - requires root privileges")
		fmt.Println("⚠️  Ensure IP forwarding is enabled: sysctl -w net.ipv4.ip_forward=1")
		fmt.Println()
	}
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println("───────────────────────────────────────────────────────────────")
	fmt.Println()
}
