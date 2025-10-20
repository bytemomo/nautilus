package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"bytemomo/siren/config"
	"bytemomo/siren/intercept"
	"bytemomo/siren/proxy"
	"bytemomo/siren/recorder"
	"bytemomo/siren/spoof"
	"bytemomo/trident/conduit/transport"
	tlscond "bytemomo/trident/conduit/transport/tls"
)

const version = "0.1.0"

var (
	configFile  = flag.String("config", "", "Path to configuration file (required)")
	showVersion = flag.Bool("version", false, "Show version information")
)

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("Siren v%s\n", version)
		fmt.Println("Man-in-the-Middle Testing Proxy using Trident")
		return
	}

	// Configuration file is required
	if *configFile == "" {
		log.Fatal("Configuration file is required. Use: siren -config <file>")
	}

	// Load configuration
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Printf("Loaded configuration from %s", *configFile)
	printBanner(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	// Start spoofing services if configured
	var arpSpoofer *spoof.ARPSpoofer
	var dnsSpoofer *spoof.DNSSpoofer

	if cfg.Spoof != nil {
		// Start ARP spoofing if enabled
		if cfg.Spoof.ARP != nil && cfg.Spoof.ARP.Enabled {
			log.Println("[Spoof] Starting ARP spoofing...")
			arpSpoofer, err = startARPSpoof(ctx, cfg.Spoof.ARP)
			if err != nil {
				log.Fatalf("Failed to start ARP spoofing: %v", err)
			}
			defer arpSpoofer.Stop()
		}

		// Start DNS spoofing if enabled
		if cfg.Spoof.DNS != nil && cfg.Spoof.DNS.Enabled {
			log.Println("[Spoof] Starting DNS spoofing...")
			dnsSpoofer, err = startDNSSpoof(ctx, cfg.Spoof.DNS)
			if err != nil {
				log.Fatalf("Failed to start DNS spoofing: %v", err)
			}
			defer dnsSpoofer.Stop()
		}
	}

	// Start the proxy
	go func() {
		if err := runProxy(ctx, cfg); err != nil {
			log.Fatalf("Proxy error: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-sigCh
	log.Println("\nShutting down gracefully...")
	cancel()

	// Give services time to clean up
	time.Sleep(2 * time.Second)
}

func startARPSpoof(ctx context.Context, cfg *config.ARPSpoofConfig) (*spoof.ARPSpoofer, error) {
	targetIP := net.ParseIP(cfg.Target)
	if targetIP == nil {
		return nil, fmt.Errorf("invalid target IP: %s", cfg.Target)
	}

	gatewayIP := net.ParseIP(cfg.Gateway)
	if gatewayIP == nil {
		return nil, fmt.Errorf("invalid gateway IP: %s", cfg.Gateway)
	}

	arpConfig := &spoof.ARPConfig{
		Interface:      cfg.Interface,
		TargetIP:       targetIP,
		GatewayIP:      gatewayIP,
		Bidirectional:  true, // Default to bidirectional
		EnableLogging:  true,
		UpdateInterval: 2 * time.Second,
	}

	spoofer, err := spoof.NewARPSpoofer(arpConfig)
	if err != nil {
		return nil, err
	}

	if err := spoofer.Start(ctx); err != nil {
		return nil, err
	}

	log.Printf("[ARP Spoof] Active: %s <-> %s via %s", cfg.Target, cfg.Gateway, cfg.Interface)
	return spoofer, nil
}

func startDNSSpoof(ctx context.Context, cfg *config.DNSSpoofConfig) (*spoof.DNSSpoofer, error) {
	dnsConfig := &spoof.DNSConfig{
		ListenAddr:    cfg.Listen,
		UpstreamDNS:   cfg.Upstream,
		Overrides:     cfg.Overrides,
		TTL:           60, // Default TTL
		EnableLogging: true,
		Timeout:       5 * time.Second,
	}

	spoofer, err := spoof.NewDNSSpoofer(dnsConfig)
	if err != nil {
		return nil, err
	}

	if err := spoofer.Start(ctx); err != nil {
		return nil, err
	}

	log.Printf("[DNS Spoof] Active on %s, %d overrides configured", cfg.Listen, len(cfg.Overrides))
	return spoofer, nil
}

func runProxy(ctx context.Context, cfg *config.Config) error {
	// Create interception engine if rules are defined
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
			return fmt.Errorf("failed to create interception engine: %w", err)
		}
		log.Printf("Loaded %d interception rules", len(cfg.Rules))
	}

	// Create recorder if recording is enabled
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
			return fmt.Errorf("failed to create recorder: %w", err)
		}

		if err := rec.Start(); err != nil {
			return fmt.Errorf("failed to start recorder: %w", err)
		}
		defer rec.Stop()

		log.Printf("Recording enabled: %s (format: %s)", cfg.Recording.Output, cfg.Recording.Format)
	}

	// Create proxy based on protocol
	switch cfg.Proxy.Protocol {
	case "tcp":
		return runTCPProxy(ctx, cfg, engine, rec)
	case "tls":
		return runTLSProxy(ctx, cfg, engine, rec)
	case "udp":
		return runUDPProxy(ctx, cfg, engine, rec)
	case "dtls":
		return runDTLSProxy(ctx, cfg, engine, rec)
	default:
		return fmt.Errorf("unsupported protocol: %s", cfg.Proxy.Protocol)
	}
}

func runTCPProxy(ctx context.Context, cfg *config.Config, engine *intercept.Engine, rec *recorder.Recorder) error {
	// Create TCP listener for client connections
	listener, err := net.Listen("tcp", cfg.Proxy.Listen)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}
	defer listener.Close()

	log.Printf("TCP proxy listening on %s -> %s", cfg.Proxy.Listen, cfg.Proxy.Target)

	// Create Trident TCP conduit for server connections
	serverConduit := transport.TCP(cfg.Proxy.Target)

	// Create proxy configuration
	proxyConfig := &proxy.ProxyConfig{
		ListenAddr:        cfg.Proxy.Listen,
		TargetAddr:        cfg.Proxy.Target,
		MaxConnections:    cfg.Proxy.MaxConnections,
		ConnectionTimeout: cfg.Proxy.GetConnectionTimeout(),
		BufferSize:        cfg.Proxy.BufferSize,
		EnableRecording:   cfg.Recording != nil && cfg.Recording.Enabled,
		EnableLogging:     cfg.Proxy.EnableLogging,
	}

	// Create stream proxy
	streamProxy := proxy.NewStreamProxy(proxyConfig, listener, serverConduit, engine, rec)

	// Start proxy
	if err := streamProxy.Start(ctx); err != nil {
		return fmt.Errorf("failed to start proxy: %w", err)
	}

	// Wait for context cancellation
	<-ctx.Done()

	// Stop proxy
	return streamProxy.Stop()
}

func runTLSProxy(ctx context.Context, cfg *config.Config, engine *intercept.Engine, rec *recorder.Recorder) error {
	// Load TLS configuration
	if cfg.Proxy.TLS == nil {
		return fmt.Errorf("TLS configuration required for TLS proxy")
	}

	// Load server certificate for accepting client connections
	var serverTLSConfig *tls.Config
	if cfg.Proxy.TLS.CertFile != "" && cfg.Proxy.TLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.Proxy.TLS.CertFile, cfg.Proxy.TLS.KeyFile)
		if err != nil {
			return fmt.Errorf("failed to load server certificate: %w", err)
		}

		serverTLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	} else {
		return fmt.Errorf("server certificate and key required for TLS interception")
	}

	// Create TLS listener for client connections
	listener, err := tls.Listen("tcp", cfg.Proxy.Listen, serverTLSConfig)
	if err != nil {
		return fmt.Errorf("failed to create TLS listener: %w", err)
	}
	defer listener.Close()

	log.Printf("TLS proxy listening on %s -> %s", cfg.Proxy.Listen, cfg.Proxy.Target)

	// Create Trident TLS conduit for server connections
	tcpConduit := transport.TCP(cfg.Proxy.Target)

	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: cfg.Proxy.TLS.SkipVerify,
	}
	if cfg.Proxy.TLS.ServerName != "" {
		clientTLSConfig.ServerName = cfg.Proxy.TLS.ServerName
	}

	tlsConduit := tlscond.NewTlsClient(tcpConduit, clientTLSConfig)

	// Create proxy configuration
	proxyConfig := &proxy.ProxyConfig{
		ListenAddr:        cfg.Proxy.Listen,
		TargetAddr:        cfg.Proxy.Target,
		MaxConnections:    cfg.Proxy.MaxConnections,
		ConnectionTimeout: cfg.Proxy.GetConnectionTimeout(),
		BufferSize:        cfg.Proxy.BufferSize,
		EnableRecording:   cfg.Recording != nil && cfg.Recording.Enabled,
		EnableLogging:     cfg.Proxy.EnableLogging,
	}

	// Create stream proxy
	streamProxy := proxy.NewStreamProxy(proxyConfig, listener, tlsConduit, engine, rec)

	// Start proxy
	if err := streamProxy.Start(ctx); err != nil {
		return fmt.Errorf("failed to start proxy: %w", err)
	}

	// Wait for context cancellation
	<-ctx.Done()

	// Stop proxy
	return streamProxy.Stop()
}

func runUDPProxy(ctx context.Context, cfg *config.Config, engine *intercept.Engine, rec *recorder.Recorder) error {
	// Create UDP listener for client connections
	addr, err := net.ResolveUDPAddr("udp", cfg.Proxy.Listen)
	if err != nil {
		return fmt.Errorf("failed to resolve listen address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to create UDP listener: %w", err)
	}
	defer conn.Close()

	log.Printf("UDP proxy listening on %s -> %s", cfg.Proxy.Listen, cfg.Proxy.Target)

	// Create Trident UDP conduit for server connections
	serverConduit := transport.UDP(cfg.Proxy.Target)

	// Create proxy configuration
	proxyConfig := &proxy.ProxyConfig{
		ListenAddr:        cfg.Proxy.Listen,
		TargetAddr:        cfg.Proxy.Target,
		MaxConnections:    cfg.Proxy.MaxConnections,
		ConnectionTimeout: cfg.Proxy.GetConnectionTimeout(),
		BufferSize:        cfg.Proxy.BufferSize,
		EnableRecording:   cfg.Recording != nil && cfg.Recording.Enabled,
		EnableLogging:     cfg.Proxy.EnableLogging,
	}

	// Create datagram proxy
	datagramProxy := proxy.NewDatagramProxy(proxyConfig, conn, serverConduit, engine, rec)

	// Start proxy
	if err := datagramProxy.Start(ctx); err != nil {
		return fmt.Errorf("failed to start proxy: %w", err)
	}

	// Wait for context cancellation
	<-ctx.Done()

	// Stop proxy
	return datagramProxy.Stop()
}

func runDTLSProxy(ctx context.Context, cfg *config.Config, engine *intercept.Engine, rec *recorder.Recorder) error {
	// DTLS proxy requires pion/dtls which is already imported
	// For now, return not implemented - would need DTLS listener setup similar to TLS
	// The DatagramProxy supports it, but we need to set up DTLS listener on client side
	return fmt.Errorf("DTLS proxy not yet fully implemented - DTLS listener setup needed")
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
	fmt.Printf("Protocol:      %s\n", cfg.Proxy.Protocol)
	fmt.Printf("Listen:        %s\n", cfg.Proxy.Listen)
	fmt.Printf("Target:        %s\n", cfg.Proxy.Target)
	fmt.Printf("Max Conns:     %d\n", cfg.Proxy.MaxConnections)
	fmt.Printf("Rules:         %d loaded\n", len(cfg.Rules))

	// Show spoofing status
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
	fmt.Println("Using Trident for transport abstraction")
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
