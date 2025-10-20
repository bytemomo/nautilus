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

	"bytemomo/siren/config"
	"bytemomo/siren/intercept"
	"bytemomo/siren/proxy"
	"bytemomo/siren/recorder"
	"bytemomo/trident/conduit/transport"
	tlscond "bytemomo/trident/conduit/transport/tls"
)

const version = "0.1.0"

var (
	configFile  = flag.String("config", "", "Path to configuration file")
	listenAddr  = flag.String("listen", "", "Listen address (e.g., :8080)")
	targetAddr  = flag.String("target", "", "Target server address (e.g., server.com:80)")
	protocol    = flag.String("proto", "tcp", "Protocol: tcp, tls, udp, dtls")
	recordPath  = flag.String("record", "", "Record traffic to file")
	certFile    = flag.String("cert", "", "TLS certificate file (for TLS interception)")
	keyFile     = flag.String("key", "", "TLS key file (for TLS interception)")
	skipVerify  = flag.Bool("skip-verify", false, "Skip TLS verification when connecting to server")
	showVersion = flag.Bool("version", false, "Show version information")
)

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("Siren v%s\n", version)
		fmt.Println("Man-in-the-Middle Testing Proxy using Trident")
		return
	}

	// Load or build configuration
	var cfg *config.Config
	var err error

	if *configFile != "" {
		cfg, err = config.LoadConfig(*configFile)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
		log.Printf("Loaded configuration from %s", *configFile)
	} else {
		// Build config from command-line flags
		if *listenAddr == "" || *targetAddr == "" {
			log.Fatal("Either -config or both -listen and -target must be provided")
		}

		cfg = &config.Config{
			Name:        "CLI Config",
			Description: "Configuration from command-line arguments",
			Proxy: &config.ProxyConfig{
				Listen:            *listenAddr,
				Target:            *targetAddr,
				Protocol:          *protocol,
				MaxConnections:    1000,
				ConnectionTimeout: "30s",
				BufferSize:        32768,
				EnableLogging:     true,
			},
			Rules: []*intercept.Rule{},
		}

		// Add TLS config if provided
		if *certFile != "" && *keyFile != "" {
			cfg.Proxy.TLS = &config.TLSConfig{
				CertFile:   *certFile,
				KeyFile:    *keyFile,
				SkipVerify: *skipVerify,
			}
		}

		// Add recording config if provided
		if *recordPath != "" {
			cfg.Recording = &config.RecordingConfig{
				Enabled:        true,
				Output:         *recordPath,
				Format:         "json",
				IncludePayload: true,
				MaxFileSize:    "100MB",
				FlushInterval:  "5s",
			}
		}

		if err := cfg.Validate(); err != nil {
			log.Fatalf("Invalid configuration: %v", err)
		}
	}

	// Print banner
	printBanner(cfg)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	// Start the proxy
	if err := runProxy(ctx, cfg); err != nil {
		log.Fatalf("Proxy error: %v", err)
	}

	// Wait for shutdown signal
	<-sigCh
	log.Println("\nShutting down gracefully...")
	cancel()
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
	// UDP proxy not yet implemented
	return fmt.Errorf("UDP proxy not yet implemented - coming soon")
}

func runDTLSProxy(ctx context.Context, cfg *config.Config, engine *intercept.Engine, rec *recorder.Recorder) error {
	// DTLS proxy not yet implemented
	return fmt.Errorf("DTLS proxy not yet implemented - coming soon")
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
	if cfg.Recording != nil && cfg.Recording.Enabled {
		fmt.Printf("Recording:     %s (%s)\n", cfg.Recording.Output, cfg.Recording.Format)
	}
	fmt.Println()
	fmt.Println("Using Trident for transport abstraction")
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println("───────────────────────────────────────────────────────────────")
	fmt.Println()
}
