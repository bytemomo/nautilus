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
	"bytemomo/siren/pkg/core"
	"bytemomo/siren/pkg/ebpf"
	"bytemomo/siren/pkg/logger"
	"bytemomo/siren/pkg/manipulator"
	"bytemomo/siren/pkg/sirenerr"
	"bytemomo/siren/spoof"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
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

	if cfg.Ebpf != nil && cfg.Ebpf.Enabled {
		ebpfManager, err := ebpf.NewManager(cfg.Ebpf.Interface, log.WithField("component", "ebpf"))
		if err != nil {
			log.Fatalf("Failed to create eBPF manager: %v", err)
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

func processPacket(ctx context.Context, packet gopacket.Packet, manipulators []*config.ManipulatorConfig, ifaceName string) error {
	op := "main.processPacket"
	var direction core.Direction

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}
	ip, _ := ipLayer.(*layers.IPv4)

	if ip.DstIP.IsLoopback() {
		direction = core.ClientToServer
	} else {
		direction = core.ServerToClient
	}

	var payload []byte
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		payload = tcp.Payload
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		payload = udp.Payload
	} else {
		return nil
	}

	tc := &core.TrafficContext{
		Direction: direction,
		Payload:   payload,
		Size:      len(payload),
	}
	pr := &core.ProcessingResult{
		ModifiedPayload: payload,
	}

	for _, mcfg := range manipulators {
		m, err := manipulator.Get(mcfg.Name)
		if err != nil {
			return sirenerr.E(op, fmt.Sprintf("failed to get manipulator: %s", mcfg.Name), 0, err)
		}
		if err := m.Configure(mcfg.Params); err != nil {
			return sirenerr.E(op, fmt.Sprintf("failed to configure manipulator: %s", mcfg.Name), 0, err)
		}
		pr, err = m.Process(ctx, tc, pr)
		if err != nil {
			return sirenerr.E(op, fmt.Sprintf("failed to process manipulator: %s", mcfg.Name), 0, err)
		}
	}

	if pr.ModifiedPayload != nil {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			tcp.Payload = pr.ModifiedPayload
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			udp.Payload = pr.ModifiedPayload
		}

		buffer := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		if err := gopacket.SerializePacket(buffer, opts, packet); err != nil {
			return sirenerr.E(op, "failed to serialize packet", 0, err)
		}

		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return sirenerr.E(op, "failed to get interface", 0, err)
		}

		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
		if err != nil {
			return sirenerr.E(op, "failed to create raw socket", 0, err)
		}
		defer unix.Close(fd)

		addr := unix.SockaddrLinklayer{
			Ifindex: iface.Index,
		}
		if err := unix.Sendto(fd, buffer.Bytes(), 0, &addr); err != nil {
			return sirenerr.E(op, "failed to send packet", 0, err)
		}
	}

	return nil
}

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
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
