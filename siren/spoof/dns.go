package spoof

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DNSSpoofer performs DNS spoofing to redirect clients
type DNSSpoofer struct {
	config    *DNSConfig
	server    *dns.Server
	client    *dns.Client
	running   bool
	mu        sync.RWMutex
	stats     *DNSStats
	overrides map[string]net.IP // domain -> spoofed IP
}

// DNSConfig configures DNS spoofing
type DNSConfig struct {
	ListenAddr    string            // Address to listen on (e.g., ":53")
	UpstreamDNS   string            // Upstream DNS server (e.g., "8.8.8.8:53")
	Overrides     map[string]string // domain -> IP overrides
	TTL           uint32            // TTL for spoofed records (default: 60)
	EnableLogging bool
	Timeout       time.Duration
}

// DNSStats tracks DNS spoofing statistics
type DNSStats struct {
	mu              sync.RWMutex
	QueriesTotal    uint64
	QueriesSpoofed  uint64
	QueriesProxied  uint64
	QueriesFailed   uint64
	StartTime       time.Time
}

// NewDNSSpoofer creates a new DNS spoofer
func NewDNSSpoofer(config *DNSConfig) (*DNSSpoofer, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if config.ListenAddr == "" {
		config.ListenAddr = ":53"
	}

	if config.UpstreamDNS == "" {
		config.UpstreamDNS = "8.8.8.8:53"
	}

	if config.TTL == 0 {
		config.TTL = 60 // Default 60 second TTL
	}

	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second
	}

	// Parse overrides
	overrides := make(map[string]net.IP)
	for domain, ipStr := range config.Overrides {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address for domain %s: %s", domain, ipStr)
		}
		// Normalize domain to lowercase
		overrides[strings.ToLower(domain)] = ip
	}

	return &DNSSpoofer{
		config:    config,
		client:    &dns.Client{Timeout: config.Timeout},
		overrides: overrides,
		stats: &DNSStats{
			StartTime: time.Now(),
		},
	}, nil
}

// Start begins DNS spoofing
func (ds *DNSSpoofer) Start(ctx context.Context) error {
	ds.mu.Lock()
	if ds.running {
		ds.mu.Unlock()
		return fmt.Errorf("DNS spoofer already running")
	}
	ds.running = true
	ds.mu.Unlock()

	if ds.config.EnableLogging {
		log.Printf("[DNS Spoof] Starting DNS server on %s", ds.config.ListenAddr)
		log.Printf("[DNS Spoof]   Upstream: %s", ds.config.UpstreamDNS)
		log.Printf("[DNS Spoof]   Overrides: %d domains", len(ds.overrides))
		for domain, ip := range ds.overrides {
			log.Printf("[DNS Spoof]     %s -> %s", domain, ip)
		}
	}

	// Create DNS server
	ds.server = &dns.Server{
		Addr: ds.config.ListenAddr,
		Net:  "udp",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			ds.handleDNSRequest(w, r)
		}),
	}

	// Start server in goroutine
	go func() {
		if err := ds.server.ListenAndServe(); err != nil {
			if ds.config.EnableLogging && ds.running {
				log.Printf("[DNS Spoof] Server error: %v", err)
			}
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	if ds.config.EnableLogging {
		log.Printf("[DNS Spoof] DNS server started")
	}

	return nil
}

// Stop stops DNS spoofing
func (ds *DNSSpoofer) Stop() error {
	ds.mu.Lock()
	if !ds.running {
		ds.mu.Unlock()
		return nil
	}
	ds.running = false
	ds.mu.Unlock()

	if ds.config.EnableLogging {
		log.Printf("[DNS Spoof] Stopping DNS server...")
	}

	// Shutdown server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ds.server.ShutdownContext(ctx); err != nil {
		return fmt.Errorf("failed to shutdown DNS server: %w", err)
	}

	if ds.config.EnableLogging {
		stats := ds.Stats()
		log.Printf("[DNS Spoof] Stopped. Stats: Total=%d, Spoofed=%d, Proxied=%d, Failed=%d",
			stats.QueriesTotal, stats.QueriesSpoofed, stats.QueriesProxied, stats.QueriesFailed)
	}

	return nil
}

// handleDNSRequest handles a DNS query
func (ds *DNSSpoofer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	ds.stats.mu.Lock()
	ds.stats.QueriesTotal++
	ds.stats.mu.Unlock()

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	// Process each question
	for _, question := range r.Question {
		domain := strings.ToLower(strings.TrimSuffix(question.Name, "."))

		if ds.config.EnableLogging {
			log.Printf("[DNS Spoof] Query: %s (type: %s) from %s",
				domain, dns.TypeToString[question.Qtype], w.RemoteAddr())
		}

		// Check if we should spoof this domain
		if spoofedIP, shouldSpoof := ds.shouldSpoofDomain(domain); shouldSpoof {
			// Spoof the response
			ds.addSpoofedAnswer(m, question, spoofedIP)

			ds.stats.mu.Lock()
			ds.stats.QueriesSpoofed++
			ds.stats.mu.Unlock()

			if ds.config.EnableLogging {
				log.Printf("[DNS Spoof] Spoofed: %s -> %s", domain, spoofedIP)
			}
		} else {
			// Proxy to upstream DNS
			if err := ds.proxyToUpstream(m, r); err != nil {
				if ds.config.EnableLogging {
					log.Printf("[DNS Spoof] Proxy error: %v", err)
				}

				ds.stats.mu.Lock()
				ds.stats.QueriesFailed++
				ds.stats.mu.Unlock()

				m.SetRcode(r, dns.RcodeServerFailure)
			} else {
				ds.stats.mu.Lock()
				ds.stats.QueriesProxied++
				ds.stats.mu.Unlock()
			}
		}
	}

	// Send response
	if err := w.WriteMsg(m); err != nil {
		if ds.config.EnableLogging {
			log.Printf("[DNS Spoof] Error writing response: %v", err)
		}
	}
}

// shouldSpoofDomain checks if a domain should be spoofed
func (ds *DNSSpoofer) shouldSpoofDomain(domain string) (net.IP, bool) {
	domain = strings.ToLower(domain)

	// Check exact match
	if ip, ok := ds.overrides[domain]; ok {
		return ip, true
	}

	// Check wildcard matches (*.example.com)
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts); i++ {
		wildcard := "*." + strings.Join(parts[i:], ".")
		if ip, ok := ds.overrides[wildcard]; ok {
			return ip, true
		}
	}

	return nil, false
}

// addSpoofedAnswer adds a spoofed DNS answer to the response
func (ds *DNSSpoofer) addSpoofedAnswer(m *dns.Msg, question dns.Question, ip net.IP) {
	switch question.Qtype {
	case dns.TypeA:
		if ip.To4() != nil {
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    ds.config.TTL,
				},
				A: ip,
			}
			m.Answer = append(m.Answer, rr)
		}

	case dns.TypeAAAA:
		if ip.To16() != nil && ip.To4() == nil {
			rr := &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    ds.config.TTL,
				},
				AAAA: ip,
			}
			m.Answer = append(m.Answer, rr)
		}

	case dns.TypeANY:
		// Respond with A record for ANY queries
		if ip.To4() != nil {
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    ds.config.TTL,
				},
				A: ip,
			}
			m.Answer = append(m.Answer, rr)
		}
	}
}

// proxyToUpstream proxies the DNS query to the upstream server
func (ds *DNSSpoofer) proxyToUpstream(m *dns.Msg, r *dns.Msg) error {
	// Query upstream DNS
	resp, _, err := ds.client.Exchange(r, ds.config.UpstreamDNS)
	if err != nil {
		return fmt.Errorf("upstream query failed: %w", err)
	}

	// Copy response
	m.Answer = resp.Answer
	m.Ns = resp.Ns
	m.Extra = resp.Extra
	m.Rcode = resp.Rcode
	m.Authoritative = resp.Authoritative
	m.RecursionAvailable = resp.RecursionAvailable

	return nil
}

// AddOverride adds a domain override
func (ds *DNSSpoofer) AddOverride(domain string, ip string) error {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()

	domain = strings.ToLower(domain)
	ds.overrides[domain] = parsedIP

	if ds.config.EnableLogging {
		log.Printf("[DNS Spoof] Added override: %s -> %s", domain, ip)
	}

	return nil
}

// RemoveOverride removes a domain override
func (ds *DNSSpoofer) RemoveOverride(domain string) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	domain = strings.ToLower(domain)
	delete(ds.overrides, domain)

	if ds.config.EnableLogging {
		log.Printf("[DNS Spoof] Removed override: %s", domain)
	}
}

// GetOverrides returns all current overrides
func (ds *DNSSpoofer) GetOverrides() map[string]string {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	overrides := make(map[string]string)
	for domain, ip := range ds.overrides {
		overrides[domain] = ip.String()
	}

	return overrides
}

// Stats returns DNS spoofing statistics
func (ds *DNSSpoofer) Stats() *DNSStats {
	ds.stats.mu.RLock()
	defer ds.stats.mu.RUnlock()

	return &DNSStats{
		QueriesTotal:   ds.stats.QueriesTotal,
		QueriesSpoofed: ds.stats.QueriesSpoofed,
		QueriesProxied: ds.stats.QueriesProxied,
		QueriesFailed:  ds.stats.QueriesFailed,
		StartTime:      ds.stats.StartTime,
	}
}

// IsRunning returns whether the spoofer is running
func (ds *DNSSpoofer) IsRunning() bool {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return ds.running
}

// GetConfig returns the current configuration
func (ds *DNSSpoofer) GetConfig() *DNSConfig {
	return ds.config
}

// Uptime returns how long the DNS spoofer has been running
func (ds *DNSSpoofer) Uptime() time.Duration {
	ds.stats.mu.RLock()
	defer ds.stats.mu.RUnlock()
	return time.Since(ds.stats.StartTime)
}
