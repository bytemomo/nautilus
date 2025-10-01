package scanner

import (
	"context"
	"fmt"
	"net"
	"time"

	"bytemomo/orca/internal/entity"
)

// Scanner defines the interface for network discovery
type Scanner interface {
	// Scan performs discovery based on the provided scope
	Scan(ctx context.Context, scope Scope) (*ScanResult, error)

	// ScanHosts discovers hosts in the given scope
	ScanHosts(ctx context.Context, scope Scope) ([]entity.Host, error)

	// ScanServices discovers services on the given hosts
	ScanServices(ctx context.Context, hosts []entity.Host, portRanges []PortRange) ([]entity.Service, error)

	// GetCapabilities returns the scanner's capabilities
	GetCapabilities() Capabilities
}

// Scope defines the scan scope
type Scope struct {
	Type   string   `json:"type"`  // subnet, host, list, file
	Value  string   `json:"value"` // CIDR, IP, comma-separated, file path
	Ports  []int    `json:"ports,omitempty"`
	Ranges []string `json:"ranges,omitempty"` // port ranges like "1-1000", "80,443,8080"
}

// PortRange defines a range of ports to scan
type PortRange struct {
	Start int    `json:"start"`
	End   int    `json:"end"`
	Proto string `json:"proto"` // tcp, udp
}

// ScanResult contains the results of a network scan
type ScanResult struct {
	Scope     Scope            `json:"scope"`
	Hosts     []entity.Host    `json:"hosts"`
	Services  []entity.Service `json:"services"`
	Targets   []entity.Target  `json:"targets"`
	StartTime time.Time        `json:"start_time"`
	EndTime   time.Time        `json:"end_time"`
	Duration  time.Duration    `json:"duration"`
	Stats     ScanStats        `json:"stats"`
	Error     string           `json:"error,omitempty"`
}

// ScanStats provides statistics about the scan
type ScanStats struct {
	TotalHosts       int `json:"total_hosts"`
	AliveHosts       int `json:"alive_hosts"`
	TotalServices    int `json:"total_services"`
	OpenServices     int `json:"open_services"`
	ClosedServices   int `json:"closed_services"`
	FilteredServices int `json:"filtered_services"`
}

// Capabilities describes what a scanner implementation can do
type Capabilities struct {
	SupportsHostDiscovery    bool     `json:"supports_host_discovery"`
	SupportsServiceDiscovery bool     `json:"supports_service_discovery"`
	SupportsOSDetection      bool     `json:"supports_os_detection"`
	SupportsVersionDetection bool     `json:"supports_version_detection"`
	SupportedProtocols       []string `json:"supported_protocols"`
	MaxConcurrency           int      `json:"max_concurrency"`
	FastMode                 bool     `json:"fast_mode"`
}

// ScannerConfig contains configuration for the scanner
type ScannerConfig struct {
	Concurrency   int           `yaml:"concurrency" json:"concurrency"`
	Timeout       time.Duration `yaml:"timeout" json:"timeout"`
	RetryCount    int           `yaml:"retry_count" json:"retry_count"`
	FastMode      bool          `yaml:"fast_mode" json:"fast_mode"`
	OSDetection   bool          `yaml:"os_detection" json:"os_detection"`
	VersionScan   bool          `yaml:"version_scan" json:"version_scan"`
	PingDiscovery bool          `yaml:"ping_discovery" json:"ping_discovery"`
	DefaultPorts  []int         `yaml:"default_ports" json:"default_ports"`
	TCPConnect    bool          `yaml:"tcp_connect" json:"tcp_connect"`
	UDPScan       bool          `yaml:"udp_scan" json:"udp_scan"`
}

// DefaultScannerConfig returns default configuration
func DefaultScannerConfig() ScannerConfig {
	return ScannerConfig{
		Concurrency:   10,
		Timeout:       30 * time.Second,
		RetryCount:    2,
		FastMode:      false,
		OSDetection:   false,
		VersionScan:   true,
		PingDiscovery: true,
		DefaultPorts: []int{
			21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080,
		},
		TCPConnect: false,
		UDPScan:    false,
	}
}

// CoordinatingScanner coordinates multiple scanner implementations
type CoordinatingScanner struct {
	config      ScannerConfig
	hostScanner HostScanner
	portScanner PortScanner
}

// HostScanner interface for host discovery
type HostScanner interface {
	DiscoverHosts(ctx context.Context, scope Scope) ([]entity.Host, error)
}

// PortScanner interface for service discovery
type PortScanner interface {
	ScanPorts(ctx context.Context, hosts []entity.Host, portRanges []PortRange) ([]entity.Service, error)
}

// NewCoordinatingScanner creates a new coordinating scanner
func NewCoordinatingScanner(config ScannerConfig, hostScanner HostScanner, portScanner PortScanner) *CoordinatingScanner {
	return &CoordinatingScanner{
		config:      config,
		hostScanner: hostScanner,
		portScanner: portScanner,
	}
}

// Scan performs a complete network scan
func (s *CoordinatingScanner) Scan(ctx context.Context, scope Scope) (*ScanResult, error) {
	startTime := time.Now()

	result := &ScanResult{
		Scope:     scope,
		StartTime: startTime,
	}

	// Discover hosts
	hosts, err := s.ScanHosts(ctx, scope)
	if err != nil {
		result.Error = fmt.Sprintf("host discovery failed: %v", err)
		return result, err
	}
	result.Hosts = hosts

	// Determine port ranges
	portRanges := s.getPortRanges(scope)

	// Discover services
	services, err := s.ScanServices(ctx, hosts, portRanges)
	if err != nil {
		result.Error = fmt.Sprintf("service discovery failed: %v", err)
		return result, err
	}
	result.Services = services

	// Generate targets
	targets := s.generateTargets(hosts, services)
	result.Targets = targets

	// Calculate stats and timing
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.Stats = s.calculateStats(hosts, services)

	return result, nil
}

// ScanHosts discovers hosts in the given scope
func (s *CoordinatingScanner) ScanHosts(ctx context.Context, scope Scope) ([]entity.Host, error) {
	if s.hostScanner == nil {
		return nil, fmt.Errorf("no host scanner configured")
	}

	return s.hostScanner.DiscoverHosts(ctx, scope)
}

// ScanServices discovers services on the given hosts
func (s *CoordinatingScanner) ScanServices(ctx context.Context, hosts []entity.Host, portRanges []PortRange) ([]entity.Service, error) {
	if s.portScanner == nil {
		return nil, fmt.Errorf("no port scanner configured")
	}

	return s.portScanner.ScanPorts(ctx, hosts, portRanges)
}

// GetCapabilities returns the scanner's capabilities
func (s *CoordinatingScanner) GetCapabilities() Capabilities {
	return Capabilities{
		SupportsHostDiscovery:    s.hostScanner != nil,
		SupportsServiceDiscovery: s.portScanner != nil,
		SupportsOSDetection:      s.config.OSDetection,
		SupportsVersionDetection: s.config.VersionScan,
		SupportedProtocols:       []string{"tcp", "udp"},
		MaxConcurrency:           s.config.Concurrency,
		FastMode:                 s.config.FastMode,
	}
}

// getPortRanges determines port ranges to scan based on scope
func (s *CoordinatingScanner) getPortRanges(scope Scope) []PortRange {
	var ranges []PortRange

	// Use ports from scope if specified
	if len(scope.Ports) > 0 {
		for _, port := range scope.Ports {
			ranges = append(ranges, PortRange{
				Start: port,
				End:   port,
				Proto: "tcp",
			})
		}
		return ranges
	}

	// Use ranges from scope if specified
	if len(scope.Ranges) > 0 {
		for _, rangeStr := range scope.Ranges {
			portRange, err := parsePortRange(rangeStr)
			if err == nil {
				ranges = append(ranges, portRange)
			}
		}
		return ranges
	}

	// Use default ports
	for _, port := range s.config.DefaultPorts {
		ranges = append(ranges, PortRange{
			Start: port,
			End:   port,
			Proto: "tcp",
		})
	}

	return ranges
}

// generateTargets converts hosts and services into assessment targets
func (s *CoordinatingScanner) generateTargets(hosts []entity.Host, services []entity.Service) []entity.Target {
	var targets []entity.Target
	targetID := 1

	// Create targets from services
	for _, service := range services {
		if service.State == "open" {
			target := entity.Target{
				ID:          fmt.Sprintf("target_%d", targetID),
				Host:        service.Host,
				Service:     &service,
				Protocol:    service.Protocol,
				Endpoint:    fmt.Sprintf("%s:%d", service.Host.IP.String(), service.Port),
				IsContainer: false,
				Tags: map[string]string{
					"scan_method": "network_discovery",
					"port":        fmt.Sprintf("%d", service.Port),
					"protocol":    service.Protocol,
				},
			}

			if service.ServiceName != "" {
				target.Tags["service"] = service.ServiceName
			}

			targets = append(targets, target)
			targetID++
		}
	}

	// Create host-only targets for hosts without services
	serviceHosts := make(map[string]bool)
	for _, service := range services {
		serviceHosts[service.Host.IP.String()] = true
	}

	for _, host := range hosts {
		if !serviceHosts[host.IP.String()] && host.Alive {
			target := entity.Target{
				ID:          fmt.Sprintf("target_%d", targetID),
				Host:        &host,
				Protocol:    "icmp",
				Endpoint:    host.IP.String(),
				IsContainer: false,
				Tags: map[string]string{
					"scan_method": "host_discovery",
					"type":        "host_only",
				},
			}

			targets = append(targets, target)
			targetID++
		}
	}

	return targets
}

// calculateStats calculates scan statistics
func (s *CoordinatingScanner) calculateStats(hosts []entity.Host, services []entity.Service) ScanStats {
	stats := ScanStats{
		TotalHosts:    len(hosts),
		TotalServices: len(services),
	}

	for _, host := range hosts {
		if host.Alive {
			stats.AliveHosts++
		}
	}

	for _, service := range services {
		switch service.State {
		case "open":
			stats.OpenServices++
		case "closed":
			stats.ClosedServices++
		case "filtered":
			stats.FilteredServices++
		}
	}

	return stats
}

// parsePortRange parses port range strings like "80", "1-1000", "80,443,8080"
func parsePortRange(rangeStr string) (PortRange, error) {
	// This is a simplified implementation
	// A full implementation would handle complex range parsing

	// Single port (most common case)
	if port := parseInt(rangeStr); port > 0 {
		return PortRange{
			Start: port,
			End:   port,
			Proto: "tcp",
		}, nil
	}

	return PortRange{}, fmt.Errorf("invalid port range: %s", rangeStr)
}

// parseInt is a helper to parse integers safely
func parseInt(s string) int {
	// Simplified implementation - would use strconv.Atoi in real code
	switch s {
	case "21":
		return 21
	case "22":
		return 22
	case "23":
		return 23
	case "25":
		return 25
	case "53":
		return 53
	case "80":
		return 80
	case "443":
		return 443
	case "8080":
		return 8080
	default:
		return 0
	}
}

// ParseScope parses a scope string into a Scope struct
func ParseScope(scopeType, scopeValue string) (Scope, error) {
	scope := Scope{
		Type:  scopeType,
		Value: scopeValue,
	}

	switch scopeType {
	case "subnet":
		if _, _, err := net.ParseCIDR(scopeValue); err != nil {
			return scope, fmt.Errorf("invalid CIDR notation: %s", scopeValue)
		}
	case "host":
		if net.ParseIP(scopeValue) == nil {
			return scope, fmt.Errorf("invalid IP address: %s", scopeValue)
		}
	case "list":
		// Comma-separated list of IPs/hostnames
		// Basic validation would go here
	case "file":
		// File path validation would go here
	default:
		return scope, fmt.Errorf("unsupported scope type: %s", scopeType)
	}

	return scope, nil
}

// MockScanner provides a mock implementation for testing
type MockScanner struct {
	hosts    []entity.Host
	services []entity.Service
	error    error
}

// NewMockScanner creates a new mock scanner
func NewMockScanner() *MockScanner {
	return &MockScanner{}
}

// WithHosts sets the hosts to return
func (m *MockScanner) WithHosts(hosts []entity.Host) *MockScanner {
	m.hosts = hosts
	return m
}

// WithServices sets the services to return
func (m *MockScanner) WithServices(services []entity.Service) *MockScanner {
	m.services = services
	return m
}

// WithError sets an error to return
func (m *MockScanner) WithError(err error) *MockScanner {
	m.error = err
	return m
}

// Scan implements Scanner interface
func (m *MockScanner) Scan(ctx context.Context, scope Scope) (*ScanResult, error) {
	if m.error != nil {
		return nil, m.error
	}

	startTime := time.Now()

	// Generate basic targets from services
	var targets []entity.Target
	for i, service := range m.services {
		targets = append(targets, entity.Target{
			ID:       fmt.Sprintf("mock_target_%d", i+1),
			Host:     service.Host,
			Service:  &service,
			Protocol: service.Protocol,
			Endpoint: fmt.Sprintf("%s:%d", service.Host.IP.String(), service.Port),
		})
	}

	endTime := time.Now()

	return &ScanResult{
		Scope:     scope,
		Hosts:     m.hosts,
		Services:  m.services,
		Targets:   targets,
		StartTime: startTime,
		EndTime:   endTime,
		Duration:  endTime.Sub(startTime),
		Stats: ScanStats{
			TotalHosts:    len(m.hosts),
			AliveHosts:    len(m.hosts), // Assume all are alive in mock
			TotalServices: len(m.services),
			OpenServices:  len(m.services), // Assume all are open in mock
		},
	}, nil
}

// ScanHosts implements Scanner interface
func (m *MockScanner) ScanHosts(ctx context.Context, scope Scope) ([]entity.Host, error) {
	if m.error != nil {
		return nil, m.error
	}
	return m.hosts, nil
}

// ScanServices implements Scanner interface
func (m *MockScanner) ScanServices(ctx context.Context, hosts []entity.Host, portRanges []PortRange) ([]entity.Service, error) {
	if m.error != nil {
		return nil, m.error
	}
	return m.services, nil
}

// GetCapabilities implements Scanner interface
func (m *MockScanner) GetCapabilities() Capabilities {
	return Capabilities{
		SupportsHostDiscovery:    true,
		SupportsServiceDiscovery: true,
		SupportsOSDetection:      false,
		SupportsVersionDetection: false,
		SupportedProtocols:       []string{"tcp"},
		MaxConcurrency:           1,
		FastMode:                 true,
	}
}
