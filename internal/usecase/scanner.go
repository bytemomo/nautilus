package usecase

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"bytemomo/orca/internal/domain"

	nmap "github.com/Ullaakut/nmap/v3"
)

type ScannerUC struct {
	EnableUDP      bool          // add -sU (UDP scan). Slower; default false.
	ServiceDetect  bool          // -sV (service/version detection). Recommended true.
	VersionLight   bool          // --version-light
	MinRate        int           // --min-rate <pkts/s>
	Timing         nmap.Timing   // e.g., nmap.TimingAggressive
	CommandTimeout time.Duration // overall timeout for the scan
}

// Execute scans the provided CIDRs and returns per-open-port targets with derived tags.
func (s ScannerUC) Execute(ctx context.Context, cidrs []string) ([]domain.ClassifiedTarget, error) {
	targets := sanitizeCIDRs(cidrs)
	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid CIDRs provided")
	}

	opts := []nmap.Option{
		nmap.WithTargets(targets...),
		nmap.WithSYNScan(),               // -sS (falls back to -sT if not privileged)
		nmap.WithDisabledDNSResolution(), // -n
	}

	if s.EnableUDP {
		opts = append(opts, nmap.WithUDPScan()) // -sU
	}
	if s.ServiceDetect {
		opts = append(opts, nmap.WithServiceInfo()) // -sV
		if s.VersionLight {
			opts = append(opts, nmap.WithVersionLight()) // --version-light
		}
	}
	if s.MinRate > 0 {
		opts = append(opts, nmap.WithMinRate(s.MinRate))
	}
	if s.Timing != 0 {
		opts = append(opts, nmap.WithTimingTemplate(s.Timing))
	}

	// Optional overall deadline for the process.
	if s.CommandTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.CommandTimeout)
		defer cancel()
	}

	scanner, err := nmap.NewScanner(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create nmap scanner: %w", err)
	}

	result, _, err := scanner.Run()
	if err != nil {
		return nil, fmt.Errorf("run nmap: %w", err)
	}

	// Produce ClassifiedTarget list from open ports and derived tags.
	var out []domain.ClassifiedTarget
	for _, h := range result.Hosts {
		host := pickHostAddress(h)
		if host == "" {
			continue
		}
		for _, p := range h.Ports {
			state := strings.ToLower(p.State.State) // e.g., "open"
			if !strings.HasPrefix(state, "open") {
				continue
			}
			t := domain.HostPort{Host: host, Port: uint16(p.ID)}
			tags := deriveTagsFromService(t, p.Protocol, p.Service.Name, p.Service.Tunnel)
			out = append(out, domain.ClassifiedTarget{Target: t, Tags: tags})
		}
	}
	return out, nil
}

/* ---------------- helpers ---------------- */

func sanitizeCIDRs(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, c := range in {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

func pickHostAddress(h nmap.Host) string {
	// Prefer IPv4
	for _, a := range h.Addresses {
		if a.AddrType == "ipv4" {
			return a.Addr
		}
	}
	for _, a := range h.Addresses {
		if a.AddrType == "ipv6" {
			return a.Addr
		}
	}
	if len(h.Addresses) > 0 {
		return h.Addresses[0].Addr
	}
	return ""
}

func deriveTagsFromService(t domain.HostPort, proto, svcName, tunnel string) []domain.Tag {
	tagset := map[domain.Tag]struct{}{}

	// Transport/protocol baseline
	if strings.EqualFold(proto, "udp") {
		tagset[domain.Tag("transport:udp")] = struct{}{}
	} else {
		tagset[domain.Tag("transport:tcp")] = struct{}{}
		tagset[domain.Tag("protocol:tcp")] = struct{}{}
	}

	// TLS detection
	svcLower := strings.ToLower(svcName)
	if tunnel == "ssl" || strings.HasPrefix(svcLower, "ssl/") ||
		t.Port == 443 || t.Port == 8883 || t.Port == 5684 {
		tagset[domain.Tag("supports:tls")] = struct{}{}
	}

	// Service→protocol tags
	switch {
	case containsSvc(svcLower, "mqtt"):
		tagset[domain.Tag("protocol:mqtt")] = struct{}{}
	case containsSvc(svcLower, "coap"):
		tagset[domain.Tag("protocol:coap")] = struct{}{}
	case containsSvc(svcLower, "http"):
		tagset[domain.Tag("protocol:http")] = struct{}{}
	case containsSvc(svcLower, "modbus"):
		tagset[domain.Tag("protocol:modbus")] = struct{}{}
	}

	// Port fallbacks (cheap heuristics)
	switch t.Port {
	case 1883:
		tagset[domain.Tag("protocol:mqtt")] = struct{}{}
	case 8883:
		tagset[domain.Tag("protocol:mqtt")] = struct{}{}
		tagset[domain.Tag("supports:tls")] = struct{}{}
	case 5683:
		tagset[domain.Tag("protocol:coap")] = struct{}{}
	case 5684:
		tagset[domain.Tag("protocol:coap")] = struct{}{}
		tagset[domain.Tag("supports:tls")] = struct{}{}
	case 502:
		tagset[domain.Tag("protocol:modbus")] = struct{}{}
	case 80:
		tagset[domain.Tag("protocol:http")] = struct{}{}
	case 443:
		tagset[domain.Tag("protocol:http")] = struct{}{}
		tagset[domain.Tag("supports:tls")] = struct{}{}
	}

	var tags []domain.Tag
	for tg := range tagset {
		tags = append(tags, tg)
	}
	return tags
}

func containsSvc(svcLower, needle string) bool {
	return svcLower == needle ||
		strings.Contains(svcLower, needle) ||
		strings.HasSuffix(svcLower, "/"+needle)
}

func key(hp domain.HostPort) string { return hp.Host + ":" + strconv.Itoa(int(hp.Port)) }
