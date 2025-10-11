package usecase

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"bytemomo/orca/internal/domain"

	nmap "github.com/Ullaakut/nmap/v3"
	log "github.com/sirupsen/logrus"
)

type ScannerUC struct {
	EnableUDP         bool
	ServiceDetect     bool
	VersionLight      bool
	VersionAll        bool
	MinRate           int
	Timing            string
	CommandTimeout    time.Duration
	SkipHostDiscovery bool
	OpenOnly          bool
	Ports             []string
}

func (s ScannerUC) Execute(ctx context.Context, cidrs []string) ([]domain.ClassifiedTarget, error) {
	targets := sanitizeCIDRs(cidrs)
	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid CIDRs provided")
	}

	log.WithFields(log.Fields{
		"targets": targets,
		"ports":   s.Ports,
	}).Info("Starting nmap scan")

	opts := []nmap.Option{
		nmap.WithTargets(targets...),
		nmap.WithDisabledDNSResolution(),
	}

	if len(s.Ports) != 0 {
		opts = append(opts, nmap.WithPorts(strings.Join(s.Ports, ",")))
	}

	if s.OpenOnly {
		opts = append(opts, nmap.WithOpenOnly()) // --open
	}

	if s.SkipHostDiscovery {
		opts = append(opts, nmap.WithSkipHostDiscovery()) // -Pn
	}

	if s.EnableUDP {
		opts = append(opts, nmap.WithUDPScan()) // -sU
	}

	if s.ServiceDetect {
		opts = append(opts, nmap.WithServiceInfo()) // -sV
		if s.VersionAll {
			opts = append(opts, nmap.WithVersionAll()) // --version-all
		} else if s.VersionLight {
			opts = append(opts, nmap.WithVersionLight()) // --version-light
		}
	}

	if s.MinRate > 0 {
		opts = append(opts, nmap.WithMinRate(s.MinRate))
	}

	switch s.Timing {
	case "T0": // slowest
		opts = append(opts, nmap.WithTimingTemplate(nmap.TimingSlowest))
	case "T1": // sneaky
		opts = append(opts, nmap.WithTimingTemplate(nmap.TimingSneaky))
	case "T2": // sneaky
		opts = append(opts, nmap.WithTimingTemplate(nmap.TimingPolite))
	case "T3": // sneaky
		opts = append(opts, nmap.WithTimingTemplate(nmap.TimingNormal))
	case "T4": // sneaky
		opts = append(opts, nmap.WithTimingTemplate(nmap.TimingAggressive))
	case "T5": // sneaky
		opts = append(opts, nmap.WithTimingTemplate(nmap.TimingFastest))
	default:
		log.Errorf("Wrong timing for scanner: %s", s.Timing)
	}

	// Optional overall deadline for the process.
	if s.CommandTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.CommandTimeout)
		defer cancel()
	}

	log.WithField("options", fmt.Sprintf("%v", opts)).Debug("Creating nmap scanner")
	scanner, err := nmap.NewScanner(ctx, opts...)
	if err != nil {
		log.WithError(err).Error("Failed to create nmap scanner")
		return nil, fmt.Errorf("create nmap scanner: %w", err)
	}

	log.Info("Executing nmap scan")
	result, warnings, err := scanner.Run()
	if err != nil {
		log.WithError(err).Error("Nmap scan failed")
		return nil, fmt.Errorf("run nmap: %w", err)
	}
	if warnings != nil && len(*warnings) > 0 {
		log.WithField("warnings", *warnings).Warn("Nmap scan produced warnings")
	}

	log.WithFields(log.Fields{
		"hosts":   len(result.Hosts),
		"runtime": result.Stats.Finished.TimeStr,
		"summary": result.Stats.Finished.Summary,
	}).Info("Nmap scan complete")

	var out []domain.ClassifiedTarget
	seen := make(map[string]struct{})

	for _, h := range result.Hosts {
		host := pickHostAddress(h)
		if host == "" {
			continue
		}

		for _, p := range h.Ports {

			state := strings.ToLower(p.State.State)
			if !strings.HasPrefix(state, "open") {
				continue
			}

			t := domain.HostPort{Host: host, Port: uint16(p.ID)}
			tags := deriveTagsFromService(t, p.Protocol, p.Service.Name, p.Service.Tunnel, p.Service.Product)

			log.WithFields(log.Fields{
				"host": host,
				"port": p.ID,
				"svc":  p.Service.Name,
				"tags": tags,
			}).Debug("Classified target")

			ct := domain.ClassifiedTarget{Target: t, Tags: tags}
			out = append(out, ct)
			seen[key(t)] = struct{}{}
		}
	}
	log.WithField("count", len(out)).Info("Finished classifying targets")
	return out, nil
}

// ---------------- helpers ----------------

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

func deriveTagsFromService(t domain.HostPort, proto, svcName, tunnel, product string) []domain.Tag {
	tagset := map[domain.Tag]struct{}{}

	// Transport/protocol baseline
	if strings.EqualFold(proto, "udp") {
		tagset[domain.Tag("transport:udp")] = struct{}{}
	} else {
		tagset[domain.Tag("transport:tcp")] = struct{}{}
		tagset[domain.Tag("protocol:tcp")] = struct{}{}
	}

	svcLower := strings.ToLower(svcName)
	prodLower := strings.ToLower(product)

	// TLS detection
	if tunnel == "ssl" || strings.HasPrefix(svcLower, "ssl/") ||
		t.Port == 443 || t.Port == 8883 || t.Port == 5684 {
		tagset[domain.Tag("supports:tls")] = struct{}{}
	}

	// Service→protocol tags
	switch {
	case containsSvc(svcLower, "mqtt") || strings.Contains(prodLower, "mosquitto") || strings.Contains(prodLower, "mqtt"):
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
