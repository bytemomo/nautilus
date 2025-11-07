package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"bytemomo/siren/ebpf"
)

// Target parsing logic
type targetParser func(string) (ebpf.Target, error)

var targetParsers = map[string]targetParser{
	"mac":      parseMacTarget,
	"ethercat": parseEthercatTarget,
	"ec":       parseEthercatTarget,
	"ip_port":  parseIPPortTarget,
	"ip":       parseIPTarget,
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
			return nil, fmt.Errorf("target %d (%q): %w", i+1, raw, err)
		}
		if tgt.Kind != ebpf.TargetKindAny {
			targets = append(targets, tgt)
		}
	}
	return targets, nil
}

func parseTargetEntry(raw string) (ebpf.Target, error) {
	lower := strings.ToLower(raw)
	for prefix, parser := range targetParsers {
		if strings.HasPrefix(lower, prefix+":") || strings.HasPrefix(lower, prefix+"=") {
			val := raw[strings.IndexAny(raw, ":=")+1:]
			return parser(strings.TrimSpace(val))
		}
	}
	// Fallback for simple formats
	if looksLikeMAC(raw) {
		return parseMacTarget(raw)
	}
	if strings.Count(raw, ":") == 1 && !strings.Contains(raw, "[") { // Basic ip:port check
		if tgt, err := parseIPPortTarget(raw); err == nil {
			return tgt, nil
		}
	}
	return parseIPTarget(raw) // Default to IP target
}

func parseIPTarget(val string) (ebpf.Target, error) {
	ip := net.ParseIP(strings.TrimSpace(val))
	if ip == nil {
		return ebpf.Target{}, fmt.Errorf("invalid IP address")
	}
	v4 := ip.To4()
	if v4 == nil {
		return ebpf.Target{}, fmt.Errorf("only IPv4 targets are supported")
	}
	return ebpf.Target{Kind: ebpf.TargetKindIP, IP: v4}, nil
}

func parseIPPortTarget(val string) (ebpf.Target, error) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(val))
	if err != nil {
		return ebpf.Target{}, fmt.Errorf("invalid ip:port format")
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return ebpf.Target{}, fmt.Errorf("invalid port: %w", err)
	}
	tgt, err := parseIPTarget(host)
	if err != nil {
		return ebpf.Target{}, err
	}
	tgt.Kind = ebpf.TargetKindIPPort
	tgt.Port = uint16(port)
	return tgt, nil
}

func parseMacTarget(val string) (ebpf.Target, error) {
	mac, err := net.ParseMAC(strings.TrimSpace(val))
	if err != nil {
		return ebpf.Target{}, fmt.Errorf("invalid MAC address: %w", err)
	}
	var arr [6]byte
	copy(arr[:], mac)
	return ebpf.Target{Kind: ebpf.TargetKindMAC, MAC: arr}, nil
}

func parseEthercatTarget(val string) (ebpf.Target, error) {
	id, err := strconv.ParseUint(strings.TrimSpace(val), 0, 16)
	if err != nil {
		return ebpf.Target{}, fmt.Errorf("invalid EtherCAT slave ID: %w", err)
	}
	return ebpf.Target{Kind: ebpf.TargetKindEtherCAT, EtherCAT: uint16(id)}, nil
}

func looksLikeMAC(s string) bool {
	return len(s) == 17 && strings.Count(s, ":") == 5
}
