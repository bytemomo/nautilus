package scanner

import (
	"testing"

	"bytemomo/kraken/internal/domain"

	"github.com/sirupsen/logrus"
)

func TestNewScannerNmap(t *testing.T) {
	log := logrus.NewEntry(logrus.New())

	cfg := &domain.ScannerConfig{
		Type: "nmap",
		Nmap: &domain.NmapScannerConfig{
			Ports: []string{"22", "80", "443"},
		},
	}

	s, err := NewScanner(log, cfg, []string{"192.168.1.0/24"})
	if err != nil {
		t.Fatalf("NewScanner returned error: %v", err)
	}

	if s.Type() != ScannerTypeNmap {
		t.Errorf("expected type %q, got %q", ScannerTypeNmap, s.Type())
	}

	nmap, ok := s.(*NmapScanner)
	if !ok {
		t.Fatalf("expected *NmapScanner, got %T", s)
	}

	if len(nmap.Targets) != 1 || nmap.Targets[0] != "192.168.1.0/24" {
		t.Errorf("unexpected targets: %v", nmap.Targets)
	}

	if len(nmap.Config.Ports) != 3 {
		t.Errorf("expected 3 ports, got %d", len(nmap.Config.Ports))
	}
}

func TestNewScannerDefaultType(t *testing.T) {
	log := logrus.NewEntry(logrus.New())

	// Empty type should default to nmap
	cfg := &domain.ScannerConfig{}

	s, err := NewScanner(log, cfg, []string{"10.0.0.1"})
	if err != nil {
		t.Fatalf("NewScanner returned error: %v", err)
	}

	if s.Type() != ScannerTypeNmap {
		t.Errorf("expected type %q, got %q", ScannerTypeNmap, s.Type())
	}
}

func TestNewScannerEtherCAT(t *testing.T) {
	log := logrus.NewEntry(logrus.New())

	cfg := &domain.ScannerConfig{
		Type:     "ethercat",
		EtherCAT: &domain.EtherCATScannerConfig{Interface: "eth0"},
	}

	s, err := NewScanner(log, cfg, nil)
	if err != nil {
		t.Fatalf("NewScanner returned error: %v", err)
	}

	if s.Type() != ScannerTypeEtherCAT {
		t.Errorf("expected type %q, got %q", ScannerTypeEtherCAT, s.Type())
	}
}

func TestNewScannerEtherCATMissingConfig(t *testing.T) {
	log := logrus.NewEntry(logrus.New())

	cfg := &domain.ScannerConfig{
		Type: "ethercat",
		// EtherCAT config is nil
	}

	_, err := NewScanner(log, cfg, nil)
	if err == nil {
		t.Fatal("expected error for missing ethercat config")
	}
}

func TestNewScannerUnknownType(t *testing.T) {
	log := logrus.NewEntry(logrus.New())

	cfg := &domain.ScannerConfig{Type: "unknown"}

	_, err := NewScanner(log, cfg, nil)
	if err == nil {
		t.Fatal("expected error for unknown scanner type")
	}
}

func TestNewScannerNilConfig(t *testing.T) {
	log := logrus.NewEntry(logrus.New())

	_, err := NewScanner(log, nil, nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
}
