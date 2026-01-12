package domain

import "testing"

func TestHostPortTarget(t *testing.T) {
	hp := HostPort{Host: "192.168.1.1", Port: 8080}

	if hp.Kind() != TargetKindNetwork {
		t.Errorf("expected kind %q, got %q", TargetKindNetwork, hp.Kind())
	}
	if hp.String() != "192.168.1.1:8080" {
		t.Errorf("expected string %q, got %q", "192.168.1.1:8080", hp.String())
	}
	if hp.Key() != "192.168.1.1:8080" {
		t.Errorf("expected key %q, got %q", "192.168.1.1:8080", hp.Key())
	}
}

func TestHostPortIPv6(t *testing.T) {
	hp := HostPort{Host: "::1", Port: 443}

	if hp.String() != "[::1]:443" {
		t.Errorf("expected string %q, got %q", "[::1]:443", hp.String())
	}
}

func TestEtherCATSlaveTarget(t *testing.T) {
	slave := EtherCATSlave{
		Interface:   "eth0",
		Position:    5,
		StationAddr: 1001,
		VendorID:    0x00000002,
		ProductCode: 0x12345678,
	}

	if slave.Kind() != TargetKindEtherCAT {
		t.Errorf("expected kind %q, got %q", TargetKindEtherCAT, slave.Kind())
	}
	if slave.String() != "ethercat://eth0/slave/5" {
		t.Errorf("expected string %q, got %q", "ethercat://eth0/slave/5", slave.String())
	}
	if slave.Key() != "ecat:eth0:5" {
		t.Errorf("expected key %q, got %q", "ecat:eth0:5", slave.Key())
	}
}

func TestTargetInterface(t *testing.T) {
	targets := []Target{
		HostPort{Host: "10.0.0.1", Port: 22},
		EtherCATSlave{Interface: "enp3s0", Position: 0},
	}

	kinds := make(map[TargetKind]int)
	for _, tgt := range targets {
		kinds[tgt.Kind()]++
		_ = tgt.String()
		_ = tgt.Key()
	}

	if kinds[TargetKindNetwork] != 1 {
		t.Errorf("expected 1 network target, got %d", kinds[TargetKindNetwork])
	}
	if kinds[TargetKindEtherCAT] != 1 {
		t.Errorf("expected 1 ethercat target, got %d", kinds[TargetKindEtherCAT])
	}
}
