package protocol

import (
	"sort"
	"testing"

	"bytemomo/kraken/internal/domain"
)

func sortTags(tags []domain.Tag) {
	sort.Slice(tags, func(i, j int) bool {
		return string(tags[i]) < string(tags[j])
	})
}

func tagsEqual(a, b []domain.Tag) bool {
	if len(a) != len(b) {
		return false
	}
	sortTags(a)
	sortTags(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsTag(tags []domain.Tag, tag domain.Tag) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

func TestDeriveTagsFromService_TCPTransport(t *testing.T) {
	target := domain.HostPort{Host: "192.168.1.1", Port: 1883}
	tags := DeriveTagsFromService(target, "tcp", "", "", "")

	if !containsTag(tags, "transport:tcp") {
		t.Error("expected transport:tcp tag for TCP protocol")
	}
	if !containsTag(tags, "protocol:tcp") {
		t.Error("expected protocol:tcp tag for TCP protocol")
	}
}

func TestDeriveTagsFromService_UDPTransport(t *testing.T) {
	target := domain.HostPort{Host: "192.168.1.1", Port: 5683}
	tags := DeriveTagsFromService(target, "udp", "", "", "")

	if !containsTag(tags, "transport:udp") {
		t.Error("expected transport:udp tag for UDP protocol")
	}
	if containsTag(tags, "transport:tcp") {
		t.Error("should not have transport:tcp tag for UDP protocol")
	}
}

func TestDeriveTagsFromService_TLSOnlyPorts(t *testing.T) {
	tlsPorts := []uint16{443, 8883, 8884, 5684}

	for _, port := range tlsPorts {
		target := domain.HostPort{Host: "192.168.1.1", Port: port}
		tags := DeriveTagsFromService(target, "tcp", "", "", "")

		if !containsTag(tags, "transport:tls") {
			t.Errorf("port %d: expected transport:tls tag", port)
		}
		if containsTag(tags, "transport:tcp") {
			t.Errorf("port %d: should not have transport:tcp tag (TLS-only port)", port)
		}
		if containsTag(tags, "protocol:tcp") {
			t.Errorf("port %d: should not have protocol:tcp tag (TLS-only port)", port)
		}
	}
}

func TestDeriveTagsFromService_MQTTPorts(t *testing.T) {
	tests := []struct {
		port        uint16
		expectTLS   bool
		expectProto string
	}{
		{1883, false, "protocol:mqtt"},
		{8883, true, "protocol:mqtt"},
		{8884, true, "protocol:mqtt"},
	}

	for _, tc := range tests {
		target := domain.HostPort{Host: "192.168.1.1", Port: tc.port}
		tags := DeriveTagsFromService(target, "tcp", "", "", "")

		if !containsTag(tags, domain.Tag(tc.expectProto)) {
			t.Errorf("port %d: expected %s tag", tc.port, tc.expectProto)
		}
		if tc.expectTLS && !containsTag(tags, "supports:tls") {
			t.Errorf("port %d: expected supports:tls tag", tc.port)
		}
	}
}

func TestDeriveTagsFromService_CoAPPorts(t *testing.T) {
	tests := []struct {
		port      uint16
		expectTLS bool
	}{
		{5683, false},
		{5684, true},
	}

	for _, tc := range tests {
		target := domain.HostPort{Host: "192.168.1.1", Port: tc.port}
		tags := DeriveTagsFromService(target, "tcp", "", "", "")

		if !containsTag(tags, "protocol:coap") {
			t.Errorf("port %d: expected protocol:coap tag", tc.port)
		}
		if tc.expectTLS && !containsTag(tags, "supports:tls") {
			t.Errorf("port %d: expected supports:tls tag", tc.port)
		}
	}
}

func TestDeriveTagsFromService_HTTPPorts(t *testing.T) {
	tests := []struct {
		port      uint16
		expectTLS bool
	}{
		{80, false},
		{443, true},
	}

	for _, tc := range tests {
		target := domain.HostPort{Host: "192.168.1.1", Port: tc.port}
		tags := DeriveTagsFromService(target, "tcp", "", "", "")

		if !containsTag(tags, "protocol:http") {
			t.Errorf("port %d: expected protocol:http tag", tc.port)
		}
		if tc.expectTLS && !containsTag(tags, "supports:tls") {
			t.Errorf("port %d: expected supports:tls tag", tc.port)
		}
	}
}

func TestDeriveTagsFromService_ModbusPort(t *testing.T) {
	target := domain.HostPort{Host: "192.168.1.1", Port: 502}
	tags := DeriveTagsFromService(target, "tcp", "", "", "")

	if !containsTag(tags, "protocol:modbus") {
		t.Error("expected protocol:modbus tag for port 502")
	}
}

func TestDeriveTagsFromService_RTSPPorts(t *testing.T) {
	rtspPorts := []uint16{554, 8554}

	for _, port := range rtspPorts {
		target := domain.HostPort{Host: "192.168.1.1", Port: port}
		tags := DeriveTagsFromService(target, "tcp", "", "", "")

		if !containsTag(tags, "protocol:rtsp") {
			t.Errorf("port %d: expected protocol:rtsp tag", port)
		}
	}
}

func TestDeriveTagsFromService_ServiceNameKeywords(t *testing.T) {
	tests := []struct {
		svcName   string
		expectTag domain.Tag
	}{
		{"mqtt", "protocol:mqtt"},
		{"MQTT", "protocol:mqtt"},
		{"ssl/mqtt", "protocol:mqtt"},
		{"mosquitto", "protocol:mqtt"},
		{"rtsp", "protocol:rtsp"},
		{"coap", "protocol:coap"},
		{"http", "protocol:http"},
		{"modbus", "protocol:modbus"},
	}

	for _, tc := range tests {
		target := domain.HostPort{Host: "192.168.1.1", Port: 9999}
		tags := DeriveTagsFromService(target, "tcp", tc.svcName, "", "")

		if !containsTag(tags, tc.expectTag) {
			t.Errorf("service %q: expected %s tag", tc.svcName, tc.expectTag)
		}
	}
}

func TestDeriveTagsFromService_ProductKeywords(t *testing.T) {
	tests := []struct {
		product   string
		expectTag domain.Tag
	}{
		{"Mosquitto MQTT broker", "protocol:mqtt"},
		{"Eclipse Mosquitto", "protocol:mqtt"},
	}

	for _, tc := range tests {
		target := domain.HostPort{Host: "192.168.1.1", Port: 9999}
		tags := DeriveTagsFromService(target, "tcp", "", "", tc.product)

		if !containsTag(tags, tc.expectTag) {
			t.Errorf("product %q: expected %s tag", tc.product, tc.expectTag)
		}
	}
}

func TestDeriveTagsFromService_TLSTunnel(t *testing.T) {
	target := domain.HostPort{Host: "192.168.1.1", Port: 9999}
	tags := DeriveTagsFromService(target, "tcp", "", "ssl", "")

	if !containsTag(tags, "supports:tls") {
		t.Error("expected supports:tls tag when tunnel is ssl")
	}
}

func TestDeriveTagsFromService_SSLServicePrefix(t *testing.T) {
	target := domain.HostPort{Host: "192.168.1.1", Port: 9999}
	tags := DeriveTagsFromService(target, "tcp", "ssl/mqtt", "", "")

	if !containsTag(tags, "supports:tls") {
		t.Error("expected supports:tls tag for ssl/ service prefix")
	}
}

func TestDeriveTagsFromService_LocalService(t *testing.T) {
	localHosts := []string{"localhost", "127.0.0.1", "::1"}

	for _, host := range localHosts {
		target := domain.HostPort{Host: host, Port: 1883}
		tags := DeriveTagsFromService(target, "tcp", "", "", "")

		if !containsTag(tags, "service:local") {
			t.Errorf("host %q: expected service:local tag", host)
		}
	}
}

func TestDeriveTagsFromService_NonLocalService(t *testing.T) {
	target := domain.HostPort{Host: "192.168.1.1", Port: 1883}
	tags := DeriveTagsFromService(target, "tcp", "", "", "")

	if containsTag(tags, "service:local") {
		t.Error("should not have service:local tag for remote host")
	}
}

func TestContainsSvc(t *testing.T) {
	tests := []struct {
		svcLower string
		needle   string
		expected bool
	}{
		{"mqtt", "mqtt", true},
		{"ssl/mqtt", "mqtt", true},
		{"mqtt-broker", "mqtt", true},
		{"http", "mqtt", false},
		{"", "mqtt", false},
		{"mqtt", "", true},
	}

	for _, tc := range tests {
		result := containsSvc(tc.svcLower, tc.needle)
		if result != tc.expected {
			t.Errorf("containsSvc(%q, %q) = %v, want %v", tc.svcLower, tc.needle, result, tc.expected)
		}
	}
}

func TestDeriveTagsFromEtherCAT_BasicTags(t *testing.T) {
	slave := domain.EtherCATSlave{
		Position:  0,
		VendorID:  2,
		ProductCode: 0x12345678,
	}

	tags := DeriveTagsFromEtherCAT(slave)

	expectedTags := []domain.Tag{
		"protocol:ethercat",
		"transport:ethernet",
		"layer:datalink",
	}

	for _, expected := range expectedTags {
		if !containsTag(tags, expected) {
			t.Errorf("expected tag %s", expected)
		}
	}
}

func TestDeriveTagsFromEtherCAT_VendorTags(t *testing.T) {
	slave := domain.EtherCATSlave{
		Position:    0,
		VendorID:    2, // Beckhoff
		ProductCode: 0x12345678,
	}

	tags := DeriveTagsFromEtherCAT(slave)

	if !containsTag(tags, "vendor:0x00000002") {
		t.Error("expected vendor ID tag")
	}
	if !containsTag(tags, "vendor:beckhoff") {
		t.Error("expected vendor name tag for Beckhoff")
	}
	if !containsTag(tags, "product:0x12345678") {
		t.Error("expected product code tag")
	}
}

func TestDeriveTagsFromEtherCAT_UnknownVendor(t *testing.T) {
	slave := domain.EtherCATSlave{
		Position:    0,
		VendorID:    99999,
		ProductCode: 0x12345678,
	}

	tags := DeriveTagsFromEtherCAT(slave)

	if !containsTag(tags, "vendor:0x0001869f") {
		t.Error("expected vendor ID tag for unknown vendor")
	}
	// Should not have a vendor name tag
	for _, tag := range tags {
		if len(tag) > 7 && tag[:7] == "vendor:" && tag != "vendor:0x0001869f" {
			t.Errorf("unexpected vendor name tag: %s", tag)
		}
	}
}

func TestDeriveTagsFromEtherCAT_ZeroVendor(t *testing.T) {
	slave := domain.EtherCATSlave{
		Position:    0,
		VendorID:    0,
		ProductCode: 0,
	}

	tags := DeriveTagsFromEtherCAT(slave)

	// Should not have vendor or product tags when zero
	for _, tag := range tags {
		if len(tag) > 7 && tag[:7] == "vendor:" {
			t.Errorf("should not have vendor tag when vendorID is 0: %s", tag)
		}
		if len(tag) > 8 && tag[:8] == "product:" {
			t.Errorf("should not have product tag when productCode is 0: %s", tag)
		}
	}
}

func TestLookupVendorName(t *testing.T) {
	tests := []struct {
		vendorID uint32
		expected string
	}{
		{2, "beckhoff"},
		{34, "omron"},
		{106, "lenze"},
		{185, "schneider"},
		{201, "siemens"},
		{287, "abb"},
		{512, "rockwell"},
		{99999, ""},
	}

	for _, tc := range tests {
		result := lookupVendorName(tc.vendorID)
		if result != tc.expected {
			t.Errorf("lookupVendorName(%d) = %q, want %q", tc.vendorID, result, tc.expected)
		}
	}
}

func TestDerivePortStatusTags_Endpoint(t *testing.T) {
	// Only port 0 active (bit 4 set)
	portStatus := uint16(0x0010)
	tags := derivePortStatusTags(portStatus)

	if !containsTag(tags, "ports:1") {
		t.Error("expected ports:1 tag")
	}
	if !containsTag(tags, "topology:endpoint") {
		t.Error("expected topology:endpoint tag for single port")
	}
}

func TestDerivePortStatusTags_Passthrough(t *testing.T) {
	// Ports 0 and 1 active (bits 4 and 5 set)
	portStatus := uint16(0x0030)
	tags := derivePortStatusTags(portStatus)

	if !containsTag(tags, "ports:2") {
		t.Error("expected ports:2 tag")
	}
	if !containsTag(tags, "topology:passthrough") {
		t.Error("expected topology:passthrough tag for two ports")
	}
}

func TestDerivePortStatusTags_Junction(t *testing.T) {
	// Ports 0, 1, and 2 active (bits 4, 5, and 6 set)
	portStatus := uint16(0x0070)
	tags := derivePortStatusTags(portStatus)

	if !containsTag(tags, "ports:3") {
		t.Error("expected ports:3 tag")
	}
	if !containsTag(tags, "topology:junction") {
		t.Error("expected topology:junction tag for three+ ports")
	}
}

func TestDerivePortStatusTags_NoPorts(t *testing.T) {
	portStatus := uint16(0x0000)
	tags := derivePortStatusTags(portStatus)

	// Should not have any port or topology tags
	for _, tag := range tags {
		if len(tag) > 6 && tag[:6] == "ports:" {
			t.Errorf("should not have ports tag when no ports active: %s", tag)
		}
		if len(tag) > 9 && tag[:9] == "topology:" {
			t.Errorf("should not have topology tag when no ports active: %s", tag)
		}
	}
}
