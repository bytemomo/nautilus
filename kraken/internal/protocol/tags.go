package protocol

import (
	"fmt"
	"strings"

	"bytemomo/kraken/internal/domain"
)

var (
	// serviceKeywords maps keywords found in service names or products to their corresponding protocol tags.
	serviceKeywords = map[string]domain.Tag{
		"mqtt":      "protocol:mqtt",
		"mosquitto": "protocol:mqtt",
		"rtsp":      "protocol:rtsp",
		"coap":      "protocol:coap",
		"http":      "protocol:http",
		"modbus":    "protocol:modbus",
	}

	// portProtocolTags maps port numbers to a list of tags that should be applied.
	portProtocolTags = map[uint16][]domain.Tag{
		80:   {"protocol:http"},
		443:  {"protocol:http", "supports:tls"},
		502:  {"protocol:modbus"},
		554:  {"protocol:rtsp"},
		8554: {"protocol:rtsp"},
		1883: {"protocol:mqtt"},
		5683: {"protocol:coap"},
		5684: {"protocol:coap", "supports:tls"},
		8883: {"protocol:mqtt", "supports:tls"},
		8884: {"protocol:mqtt", "supports:tls"},
	}

	// tlsOnlyPorts are ports that require TLS - they should not get transport:tcp tag
	tlsOnlyPorts = map[uint16]struct{}{
		443:  {},
		8883: {},
		8884: {},
		5684: {},
	}
)

// DeriveTagsFromService derives a set of tags for a given target based on its port, protocol, and service information.
// It uses a data-driven approach to identify protocols and transport details, making it easily extensible.
func DeriveTagsFromService(t domain.HostPort, proto, svcName, tunnel, product string) []domain.Tag {
	tagSet := make(map[domain.Tag]struct{})

	// Add basic transport tags
	if strings.EqualFold(proto, "udp") {
		tagSet["transport:udp"] = struct{}{}
	} else {
		// Check if this is a TLS-only port
		if _, isTLSOnly := tlsOnlyPorts[t.Port]; isTLSOnly {
			tagSet["transport:tls"] = struct{}{}
		} else {
			tagSet["transport:tcp"] = struct{}{}
			tagSet["protocol:tcp"] = struct{}{}
		}
	}

	// Add tags based on service name and product keywords
	svcLower := strings.ToLower(svcName)
	prodLower := strings.ToLower(product)
	for keyword, tag := range serviceKeywords {
		if containsSvc(svcLower, keyword) || strings.Contains(prodLower, keyword) {
			tagSet[tag] = struct{}{}
		}
	}

	// Add tags based on well-known ports
	if tags, ok := portProtocolTags[t.Port]; ok {
		for _, tag := range tags {
			tagSet[tag] = struct{}{}
		}
	}

	// Add TLS tag based on tunnel information or common TLS ports
	if tunnel == "ssl" || strings.HasPrefix(svcLower, "ssl/") {
		tagSet["supports:tls"] = struct{}{}
	}

	// Add local service tag
	if t.Host == "localhost" || t.Host == "127.0.0.1" || t.Host == "::1" {
		tagSet["service:local"] = struct{}{}
	}

	// Convert set to slice
	tags := make([]domain.Tag, 0, len(tagSet))
	for tag := range tagSet {
		tags = append(tags, tag)
	}
	return tags
}

// containsSvc checks if the service name contains a specific keyword.
func containsSvc(svcLower, needle string) bool {
	return svcLower == needle ||
		strings.Contains(svcLower, needle) ||
		strings.HasSuffix(svcLower, "/"+needle)
}

// DeriveTagsFromEtherCAT derives tags for an EtherCAT slave device.
func DeriveTagsFromEtherCAT(slave domain.EtherCATSlave) []domain.Tag {
	tags := []domain.Tag{
		"protocol:ethercat",
		"transport:ethernet",
		"layer:datalink",
	}

	// Add vendor/product tags from vendor database
	vendorTags := deriveVendorTags(slave)
	tags = append(tags, vendorTags...)

	// Derive port status tags (from DL Status register)
	portTags := derivePortStatusTags(slave.PortStatus)
	tags = append(tags, portTags...)

	return tags
}

// deriveVendorTags generates vendor and product tags.
func deriveVendorTags(slave domain.EtherCATSlave) []domain.Tag {
	var tags []domain.Tag

	if slave.VendorID != 0 {
		tags = append(tags, domain.Tag(fmt.Sprintf("vendor:0x%08x", slave.VendorID)))

		if name := lookupVendorName(slave.VendorID); name != "" {
			tags = append(tags, domain.Tag(fmt.Sprintf("vendor:%s", name)))
		}
	}

	if slave.ProductCode != 0 {
		tags = append(tags, domain.Tag(fmt.Sprintf("product:0x%08x", slave.ProductCode)))
	}

	return tags
}

// lookupVendorName returns a human-readable vendor name for known vendor IDs.
func lookupVendorName(vendorID uint32) string {
	// Common EtherCAT vendor IDs - extended list
	vendors := map[uint32]string{
		2:    "beckhoff",
		34:   "omron",
		106:  "lenze",
		185:  "schneider",
		218:  "keb",
		1337: "delta",
		116:  "yaskawa",
		159:  "rexroth",
		201:  "siemens",
		89:   "hitachi",
		144:  "kuka",
		287:  "abb",
		341:  "mitsubishi",
		442:  "panasonic",
		512:  "rockwell",
		603:  "festo",
		678:  "smc",
		756:  "phoenix",
		823:  "wago",
		891:  "pilz",
		967:  "sick",
		1024: "turck",
		1156: "ifm",
		1289: "balluff",
		1423: "pepperl+fuchs",
		1567: "baumer",
		1698: "keyence",
		1834: "cognex",
		1978: "banner",
		2145: "datalogic",
	}
	return vendors[vendorID]
}

// derivePortStatusTags derives tags from DL Status register port states.
func derivePortStatusTags(portStatus uint16) []domain.Tag {
	var tags []domain.Tag

	// Count active ports (bits 4-7 indicate port link status)
	activeCount := 0
	for i := 0; i < 4; i++ {
		if (portStatus>>uint(4+i))&1 != 0 {
			activeCount++
		}
	}

	if activeCount > 0 {
		tags = append(tags, domain.Tag(fmt.Sprintf("ports:%d", activeCount)))
	}

	// Topology hints based on port configuration
	switch activeCount {
	case 1:
		tags = append(tags, "topology:endpoint")
	case 2:
		tags = append(tags, "topology:passthrough")
	default:
		if activeCount > 2 {
			tags = append(tags, "topology:junction")
		}
	}

	return tags
}
