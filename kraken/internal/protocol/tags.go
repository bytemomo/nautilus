package protocol

import (
	"strings"

	"bytemomo/kraken/internal/domain"
)

// DeriveTagsFromService derives tags from a service.
func DeriveTagsFromService(t domain.HostPort, proto, svcName, tunnel, product string) []domain.Tag {
	tagset := map[domain.Tag]struct{}{}

	if t.Host == "localhost" || t.Host == "127.0.0.1" || t.Host == "::1" {
		tagset[domain.Tag("service:local")] = struct{}{}
	}

	if strings.EqualFold(proto, "udp") {
		tagset[domain.Tag("transport:udp")] = struct{}{}
	} else {
		tagset[domain.Tag("transport:tcp")] = struct{}{}
		tagset[domain.Tag("protocol:tcp")] = struct{}{}
	}

	svcLower := strings.ToLower(svcName)
	prodLower := strings.ToLower(product)

	if tunnel == "ssl" || strings.HasPrefix(svcLower, "ssl/") ||
		t.Port == 443 || t.Port == 8883 || t.Port == 5684 {
		tagset[domain.Tag("supports:tls")] = struct{}{}
	}

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
