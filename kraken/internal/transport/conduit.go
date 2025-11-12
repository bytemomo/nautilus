package transport

import (
	"fmt"
	"strings"

	"bytemomo/kraken/internal/domain"

	cnd "bytemomo/trident/conduit"
	tridentlog "bytemomo/trident/conduit/logging"
	tridenttransport "bytemomo/trident/conduit/transport"
	tlscond "bytemomo/trident/conduit/transport/tls"
)

// BuildStreamConduit builds the requested stack of stream layers.
func BuildStreamConduit(addr string, stack []domain.LayerHint) (cnd.Conduit[cnd.Stream], error) {
	var current cnd.Conduit[cnd.Stream] = tridenttransport.TCP(addr)

	for _, layer := range stack {
		switch strings.ToLower(layer.Name) {
		case "", "tcp":
			continue
		case "tls":
			tlsConfig := BuildTLSConfig(layer.Params)
			current = tlscond.NewTlsClient(current, tlsConfig)
		default:
			return nil, fmt.Errorf("unknown stream layer: %s", layer.Name)
		}
	}

	return tridentlog.NewLoggingConduit(addr, current), nil
}

// BuildDatagramConduit builds the requested stack of datagram layers.
func BuildDatagramConduit(addr string, stack []domain.LayerHint) (cnd.Conduit[cnd.Datagram], error) {
	var current cnd.Conduit[cnd.Datagram] = tridenttransport.UDP(addr)

	for _, layer := range stack {
		switch strings.ToLower(layer.Name) {
		case "", "udp":
			continue
		case "dtls":
			dtlsConfig := BuildDTLSConfig(layer.Params)
			current = tlscond.NewDtlsClient(current, dtlsConfig)
		default:
			return nil, fmt.Errorf("unknown datagram layer: %s", layer.Name)
		}
	}

	return tridentlog.NewLoggingConduit(addr, current), nil
}
