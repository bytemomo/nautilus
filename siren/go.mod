module bytemomo/siren

go 1.25.1

require (
	bytemomo/trident v0.0.0
	github.com/mdlayher/arp v0.0.0-20220512170110-6706a2966875
	github.com/mdlayher/ethernet v0.0.0-20220221185849-529eae5b6118
	github.com/miekg/dns v1.1.68
	github.com/pion/dtls/v3 v3.0.7
	github.com/sirupsen/logrus v1.9.3
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/cilium/ebpf v0.20.0 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/mdlayher/packet v1.1.2 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/transport/v3 v3.0.7 // indirect
	golang.org/x/crypto v0.43.0 // indirect
	golang.org/x/mod v0.29.0 // indirect
	golang.org/x/net v0.46.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
	golang.org/x/tools v0.38.0 // indirect
)

replace bytemomo/trident => ../trident
