module bytemomo/siren

go 1.25.1

require (
	bytemomo/trident v0.0.0
	github.com/google/gopacket v1.1.19
	github.com/mdlayher/arp v0.0.0-20220512170110-6706a2966875
	github.com/miekg/dns v1.1.62
	github.com/pion/dtls/v3 v3.0.7
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/mdlayher/ethernet v0.0.0-20220221185849-529eae5b6118 // indirect
	github.com/mdlayher/packet v1.1.2 // indirect
	github.com/mdlayher/raw v0.1.0 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/transport/v3 v3.0.7 // indirect
	golang.org/x/crypto v0.32.0 // indirect
	golang.org/x/mod v0.22.0 // indirect
	golang.org/x/net v0.34.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/sys v0.29.0 // indirect
	golang.org/x/tools v0.28.0 // indirect
)

replace bytemomo/trident => ../trident
