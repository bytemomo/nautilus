module bytemomo/siren

go 1.25.1

require (
	bytemomo/trident v0.0.0
	github.com/pion/dtls/v3 v3.0.7
	github.com/sirupsen/logrus v1.9.3
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/transport/v3 v3.0.7 // indirect
	golang.org/x/crypto v0.43.0 // indirect
	golang.org/x/net v0.46.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
)

replace bytemomo/trident => ../trident
