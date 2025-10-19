package module

import (
	cnd "bytemomo/trident/conduit"
	"time"
)

type ModuleType string

const (
    Native ModuleType = "native"
    Lib     ModuleType = "lib"
    Grpc    ModuleType = "grpc"
)

type ModuleApiVersion uint8

const (
    ModuleV1 ModuleApiVersion = iota
    ModuleV2
)

type Module struct {
	ModuleID     string          `yaml:"id"`
	RequiredTags []string        `yaml:"required_tags,omitempty"`
	MaxDuration  time.Duration   `yaml:"max_duration,omitempty"`
	Type         ModuleType      `yaml:"type"`     // native|lib|grpc|cli
	Version      ModuleApiVersion `yaml:"api"`     // v1|v2

	ExecConfig struct {
		ABI *struct {
			LibraryPath string `yaml:"library_path"`
			Symbol      string `yaml:"symbol"`
		} `yaml:"abi,omitempty"`

		GRPC *struct {
			ServerAddr  string         `yaml:"server_addr"`
			DialTimeout *time.Duration `yaml:"dial_timeout,omitempty"`
		} `yaml:"grpc,omitempty"`

		CLI *struct { // Only runnable with V1
			Path string   `yaml:"path"`
			Args []string `yaml:"args,omitempty"`
		} `yaml:"cli,omitempty"`

		Conduit *struct {
			Kind  cnd.Kind   `yaml:"kind"`
			Stack []LayerHint `yaml:"stack,omitempty"`
		} `yaml:"conduit"`

		Params map[string]any `yaml:"params,omitempty"`
	} `yaml:"exec"`
}

type LayerHint struct {
	Name   string         `yaml:"name"`
	Params map[string]any `yaml:"params,omitempty"`
}
