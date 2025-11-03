package domain

import (
	cnd "bytemomo/trident/conduit"
	"fmt"
	"time"
)

type ModuleType string

const (
	Native ModuleType = "native"
	Lib    ModuleType = "lib"
	Grpc   ModuleType = "grpc"
	Cli    ModuleType = "cli"
)

type ModuleApiVersion string

const (
	ModuleV1 ModuleApiVersion = "v1"
	ModuleV2 ModuleApiVersion = "v2"
)

type Module struct {
	ModuleID     string        `yaml:"id"`
	RequiredTags []string      `yaml:"required_tags,omitempty"`
	MaxDuration  time.Duration `yaml:"max_duration,omitempty"`
	Type         ModuleType    `yaml:"type"` // native|lib|grpc|cli

	ExecConfig struct {
		ABI *struct {
			Version     ModuleApiVersion `yaml:"api"`
			LibraryPath string           `yaml:"library_path"`
			Symbol      string           `yaml:"symbol"`
		} `yaml:"abi,omitempty"`

		GRPC *struct {
			ServerAddr  string         `yaml:"server_addr"`
			DialTimeout *time.Duration `yaml:"dial_timeout,omitempty"`
		} `yaml:"grpc,omitempty"`

		CLI *struct {
			Executable string `yaml:"exec"`
			Command    string `yaml:"command"`
		} `yaml:"cli,omitempty"`

		Conduit *struct {
			Kind  cnd.Kind    `yaml:"kind"`
			Stack []LayerHint `yaml:"stack,omitempty"`
		} `yaml:"conduit"`

		Params map[string]any `yaml:"params,omitempty"`
	} `yaml:"exec"`
}

type LayerHint struct {
	Name   string         `yaml:"name"`
	Params map[string]any `yaml:"params,omitempty"`
}

func (m *Module) Validate() error {
	if m.ModuleID == "" {
		return fmt.Errorf("module ID is required")
	}

	// Check that exactly one execution type is configured
	// Note: Conduit is transport configuration, not an execution type
	hasABI := m.ExecConfig.ABI != nil
	hasGRPC := m.ExecConfig.GRPC != nil
	hasCLI := m.ExecConfig.CLI != nil

	count := 0
	if hasABI {
		count++
	}
	if hasGRPC {
		count++
	}
	if hasCLI {
		count++
	}

	if count == 0 {
		return fmt.Errorf("module must specify one execution type (abi, grpc, or cli)")
	}
	if count > 1 {
		return fmt.Errorf("module can only specify one execution type")
	}

	// Validate ABI config
	// ABI supports both V1 and V2
	if hasABI {
		if m.ExecConfig.ABI.Version != "v1" && m.ExecConfig.ABI.Version != "v2" {
			return fmt.Errorf("abi.version is required and accept only two valid values: v1 or v2")
		}

		if m.ExecConfig.ABI.LibraryPath == "" {
			return fmt.Errorf("abi.library_path is required")
		}
		if m.ExecConfig.ABI.Symbol == "" {
			return fmt.Errorf("abi.symbol is required")
		}
		if m.Type != Native && m.Type != Lib {
			return fmt.Errorf("abi execution requires type 'native' or 'lib'")
		}
		// ABI works with both V1 and V2 - no version restriction
	}

	// Validate GRPC config
	if hasGRPC {
		if m.ExecConfig.GRPC.ServerAddr == "" {
			return fmt.Errorf("grpc.server_addr is required")
		}
		if m.Type != Grpc {
			return fmt.Errorf("grpc execution requires type 'grpc'")
		}
	}

	// Validate CLI config
	if hasCLI {
		if m.ExecConfig.CLI.Command == "" {
			return fmt.Errorf("cli.path is required")
		}
	}

	// Validate Conduit config (if present)
	// Conduit is optional and only used in V2 execution
	// For V1 modules with conduit config, it will be ignored (allows transition)
	if m.ExecConfig.Conduit != nil {
		if m.ExecConfig.Conduit.Kind == 0 {
			return fmt.Errorf("conduit.kind is required when conduit is specified")
		}
		// Conduit is only meaningful for V2, but we allow it in V1 for transition
		// (it will simply be ignored by V1 executors)
	}

	return nil
}
