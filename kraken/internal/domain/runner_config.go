package domain

import "fmt"

// CLIConfig is the configuration for a CLI module.
type CLIConfig struct {
	Executable string `yaml:"executable"`
	Command    string `yaml:"command"`
}

// ABIConfig is the configuration for an ABI module.
type ABIConfig struct {
	LibraryPath string `yaml:"library"`
	Symbol      string `yaml:"symbol"`
}

// GRPCConfig is the configuration for a gRPC module.
type GRPCConfig struct {
	Server string `yaml:"server"`
}

// ExecConfig is the configuration for a module's execution.
type ExecConfig struct {
	ABI       *ABIConfig     `yaml:"abi,omitempty"`
	GRPC      *GRPCConfig    `yaml:"grpc,omitempty"`
	CLI       *CLIConfig     `yaml:"cli,omitempty"`
	Transport string         `yaml:"transport,omitempty"`
	Params    map[string]any `yaml:"params,omitempty"`
}

// Validate validates the ExecConfig.
func (e ExecConfig) Validate() error {
	hasABI := e.ABI != nil
	hasGRPC := e.GRPC != nil
	hasCLI := e.CLI != nil

	if !(hasABI || hasCLI || hasGRPC) {
		return fmt.Errorf("exec config: one of abi, grpc or cli must be set")
	}

	if e.ABI != nil {
		if e.ABI.LibraryPath == "" {
			return fmt.Errorf("exec.abi.library is required")
		}
	}
	if e.GRPC != nil {
		if e.GRPC.Server == "" {
			return fmt.Errorf("exec.grpc.server is required")
		}
	}
	if e.CLI != nil {
		if e.CLI.Command == "" {
			return fmt.Errorf("exec.cli.command is required")
		}
	}

	return nil
}


