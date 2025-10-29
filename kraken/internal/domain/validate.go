package domain

import "fmt"

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
			return fmt.Errorf("exec.abi.library is required")
		}
	}

	return nil
}
