package domain

import "fmt"

func (e ExecConfig) Validate() error {
	hasABI := e.ABI != nil
	hasGRPC := e.GRPC != nil

	switch {
	case hasABI && hasGRPC:
		return fmt.Errorf("exec: abi and grpc are mutually exclusive; set only one")
	case !hasABI && !hasGRPC:
		return fmt.Errorf("exec: one of abi or grpc must be set")
	}

	if e.ABI != nil {
		if e.ABI.LibraryPath == "" {
			return fmt.Errorf("exec.abi.library is required")
		}
		if e.ABI.Symbol == "" {
			// allow empty -> default in runner
		}
	}
	if e.GRPC != nil {
		if e.GRPC.Server == "" {
			return fmt.Errorf("exec.grpc.server is required")
		}
	}
	return nil
}
