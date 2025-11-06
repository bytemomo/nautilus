package contextkeys

// contextKey is a typed key for storing runner-specific values in a context.Context.
type contextKey string

func (k contextKey) String() string {
	return "kraken runner context key " + string(k)
}

var (
	// OutDir stores the path where modules should write their outputs.
	OutDir contextKey = "out_dir"
	// CLIConfig stores the CLI execution configuration.
	CLIConfig contextKey = "cli_config"
	// GRPCConfig stores the gRPC execution configuration.
	GRPCConfig contextKey = "grpc_config"
	// ABIConfig stores the ABI execution configuration.
	ABIConfig contextKey = "abi_config"
)
