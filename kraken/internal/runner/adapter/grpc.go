package adapter

import (
	"context"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/runner/grpc"
)

// GRPCModuleAdapter is a runner for gRPC modules.
type GRPCModuleAdapter struct {
	module *grpc.GRPCModule
}

// NewGRPCModuleAdapter creates a new gRPC module adapter.
func NewGRPCModuleAdapter() *GRPCModuleAdapter {
	return &GRPCModuleAdapter{
		module: grpc.New(),
	}
}

// Supports returns true if the module is a gRPC module.
func (a *GRPCModuleAdapter) Supports(m *domain.Module) bool {
	if m == nil {
		return false
	}

	return m.ExecConfig.GRPC != nil && m.Type == domain.Grpc
}

// Run runs the gRPC module.
func (a *GRPCModuleAdapter) Run(ctx context.Context, m *domain.Module, params map[string]any, t domain.HostPort, timeout time.Duration) (domain.RunResult, error) {
	grpcConfig := &domain.GRPCConfig{
		Server: m.ExecConfig.GRPC.ServerAddr,
	}

	grpcCtx := context.WithValue(ctx, "grpc", grpcConfig)
	return a.module.Run(grpcCtx, params, t, timeout)
}
