package adapter

import (
	"context"
	"fmt"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/pkg/modulepb"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
)

// GRPCModuleAdapter is a runner for gRPC modules.
type GRPCModuleAdapter struct {
}

// NewGRPCModuleAdapter creates a new gRPC module adapter.
func NewGRPCModuleAdapter() *GRPCModuleAdapter {
	return &GRPCModuleAdapter{}
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

	endpoint := grpcConfig.Server
	if endpoint == "" {
		return domain.RunResult{}, fmt.Errorf("grpc endpoint missing in exec.params")
	}

	conn, err := grpc.DialContext(ctx, endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return domain.RunResult{}, err
	}
	defer conn.Close()

	timeoutMs := uint32(timeout.Milliseconds())

	paramsVals := make(map[string]*structpb.Value, len(params))
	for k, v := range params {
		pv, err := structpb.NewValue(v)
		if err != nil {
			panic(err)
		}
		paramsVals[k] = pv
	}

	cl := modulepb.NewKrakenModuleClient(conn)
	resp, err := cl.Run(ctx, &modulepb.RunRequest{
		Target:    &modulepb.Target{Host: t.Host, Port: uint32(t.Port)},
		TimeoutMs: timeoutMs,
		Params:    paramsVals,
	})
	if err != nil {
		return domain.RunResult{}, fmt.Errorf("module run: %w", err)
	}

	var findings []domain.Finding
	for _, f := range resp.GetFindings() {
		ev := map[string]any{}
		for k, v := range f.GetEvidence() {
			ev[k] = v
		}
		var tags []domain.Tag
		for _, s := range f.GetTags() {
			tags = append(tags, domain.Tag(s))
		}
		findings = append(findings, domain.Finding{
			ID: f.GetId(), ModuleID: f.GetModuleId(), Title: f.GetTitle(), Severity: f.GetSeverity(),
			Description: f.GetDescription(), Evidence: ev, Tags: tags, Timestamp: time.Unix(f.GetTimestamp(), 0).UTC(),
			Target: t, Success: f.Success,
		})
	}
	var logs []string
	for _, l := range resp.GetLogs() {
		logs = append(logs, l.GetLine())
	}

	return domain.RunResult{Target: t, Findings: findings, Logs: logs}, nil
}
