package grpcplugin

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"bytemomo/orca/internal/domain"
	pluginpb "bytemomo/orca/pkg/plugpb"
)

type Client struct{}

func New() *Client { return &Client{} }

// Implements domain.PluginExecutor
func (c *Client) Run(ctx context.Context, endpoint string, t domain.HostPort) (domain.RunResult, error) {
	conn, err := grpc.DialContext(ctx, endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return domain.RunResult{}, err
	}
	defer conn.Close()

	cl := pluginpb.NewOrcaPluginClient(conn)
	resp, err := cl.Run(ctx, &pluginpb.RunRequest{
		Target: &pluginpb.Target{Host: t.Host, Port: uint32(t.Port)},
	})
	if err != nil {
		return domain.RunResult{}, fmt.Errorf("plugin run: %w", err)
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
			ID: f.GetId(), PluginID: f.GetPluginId(), Title: f.GetTitle(), Severity: f.GetSeverity(),
			Description: f.GetDescription(), Evidence: ev, Tags: tags, Timestamp: f.GetTimestamp(),
			Target: t,
		})
	}
	var logs []string
	for _, l := range resp.GetLogs() {
		logs = append(logs, l.GetLine())
	}

	return domain.RunResult{Target: t, Findings: findings, Logs: logs}, nil
}
