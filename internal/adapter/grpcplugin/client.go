package grpcplugin

import (
	"context"
	"fmt"
	"strings"
	"time"

	"bytemomo/orca/internal/domain"
	plugpb "bytemomo/orca/pkg/plugpb"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
)

type Client struct{}

func New() *Client { return &Client{} }

func (c *Client) Supports(transport string) bool {
	return strings.EqualFold(transport, "grpc")
}

func (c *Client) Run(ctx context.Context, params map[string]any, t domain.HostPort, timeout time.Duration) (domain.RunResult, error) {
	grpcConfig := ctx.Value("grpc").(*domain.GRPCConfig)

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

	cl := plugpb.NewOrcaPluginClient(conn)
	resp, err := cl.Run(ctx, &plugpb.RunRequest{
		Target:    &plugpb.Target{Host: t.Host, Port: uint32(t.Port)},
		TimeoutMs: timeoutMs,
		Params:    paramsVals,
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
