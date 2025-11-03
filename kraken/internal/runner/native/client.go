package native

import (
	"bytemomo/kraken/internal/domain"
	"context"
	"strings"
	"time"
)

type Client struct{}

func New() *Client { return &Client{} }

func (c *Client) Supports(transport string) bool {
	return strings.EqualFold(transport, "native")
}

func (c *Client) Run(ctx context.Context, params map[string]any, t domain.HostPort, timeout time.Duration) (domain.RunResult, error) {
	return domain.RunResult{}, nil
}
