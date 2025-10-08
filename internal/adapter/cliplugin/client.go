package cliplugin

import (
	"bytemomo/orca/internal/domain"
	"context"
	"errors"
	"strings"
	"time"
)

type Client struct {
}

func New() *Client { return &Client{} }

func (c *Client) Supports(transport string) bool {
	return strings.EqualFold(transport, "cli")
}

// This will accept every plugin with the following api: ./plugin --host --port <OTHER_PARAMS>
// OTHER_PARAMS can be passed using the campaign params field in the following way:
//
// params:
//
//	param-flag: param-value
//
// will translate into: ./plugin --host <HOST> --port <PORT> --param-flag param-value

func (c *Client) Run(ctx context.Context, params map[string]any, t domain.HostPort, timeout time.Duration) (domain.RunResult, error) {
	return domain.RunResult{}, errors.New("[ERROR] Not yet implemented!")
}
