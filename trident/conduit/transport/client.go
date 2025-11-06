package transport

import (
	"context"

	"bytemomo/trident/conduit"
)

// NewClient creates a new client conduit.
func NewClient[V any](inner conduit.Conduit[V], wrap func(context.Context, V) (V, error)) conduit.Conduit[V] {
	return &client[V]{
		inner: inner,
		wrap:  wrap,
	}
}

type client[V any] struct {
	inner conduit.Conduit[V]
	wrap  func(context.Context, V) (V, error)
	conn  V
}

func (c *client[V]) Dial(ctx context.Context) error {
	if err := c.inner.Dial(ctx); err != nil {
		return err
	}
	conn, err := c.wrap(ctx, c.inner.Underlying())
	if err != nil {
		return err
	}
	c.conn = conn
	return nil
}

func (c *client[V]) Close() error {
	return c.inner.Close()
}

func (c *client[V]) Kind() conduit.Kind {
	return c.inner.Kind()
}

func (c *client[V]) Stack() []string {
	return c.inner.Stack()
}

func (c *client[V]) Underlying() V {
	return c.conn
}
