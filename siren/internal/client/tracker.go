package client

import (
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Client represents a discovered client.
type Client struct {
	IP        net.IP
	MAC       net.HardwareAddr
	Port      uint16
	Protocol  string
	ServerIP  net.IP
	ServerPort uint16
	LastSeen  time.Time
}

// Tracker discovers and manages active clients.
type Tracker struct {
	mu      sync.RWMutex
	clients map[string]*Client
	logger  *logrus.Logger
}

// NewTracker creates a new client tracker.
func NewTracker(logger *logrus.Logger) *Tracker {
	return &Tracker{
		clients: make(map[string]*Client),
		logger:  logger,
	}
}

// AddOrUpdate adds a new client or updates the last-seen time of an existing one.
func (t *Tracker) AddOrUpdate(client *Client) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := client.IP.String()
	if _, ok := t.clients[key]; !ok {
		t.logger.Infof("Discovered new client: %s", key)
	}
	t.clients[key] = client
}

// GetClient returns the details for a given client IP.
func (t *Tracker) GetClient(ip net.IP) (*Client, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	client, ok := t.clients[ip.String()]
	return client, ok
}

// AllClients returns a slice of all tracked clients.
func (t *Tracker) AllClients() []*Client {
	t.mu.RLock()
	defer t.mu.RUnlock()
	clients := make([]*Client, 0, len(t.clients))
	for _, client := range t.clients {
		clients = append(clients, client)
	}
	return clients
}

// Prune removes clients that have not been seen in the given duration.
func (t *Tracker) Prune(maxAge time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	for key, client := range t.clients {
		if now.Sub(client.LastSeen) > maxAge {
			delete(t.clients, key)
			t.logger.Infof("Pruned inactive client: %s", key)
		}
	}
}
