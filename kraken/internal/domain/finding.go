package domain

import "time"

// Finding is a security finding that has been identified by a module.
type Finding struct {
	ID          string         `json:"id"`
	ModuleID    string         `json:"module_id"`
	Success     bool           `json:"success"`
	Title       string         `json:"title"`
	Severity    string         `json:"severity"`
	Description string         `json:"description"`
	Evidence    map[string]any `json:"evidence"`
	Tags        []Tag          `json:"tags"`
	Timestamp   time.Time      `json:"timestamp"`
	Target      HostPort       `json:"target"`
}
