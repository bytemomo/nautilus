package domain

import "time"

type RunnerConfig struct {
	GlobalTimeout time.Duration
	MaxTargets    int 
}
