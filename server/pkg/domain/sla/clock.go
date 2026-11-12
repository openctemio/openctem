package sla

import "time"

// Clock is when a finding's SLA clock started and how often it restarted.
type Clock struct {
	// StartedAt: the start of the current clock (nil: the first detection).
	StartedAt *time.Time
	// LastReopenedAt: the finding's latest reopen, nil when never reopened.
	LastReopenedAt *time.Time
	// Restarts: regressions that gave the finding a fresh deadline.
	Restarts int
	// LastRestartTrigger: what detected the latest regression (scan, retest).
	LastRestartTrigger string
}
