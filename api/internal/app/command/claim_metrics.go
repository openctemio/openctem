package command

// Claim metrics: how long a claim takes, how long a claimed command waited
// and why poll candidates were not handed out (docs/rfcs/RFC-090-work-pool.md,
// observability). No tenant, sensor or run label.

import (
	"time"

	"github.com/openctemio/openctem/api/internal/metrics"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
)

// Claim modes (the mode label).
const (
	claimModeByID = "claim"
	claimModePoll = "claim_n"
	// claimModeShared: a shared sensor's claim-N (shared_claim.go).
	claimModeShared = "shared_claim_n"
)

// Reasons a poll candidate was not handed out (the reason label).
const (
	skipLocalPolicy  = "local_policy"
	skipNoSlot       = "no_slot"
	skipScopeChanged = "scope_changed"
	skipWindowHold   = "window_hold"
	skipProgramHold  = "program_hold"
	skipToolSettings = "tool_settings"
	skipTaken        = "taken"
)

// claimSkipped counts the candidates one step of the poll left out.
func claimSkipped(reason string, before, after int) {
	if n := before - after; n > 0 {
		metrics.CommandClaimSkippedTotal.WithLabelValues(reason).Add(float64(n))
	}
}

// claimPaged counts one extra candidate page read by a claim of mode.
func claimPaged(mode string) { metrics.CommandClaimPagesTotal.WithLabelValues(mode).Inc() }

// observeHostSplit counts one command split for busy hosts.
func observeHostSplit() { metrics.CommandHostSplitsTotal.Inc() }

// observeClaimDuration records how long a claim took since start.
func observeClaimDuration(mode string, start time.Time) {
	metrics.CommandClaimDuration.WithLabelValues(mode).Observe(time.Since(start).Seconds())
}

// observeClaimed counts claimed commands and how long each waited, from
// when it was due (created, or its scan window's opening) to now.
func observeClaimed(mode string, cmds []*commanddom.Command, now time.Time) {
	if len(cmds) == 0 {
		return
	}
	metrics.CommandClaimsTotal.WithLabelValues(mode).Add(float64(len(cmds)))
	for _, c := range cmds {
		if c == nil {
			continue
		}
		due := c.CreatedAt
		if c.ScheduledAt != nil && c.ScheduledAt.After(due) {
			due = *c.ScheduledAt
		}
		metrics.CommandClaimWait.WithLabelValues(claimClass(c.Priority)).Observe(max(now.Sub(due).Seconds(), 0))
	}
}

// claimClass is a command's priority as a bounded label.
func claimClass(p commanddom.CommandPriority) string {
	switch p {
	case commanddom.CommandPriorityLow, commanddom.CommandPriorityNormal,
		commanddom.CommandPriorityHigh, commanddom.CommandPriorityCritical:
		return string(p)
	}
	return string(commanddom.CommandPriorityNormal)
}
