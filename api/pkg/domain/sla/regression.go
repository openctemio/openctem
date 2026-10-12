package sla

import (
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A regression gets a fresh SLA deadline from the reopen (RFC-039 D2, owner
// decision 2026-10-03). Before, a reopened finding kept the deadline of its
// first detection and was usually overdue the moment it came back, which hid
// the new exposure window in the SLA metrics.

// RegressionRestartReason is recorded on the finding's sla_restarted activity.
const RegressionRestartReason = "regression: fresh SLA deadline from the reopen"

// RegressionCandidate is what is needed to recompute a reopened finding's
// deadline: its asset (for an asset policy), priority class and severity.
type RegressionCandidate struct {
	FindingID     shared.ID
	AssetID       shared.ID
	PriorityClass string
	Severity      string
	SLADeadline   *time.Time
	SLAStatus     string
}

// RegressionRestart is one deadline to write, with what it replaces.
type RegressionRestart struct {
	FindingID        shared.ID
	Deadline         time.Time
	PreviousDeadline *time.Time
	PreviousStatus   string
	// Trigger is what detected the regression: "scan" or "retest".
	Trigger string
	// RestartedAt is "now" for the restart (the deadline is computed from it).
	RestartedAt time.Time
}
