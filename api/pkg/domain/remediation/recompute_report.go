package remediation

import "github.com/openctemio/openctem/api/pkg/domain/shared"

// StateChange is a task whose derived state a recompute changed.
type StateChange struct {
	TaskID shared.ID
	Title  string
	From   TaskState
	To     TaskState
}

// Regression is a closed task whose findings reopened: they moved to a new
// task linked to it.
type Regression struct {
	SourceID    shared.ID
	SourceTitle string
	TaskID      shared.ID
	Title       string
	Findings    int
}

// RecomputeReport is what a background recompute did, for the audit log (a
// person's change is audited on its own; these are changes no person made).
type RecomputeReport struct {
	StateChanges []StateChange
	Regressions  []Regression
}
