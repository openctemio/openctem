// Package lifecycle holds the idle-organization policy
// (docs/architecture/idle-workspaces.md): an organization the policy is on
// for, that nobody signs in to, is reminded, then made read-only, warned
// again, and finally marked for deletion. A sign-in by any member resets it.
// The policy is off for every organization until a platform administrator
// turns it on for that organization.
package lifecycle

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Stage is where an organization is in the idle lifecycle.
type Stage string

const (
	// StageActive: signed in to within ReminderAfter.
	StageActive Stage = "active"
	// StageReminded: the owners and admins were reminded.
	StageReminded Stage = "reminded"
	// StageReadOnly: no changes until someone signs in (first warning).
	StageReadOnly Stage = "read_only"
	// StageFinalWarning: the last warning before deletion.
	StageFinalWarning Stage = "final_warning"
	// StageDeletionDue: idle past DeleteAfter, after both warnings. The
	// platform administrators are alerted; deletion itself waits for an
	// administrator (and the organization export) until it is automated.
	StageDeletionDue Stage = "deletion_due"
)

// IsValid reports whether s is a known stage.
func (s Stage) IsValid() bool {
	switch s {
	case StageActive, StageReminded, StageReadOnly, StageFinalWarning, StageDeletionDue:
		return true
	}
	return false
}

// ReadOnly reports whether the stage blocks changes.
func (s Stage) ReadOnly() bool {
	return s == StageReadOnly || s == StageFinalWarning || s == StageDeletionDue
}

// Thresholds are the idle days at which each stage starts (owner decision
// 2026-10-08: 60 / 90 / 120, two warnings before deletion).
type Thresholds struct {
	Reminder     time.Duration
	ReadOnly     time.Duration
	FinalWarning time.Duration
	DeletionDue  time.Duration
}

const day = 24 * time.Hour

// DefaultThresholds: reminder at 60 days, read-only (first warning) at 90,
// final warning at 113 (a week before), deletion due at 120.
func DefaultThresholds() Thresholds {
	return Thresholds{Reminder: 60 * day, ReadOnly: 90 * day, FinalWarning: 113 * day, DeletionDue: 120 * day}
}

// Next is the stage an organization moves to, given its current stage and
// how long nobody signed in. Stages only advance one step per call, so no
// warning is ever skipped (an organization idle for 200 days on its first
// sweep is reminded first, not marked for deletion). Activity within the
// reminder window returns it to active from any stage.
func (t Thresholds) Next(current Stage, idle time.Duration) Stage {
	if idle < t.Reminder {
		return StageActive
	}
	switch current {
	case StageActive, "":
		return StageReminded
	case StageReminded:
		if idle >= t.ReadOnly {
			return StageReadOnly
		}
	case StageReadOnly:
		if idle >= t.FinalWarning {
			return StageFinalWarning
		}
	case StageFinalWarning:
		if idle >= t.DeletionDue {
			return StageDeletionDue
		}
	}
	return current
}

// MinStageGap is the least time between two warnings, so a sweep that was
// down for a while still gives the owners time to act between steps.
const MinStageGap = 7 * day

// Decide is the stage the organization should be in at now: Next, except
// that a warning step waits at least MinStageGap after the previous one.
func (t Thresholds) Decide(w Workspace, now time.Time) Stage {
	current := w.Stage
	if !current.IsValid() {
		current = StageActive
	}
	next := t.Next(current, w.Idle(now))
	if next == StageActive || next == current || current == StageActive {
		return next
	}
	if now.Sub(w.StageChangedAt) < MinStageGap {
		return current
	}
	return next
}

// Workspace is one organization under the idle policy, with its activity.
type Workspace struct {
	TenantID       shared.ID
	Name           string
	Slug           string
	Stage          Stage
	StageChangedAt time.Time
	// LastSignIn is the latest sign-in of any active member (zero: none;
	// the organization's creation time is used instead).
	LastSignIn time.Time
	CreatedAt  time.Time
}

// Idle is how long nobody signed in, at now.
func (w Workspace) Idle(now time.Time) time.Duration {
	since := w.LastSignIn
	if since.IsZero() || since.Before(w.CreatedAt) {
		since = w.CreatedAt
	}
	return now.Sub(since)
}

// Policy is a platform administrator's decision to put an organization under
// the idle policy (Enabled) or take it out. Off is the default for every
// organization: no row, or a row with Enabled false.
type Policy struct {
	Enabled bool
	Reason  string
	By      *shared.ID
	At      time.Time
}

// Status is an organization's lifecycle as the console shows it.
type Status struct {
	Stage          Stage
	StageChangedAt *time.Time
	LastSignIn     *time.Time
	PolicyEnabled  bool
	PolicyReason   string
	PolicySetAt    *time.Time
}

// Repository persists the lifecycle. Every per-organization query is scoped
// by tenant_id.
type Repository interface {
	// Workspaces lists the organizations the policy is on for, with their
	// stage and the latest member sign-in.
	Workspaces(ctx context.Context) ([]Workspace, error)
	SetStage(ctx context.Context, tenantID shared.ID, stage Stage, at time.Time) error
	Status(ctx context.Context, tenantID shared.ID) (*Status, error)
	// SetPolicy turns the policy on or off for the organization. Turning it
	// off returns the organization to active.
	SetPolicy(ctx context.Context, tenantID shared.ID, p Policy) error
	// ReadOnly reports whether the organization is read-only now: the policy
	// is on, it is in a read-only stage, and nobody signed in since the stage
	// started (a sign-in lifts it at once; the sweep then resets the stage).
	ReadOnly(ctx context.Context, tenantID shared.ID) (bool, error)
	// Recipients are the emails of the organization's active owners and
	// admins.
	Recipients(ctx context.Context, tenantID shared.ID) ([]string, error)
}
