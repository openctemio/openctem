package asset

// Asset change timeline: one event each time the value an asset shows for a
// reconciled attribute changes, or the source that decides it changes.
// Design: docs/rfcs/RFC-069-asset-attribute-reconciliation.md (§11).
//
// A re-sighting of the same value writes no event; the observation's
// observed_at is refreshed in place at most once per
// ResightingRefreshInterval. A value that flips back and forth within
// FlapWindow is one event with a count.

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ResightingRefreshInterval is how often a source re-reporting the same
// value refreshes its stored observed_at (it keeps the source fresh for its
// TTL without a write per report).
const ResightingRefreshInterval = time.Hour

// FlapWindow is how long after an event a reversal of the same attribute is
// folded into it instead of writing another event.
const FlapWindow = time.Hour

// DefaultChangeRetentionDays is how long timeline events are kept.
const DefaultChangeRetentionDays = 400

// ChangeReason says why the value or its deciding source changed.
type ChangeReason string

const (
	// ChangeReasonNewerObservation: a source reported a newer value that wins.
	ChangeReasonNewerObservation ChangeReason = "newer_observation"
	// ChangeReasonManualLock: a person set and locked the value.
	ChangeReasonManualLock ChangeReason = "manual_lock"
	// ChangeReasonLockReleased: a person released the lock; sources decide again.
	ChangeReasonLockReleased ChangeReason = "lock_released"
	// ChangeReasonTTLExpiry: the deciding source was not re-seen within its TTL.
	ChangeReasonTTLExpiry ChangeReason = "ttl_expiry"
	// ChangeReasonPolicyChange: the organization changed which source wins.
	ChangeReasonPolicyChange ChangeReason = "policy_change"
	// ChangeReasonSourceRemoved: the deciding source's record was removed.
	ChangeReasonSourceRemoved ChangeReason = "source_removed"
)

// IsValid reports whether r is a known reason.
func (r ChangeReason) IsValid() bool {
	switch r {
	case ChangeReasonNewerObservation, ChangeReasonManualLock, ChangeReasonLockReleased,
		ChangeReasonTTLExpiry, ChangeReasonPolicyChange, ChangeReasonSourceRemoved:
		return true
	}
	return false
}

// ChangeEvent is one entry of an asset's timeline.
type ChangeEvent struct {
	ID        shared.ID
	TenantID  shared.ID
	AssetID   shared.ID
	At        time.Time // when the deciding source saw the value (observed_at)
	Attribute string
	Old, New  string
	// Added and Removed are the elements a set attribute gained and lost.
	Added, Removed []string
	SourceKind     SourceKind
	SourceName     string
	SourceRun      string
	// ActorID is the person, for a manual change.
	ActorID   *shared.ID
	Reason    ChangeReason
	FlapCount int
	CreatedAt time.Time

	// Filled on the organization feed only.
	AssetName string
	AssetType string
}

// Coalesces reports whether next, a change of the same asset attribute,
// folds into latest (the newest event of that attribute) instead of being
// written: latest was recorded within FlapWindow of next, it ended on the
// value next starts from, and next flips back (or latest already flapped).
func (latest *ChangeEvent) Coalesces(next ChangeEvent, now time.Time) bool {
	if latest == nil || latest.Attribute != next.Attribute || latest.AssetID != next.AssetID {
		return false
	}
	if latest.Reason != ChangeReasonNewerObservation || next.Reason != ChangeReasonNewerObservation {
		// Only sources reporting back and forth flap; a person's lock or
		// release, a TTL expiry or a policy change is always its own entry.
		return false
	}
	if now.Sub(latest.CreatedAt) > FlapWindow {
		return false
	}
	if latest.isSetChange() || next.isSetChange() {
		// A set change folds when it undoes the newest one exactly (the
		// same elements back and forth); the event then shows the latest
		// direction with the count.
		return latest.isSetChange() && next.isSetChange() &&
			sameElements(next.Added, latest.Removed) && sameElements(next.Removed, latest.Added)
	}
	if latest.New != next.Old || next.Old == next.New {
		return false
	}
	return next.New == latest.Old || latest.FlapCount > 1
}

func (e *ChangeEvent) isSetChange() bool { return len(e.Added) > 0 || len(e.Removed) > 0 }

func sameElements(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, v := range a {
		seen[v]++
	}
	for _, v := range b {
		if seen[v] == 0 {
			return false
		}
		seen[v]--
	}
	return true
}

// ChangeQuery filters and pages a timeline, newest first.
type ChangeQuery struct {
	AssetID     *shared.ID // nil: the organization feed
	Attributes  []string
	SourceKinds []SourceKind
	SourceName  string
	Tag         string // feed only: assets carrying this tag
	// ScopeUserID restricts the feed to the assets this member may see
	// (nil: unrestricted).
	ScopeUserID *shared.ID
	// ScopeUnrestricted: ScopeUserID sees every asset except the private
	// program assets hidden from them (RFC-065 §15.3).
	ScopeUnrestricted bool
	// Before is the keyset cursor: events strictly older than (At, ID).
	BeforeAt *time.Time
	BeforeID *shared.ID
	Limit    int
}

// MaxChangePageSize bounds one page of a timeline.
const MaxChangePageSize = 200

// ChangeEventRepository reads the timeline. Events are written by
// AttributeSourceRepository.Apply in the same transaction as the change.
type ChangeEventRepository interface {
	// ListChanges returns up to q.Limit events of the tenant, newest first,
	// and whether more follow.
	ListChanges(ctx context.Context, tenantID shared.ID, q ChangeQuery) ([]ChangeEvent, bool, error)
}

// ChangeTimelineMaintainer applies the timeline's retention.
type ChangeTimelineMaintainer interface {
	// DeleteBefore removes events older than cutoff, in bounded batches, and
	// returns how many rows went.
	DeleteBefore(ctx context.Context, cutoff time.Time) (int64, error)
}
