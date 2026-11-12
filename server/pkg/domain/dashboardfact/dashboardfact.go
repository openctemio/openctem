// Package dashboardfact holds the types of the dashboard fact layer's
// upkeep (api/docs/architecture/dashboards.md, "Facts maintainer"): the
// dirty-queue batches, the per-tenant full runs and the tenant's fact status.
package dashboardfact

import (
	"errors"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RunKind is why a tenant's facts are being rebuilt in full.
type RunKind string

const (
	// RunInitial builds a tenant's facts for the first time.
	RunInitial RunKind = "initial"
	// RunRequested is a "Rebuild dashboard data" request.
	RunRequested RunKind = "requested"
	// RunNightly is the daily reconciliation.
	RunNightly RunKind = "nightly"
)

// RebuildInterval is the least time between two rebuild requests of one
// tenant, whoever asks (the organization or the console).
const RebuildInterval = time.Hour

// ErrRebuildTooSoon is returned when a rebuild was requested less than
// RebuildInterval ago; RetryAfter says when the next one is accepted.
var ErrRebuildTooSoon = errors.New("dashboard data rebuild was requested less than an hour ago")

// TooSoonError carries when the next rebuild request is accepted.
type TooSoonError struct {
	RetryAt time.Time
}

func (e *TooSoonError) Error() string { return ErrRebuildTooSoon.Error() }

// Unwrap lets errors.Is match ErrRebuildTooSoon.
func (e *TooSoonError) Unwrap() error { return ErrRebuildTooSoon }

// AsTooSoon returns the TooSoonError in err's chain.
func AsTooSoon(err error) (*TooSoonError, bool) {
	var e *TooSoonError
	ok := errors.As(err, &e)
	return e, ok
}

// DirtyBatch is what one claim of a tenant's dirty queue did.
type DirtyBatch struct {
	Claimed    int // queue rows claimed and deleted
	Assets     int // distinct assets among them
	Recomputed int // assets recomputed (findings changed or an age band crossed)
	Changed    int // fact rows written
	// OldestMarkedAt is when the oldest claimed row was marked (zero when
	// nothing was claimed): the fact lag of this batch.
	OldestMarkedAt time.Time
}

// PendingRun is a tenant whose facts need a full run, and why.
type PendingRun struct {
	TenantID shared.ID
	Kind     RunKind
	// InProgress is true when the run already started (resume it).
	InProgress bool
}

// AgedMarkingDue is a tenant whose age bands have to be marked, and the
// start of the interval to mark.
type AgedMarkingDue struct {
	TenantID shared.ID
	Since    time.Time
}

// RunStep is the outcome of one step of a full run.
type RunStep struct {
	Done  bool
	Kind  RunKind
	Drift int // fact rows this step corrected that no change mark explained
}

// Status is a tenant's fact status, for the "Rebuild dashboard data" action.
type Status struct {
	RebuiltAt          *time.Time `json:"rebuilt_at"`
	ReconciledAt       *time.Time `json:"reconciled_at"`
	LastDrift          *int       `json:"last_drift"`
	RebuildRequestedAt *time.Time `json:"rebuild_requested_at"`
	// Running is the kind of the run in progress ("" when none).
	Running RunKind `json:"running,omitempty"`
	// Pending is true when a requested rebuild has not started yet.
	Pending bool `json:"pending"`
	// QueueDepth is the tenant's unprocessed change marks.
	QueueDepth int `json:"queue_depth"`
	// NextRebuildAt is when a new rebuild request is accepted (nil = now).
	NextRebuildAt *time.Time `json:"next_rebuild_at"`
}
