package aianalysis

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// NewAnalyst is what creating an analyst stores: the service account, its AI
// profile and its first owners, in one transaction.
type NewAnalyst struct {
	Analyst *Analyst
	Owners  []OwnerRef
}

// AnalystRepository stores analysts and their owners. Every method is
// tenant-scoped.
type AnalystRepository interface {
	// Create stores the service account (no role yet), the AI profile and the
	// owners in one transaction.
	Create(ctx context.Context, in NewAnalyst) error
	Get(ctx context.Context, tenantID, id shared.ID) (*Analyst, error)
	List(ctx context.Context, tenantID shared.ID) ([]*Analyst, error)
	// SetOwners replaces the owners (at least one) in one transaction.
	SetOwners(ctx context.Context, tenantID, id shared.ID, owners []OwnerRef, by shared.ID) error
	// SetStatus moves an analyst to status with reason ("" for active).
	// from limits which current statuses may move (nil: any); false when the
	// stored status was not one of them.
	SetStatus(ctx context.Context, tenantID, id shared.ID, from []Status, to Status, reason PauseReason) (bool, error)
	SetPreset(ctx context.Context, tenantID, id shared.ID, p Preset) error
	Attest(ctx context.Context, tenantID, id, by shared.ID, at, due time.Time) error
	// PeopleOf lists the people who answer for an owner list now: person
	// owners who are active members, and active person members of active
	// owner teams (membership not past its end).
	PeopleOf(ctx context.Context, tenantID shared.ID, owners []OwnerRef, now time.Time) ([]shared.ID, error)
	// Delete removes the analyst with its service account (roles, team
	// memberships and keys go with it); runs keep their rows.
	Delete(ctx context.Context, tenantID, id shared.ID) error
	// ListActive lists every active analyst of every organization (the
	// sweep; a system job).
	ListActive(ctx context.Context, limit int) ([]*Analyst, error)
	// IsAnalyst reports whether the user is one of the tenant's analysts.
	IsAnalyst(ctx context.Context, tenantID, userID shared.ID) (bool, error)
}

// RunRepository is the run ledger. Every method is tenant-scoped.
type RunRepository interface {
	// CreateRun inserts a run; ErrRunInFlight when the subject already has a
	// live run of the same use case within its deadline (a live run past its
	// deadline is failed with ErrorTimeout first, in the same statement).
	CreateRun(ctx context.Context, r *Run) error
	UpdateRun(ctx context.Context, r *Run) error
	GetRun(ctx context.Context, tenantID, id shared.ID) (*Run, error)
	ListRunsBySubject(ctx context.Context, tenantID shared.ID, subjectType SubjectType, subjectID shared.ID, limit int) ([]*Run, error)
	// Usage is what an analyst used since: runs started and tokens.
	Usage(ctx context.Context, tenantID, analystID shared.ID, since time.Time) (runs, tokens int, err error)
}
