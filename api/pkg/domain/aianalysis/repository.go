package aianalysis

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// NewAgent is what creating an AI agent stores: the service account, its AI
// profile and its first owners, in one transaction.
type NewAgent struct {
	Agent  *Agent
	Owners []OwnerRef
}

// AgentRepository stores AI agents and their owners. Every method is
// tenant-scoped.
type AgentRepository interface {
	// Create stores the service account (no role yet), the AI profile and the
	// owners in one transaction.
	Create(ctx context.Context, in NewAgent) error
	Get(ctx context.Context, tenantID, id shared.ID) (*Agent, error)
	List(ctx context.Context, tenantID shared.ID) ([]*Agent, error)
	// SetOwners replaces the owners (at least one) in one transaction.
	SetOwners(ctx context.Context, tenantID, id shared.ID, owners []OwnerRef, by shared.ID) error
	// SetStatus moves an AI agent to status with reason ("" for active).
	// from limits which current statuses may move (nil: any); false when the
	// stored status was not one of them.
	SetStatus(ctx context.Context, tenantID, id shared.ID, from []Status, to Status, reason PauseReason) (bool, error)
	SetPreset(ctx context.Context, tenantID, id shared.ID, p Preset) error
	Attest(ctx context.Context, tenantID, id, by shared.ID, at, due time.Time) error
	// PeopleOf lists the people who answer for an owner list now: person
	// owners who are active members, and active person members of active
	// owner teams (membership not past its end).
	PeopleOf(ctx context.Context, tenantID shared.ID, owners []OwnerRef, now time.Time) ([]shared.ID, error)
	// Delete removes the AI agent with its service account (roles, team
	// memberships and keys go with it); runs keep their rows.
	Delete(ctx context.Context, tenantID, id shared.ID) error
	// ListActive lists every active AI agent of every organization (the
	// sweep; a system job).
	ListActive(ctx context.Context, limit int) ([]*Agent, error)
	// IsAgent reports whether the user is one of the tenant's AI agents.
	IsAgent(ctx context.Context, tenantID, userID shared.ID) (bool, error)
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
	// Usage is what an AI agent used since: runs started and tokens.
	Usage(ctx context.Context, tenantID, agentID shared.ID, since time.Time) (runs, tokens int, err error)
}
