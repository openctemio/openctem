package exploration

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ErrStale: the lead changed since it was read (row_version moved on).
var ErrStale = fmt.Errorf("%w: the lead changed meanwhile", shared.ErrConflict)

// MaxListLimit bounds one page of leads.
const MaxListLimit = 200

// LeadFilter selects leads of one tenant. Scope is the reader's data scope
// (nil: unrestricted, for the platform's own passes); a restricted reader
// sees only leads whose subject asset (or the subject finding's asset) is in
// scope.
type LeadFilter struct {
	States         []LeadState
	SubjectAssetID *shared.ID
	Scope          *shared.DataScope
	// Before pages by updated_at (keyset, newest first).
	Before *time.Time
	Limit  int
}

// Repository stores explorations, leads, links and verdicts. Every method is
// bound to one tenant; the tenant comes from the caller's principal.
type Repository interface {
	// EnsureContinuous returns the tenant's continuous exploration,
	// creating it on first use.
	EnsureContinuous(ctx context.Context, tenantID shared.ID) (shared.ID, error)
	// OpenLead stores a new lead with its derived_from links in one
	// transaction. created is false (and nothing is written) when a live
	// lead already asks the same question (its dedup key).
	OpenLead(ctx context.Context, l *Lead, parents []Link) (created bool, err error)
	// GetLead reads one lead in the scope; another tenant's or an
	// out-of-scope lead is shared.ErrNotFound.
	GetLead(ctx context.Context, tenantID, id shared.ID, scope *shared.DataScope) (*Lead, error)
	// ListLeads reads leads newest first.
	ListLeads(ctx context.Context, tenantID shared.ID, f LeadFilter) ([]*Lead, error)
	// SaveLead writes the mutable fields of a lead read at RowVersion
	// (compare and set); ErrStale when it changed meanwhile.
	SaveLead(ctx context.Context, l *Lead) error
	// AddLinks stores links; a link the lead already has is skipped. It
	// returns how many were added.
	AddLinks(ctx context.Context, links []Link) (int, error)
	// AddVerdict appends a verdict.
	AddVerdict(ctx context.Context, v Verdict) error
	// Links reads a lead's links, oldest first.
	Links(ctx context.Context, tenantID, leadID shared.ID) ([]Link, error)
	// Verdicts reads a lead's verdicts, oldest first.
	Verdicts(ctx context.Context, tenantID, leadID shared.ID) ([]Verdict, error)
}
