package scanworkflow

import (
	"context"
	"encoding/json"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Draft is a scan workflow's editable head: what the builder saved last,
// valid or not. Runs never read it; publishing turns it into the steps runs
// use. Spec and Issues are stored as the app layer wrote them.
type Draft struct {
	// Spec holds the steps and the Start/End node positions.
	Spec json.RawMessage
	// Issues are what the last check of the draft found.
	Issues    json.RawMessage
	UpdatedAt time.Time
}

// DraftRepository stores drafts. Every call is scoped to the tenant: a
// workflow of another tenant is ErrNotFound.
type DraftRepository interface {
	// GetDraft returns the draft, ErrNotFound when the workflow has none.
	GetDraft(ctx context.Context, tenantID, workflowID shared.ID) (*Draft, error)
	// SaveDraft writes the draft (the workflow must be the tenant's own).
	SaveDraft(ctx context.Context, tenantID, workflowID shared.ID, d *Draft) error
	// ClearDraft removes the draft; no draft is not an error.
	ClearDraft(ctx context.Context, tenantID, workflowID shared.ID) error
}

// ErrNoDraft refuses a publish of a workflow that has no draft.
var ErrNoDraft = shared.NewDomainError("NO_DRAFT", "this scan workflow has no draft to publish", shared.ErrValidation)
