package aianalysis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Errors.
var (
	ErrRunNotFound        = fmt.Errorf("%w: AI run not found", shared.ErrNotFound)
	ErrSuggestionNotFound = fmt.Errorf("%w: AI suggestion not found", shared.ErrNotFound)
	// ErrRunInFlight: a run of this use case for this subject is already
	// pending or running.
	ErrRunInFlight = fmt.Errorf("%w: an AI run for this subject is already in progress", shared.ErrConflict)
	// ErrStateChanged: the suggestion moved on since it was read (another
	// person decided it first).
	ErrStateChanged = fmt.Errorf("%w: the AI suggestion was already decided", shared.ErrConflict)
	// ErrUndoConflict: the field was changed after the suggestion was
	// applied; undo would overwrite a later decision.
	ErrUndoConflict = errors.New("ai_undo_conflict")
)

// UndoConflictError wraps ErrUndoConflict and shared.ErrConflict.
type UndoConflictError struct{ Current string }

func (e *UndoConflictError) Error() string {
	return "the field changed after the AI suggestion was applied; edit it by hand"
}

// Is matches ErrUndoConflict and shared.ErrConflict.
func (e *UndoConflictError) Is(target error) bool {
	return target == ErrUndoConflict || target == shared.ErrConflict
}

// Transition is a guarded state change of a suggestion: it happens only when
// the stored state is one of From.
type Transition struct {
	From          []State
	To            State
	Actor         *shared.ID
	At            time.Time
	PreviousValue []byte
	ApprovalKind  ApprovalKind
	ApprovalID    *shared.ID
	// Applied sets applied_by/applied_at; Undone sets undone_by/undone_at.
	Applied bool
	Undone  bool
}

// Repository stores runs, suggestions and use-case policies. Every method is
// tenant-scoped.
type Repository interface {
	CreateRun(ctx context.Context, r *Run) error
	UpdateRun(ctx context.Context, r *Run) error
	GetRun(ctx context.Context, tenantID, id shared.ID) (*Run, error)

	// CreateSuggestions inserts the suggestions of one run and marks every
	// earlier open suggestion of the same kind for the same subject
	// superseded, in one transaction.
	CreateSuggestions(ctx context.Context, tenantID shared.ID, items []*Suggestion) error
	GetSuggestion(ctx context.Context, tenantID, id shared.ID) (*Suggestion, error)
	ListSuggestionsBySubject(ctx context.Context, tenantID shared.ID, subjectType SubjectType, subjectID shared.ID, limit int) ([]*Suggestion, error)
	ListSuggestionsByRun(ctx context.Context, tenantID, runID shared.ID) ([]*Suggestion, error)
	// Transition applies a guarded state change; ErrStateChanged when the
	// stored state is not one of t.From.
	Transition(ctx context.Context, tenantID, id shared.ID, t Transition) (*Suggestion, error)

	ListPolicies(ctx context.Context, tenantID shared.ID) ([]UseCasePolicy, error)
	UpsertPolicy(ctx context.Context, p UseCasePolicy) error
	// Downgrade moves an auto_apply use case to suggest, recording when and
	// why; false when it was not auto_apply any more.
	Downgrade(ctx context.Context, tenantID shared.ID, u UseCase, reason string, at time.Time) (bool, error)
	// RecentDecisions counts the last window decisions of a use case and how
	// many of them were overrides (dismissed, undone, approval rejected or
	// canceled).
	RecentDecisions(ctx context.Context, tenantID shared.ID, u UseCase, window int) (Decisions, error)
}
