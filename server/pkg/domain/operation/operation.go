// Package operation is long-running work a person started from the API
// (docs/architecture/operations.md): created by the request, run in the
// background, read back by its creator with GET /api/v1/operations/{id}.
package operation

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Kind names what an operation does (the table's CHECK lists the same).
type Kind string

const (
	KindFindingsBulkStatus Kind = "findings_bulk_status"
	KindFindingsBulkAssign Kind = "findings_bulk_assign"
)

// Status of an operation.
type Status string

const (
	StatusRunning   Status = "running"
	StatusSucceeded Status = "succeeded"
	StatusFailed    Status = "failed"
	// StatusInterrupted: the process running it stopped. Items already
	// processed stay done; running the same request again finishes the rest.
	StatusInterrupted Status = "interrupted"
)

// StaleAfter is how long a running operation may go without progress before
// it counts as interrupted.
const StaleAfter = 5 * time.Minute

// MaxResultRows bounds the per-item outcomes an operation keeps.
const MaxResultRows = 200

// ItemResult is the outcome of one item that did not succeed.
type ItemResult struct {
	ID      string `json:"id"`
	Outcome string `json:"outcome"`
	Reason  string `json:"reason"`
}

// Operation is one row.
type Operation struct {
	ID             shared.ID
	TenantID       shared.ID
	CreatedBy      shared.ID
	Kind           Kind
	Status         Status
	IdempotencyKey string
	RequestHash    string
	Total          int
	Processed      int
	Succeeded      int
	Skipped        int
	Failed         int
	Items          []ItemResult
	Error          string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	FinishedAt     *time.Time
}

// Progress is a running operation's counters after a chunk.
type Progress struct {
	Processed, Succeeded, Skipped, Failed int
	Items                                 []ItemResult
}

// ResultJSON is the stored result document.
func (p Progress) ResultJSON() []byte {
	items := p.Items
	if len(items) > MaxResultRows {
		items = items[:MaxResultRows]
	}
	b, _ := json.Marshal(map[string]any{"items": items})
	return b
}

var (
	// ErrNotFound: no such operation for this tenant and creator.
	ErrNotFound = errors.New("operation not found")
	// ErrBusy: the creator already has a running operation.
	ErrBusy = errors.New("you already have an operation running; wait for it to finish")
	// ErrIdempotencyMismatch: the idempotency key was used with another request.
	ErrIdempotencyMismatch = errors.New("idempotency key was already used with a different request")
	// ErrBudget: the new operation would take the tenant over its budget.
	ErrBudget = errors.New("the organization's budget for this kind of operation is spent")
)

// Budget bounds the items a tenant's operations of Kinds may total since
// Since, the new one included. Max 0 means no budget.
type Budget struct {
	Kinds []Kind
	Since time.Time
	Max   int
}

// Store persists operations. Every read and write is bound to the tenant
// and the creator.
type Store interface {
	// Create inserts a running operation. A replay (same tenant, creator
	// and idempotency key) returns the existing row and replay=true, or
	// ErrIdempotencyMismatch when its request hash differs. A creator with a
	// running operation gets ErrBusy (a stale one is marked interrupted
	// first). With a budget, the tenant's total is checked and the row
	// inserted under one per-tenant lock, so concurrent creators (other
	// people, other replicas) cannot overrun it together: ErrBudget.
	Create(ctx context.Context, op *Operation, budget Budget) (stored *Operation, replay bool, err error)
	// ByKey reads the creator's operation with this idempotency key.
	ByKey(ctx context.Context, tenantID, createdBy shared.ID, key string) (*Operation, error)
	// Get reads one operation of the creator.
	Get(ctx context.Context, tenantID, createdBy, id shared.ID) (*Operation, error)
	// Advance records progress of a running operation.
	Advance(ctx context.Context, tenantID, id shared.ID, p Progress) error
	// Finish ends an operation with a final status.
	Finish(ctx context.Context, tenantID, id shared.ID, status Status, p Progress, errMsg string) error
}
