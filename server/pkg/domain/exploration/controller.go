package exploration

import (
	"context"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// LeadSubject is what the controller reads about a lead's subject asset.
type LeadSubject struct {
	ID       shared.ID
	Name     string
	Type     asset.AssetType
	SubType  string
	Archived bool
	Value    SubjectValue
}

// RunFacts is the state of a run a lead was dispatched as.
type RunFacts struct {
	Status      string
	CreatedAt   time.Time
	StartedAt   *time.Time
	CompletedAt *time.Time
}

// Terminal reports whether the run finished.
func (r RunFacts) Terminal() bool {
	switch r.Status {
	case "completed", "partial", "failed", "canceled", "timeout", "blocked":
		return true
	}
	return false
}

// Succeeded reports whether the run finished its work (all or part).
func (r RunFacts) Succeeded() bool { return r.Status == "completed" || r.Status == "partial" }

// FindingYield is a finding a run reported on a subject; Created when the
// run was its first report.
type FindingYield struct {
	ID      shared.ID
	Created bool
}

// MatchState summarizes cited version-match findings after a step.
type MatchState struct {
	Total int
	// Confirmed: now likely, or reported by a scanner since.
	Confirmed int
	// Closed: no longer open.
	Closed int
}

// ControllerStore is what the frontier controller reads. Every read is bound
// to one tenant.
type ControllerStore interface {
	// Tenants returns the tenants that have assets.
	Tenants(ctx context.Context) ([]shared.ID, error)
	// Subjects reads the subject assets (missing or soft-deleted ones are absent).
	Subjects(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]LeadSubject, error)
	// Cells returns the tenant's settled outcomes per (lead type, capability).
	Cells(ctx context.Context, tenantID shared.ID) (map[string]CellStats, error)
	// ToolMeanMs returns the tenant's learned mean duration per tool.
	ToolMeanMs(ctx context.Context, tenantID shared.ID, tools []string) (map[string]float64, error)
	// DispatchesSince counts the tenant's lead dispatches since t.
	DispatchesSince(ctx context.Context, tenantID shared.ID, t time.Time) (int, error)
	// Runs reads runs of the tenant.
	Runs(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]RunFacts, error)
	// RunFindings returns the findings a run reported on an asset.
	RunFindings(ctx context.Context, tenantID, runID, assetID shared.ID) ([]FindingYield, error)
	// Liveness returns the asset's liveness state and when it was last checked.
	Liveness(ctx context.Context, tenantID, assetID shared.ID) (string, *time.Time, error)
	// MatchState summarizes findings of the tenant.
	MatchState(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID) (MatchState, error)
}
