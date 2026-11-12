package exploration

import (
	"context"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Summary is the exploration's figures. Organization-wide figures come from
// the precomputed rollup (ComputedAt is its freshness); a restricted viewer
// gets live counts within their data scope instead (Scoped).
type Summary struct {
	Open             int
	AwaitingApproval int
	Running          int
	Blocked          int
	Done30d          int
	Proven30d        int
	Refuted30d       int
	Dispatches30d    int
	// RuleShare is the share of leads opened by rules (nil: no leads).
	RuleShare *float64
	// MedianVerdictSeconds is the median time from opening to the first
	// verdict over the last 30 days (nil: none).
	MedianVerdictSeconds *int
	LastStepAt           *time.Time
	ComputedAt           time.Time
	Scoped               bool
}

// RollupStore precomputes and reads the figures.
type RollupStore interface {
	// RefreshRollup recomputes the tenant's continuous exploration rollup.
	RefreshRollup(ctx context.Context, tenantID, explorationID shared.ID) error
	// Rollup reads it (shared.ErrNotFound before the first refresh).
	Rollup(ctx context.Context, tenantID, explorationID shared.ID) (*Summary, error)
	// ScopedSummary counts live and recent leads within a data scope.
	ScopedSummary(ctx context.Context, tenantID, explorationID shared.ID, scope *shared.DataScope) (*Summary, error)
}
