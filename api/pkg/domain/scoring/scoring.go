// Package scoring holds the versions of the scoring models and the queue
// that recomputes finding priorities when a model, a tenant's scoring
// settings or a score input changes (docs/architecture/scoring-versions.md).
//
// A version is the id of a scoring_changes row: a platform row per model
// version, a tenant row per change of the tenant's risk scoring settings,
// priority rules or SLA policies. Every computed asset risk score and
// finding priority stores the version it was computed with; a value with an
// older version is stale and is queued again. Closed findings are never
// recomputed: they keep the values they had when they were closed.
package scoring

import (
	"context"
	"database/sql"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Kind is what a scoring version applies to.
type Kind string

const (
	// KindAssetRisk is the asset risk score.
	KindAssetRisk Kind = "asset_risk"
	// KindFindingPriority is the finding priority class and its SLA deadline.
	KindFindingPriority Kind = "finding_priority"
)

// Model versions of this build. Bump one when a change to the code changes
// the values the model computes: the start-up registration records the new
// version and every open finding (or live asset) is recomputed once, in the
// background. No migration is needed.
const (
	RiskModelVersion     = 2
	PriorityModelVersion = 2
)

// ModelVersion returns this build's model version for a kind.
func ModelVersion(k Kind) int {
	if k == KindAssetRisk {
		return RiskModelVersion
	}
	return PriorityModelVersion
}

// ModelSummary is the change summary recorded for this build's model.
func ModelSummary(k Kind) string {
	if k == KindAssetRisk {
		return "Likelihood and impact asset risk model"
	}
	return "Priority classification P0 to P3 with the exploitation floor: a known-exploited (KEV) or validated finding is at least P1 after controls, AI triage and tenant rules"
}

// Kinds lists every kind.
func Kinds() []Kind { return []Kind{KindAssetRisk, KindFindingPriority} }

// VersionRepository reads and registers scoring versions.
type VersionRepository interface {
	// CurrentVersion is the version a value of the tenant computed now by
	// this build must store.
	CurrentVersion(ctx context.Context, tenantID shared.ID, kind Kind) (int64, error)
	// RegisterModels records this build's model versions (idempotent).
	RegisterModels(ctx context.Context) error
}

// Queue reasons.
const (
	ReasonFindingChange = "finding_change"
	ReasonNewFinding    = "new_finding"
	ReasonAssetChange   = "asset_change"
	ReasonScoringChange = "scoring_change"
	ReasonIntel         = "intel"
	ReasonControl       = "control_change"
	ReasonAttribution   = "attribution"
	ReasonAITriage      = "ai_triage"
	ReasonReconcile     = "reconcile"
)

// QueueItem is one claimed asset of the finding-priority queue.
type QueueItem struct {
	TenantID        shared.ID
	AssetID         shared.ID
	Reason          string
	ScoringChangeID *int64
}

// QueueStats is the depth of the queue and the age of its oldest due row.
type QueueStats struct {
	Depth     int64
	OldestAge time.Duration
}

// QueueResult is what one worker pass did.
type QueueResult struct {
	Claimed int // assets taken from the queue
	Checked int // open findings whose priority was recomputed
	Changed int // findings whose stored priority or SLA deadline changed
}

// ChangeImpact is what a recompute did to open findings.
type ChangeImpact struct {
	Checked            int // open findings recomputed
	Changed            int // findings whose class moved
	Raised             int // moved to a higher priority
	RaisedToP0         int // of those, now P0
	Lowered            int // moved to a lower priority
	DeadlinesTightened int // SLA deadlines that moved earlier
}

// Add sums o into c.
func (c *ChangeImpact) Add(o ChangeImpact) {
	c.Checked += o.Checked
	c.Changed += o.Changed
	c.Raised += o.Raised
	c.RaisedToP0 += o.RaisedToP0
	c.Lowered += o.Lowered
	c.DeadlinesTightened += o.DeadlinesTightened
}

// ChangeSummary is the one notification a scoring change sends a tenant
// once its recompute has drained.
type ChangeSummary struct {
	TenantID shared.ID
	ChangeID int64
	Source   string
	Summary  string
	ChangeImpact
}

// PriorityQueue is the durable finding-priority queue: one row per asset,
// claimed fairly across tenants.
type PriorityQueue interface {
	// EnqueueAssets queues the given assets of the tenant; ids of another
	// tenant's assets are ignored.
	EnqueueAssets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID, reason string) error
	// EnqueueTenant queues every asset of the tenant that has an open finding.
	EnqueueTenant(ctx context.Context, tenantID shared.ID, reason string) error
	// Claim removes up to limit due rows, at most perTenant per tenant.
	Claim(ctx context.Context, limit, perTenant int) ([]QueueItem, error)
	// Stats returns the queue depth and the oldest due row's age.
	Stats(ctx context.Context) (QueueStats, error)
	// EnqueueReconcile queues, for every tenant, the assets with open
	// findings: those with a stale or missing version now, the others after
	// delay (a safety net for inputs no trigger watches).
	EnqueueReconcile(ctx context.Context, delay time.Duration) (int64, error)
	// StampVersion records the version the given open findings were computed
	// with. Closed findings are never stamped (they stay frozen).
	StampVersion(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID, version int64) error
	// RecordImpact adds a pass's counts to a scoring change's summary row.
	RecordImpact(ctx context.Context, tenantID shared.ID, changeID int64, impact ChangeImpact) error
	// ClaimDrainedSummaries hands up to limit summaries whose change has no
	// asset left in the queue to send, each in the transaction that marks it
	// notified: a summary whose send fails stays unmarked and is retried by
	// a later pass. Returns how many were marked.
	ClaimDrainedSummaries(ctx context.Context, limit int, send SummarySender) (int, error)
}

// SummarySender sends one scoring change summary inside tx (the transaction
// that marks it notified), typically by writing a notification outbox row.
type SummarySender func(ctx context.Context, tx *sql.Tx, s ChangeSummary) error
