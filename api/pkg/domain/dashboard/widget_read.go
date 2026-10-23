package dashboard

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ReadScope is whose numbers a widget read computes. It is built by the
// server from the authenticated caller or the organization, never from a
// widget spec or the request.
type ReadScope struct {
	TenantID shared.ID
	// Assets is the asset scope: nil reads the whole organization
	// (findings without an asset included); otherwise the data scope of
	// the person the numbers are for (Unrestricted: every asset but the
	// private program assets hidden from them).
	Assets *shared.DataScope
	// CampaignViewer applies the pentest member-visibility rule: pentest
	// findings count only for members of their campaign. Nil counts every
	// published pentest finding (administrators, organization aggregates).
	CampaignViewer *shared.ID
}

// CountRow is one group of an open-findings count. Keys follow the
// requested group-by order; booleans are "true" / "false".
type CountRow struct {
	Keys  []string
	Count int64
}

// DayRow is one UTC day of flows for one key (empty key without group-by).
type DayRow struct {
	Day      time.Time
	Key      string
	Opened   int64
	Fixed    int64
	NetDelta int64
}

// FixHistRow is the fix-hours histogram of one key (12 log2 buckets: under
// 1 h, 1-2 h, ..., 512-1024 h, 1024 h and more).
type FixHistRow struct {
	Key  string
	Hist [12]int64
}

// RankItem is one finding of a rank list, with what a list row shows.
type RankItem struct {
	FindingID     shared.ID
	Title         string
	Severity      string
	PriorityClass string
	AssetID       *shared.ID
	AssetName     string
	SortAt        *time.Time
	SLADeadline   *time.Time
	KEV           bool
	// Pentest marks a pentest finding; CampaignID is its campaign (zero
	// when it has none). Organization lists keep them so the viewer's
	// campaign membership can be applied on read.
	Pentest    bool
	CampaignID shared.ID
}

// RankKind names a rank list of the facts.
type RankKind string

// Rank lists.
const (
	RankFixNext RankKind = "fix_next"
	RankSLADue  RankKind = "sla_due"
)

// FactReader reads the dashboard fact tables for one scope. Every method
// filters on scope.TenantID first and applies the asset scope and the
// campaign rule; filter dimensions the table does not carry are ignored by
// the caller's contract (the catalog only allows the ones it carries).
type FactReader interface {
	// FactsBuiltAt is when the tenant's facts were last fully built (nil:
	// never, the first build has not finished).
	FactsBuiltAt(ctx context.Context, tenantID shared.ID) (*time.Time, error)
	// CountOpen counts open findings (F1) grouped by groupBy.
	CountOpen(ctx context.Context, scope ReadScope, f WidgetFilter, groupBy []Dimension) ([]CountRow, error)
	// SLAWithin returns open findings with an SLA not breached (num) and
	// open findings with an SLA (den) (F1).
	SLAWithin(ctx context.Context, scope ReadScope, f WidgetFilter) (num, den int64, err error)
	// Days returns the daily flows (F2) for days in [from, to], by key.
	Days(ctx context.Context, scope ReadScope, f WidgetFilter, groupBy Dimension, from, to time.Time) ([]DayRow, error)
	// FixHist sums the fix-hours histograms (F2) of days in [from, to].
	FixHist(ctx context.Context, scope ReadScope, f WidgetFilter, groupBy Dimension, from, to time.Time) ([]FixHistRow, error)
	// Rank returns up to limit findings of a rank list (F3), merged across
	// the in-scope assets, with their list fields, still open.
	Rank(ctx context.Context, scope ReadScope, kind RankKind, f WidgetFilter, limit int) ([]RankItem, error)
	// CampaignsOf lists the pentest campaigns userID is a member of in the
	// tenant.
	CampaignsOf(ctx context.Context, tenantID, userID shared.ID) ([]shared.ID, error)

	// CrownJewels counts the crown jewels in scope (designated) and those
	// with at least one open finding of the given priority classes (F1,
	// campaign rule applied).
	CrownJewels(ctx context.Context, scope ReadScope, priorities []string) (CrownJewelCounts, error)
	// Discovery reads the coverage ledger (asset_coverage) for the assets in
	// scope: assets the ledger tracks, and those with a successful run of
	// any capability since the given time.
	Discovery(ctx context.Context, scope ReadScope, since time.Time) (DiscoveryCounts, error)
	// Validation counts open findings in scope with validation evidence,
	// and the retests completed since the given time.
	Validation(ctx context.Context, scope ReadScope, since time.Time) (ValidationCounts, error)
	// VisibleAssets keeps the ids that are assets of the tenant, not
	// deleted, not program-only and inside the scope.
	VisibleAssets(ctx context.Context, scope ReadScope, ids []shared.ID) (map[shared.ID]bool, error)
}

// CrownJewelCounts are the crown jewels of a scope.
type CrownJewelCounts struct {
	Designated int64
	Exposed    int64
}

// DiscoveryCounts are the coverage ledger figures of a scope. Uncovered =
// Tracked - Covered.
type DiscoveryCounts struct {
	Tracked int64
	Covered int64
}

// ValidationCounts are the validation figures of a scope.
type ValidationCounts struct {
	// Open findings, and those of them with validation evidence.
	Open      int64
	Validated int64
	// RetestsRun is the retests completed in the window.
	RetestsRun int64
}
