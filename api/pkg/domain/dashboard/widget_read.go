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
	// EPSS is the finding's exploitation probability (0 to 1), nil when the
	// feed has no score for it.
	EPSS *float64
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

	// Outcomes counts the findings in scope by where they went: in progress
	// now, and fixed, accepted and false positive since the given time
	// (resolved_at), with the findings list's rules (campaign rule applied).
	Outcomes(ctx context.Context, scope ReadScope, since time.Time) (OutcomeCounts, error)
	// OrgIntake sums the organization's receipts with activity since the
	// given time, per source group and tool. Receipts are organization-wide
	// (tool volumes are not asset-scoped): callers use it for an
	// organization read only.
	OrgIntake(ctx context.Context, tenantID shared.ID, since time.Time) ([]IntakeRow, error)
	// TopFix returns the proposed remediation suggestion that clears the most
	// risk points over its members that are open and inside the scope (asset
	// rule, data scope, campaign rule), pentest findings left out; nil when no
	// suggestion has such a member.
	TopFix(ctx context.Context, scope ReadScope) (*FixLever, error)

	// NewAssets counts the assets in scope added to the inventory
	// (created_at) since from, and between prevFrom and from, by asset type.
	NewAssets(ctx context.Context, scope ReadScope, from, prevFrom time.Time) ([]NewAssetRow, error)
	// CertificateExpiry counts the certificates in scope by how soon they
	// expire, measured from now.
	CertificateExpiry(ctx context.Context, scope ReadScope, now time.Time) (CertificateExpiryCounts, error)
	// AcceptanceExpiry counts the accepted findings in scope (campaign rule
	// applied) by how soon their risk acceptance ends, measured from now.
	AcceptanceExpiry(ctx context.Context, scope ReadScope, now time.Time) (AcceptanceExpiryCounts, error)
}

// NewAssetRow is one asset type's additions: in the window and in the
// window before it.
type NewAssetRow struct {
	AssetType string
	Current   int64
	Previous  int64
}

// CertificateExpiryCounts are the certificates of a scope by expiry band.
// The bands use the asset list's expiry filters (expires_after is strictly
// after, expires_before strictly before), so each band equals its list.
type CertificateExpiryCounts struct {
	// Total is every certificate in scope, with or without a known expiry.
	Total int64
	// Expired: expiry before now. Within7d: after now, before now + 7 days.
	// Within30d: after now + 7 days, before now + 30 days. Within90d: after
	// now + 30 days, before now + 90 days.
	Expired, Within7d, Within30d, Within90d int64
}

// AcceptanceExpiryCounts are the accepted findings of a scope by when their
// acceptance ends.
type AcceptanceExpiryCounts struct {
	// Accepted is every accepted finding in scope.
	Accepted int64
	// Within7d: ends at or before now + 7 days. Within30d: after now + 7
	// days, at or before now + 30 days. Later: after now + 30 days.
	Within7d, Within30d, Later int64
}

// FixLever is one remediation suggestion re-counted in a read's scope:
// Findings open members, Assets their distinct assets, PriorityOpen those of
// class P0 or P1, Points their risk points.
type FixLever struct {
	SuggestionID shared.ID
	Title        string
	Findings     int64
	Assets       int64
	PriorityOpen int64
	Points       int64
}

// RiskPoints is the risk weight of n open findings, the same formula as
// the remediation risk points: by priority class (P0 8, P1 4, P2 2, P3 1),
// or by severity for an unclassified finding (critical 4, high 2, medium and
// low 1).
func RiskPoints(priorityClass, severity string, n int64) int64 {
	switch priorityClass {
	case "P0":
		return 8 * n
	case "P1":
		return 4 * n
	case "P2":
		return 2 * n
	case "P3":
		return n
	}
	switch severity {
	case "critical":
		return 4 * n
	case "high":
		return 2 * n
	case "medium", "low":
		return n
	}
	return 0
}

// OutcomeCounts are the findings of a scope by outcome.
type OutcomeCounts struct {
	InProgress    int64
	Fixed         int64
	Accepted      int64
	FalsePositive int64
}

// IntakeRow is the receipts of one source (a source group and a tool) in a
// window: their sums, the latest receipt and the median time between
// receipts (nil with fewer than three).
type IntakeRow struct {
	Origin        string
	Tool          string
	Receipts      int64
	Received      int64
	Created       int64
	StillDetected int64
	Reopened      int64
	Closed        int64
	Skipped       int64
	Failed        int64
	Suppressed    int64
	LastAt        time.Time
	LastStatus    string
	LastReceiptID shared.ID
	MedianGap     *time.Duration
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
