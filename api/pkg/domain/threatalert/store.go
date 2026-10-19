package threatalert

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnevent"
)

// QueueItem is one organization and vulnerability waiting to be planned.
type QueueItem struct {
	TenantID shared.ID
	VulnID   string
}

// TenantState is one organization's delivery state.
type TenantState struct {
	TenantID          shared.ID
	Exists            bool
	BaselineAt        *time.Time
	BaselineDigestDue bool
	// LastDigestOn is the organization-local date of the last digest
	// (YYYY-MM-DD, "" when none).
	LastDigestOn string
	LastDigestAt *time.Time
	LastFoldAt   *time.Time
}

// DigestItem is one alert named in a digest.
type DigestItem struct {
	ID             shared.ID
	VulnID         string
	Title          string
	Level          Level
	ETS            int
	InKEV          bool
	Confirmed      int
	Possible       int
	InternetFacing int
}

// Digest summarizes what changed since the last digest.
type Digest struct {
	Immediate int
	Digest    int
	Listed    int
	Resolved  int
	KEV       int
	Top       []DigestItem
	// Exploited counts the open alerts whose CVE is in KEV (the baseline
	// digest's headline).
	Exploited int
}

// Empty reports whether there is nothing to say.
func (d Digest) Empty() bool { return d.Immediate+d.Digest+d.Listed+d.Resolved == 0 }

// Recipient is a member who asked for the e-mail digest.
type Recipient struct {
	UserID shared.ID
	Email  string
	// Frequency is daily or weekly.
	Frequency string
	Muted     bool
}

// PlannerStore is what the planner reads and writes.
type PlannerStore interface {
	PlannerCursor(ctx context.Context) (int64, error)
	SetPlannerCursor(ctx context.Context, id int64) error
	// EventsAfter returns up to limit events with an id above id, in id
	// order.
	EventsAfter(ctx context.Context, id int64, limit int) ([]vulnevent.Event, error)
	// TenantsAffectedBy lists the organizations with an open finding for
	// the vulnerability or a possibly affected asset (product known,
	// version unknown).
	TenantsAffectedBy(ctx context.Context, vulnID string) ([]shared.ID, error)
	Enqueue(ctx context.Context, items []QueueItem) error
	// Dequeue removes and returns up to limit queued items (oldest first).
	Dequeue(ctx context.Context, limit int) ([]QueueItem, error)
	// Vuln returns the public facts of a vulnerability (nil when unknown);
	// the last event is the newest one within the active window.
	Vuln(ctx context.Context, vulnID string, eventsSince time.Time) (*Vuln, error)
	// AffectedAssets lists the organization's affected assets: open
	// findings for the vulnerability (confirmed or likely) and assets
	// running a product the vulnerability names whose version is unknown
	// (possible).
	AffectedAssets(ctx context.Context, tenantID shared.ID, vulnID string) ([]Asset, error)
	// AlertByVuln returns the organization's alert for the vulnerability
	// (nil when none).
	AlertByVuln(ctx context.Context, tenantID shared.ID, vulnID string) (*Alert, error)
	// SaveAlert inserts or updates the alert (by organization and
	// vulnerability), sets its id and replaces its assets, in one
	// transaction. An alert read before (non-zero id) is updated only when
	// it has not changed since (its updated_at); otherwise ErrStale, so a
	// triage decision made meanwhile is never overwritten.
	SaveAlert(ctx context.Context, a *Alert, assets []Asset) error
	// ResolveVuln resolves every open alert of a vulnerability (a rejection
	// upstream) and reports how many.
	ResolveVuln(ctx context.Context, vulnID, reason string, at time.Time) (int, error)
	// PendingImmediate lists the organization's open immediate alerts not
	// sent yet, highest score first.
	PendingImmediate(ctx context.Context, tenantID shared.ID) ([]*Alert, error)
	TenantsWithPendingImmediate(ctx context.Context, limit int) ([]shared.ID, error)
	// MarkNotified records that the alerts were sent at level (counted in
	// the hourly cap when counted is true).
	MarkNotified(ctx context.Context, tenantID shared.ID, ids []shared.ID, level Level, counted bool, at time.Time) error
	// SetHeld marks alerts held by quiet hours.
	SetHeld(ctx context.Context, tenantID shared.ID, ids []shared.ID) error
	// ImmediateSentSince counts the immediate messages sent since.
	ImmediateSentSince(ctx context.Context, tenantID shared.ID, since time.Time) (int, error)
	TenantState(ctx context.Context, tenantID shared.ID) (TenantState, error)
	SaveTenantState(ctx context.Context, st TenantState) error
	// TenantsWithoutBaseline lists organizations never planned (and those
	// whose baseline waits, re-checked hourly).
	TenantsWithoutBaseline(ctx context.Context, limit int) ([]shared.ID, error)
	// ActiveWindowVulns lists the vulnerabilities with an event since
	// eventsSince, or added to KEV since kevSince, that affect the
	// organization.
	ActiveWindowVulns(ctx context.Context, tenantID shared.ID, eventsSince, kevSince time.Time) ([]string, error)
	// DigestTenants lists organizations with something for the digest.
	DigestTenants(ctx context.Context) ([]shared.ID, error)
	// DigestSummary summarizes the alerts that changed since, counted
	// within scope (nil: the whole organization).
	DigestSummary(ctx context.Context, tenantID shared.ID, since time.Time, scope *shared.DataScope) (Digest, error)
	// ClearDigest marks the pending digest content as sent.
	ClearDigest(ctx context.Context, tenantID shared.ID) error
	// DigestRecipients lists the active people who asked for the e-mail
	// digest and may read vulnerabilities.
	DigestRecipients(ctx context.Context, tenantID shared.ID) ([]Recipient, error)
}

// ListFilter narrows the alert list.
type ListFilter struct {
	Level        Level
	States       []State
	Tier         Tier
	InternetOnly bool
	Search       string
	Page         int
	PerPage      int
}

// Summary counts the open alerts a viewer sees.
type Summary struct {
	Open           int `json:"open"`
	Immediate      int `json:"immediate"`
	Digest         int `json:"digest"`
	Listed         int `json:"listed"`
	KEV            int `json:"kev"`
	InternetFacing int `json:"internet_facing"`
}

// AssetView is one affected asset as a viewer sees it.
type AssetView struct {
	Asset
	FindingStatus string
	TaskID        *shared.ID
}

// TimelineEntry is one public event of the alert's vulnerability.
type TimelineEntry struct {
	Kind     string
	At       time.Time
	SourceAt *time.Time
	Detail   map[string]any
}

// Detail is an alert with what a viewer may see of it.
type Detail struct {
	Alert    Alert
	Vuln     Vuln
	Assets   []AssetView
	Timeline []TimelineEntry
	// AllInScope: every asset of the alert is in the viewer's scope.
	AllInScope bool
}

// ReadStore is what the alert API reads and writes. Every method takes
// the organization; scope narrows to the viewer (nil: unrestricted).
type ReadStore interface {
	List(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, f ListFilter) ([]Alert, int, Summary, error)
	Get(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, id shared.ID) (*Detail, error)
	// SetState records a triage decision.
	SetState(ctx context.Context, tenantID, id shared.ID, to State, reason, note string, by shared.ID, at time.Time, suppressedUntil *time.Time) error
}
