package posture

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// NoAsset is the asset id of the row that holds the issues without an asset
// (a lookalike domain, a leaked credential of the organization). Only a
// reader who sees the whole organization counts it: the data scope never
// admits it.
var NoAsset = shared.MustIDFromString("00000000-0000-0000-0000-000000000000")

// ErrBusy: the organization's posture is being recomputed right now.
var ErrBusy = errors.New("posture is being recalculated")

// State is an organization's posture bookkeeping.
type State struct {
	TenantID      shared.ID
	RefreshEvery  Schedule
	NextRefreshAt *time.Time
	ComputedAt    *time.Time
	DurationMS    int
	Assets        int
	// Score and Grade are the organization-wide result of the last
	// computation (nil / "" before the first or when nothing is measured).
	Score         *int
	Grade         string
	PreviousScore *int
	PreviousGrade string
	LastError     string
	FailedAt      *time.Time
	// LastRequestedAt is the last Recalculate now.
	LastRequestedAt *time.Time
}

// Result is what one computation stores on the state.
type Result struct {
	ComputedAt time.Time
	DurationMS int
	Assets     int
	Score      *int
	Grade      string
}

// GroupRow is the sums of the readable surface assets of one root domain
// and effective criticality.
type GroupRow struct {
	RootDomain  string
	Criticality string
	Sums        Sums
}

// Repository stores posture facts and state. Every per-tenant method takes
// the tenant from the caller; ClaimDueForPlatform works across tenants and
// is called only by the refresher.
type Repository interface {
	// EnsureState returns the organization's state, creating it (due now,
	// default schedule) on first use.
	EnsureState(ctx context.Context, tenantID shared.ID) (*State, error)
	// SetSchedule changes the refresh schedule and the next refresh time
	// (nil: manual).
	SetSchedule(ctx context.Context, tenantID shared.ID, s Schedule, next *time.Time) (*State, error)
	// TakeRecalculateBudget records a Recalculate now when the last one is
	// older than every; otherwise it returns how long to wait.
	TakeRecalculateBudget(ctx context.Context, tenantID shared.ID, now time.Time, every time.Duration) (bool, time.Duration, error)
	// ClaimDueForPlatform returns up to limit organizations whose refresh is
	// due and moves their next refresh by lease.
	ClaimDueForPlatform(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]shared.ID, error)
	// Rebuild recomputes the organization's facts in one transaction and
	// returns the organization-wide sums. ErrBusy when another rebuild of
	// the organization runs.
	Rebuild(ctx context.Context, tenantID shared.ID) (Sums, error)
	// SaveResult stores a computation (previous score kept) and the next
	// refresh time.
	SaveResult(ctx context.Context, tenantID shared.ID, r Result, next *time.Time) error
	// MarkFailed keeps the last result and records why the refresh failed.
	MarkFailed(ctx context.Context, tenantID shared.ID, code string, next *time.Time) error
	// GroupsWhere sums the facts matching a compiled filter by root domain
	// and criticality.
	GroupsWhere(ctx context.Context, w *filterspec.Where) ([]GroupRow, error)
	// ItemsWhere returns up to limit asset and category items matching a
	// compiled filter, most urgent first.
	ItemsWhere(ctx context.Context, w *filterspec.Where, limit int) ([]Item, error)
}

// RootDomain is the registrable domain (public suffix list) of an asset
// name: a host, host:port, URL or certificate name. Addresses and names
// with no registrable domain give "".
func RootDomain(name string) string {
	h := strings.ToLower(strings.TrimSpace(name))
	if h == "" {
		return ""
	}
	if strings.Contains(h, "://") {
		if u, err := url.Parse(h); err == nil {
			h = u.Hostname()
		}
	}
	if i := strings.IndexAny(h, "/ "); i >= 0 {
		h = h[:i]
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimPrefix(strings.TrimSuffix(h, "."), "*.")
	if h == "" || net.ParseIP(strings.Trim(h, "[]")) != nil || !strings.Contains(h, ".") {
		return ""
	}
	root, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err != nil {
		return ""
	}
	return root
}
