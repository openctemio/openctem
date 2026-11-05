package coverage

// The path discovery ledger (docs/architecture/web-discovery.md): the one
// record every caller of path discovery checks and claims, so the per-origin
// request cap holds per 30 days whoever dispatches (the coverage planner, a
// workflow's paths step, a scan someone started).

import (
	"context"
	"strings"
	"time"

	"github.com/openctemio/ctis/v2/weburl"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// PathEvery is how often one origin may be dispatched (the 30 day floor of
// the coverage rule, held for every caller).
const PathEvery = 30 * 24 * time.Hour

// Refusals of the ledger and of the origin checks (the reason of a blocked
// pair, or of a skipped origin).
const (
	// ReasonNotAnOrigin: no live web service of the organization is named
	// by the target.
	ReasonNotAnOrigin = "not_an_origin"
	// ReasonNoOriginScopeEntry: no active scope entry names the origin's host.
	ReasonNoOriginScopeEntry = RequiresOriginScopeEntry
	// ReasonEdgeChallenged: the last probe was challenged or blocked by an
	// edge protection.
	ReasonEdgeChallenged = RequiresEdgeClear
	// ReasonInventoryUnchanged: nothing new in the inventory since the last
	// run.
	ReasonInventoryUnchanged = RequiresInventoryChanged
	// ReasonPathRanRecently: the origin was dispatched within PathEvery.
	ReasonPathRanRecently = "path_ran_recently"
	// ReasonHostBudgetSpent: the run's per-host budget is spent by other
	// origins of the host.
	ReasonHostBudgetSpent = "host_budget"
	// ReasonDailyBudgetSpent is ReadyBudgetSpent: the organization's daily
	// request budget cannot hold the origin's cap.
	ReasonDailyBudgetSpent = ReadyBudgetSpent
)

// MinPathGrant is the smallest request cap a job is granted (the web scope's
// floor): a claim that cannot grant it is refused.
const MinPathGrant = 50

// PathOrigin is a target's web origin: the normalised origin and its host
// name.
func PathOrigin(target string) (origin, host string, ok bool) {
	u, err := weburl.Parse(strings.TrimSpace(target))
	if err != nil {
		return "", "", false
	}
	return u.Origin(), u.Host, true
}

// PathOriginFacts are the stored facts about one web origin of the
// organization the path discovery gate reads.
type PathOriginFacts struct {
	AssetID shared.ID
	Host    string
	// ScopeEntry: an active scope entry names the origin's host itself.
	ScopeEntry bool
	// InventoryChanged: endpoints first seen since the last run (never run:
	// any endpoint).
	InventoryChanged bool
	// EdgeClear: the last probe was not challenged or blocked by an edge.
	EdgeClear bool
	// LastDispatch is when the ledger last recorded a dispatch on the origin
	// (zero: never).
	LastDispatch time.Time
}

// PathClaim asks the ledger to record a dispatch on one origin.
type PathClaim struct {
	TenantID shared.ID
	// Origin is a normalised origin (PathOrigin).
	Origin string
	// RunID is the run the dispatch belongs to (nil: none known).
	RunID *shared.ID
	// Requested is the request cap the job would carry.
	Requested int
	// PerHost is the most requests one run may spend on one host name across
	// its tasks.
	PerHost int
	// Daily is the organization's request budget per rolling day.
	Daily int
}

// PathLedger is the ledger and the facts behind the gate. Every
// implementation is scoped to the tenant.
type PathLedger interface {
	// PathOriginFacts returns the facts of the origins (keyed by the
	// normalised origin); an origin that is no live web service of the
	// organization is absent.
	PathOriginFacts(ctx context.Context, tenantID shared.ID, origins []string) (map[string]PathOriginFacts, error)
	// PathRequestsGrantedSince sums the request caps granted since t.
	PathRequestsGrantedSince(ctx context.Context, tenantID shared.ID, t time.Time) (int, error)
	// ClaimPathOrigin records a dispatch atomically: refused (reason) when
	// the origin was dispatched within PathEvery, when the daily budget does
	// not hold the request cap, or when the run's host budget is spent. It
	// returns the request cap granted (at most Requested).
	ClaimPathOrigin(ctx context.Context, c PathClaim) (granted int, reason string, err error)
}
