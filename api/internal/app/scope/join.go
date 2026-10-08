package scope

// The scope join after scope changes (RFC-054 §4.3). A discovered name that
// waits for review joins the inventory once a permanent scope entry covers
// it. The service asks for a join run after every change that can confirm
// such a name, once the change is committed, so every path (API, review
// rules, automations) gets it:
//
//   - an entry comes into effect: created in effect, approved, activated;
//   - an entry in effect changes (pattern, type, expiry);
//   - an exclusion goes away or narrows: deleted, taken out of effect,
//     changed.
//
// The joiner (*easm.JoinScheduler) debounces the requests per tenant and
// never runs two joins of one tenant at once. The apply and preview counts
// are limited to the assets the caller may see (Layer 2 data scope).

import (
	"context"
	"fmt"
	"time"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// JoinedAsset is a discovered asset the scope join confirmed, or would.
type JoinedAsset struct {
	AssetID string
	Name    string
	// CoveredBy is the evidence source: "scope_target:<entry id>".
	CoveredBy string
}

// ScopeJoiner runs the scope join (*easm.JoinScheduler).
type ScopeJoiner interface {
	// Schedule asks for a debounced background run.
	Schedule(tenantID shared.ID)
	// RunNow runs at once and returns what it confirmed.
	RunNow(ctx context.Context, tenantID shared.ID) ([]JoinedAsset, error)
	// Preview lists what a candidate entry would confirm; nothing is written.
	Preview(ctx context.Context, tenantID shared.ID, candidate *scopedom.Target) ([]JoinedAsset, error)
}

// VisibleAssetCounter counts the given assets of the tenant the data scope
// lets the caller see (nil scope: every one).
type VisibleAssetCounter interface {
	CountVisibleAssets(ctx context.Context, tenantID shared.ID, ds *shared.DataScope, assetIDs []string) (int, error)
}

// SetScopeJoin wires the join run after scope changes and the counter of the
// assets the caller may see. Nil joiner: the periodic run picks changes up.
func (s *Service) SetScopeJoin(j ScopeJoiner, visible VisibleAssetCounter) {
	s.joiner, s.visible = j, visible
}

// scheduleJoin asks for a join run of the tenant; called after a committed
// change.
func (s *Service) scheduleJoin(tenantID shared.ID) {
	if s.joiner != nil {
		s.joiner.Schedule(tenantID)
	}
}

// JoinFeedback is what a join run means for one entry, counted over the
// caller's data scope.
type JoinFeedback struct {
	// ConfirmedCount: waiting names this entry confirmed (or would).
	ConfirmedCount int
	// CoveredBy is the asset-list filter value (covered_by=<entry id>).
	CoveredBy string
}

// joinRunTimeout bounds the join run of an apply response.
const joinRunTimeout = 30 * time.Second

// JoinNow runs the tenant's join at once after the entry t came into effect
// or changed, and reports how many waiting names t confirmed that the caller
// may see. Nil when there is nothing to report (no joiner, t not in effect
// or not permanent). The run is idempotent; it takes over the pending
// background run.
func (s *Service) JoinNow(ctx context.Context, tenantID string, t *scopedom.Target) (*JoinFeedback, error) {
	if s.joiner == nil || t == nil || !t.InEffect(time.Now().UTC()) || t.ExpiresAt() != nil {
		return nil, nil
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	ctx, cancel := context.WithTimeout(ctx, joinRunTimeout)
	defer cancel()
	done, err := s.joiner.RunNow(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("scope join: %w", err)
	}
	return s.joinFeedback(ctx, tid, t.ID().String(), done)
}

// PreviewJoin reports how many names waiting for review a new permanent
// entry (targetType, pattern) would confirm, over the caller's data scope.
func (s *Service) PreviewJoin(ctx context.Context, tenantID, targetType, pattern string) (*JoinFeedback, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	tt, err := scopedom.ParseTargetType(targetType)
	if err != nil {
		return nil, err // wraps shared.ErrValidation
	}
	candidate, err := scopedom.NewTarget(tid, tt, pattern, "", "")
	if err != nil {
		return nil, err
	}
	if s.joiner == nil {
		return &JoinFeedback{}, nil
	}
	would, err := s.joiner.Preview(ctx, tid, candidate)
	if err != nil {
		return nil, fmt.Errorf("scope join preview: %w", err)
	}
	fb, err := s.joinFeedback(ctx, tid, candidate.ID().String(), would)
	if err != nil {
		return nil, err
	}
	fb.CoveredBy = "" // the candidate does not exist yet
	return fb, nil
}

// joinFeedback counts the assets entryID covers among done that the caller
// may see. Without a counter or data scope it refuses (fail closed): a
// restricted caller never sees tenant-wide counts.
func (s *Service) joinFeedback(ctx context.Context, tid shared.ID, entryID string, done []JoinedAsset) (*JoinFeedback, error) {
	fb := &JoinFeedback{CoveredBy: entryID}
	src := "scope_target:" + entryID
	ids := make([]string, 0, len(done))
	for _, d := range done {
		if d.CoveredBy == src {
			ids = append(ids, d.AssetID)
		}
	}
	if len(ids) == 0 {
		return fb, nil
	}
	if s.visible == nil || s.dataScope == nil {
		return nil, fmt.Errorf("scope join count: the data scope is not configured")
	}
	ds, err := s.dataScope.Resolve(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("resolve data scope: %w", err)
	}
	if fb.ConfirmedCount, err = s.visible.CountVisibleAssets(ctx, tid, ds, ids); err != nil {
		return nil, err
	}
	return fb, nil
}
