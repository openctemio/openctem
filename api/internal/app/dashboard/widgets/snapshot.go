package widgets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	dashboardapp "github.com/openctemio/openctem/api/internal/app/dashboard"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Snapshots (docs/architecture/dashboards.md, "Snapshots and refresh").
//
// Opening a dashboard serves its stored snapshot. A snapshot is recomputed
// (and stored) on open only when there is none, when the layout changed,
// or, for a personal dashboard, when the owner's scope changed since it was
// computed: a snapshot of another scope is never served. The refresher
// recomputes snapshots on their schedule; Refresh now recomputes one at
// once within a budget.

// ErrRefreshBudget is returned when Refresh now is over its budget (429).
type ErrRefreshBudget struct{ RetryAfter time.Duration }

func (e *ErrRefreshBudget) Error() string {
	return "refresh budget used up; try again later"
}

// ErrRefreshRunning is returned when the dashboard is already being
// recomputed (429): one Refresh now or scheduled refresh per dashboard at
// a time.
var ErrRefreshRunning = errors.New("this dashboard is already being refreshed; try again in a moment")

// MembershipReader reads a member's role and state (the tenant repository).
type MembershipReader = dashboardapp.MembershipReader

// orgScopeKey is the scope key of every organization snapshot.
const orgScopeKey = "organization"

const (
	// refreshLease keeps a claimed snapshot from another replica while it
	// is recomputed.
	refreshLease = 5 * time.Minute
	// retryAfterFailure is when a failed scheduled refresh is tried again
	// when its schedule is longer.
	retryAfterFailure = 15 * time.Minute
	// personalUnviewed drops a personal snapshot nobody opened for this
	// long; it is recomputed on the next open.
	personalUnviewed = 14 * 24 * time.Hour
)

// SetSnapshots wires snapshot storage and the refresher's readers. Without
// it every read computes (and nothing is stored).
func (s *Service) SetSnapshots(store dashboard.SnapshotStore, repo dashboard.Repository, members MembershipReader, settings dashboardapp.SettingsStore) {
	s.snapshots, s.repo, s.members, s.settings = store, repo, members, settings
}

// layoutHash fingerprints the widgets a snapshot was computed from.
func layoutHash(ws []dashboard.Widget) string {
	raw, _ := json.Marshal(ws)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:16])
}

func (s *Service) scopeKey(ctx context.Context, d *dashboard.Dashboard, scope dashboard.ReadScope) (string, error) {
	if d.Kind() == dashboard.KindOrganization {
		return orgScopeKey, nil
	}
	return s.snapshots.ScopeFingerprint(ctx, d.TenantID(), d.UserID(), scope.Assets, scope.CampaignViewer == nil)
}

// read serves the snapshot of d for scope, or computes and stores a new one.
// force recomputes whatever is stored (Refresh now).
func (s *Service) read(ctx context.Context, c dashboardapp.Caller, d *dashboard.Dashboard, scope dashboard.ReadScope, force bool) (*DashboardData, error) {
	kind := string(d.Kind())
	if s.snapshots == nil {
		return s.compute(ctx, c.TenantID, c.UserID, d.ID().String(), d.Widgets(), kind, scope, true)
	}
	key, err := s.scopeKey(ctx, d, scope)
	if err != nil {
		return nil, err
	}
	lh := layoutHash(d.Widgets())
	if !force {
		snap, err := s.snapshots.GetSnapshot(ctx, d.TenantID(), d.ID())
		if err != nil {
			return nil, err
		}
		if snap != nil && snap.ScopeKey == key && snap.LayoutHash == lh && snap.Kind == d.Kind() && snap.OwnerID == d.UserID() {
			var out DashboardData
			if err := json.Unmarshal(snap.Data, &out); err == nil {
				s.decorate(ctx, &out, d, snap)
				if terr := s.snapshots.TouchSnapshot(ctx, d.TenantID(), d.ID(), s.now()); terr != nil {
					s.logger.Warn("touch dashboard snapshot", "error", terr.Error())
				}
				return &out, nil
			}
			s.logger.Warn("unreadable dashboard snapshot, recomputing", "dashboard_id", d.ID().String())
		}
	}
	return s.computeAndStore(ctx, c.TenantID, c.UserID, d, scope, key, lh, true)
}

func (s *Service) computeAndStore(ctx context.Context, tenantID, userID shared.ID, d *dashboard.Dashboard, scope dashboard.ReadScope, key, lh string, limited bool) (*DashboardData, error) {
	started := s.now()
	out, err := s.compute(ctx, tenantID, userID, d.ID().String(), d.Widgets(), string(d.Kind()), scope, limited)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("encode dashboard snapshot: %w", err)
	}
	interval, next := s.nextRefresh(ctx, d, s.now())
	out.RefreshSchedule, out.NextRefreshAt = string(interval), next
	// The scope moved while computing: the figures are not stored under a
	// key they may not match (the next open computes again).
	if !s.sameScope(ctx, d, scope, key) {
		return out, nil
	}
	snap := dashboard.Snapshot{
		TenantID: d.TenantID(), DashboardID: d.ID(), Kind: d.Kind(), OwnerID: d.UserID(), ScopeKey: key, LayoutHash: lh,
		Data: raw, ComputedAt: out.ComputedAt, DurationMS: int(s.now().Sub(started).Milliseconds()), NextRefreshAt: next,
	}
	if err := s.snapshots.PutSnapshot(ctx, snap); err != nil {
		return nil, err
	}
	return out, nil
}

// sameScope reports whether the scope key is still key (false when it
// cannot be read).
func (s *Service) sameScope(ctx context.Context, d *dashboard.Dashboard, scope dashboard.ReadScope, key string) bool {
	after, err := s.scopeKey(ctx, d, scope)
	if err != nil {
		s.logger.Warn("dashboard scope key after compute", "error", err.Error())
		return false
	}
	return after == key
}

// decorate adds the schedule and freshness of a stored snapshot.
func (s *Service) decorate(ctx context.Context, out *DashboardData, d *dashboard.Dashboard, snap *dashboard.Snapshot) {
	interval, _ := s.effectiveSchedule(ctx, d)
	out.RefreshSchedule = string(interval)
	if d.Schedule().PausedAt == nil {
		out.NextRefreshAt = snap.NextRefreshAt
	}
	out.LastRefreshError = snap.LastError
	out.Stale = snap.LastError != ""
	if p := interval.Period(); p > 0 && s.now().Sub(snap.ComputedAt) > 2*p {
		out.Stale = true
	}
}

// effectiveSchedule resolves the organization default. A default that
// cannot be read falls back to the platform default.
func (s *Service) effectiveSchedule(ctx context.Context, d *dashboard.Dashboard) (dashboard.Interval, *int) {
	sch := d.Schedule()
	if sch.Interval != dashboard.IntervalDefault {
		return sch.Interval, sch.DailyMinute
	}
	if s.settings != nil {
		if ds, err := s.settings.GetDashboardSettings(ctx, d.TenantID().String()); err == nil && ds != nil && ds.DefaultRefreshSchedule != "" {
			return dashboard.Interval(ds.DefaultRefreshSchedule), ds.DefaultRefreshDailyMinute
		}
	}
	return dashboard.DefaultInterval, nil
}

// nextRefresh is the effective interval and the next scheduled refresh (nil
// for manual or paused).
func (s *Service) nextRefresh(ctx context.Context, d *dashboard.Dashboard, now time.Time) (dashboard.Interval, *time.Time) {
	interval, minute := s.effectiveSchedule(ctx, d)
	if d.Schedule().PausedAt != nil {
		return interval, nil
	}
	return interval, dashboard.Schedule{Interval: interval, DailyMinute: minute}.Next(now)
}

// RefreshPersonal recomputes the caller's own dashboard now (Refresh now),
// within the budget.
func (s *Service) RefreshPersonal(ctx context.Context, c dashboardapp.Caller, id string) (*DashboardData, error) {
	d, err := s.dash.Get(ctx, c.TenantID.String(), c.UserID.String(), id)
	if err != nil {
		return nil, err
	}
	scope, err := s.personalScope(ctx, c)
	if err != nil {
		return nil, err
	}
	out, err := s.refreshNow(ctx, c, d, scope)
	if err != nil {
		return nil, err
	}
	return s.forViewer(ctx, out, c, scope.CampaignViewer)
}

// RefreshOrg recomputes an organization dashboard the caller may read, within
// the budget (every viewer's Refresh now counts against the organization's
// hourly budget).
func (s *Service) RefreshOrg(ctx context.Context, c dashboardapp.Caller, id string) (*DashboardData, error) {
	d, err := s.dash.GetOrg(ctx, c, id)
	if err != nil {
		return nil, err
	}
	out, err := s.refreshNow(ctx, c, d.Dashboard, orgScope(c.TenantID))
	if err != nil {
		return nil, err
	}
	return s.forViewer(ctx, out, c, s.campaignViewer(ctx, c))
}

// refreshNow recomputes d for scope under the dashboard's refresh lock and
// within the budget. A refresh already running for the dashboard answers
// ErrRefreshRunning without using the budget; a refresh that takes the
// budget and then cannot compute (busy, failed) gives it back.
func (s *Service) refreshNow(ctx context.Context, c dashboardapp.Caller, d *dashboard.Dashboard, scope dashboard.ReadScope) (*DashboardData, error) {
	if s.snapshots == nil {
		return s.read(ctx, c, d, scope, true)
	}
	release, ok, err := s.snapshots.TryRefreshLock(ctx, d.TenantID(), d.ID())
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrRefreshRunning
	}
	defer release()
	if err := s.takeBudget(ctx, c, d.ID()); err != nil {
		return nil, err
	}
	out, err := s.read(ctx, c, d, scope, true)
	if err != nil {
		if rerr := s.snapshots.RefundRefreshBudget(context.WithoutCancel(ctx), c.TenantID, d.ID(), c.UserID); rerr != nil {
			s.logger.Warn("refund dashboard refresh budget", "dashboard_id", d.ID().String(), "error", rerr.Error())
		}
		return nil, err
	}
	return out, nil
}

func (s *Service) takeBudget(ctx context.Context, c dashboardapp.Caller, dashboardID shared.ID) error {
	if s.snapshots == nil {
		return nil
	}
	ok, wait, err := s.snapshots.TakeRefreshBudget(ctx, c.TenantID, dashboardID, c.UserID)
	if err != nil {
		return err
	}
	if !ok {
		return &ErrRefreshBudget{RetryAfter: wait}
	}
	return nil
}

// RefreshDue recomputes up to limit snapshots whose scheduled refresh is due
// and returns how many were refreshed. A personal snapshot is computed for
// its owner as they are now (an owner who is no longer an active member has
// the snapshot removed); a failure keeps the last good snapshot.
func (s *Service) RefreshDue(ctx context.Context, limit int) (int, error) {
	if s.snapshots == nil {
		return 0, nil
	}
	now := s.now()
	if err := s.snapshots.PruneForPlatform(ctx, now.Add(-24*time.Hour), now.Add(-personalUnviewed)); err != nil {
		s.logger.Warn("prune dashboard snapshots", "error", err.Error())
	}
	due, err := s.snapshots.ClaimDueSnapshotsForPlatform(ctx, now, limit, refreshLease)
	if err != nil {
		return 0, err
	}
	done := 0
	for i := 0; i < len(due) && ctx.Err() == nil; i++ {
		ds := due[i]
		// One failing dashboard is recorded on its snapshot and must not
		// stop the others.
		if refreshed, rerr := s.refreshOne(ctx, ds); rerr != nil {
			s.logger.Warn("dashboard snapshot refresh failed", "dashboard_id", ds.DashboardID.String(), "error", rerr.Error())
		} else if refreshed {
			done++
		}
	}
	return done, nil
}

// refreshOne recomputes one due snapshot; false when the snapshot was
// removed instead (its dashboard is gone or its owner is no longer active).
func (s *Service) refreshOne(ctx context.Context, ds dashboard.DueSnapshot) (bool, error) {
	var (
		d     *dashboard.Dashboard
		scope dashboard.ReadScope
		err   error
	)
	switch ds.Kind {
	case dashboard.KindOrganization:
		d, err = s.repo.GetOrg(ctx, ds.TenantID, ds.DashboardID)
		scope = orgScope(ds.TenantID)
	default:
		d, err = s.repo.GetByID(ctx, ds.TenantID, ds.OwnerID, ds.DashboardID)
		if err == nil {
			scope, err = s.ownerScope(ctx, ds.TenantID, ds.OwnerID)
		}
	}
	if errors.Is(err, shared.ErrNotFound) || errors.Is(err, datascope.ErrInactivePrincipal) {
		return false, s.snapshots.DeleteSnapshot(ctx, ds.TenantID, ds.DashboardID)
	}
	if err != nil {
		return false, s.markFailed(ctx, ds, nil, err)
	}
	// A Refresh now of this dashboard is running and stores a fresh
	// snapshot with its own next refresh time: nothing to do.
	release, ok, err := s.snapshots.TryRefreshLock(ctx, ds.TenantID, ds.DashboardID)
	if err != nil {
		return false, s.markFailed(ctx, ds, d, err)
	}
	if !ok {
		return false, nil
	}
	defer release()
	key, err := s.scopeKey(ctx, d, scope)
	if err != nil {
		return false, s.markFailed(ctx, ds, d, err)
	}
	if _, err := s.computeAndStore(ctx, ds.TenantID, ds.OwnerID, d, scope, key, layoutHash(d.Widgets()), false); err != nil {
		return false, s.markFailed(ctx, ds, d, err)
	}
	return true, nil
}

func (s *Service) markFailed(ctx context.Context, ds dashboard.DueSnapshot, d *dashboard.Dashboard, cause error) error {
	next := s.now().Add(retryAfterFailure)
	if d != nil {
		if _, n := s.nextRefresh(ctx, d, s.now()); n != nil && n.Before(next) {
			next = *n
		}
	}
	if err := s.snapshots.MarkSnapshotFailed(ctx, ds.TenantID, ds.DashboardID, ReasonFailed, &next); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}

// ownerScope is the read scope of a personal dashboard's owner outside a
// request: their membership decides administrator and owner, the data scope
// follows from it (the same decision a request of theirs gets).
func (s *Service) ownerScope(ctx context.Context, tenantID, userID shared.ID) (dashboard.ReadScope, error) {
	if s.members == nil {
		return dashboard.ReadScope{}, errors.New("membership reader not wired")
	}
	m, err := s.members.GetMembership(ctx, userID, tenantID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return dashboard.ReadScope{}, datascope.ErrInactivePrincipal
		}
		return dashboard.ReadScope{}, err
	}
	if m == nil || !m.IsActive() {
		return dashboard.ReadScope{}, datascope.ErrInactivePrincipal
	}
	admin := m.IsOwner() || m.IsAdmin()
	assets, err := s.dataScope.ResolveForStrict(ctx, tenantID, datascope.Caller{UserID: userID.String(), IsAdmin: admin, IsOwner: m.IsOwner()})
	if err != nil {
		return dashboard.ReadScope{}, err
	}
	scope := dashboard.ReadScope{TenantID: tenantID, Assets: assets}
	if !admin {
		uid := userID
		scope.CampaignViewer = &uid
	}
	return scope, nil
}
