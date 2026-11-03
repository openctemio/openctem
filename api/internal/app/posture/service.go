// Package posture serves the external attack surface posture score
// (docs/architecture/easm-posture.md): the precomputed per-asset facts are
// rebuilt on each organization's schedule or on Recalculate now, and every
// read sums the facts of the assets the reader may see, compiled through
// the list query contract, so the tenant and the data scope are always in
// the WHERE.
package posture

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/posture"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Caller is the request's caller.
type Caller = datascope.ListCaller

const (
	// RecalculateEvery is the Recalculate now budget: once per organization.
	RecalculateEvery = 5 * time.Minute
	// refreshLease keeps a claimed organization from another replica.
	refreshLease = 10 * time.Minute
	// retryAfterFailure is when a failed refresh is tried again.
	retryAfterFailure = 15 * time.Minute
	// planCandidates is how many items a fix plan is chosen from.
	planCandidates = 200
	// MaxRoots caps the root domain rows of a view (worst first).
	MaxRoots = 100
)

// ErrTooSoon: Recalculate now ran less than RecalculateEvery ago.
var ErrTooSoon = errors.New("posture was recalculated recently")

// Service computes and reads posture.
type Service struct {
	repo      posture.Repository
	dataScope *datascope.Enforcer
	log       *logger.Logger
	now       func() time.Time
}

// NewService creates a Service. dataScope must be wired in production; a nil
// enforcer refuses every member read (fail closed).
func NewService(repo posture.Repository, dataScope *datascope.Enforcer, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{repo: repo, dataScope: dataScope, log: log, now: time.Now}
}

// RootScore is one root domain's score.
type RootScore struct {
	RootDomain string
	Score      posture.Score
	Issues     int64
	// Top is the category that takes the most points away.
	Top posture.Category
}

// View is what a reader sees.
type View struct {
	State *posture.State
	// Scoped is true when the figures cover only the reader's data scope
	// (the organization-wide score and its trend are not shown then).
	Scoped bool
	// Filtered is true when the read named root domains or other filters.
	Filtered   bool
	Score      posture.Score
	Gains      []posture.CategoryGain
	Plan       posture.Plan
	Reductions []posture.Reduction
	Roots      []RootScore
	// RootsTotal is the number of root domains before MaxRoots.
	RootsTotal int
}

// Read computes the view of the caller for a decoded filter.
func (s *Service) Read(ctx context.Context, c Caller, spec *filterspec.Spec) (*View, error) {
	a, tenantID, err := datascope.ListActor(ctx, s.dataScope, c)
	if err != nil {
		return nil, err
	}
	v, err := s.read(ctx, tenantID, a, spec)
	if err != nil {
		return nil, err
	}
	v.Filtered = spec != nil && (spec.Root != nil || spec.Q != "")
	return v, nil
}

// ReadForScope computes the view for a dashboard read: assets nil is the
// whole organization, otherwise the data scope of the person the numbers
// are for.
func (s *Service) ReadForScope(ctx context.Context, tenantID shared.ID, assets *shared.DataScope) (*View, error) {
	in := filterspec.UserActorInput{TenantID: tenantID, IsAdmin: assets == nil, Scope: assets}
	if assets != nil {
		in.UserID = assets.UserID
	}
	a, err := filterspec.UserActor(in)
	if err != nil {
		return nil, err
	}
	return s.read(ctx, tenantID, a, &filterspec.Spec{})
}

func (s *Service) read(ctx context.Context, tenantID shared.ID, a filterspec.Actor, spec *filterspec.Spec) (*View, error) {
	if spec == nil {
		spec = &filterspec.Spec{}
	}
	st, err := s.repo.EnsureState(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	w, err := filterspec.Compile(spec, posture.Fields, a)
	if err != nil {
		return nil, err
	}
	groups, err := s.repo.GroupsWhere(ctx, w)
	if err != nil {
		return nil, err
	}
	items, err := s.repo.ItemsWhere(ctx, w, planCandidates)
	if err != nil {
		return nil, err
	}
	v := &View{State: st, Scoped: a.Restricted()}
	var total posture.Sums
	byRoot := map[string]posture.Sums{}
	levels := make([]posture.LevelSums, 0, len(groups))
	for _, g := range groups {
		total.Add(g.Sums)
		r := byRoot[g.RootDomain]
		r.Add(g.Sums)
		byRoot[g.RootDomain] = r
		levels = append(levels, posture.LevelSums{Criticality: g.Criticality, Sums: g.Sums})
	}
	v.Score = posture.Compute(total)
	v.Gains = posture.CategoryGains(total)
	v.Plan = posture.FixPlan(total, items)
	v.Reductions = posture.Reductions(total, levels)
	for root, rs := range byRoot {
		if root == "" {
			continue // addresses and issues without an asset: in the total only
		}
		sc := posture.Compute(rs)
		row := RootScore{RootDomain: root, Score: sc}
		var worst float64
		for _, cs := range sc.Categories {
			row.Issues += cs.Issues
			if cs.Deduction > worst {
				worst, row.Top = cs.Deduction, cs.Category
			}
		}
		v.Roots = append(v.Roots, row)
	}
	sort.Slice(v.Roots, func(i, j int) bool {
		if v.Roots[i].Score.Raw != v.Roots[j].Score.Raw {
			return v.Roots[i].Score.Raw < v.Roots[j].Score.Raw
		}
		return v.Roots[i].RootDomain < v.Roots[j].RootDomain
	})
	v.RootsTotal = len(v.Roots)
	if len(v.Roots) > MaxRoots {
		v.Roots = v.Roots[:MaxRoots]
	}
	return v, nil
}

// next is the next scheduled refresh after from (nil: manual).
func next(sched posture.Schedule, from time.Time) *time.Time {
	var d time.Duration
	switch sched {
	case posture.ScheduleHourly:
		d = time.Hour
	case posture.Schedule6h:
		d = 6 * time.Hour
	case posture.ScheduleDaily:
		d = 24 * time.Hour
	default:
		return nil
	}
	t := from.Add(d)
	return &t
}

// refresh rebuilds one organization's facts and stores the result. A
// failure keeps the last result and is retried later.
func (s *Service) refresh(ctx context.Context, tenantID shared.ID, sched posture.Schedule) error {
	start := s.now()
	total, err := s.repo.Rebuild(ctx, tenantID)
	if err != nil {
		if errors.Is(err, posture.ErrBusy) {
			return err
		}
		retry := start.Add(retryAfterFailure)
		if n := next(sched, start); n == nil {
			retry = time.Time{}
		}
		var at *time.Time
		if !retry.IsZero() {
			at = &retry
		}
		if merr := s.repo.MarkFailed(ctx, tenantID, "refresh_failed", at); merr != nil {
			s.log.Warn("posture: record failure", "tenant_id", tenantID.String(), "error", merr)
		}
		return fmt.Errorf("rebuild posture: %w", err)
	}
	sc := posture.Compute(total)
	res := posture.Result{ComputedAt: s.now(), DurationMS: int(s.now().Sub(start).Milliseconds()), Assets: int(total.Assets)}
	if sc.Measured {
		v := sc.Value
		res.Score, res.Grade = &v, sc.Grade
	}
	return s.repo.SaveResult(ctx, tenantID, res, next(sched, s.now()))
}

// Recalculate rebuilds the organization's posture now, at most once per
// RecalculateEvery. ErrTooSoon comes with how long to wait; posture.ErrBusy
// when a refresh is running.
func (s *Service) Recalculate(ctx context.Context, tenantID shared.ID) (*posture.State, time.Duration, error) {
	ok, wait, err := s.repo.TakeRecalculateBudget(ctx, tenantID, s.now(), RecalculateEvery)
	if err != nil {
		return nil, 0, err
	}
	if !ok {
		return nil, wait, ErrTooSoon
	}
	st, err := s.repo.EnsureState(ctx, tenantID)
	if err != nil {
		return nil, 0, err
	}
	if err := s.refresh(ctx, tenantID, st.RefreshEvery); err != nil {
		return nil, 0, err
	}
	st, err = s.repo.EnsureState(ctx, tenantID)
	return st, 0, err
}

// ChangeSchedule changes the organization's refresh schedule.
func (s *Service) ChangeSchedule(ctx context.Context, tenantID shared.ID, sched posture.Schedule) (*posture.State, error) {
	if !sched.Valid() {
		return nil, fmt.Errorf("%w: refresh must be one of manual, 1h, 6h, 24h", shared.ErrValidation)
	}
	st, err := s.repo.EnsureState(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	from := s.now()
	if st.ComputedAt != nil {
		from = *st.ComputedAt
	}
	n := next(sched, from)
	if n != nil && n.Before(s.now()) {
		now := s.now()
		n = &now
	}
	return s.repo.SetSchedule(ctx, tenantID, sched, n)
}

// RefreshDue recomputes up to limit organizations whose refresh is due
// (the refresher controller).
func (s *Service) RefreshDue(ctx context.Context, limit int) (int, error) {
	ids, err := s.repo.ClaimDueForPlatform(ctx, s.now(), limit, refreshLease)
	if err != nil {
		return 0, err
	}
	done := 0
	// A canceled context fails each remaining rebuild at once; the claimed
	// organizations are retried when their lease ends.
	for _, id := range ids {
		if s.refreshOne(ctx, id) {
			done++
		}
	}
	return done, nil
}

// refreshOne refreshes one claimed organization; a failure is logged (it is
// retried on the organization's next due time) and never stops the batch.
func (s *Service) refreshOne(ctx context.Context, id shared.ID) bool {
	st, err := s.repo.EnsureState(ctx, id)
	if err != nil {
		s.log.Warn("posture: read state", "tenant_id", id.String(), "error", err)
		return false
	}
	if err := s.refresh(ctx, id, st.RefreshEvery); err != nil {
		if !errors.Is(err, posture.ErrBusy) {
			s.log.Warn("posture: refresh", "tenant_id", id.String(), "error", err)
		}
		return false
	}
	return true
}
