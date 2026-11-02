package posture

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/posture"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

type fakeRepo struct {
	state      posture.State
	budgetOK   bool
	rebuildErr error
	total      posture.Sums
	saved      *posture.Result
	savedNext  *time.Time
	failed     string
	failedNext *time.Time
	due        []shared.ID
	groups     []posture.GroupRow
	items      []posture.Item
	where      *filterspec.Where
}

func (f *fakeRepo) EnsureState(context.Context, shared.ID) (*posture.State, error) {
	s := f.state
	return &s, nil
}

func (f *fakeRepo) SetSchedule(_ context.Context, _ shared.ID, s posture.Schedule, next *time.Time) (*posture.State, error) {
	f.state.RefreshEvery, f.state.NextRefreshAt = s, next
	st := f.state
	return &st, nil
}

func (f *fakeRepo) TakeRecalculateBudget(context.Context, shared.ID, time.Time, time.Duration) (bool, time.Duration, error) {
	return f.budgetOK, 42 * time.Second, nil
}

func (f *fakeRepo) ClaimDueForPlatform(context.Context, time.Time, int, time.Duration) ([]shared.ID, error) {
	return f.due, nil
}

func (f *fakeRepo) Rebuild(context.Context, shared.ID) (posture.Sums, error) {
	return f.total, f.rebuildErr
}

func (f *fakeRepo) SaveResult(_ context.Context, _ shared.ID, r posture.Result, next *time.Time) error {
	f.saved, f.savedNext = &r, next
	return nil
}

func (f *fakeRepo) MarkFailed(_ context.Context, _ shared.ID, code string, next *time.Time) error {
	f.failed, f.failedNext = code, next
	return nil
}

func (f *fakeRepo) GroupsWhere(_ context.Context, w *filterspec.Where) ([]posture.GroupRow, error) {
	f.where = w
	return f.groups, nil
}

func (f *fakeRepo) ItemsWhere(context.Context, *filterspec.Where, int) ([]posture.Item, error) {
	return f.items, nil
}

var fixedNow = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

func newSvc(r *fakeRepo) *Service {
	s := NewService(r, nil, nil)
	s.now = func() time.Time { return fixedNow }
	return s
}

func TestRecalculateBudget(t *testing.T) {
	r := &fakeRepo{state: posture.State{RefreshEvery: posture.Schedule6h}}
	if _, wait, err := newSvc(r).Recalculate(context.Background(), shared.NewID()); !errors.Is(err, ErrTooSoon) || wait != 42*time.Second {
		t.Fatalf("over budget: %v %v", wait, err)
	}
	r.budgetOK = true
	r.total = posture.Sums{Assets: 10, Points: [6]float64{10}}
	if _, _, err := newSvc(r).Recalculate(context.Background(), shared.NewID()); err != nil {
		t.Fatal(err)
	}
	if r.saved == nil || r.saved.Score == nil || *r.saved.Score != 88 || r.saved.Grade != "B" || r.saved.Assets != 10 {
		t.Fatalf("saved = %+v", r.saved)
	}
	if r.savedNext == nil || !r.savedNext.Equal(fixedNow.Add(6*time.Hour)) {
		t.Fatalf("next = %v", r.savedNext)
	}
}

func TestRefreshNothingMeasuredStoresNoGrade(t *testing.T) {
	r := &fakeRepo{state: posture.State{RefreshEvery: posture.ScheduleManual}, budgetOK: true}
	if _, _, err := newSvc(r).Recalculate(context.Background(), shared.NewID()); err != nil {
		t.Fatal(err)
	}
	if r.saved.Score != nil || r.saved.Grade != "" || r.savedNext != nil {
		t.Fatalf("empty surface saved %+v next %v", r.saved, r.savedNext)
	}
}

func TestRefreshFailureKeepsResultAndRetries(t *testing.T) {
	r := &fakeRepo{state: posture.State{RefreshEvery: posture.ScheduleDaily}, budgetOK: true, rebuildErr: errors.New("boom")}
	if _, _, err := newSvc(r).Recalculate(context.Background(), shared.NewID()); err == nil {
		t.Fatal("want error")
	}
	if r.saved != nil || r.failed != "refresh_failed" || r.failedNext == nil || !r.failedNext.Equal(fixedNow.Add(retryAfterFailure)) {
		t.Fatalf("failure: saved %v failed %q next %v", r.saved, r.failed, r.failedNext)
	}
	// Busy is not a failure.
	r2 := &fakeRepo{state: posture.State{RefreshEvery: posture.ScheduleDaily}, budgetOK: true, rebuildErr: posture.ErrBusy}
	if _, _, err := newSvc(r2).Recalculate(context.Background(), shared.NewID()); !errors.Is(err, posture.ErrBusy) || r2.failed != "" {
		t.Fatalf("busy: %v %q", err, r2.failed)
	}
}

func TestChangeSchedule(t *testing.T) {
	r := &fakeRepo{state: posture.State{RefreshEvery: posture.Schedule6h}}
	if _, err := newSvc(r).ChangeSchedule(context.Background(), shared.NewID(), "5m"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid schedule: %v", err)
	}
	computed := fixedNow.Add(-2 * time.Hour)
	r.state.ComputedAt = &computed
	st, err := newSvc(r).ChangeSchedule(context.Background(), shared.NewID(), posture.ScheduleHourly)
	if err != nil || st.NextRefreshAt == nil || !st.NextRefreshAt.Equal(fixedNow) {
		t.Fatalf("hourly after a 2h-old computation is due now: %v %v", st, err)
	}
	st, _ = newSvc(r).ChangeSchedule(context.Background(), shared.NewID(), posture.ScheduleManual)
	if st.NextRefreshAt != nil {
		t.Fatal("manual has no next refresh")
	}
}

func TestRefreshDue(t *testing.T) {
	r := &fakeRepo{state: posture.State{RefreshEvery: posture.Schedule6h}, due: []shared.ID{shared.NewID(), shared.NewID()}}
	n, err := newSvc(r).RefreshDue(context.Background(), 10)
	if err != nil || n != 2 {
		t.Fatalf("refresh due = %d %v", n, err)
	}
}

func TestReadForScopeCompilesTheScope(t *testing.T) {
	tenant, user := shared.NewID(), shared.NewID()
	r := &fakeRepo{state: posture.State{RefreshEvery: posture.Schedule6h}, groups: []posture.GroupRow{
		{RootDomain: "example.com", Criticality: "high", Sums: posture.Sums{Assets: 3, Points: [6]float64{5}, Issues: [6]int64{1}}},
		{RootDomain: "", Criticality: "medium", Sums: posture.Sums{Assets: 0, Points: [6]float64{0, 0, 0, 0, 0, 2}, Issues: [6]int64{0, 0, 0, 0, 0, 1}}},
	}}
	// Organization read: the tenant predicate only.
	v, err := newSvc(r).ReadForScope(context.Background(), tenant, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v.Scoped || len(r.where.Args) != 1 || v.Score.Assets != 3 || len(v.Roots) != 1 || v.Roots[0].RootDomain != "example.com" {
		t.Fatalf("org read: scoped=%v args=%v view=%+v", v.Scoped, r.where.Args, v.Roots)
	}
	// A restricted reader: the scope predicate is compiled in.
	scope := &shared.DataScope{TenantID: tenant, UserID: user}
	v, err = newSvc(r).ReadForScope(context.Background(), tenant, scope)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Scoped || len(r.where.Args) < 3 {
		t.Fatalf("scoped read: scoped=%v sql=%s", v.Scoped, r.where.SQL)
	}
}

func TestReadRefusesMemberWithoutEnforcer(t *testing.T) {
	r := &fakeRepo{}
	_, err := newSvc(r).Read(context.Background(), Caller{TenantID: shared.NewID().String(), UserID: shared.NewID().String()}, &filterspec.Spec{})
	if err == nil {
		t.Fatal("a member read without a data scope enforcer must fail closed")
	}
}
