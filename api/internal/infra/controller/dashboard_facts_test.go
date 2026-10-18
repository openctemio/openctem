package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/dashboardfact"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeFactQueue struct {
	tenants []shared.ID
	left    map[shared.ID]int // queue rows per tenant
	served  []shared.ID
	fail    shared.ID
}

func (f *fakeFactQueue) TenantsWithDirtyForPlatform(context.Context, int) ([]shared.ID, error) {
	return f.tenants, nil
}

func (f *fakeFactQueue) ProcessDirty(_ context.Context, tid shared.ID, limit int) (dashboardfact.DirtyBatch, error) {
	f.served = append(f.served, tid)
	if tid == f.fail {
		return dashboardfact.DirtyBatch{}, errors.New("boom")
	}
	n := min(f.left[tid], limit)
	f.left[tid] -= n
	b := dashboardfact.DirtyBatch{Claimed: n, Assets: n, Recomputed: n}
	if n > 0 {
		b.OldestMarkedAt = time.Now().Add(-time.Minute)
	}
	return b, nil
}

func (f *fakeFactQueue) QueueStatsForPlatform(context.Context) (int, time.Time, error) {
	total := 0
	for _, n := range f.left {
		total += n
	}
	return total, time.Time{}, nil
}

func sortedIDs(n int) []shared.ID {
	ids := []shared.ID{
		shared.MustIDFromString("00000000-0000-0000-0000-00000000000a"),
		shared.MustIDFromString("00000000-0000-0000-0000-00000000000b"),
		shared.MustIDFromString("00000000-0000-0000-0000-00000000000c"),
	}
	return ids[:n]
}

func TestDashboardFactsController_DrainsEveryTenantAndSurvivesFailures(t *testing.T) {
	ids := sortedIDs(3)
	q := &fakeFactQueue{tenants: ids, left: map[shared.ID]int{ids[0]: 1200, ids[2]: 3}, fail: ids[1]}
	c := NewDashboardFactsController(q, nil)
	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1203 || q.left[ids[0]] != 0 || q.left[ids[2]] != 0 {
		t.Fatalf("processed %d, left %v", n, q.left)
	}
	if got := testutil.ToFloat64(metrics.DashboardFactQueueDepth); got != 0 {
		t.Fatalf("queue depth gauge %v", got)
	}
}

// A tenant that uses its whole slice does not keep the next tick: the next
// tick starts after it.
func TestDashboardFactsController_RoundRobin(t *testing.T) {
	ids := sortedIDs(3)
	q := &fakeFactQueue{tenants: ids, left: map[shared.ID]int{ids[0]: 1 << 30, ids[1]: 1 << 30, ids[2]: 1 << 30}}
	c := NewDashboardFactsController(q, nil)
	clock := time.Unix(0, 0)
	c.now = func() time.Time { clock = clock.Add(time.Second); return clock }
	c.budget, c.slice = 4*time.Second, 2*time.Second

	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := q.served[0]
	q.served = nil
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if q.served[0] == first {
		t.Fatalf("second tick started with the same tenant %s", first)
	}
	if got := rotateAfter(ids, ids[2]); got[0] != ids[0] || len(got) != 3 {
		t.Fatalf("rotate after the last id: %v", got)
	}
	if got := rotateAfter(ids, ids[0]); got[0] != ids[1] || got[2] != ids[0] {
		t.Fatalf("rotate after the first id: %v", got)
	}
}

type fakeFactRuns struct {
	pending  []dashboardfact.PendingRun
	steps    map[shared.ID][]dashboardfact.RunStep
	started  []dashboardfact.RunKind
	aged     []shared.ID
	maintain int
}

func (f *fakeFactRuns) PendingRunsForPlatform(context.Context, time.Duration, int) ([]dashboardfact.PendingRun, error) {
	return f.pending, nil
}

func (f *fakeFactRuns) StartRun(_ context.Context, _ shared.ID, k dashboardfact.RunKind) (bool, error) {
	f.started = append(f.started, k)
	return true, nil
}

func (f *fakeFactRuns) RunStep(_ context.Context, tid shared.ID, _ int) (dashboardfact.RunStep, error) {
	s := f.steps[tid][0]
	f.steps[tid] = f.steps[tid][1:]
	return s, nil
}

func (f *fakeFactRuns) AgedMarkingDueForPlatform(context.Context, time.Duration, int) ([]dashboardfact.AgedMarkingDue, error) {
	return []dashboardfact.AgedMarkingDue{{TenantID: sortedIDs(1)[0], Since: time.Now().Add(-25 * time.Hour)}}, nil
}

func (f *fakeFactRuns) MarkAgedAssets(_ context.Context, tid shared.ID, _, _ time.Time) (int, error) {
	f.aged = append(f.aged, tid)
	return 0, nil
}

func (f *fakeFactRuns) MaintainPartitionsForPlatform(context.Context) (int, int, int, error) {
	f.maintain++
	return 0, 0, 0, nil
}

// Drift found by a first build is not counted; drift found by a nightly run
// is; a run in progress is resumed, not restarted; partitions are kept once
// a day.
func TestDashboardFactReconcileController_RunsAndDrift(t *testing.T) {
	ids := sortedIDs(2)
	f := &fakeFactRuns{
		pending: []dashboardfact.PendingRun{
			{TenantID: ids[0], Kind: dashboardfact.RunInitial},
			{TenantID: ids[1], Kind: dashboardfact.RunNightly, InProgress: true},
		},
		steps: map[shared.ID][]dashboardfact.RunStep{
			ids[0]: {{Kind: dashboardfact.RunInitial, Drift: 50}, {Kind: dashboardfact.RunInitial, Drift: 7, Done: true}},
			ids[1]: {{Kind: dashboardfact.RunNightly, Drift: 2, Done: true}},
		},
	}
	initialBefore := testutil.ToFloat64(metrics.DashboardFactDriftRowsTotal.WithLabelValues("initial"))
	nightlyBefore := testutil.ToFloat64(metrics.DashboardFactDriftRowsTotal.WithLabelValues("nightly"))
	c := NewDashboardFactReconcileController(f, nil)
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.started) != 1 || f.started[0] != dashboardfact.RunInitial {
		t.Fatalf("started %v, want only the initial run (the nightly one resumes)", f.started)
	}
	if got := testutil.ToFloat64(metrics.DashboardFactDriftRowsTotal.WithLabelValues("initial")) - initialBefore; got != 0 {
		t.Fatalf("a first build counted %v drift rows", got)
	}
	if got := testutil.ToFloat64(metrics.DashboardFactDriftRowsTotal.WithLabelValues("nightly")) - nightlyBefore; got != 2 {
		t.Fatalf("nightly drift counted %v, want 2", got)
	}
	if len(f.aged) != 1 || f.maintain != 1 {
		t.Fatalf("aged %v, maintain %d", f.aged, f.maintain)
	}
	f.pending = nil
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.maintain != 1 {
		t.Fatalf("partitions kept %d times in one day", f.maintain)
	}
}
