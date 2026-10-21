package widgets

import (
	"math"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
)

func day(s string) time.Time {
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestNewWindow(t *testing.T) {
	now := time.Date(2026, 10, 21, 15, 4, 0, 0, time.UTC)
	w := newWindow(now, dashboard.WidgetTime{Range: dashboard.TimeRange7d, Compare: dashboard.ComparePreviousPeriod})
	if w.From != "2026-10-15" || w.To != "2026-10-21" || w.PreviousFrom != "2026-10-08" || w.PreviousTo != "2026-10-14" || w.Bucket != "day" {
		t.Errorf("7d window = %+v", w)
	}
	if w := newWindow(now, dashboard.WidgetTime{Range: dashboard.TimeRangeInherit}); w.Days != 30 || w.PreviousFrom != "" {
		t.Errorf("inherit = %+v (30 days, no comparison)", w)
	}
	if w := newWindow(now, dashboard.WidgetTime{Range: dashboard.TimeRange90d}); w.Bucket != "week" {
		t.Errorf("90d bucket = %s", w.Bucket)
	}
	if w := newWindow(now, dashboard.WidgetTime{Range: dashboard.TimeRange365d}); w.Bucket != "month" {
		t.Errorf("365d bucket = %s", w.Bucket)
	}
}

func TestBucketEnds(t *testing.T) {
	if got := bucketEnds(day("2026-10-01"), day("2026-10-03"), "day"); len(got) != 3 || !got[2].Equal(day("2026-10-03")) {
		t.Errorf("days = %v", got)
	}
	w := bucketEnds(day("2026-10-01"), day("2026-10-21"), "week")
	if len(w) != 3 || !w[0].Equal(day("2026-10-07")) || !w[2].Equal(day("2026-10-21")) {
		t.Errorf("weeks = %v", w)
	}
	m := bucketEnds(day("2026-08-15"), day("2026-10-21"), "month")
	if len(m) != 3 || !m[0].Equal(day("2026-08-31")) || !m[1].Equal(day("2026-09-30")) || !m[2].Equal(day("2026-10-21")) {
		t.Errorf("months = %v", m)
	}
}

func TestBackcastAndFlows(t *testing.T) {
	days := []dashboard.DayRow{
		{Day: day("2026-10-02"), Opened: 3, NetDelta: 3},
		{Day: day("2026-10-03"), Opened: 1, Fixed: 2, NetDelta: -1},
	}
	ends := bucketEnds(day("2026-10-01"), day("2026-10-03"), "day")
	got := backcast(10, days, ends)
	// Open now 10; after 10-01 the net change was +2, after 10-02 it was -1.
	want := []float64{8, 11, 10}
	for i, p := range got {
		if p.V != want[i] {
			t.Errorf("open at %s = %v, want %v", p.T, p.V, want[i])
		}
	}
	opened, fixed := flows(days, day("2026-10-01"), ends)
	if opened[1].V != 3 || opened[2].V != 1 || fixed[2].V != 2 || opened[0].V != 0 {
		t.Errorf("flows = %v %v", opened, fixed)
	}
}

func TestHistQuantile(t *testing.T) {
	var h [12]int64
	if _, n := histQuantile(h, 0.5); n != 0 {
		t.Error("empty histogram has a sample")
	}
	// Ten fixes in the 8-16 h bucket (k = 4): the median is geometric
	// inside the bucket (8 * 2^0.5).
	h[4] = 10
	med, n := histQuantile(h, 0.5)
	if n != 10 || math.Abs(med-8*math.Sqrt2) > 1e-9 {
		t.Errorf("median = %v (n %d)", med, n)
	}
	// Everything under an hour: linear inside [0, 1).
	var u [12]int64
	u[0] = 4
	if med, _ := histQuantile(u, 0.5); med != 0.5 {
		t.Errorf("sub-hour median = %v", med)
	}
	// The open-ended last bucket reports its lower bound.
	var l [12]int64
	l[11] = 3
	if p90, _ := histQuantile(l, 0.9); p90 != 1024 {
		t.Errorf("last bucket = %v", p90)
	}
}

func TestDrillHref(t *testing.T) {
	yes, no := true, false
	for _, tc := range []struct {
		f    dashboard.WidgetFilter
		want string
	}{
		{dashboard.WidgetFilter{}, "/findings?state=open"},
		{dashboard.WidgetFilter{Severity: []string{"critical", "high"}, KEV: &yes}, "/findings?is_in_kev=true&severity=critical,high&state=open"},
		{dashboard.WidgetFilter{SLAState: []string{"breached"}}, "/findings?sla_status=overdue,exceeded&state=open"},
		{dashboard.WidgetFilter{AssetGroupIDs: []string{"6f0b9c56-1c1c-4c3d-9f21-6b1d4a3b2c10"}}, "/findings?asset_group_id=6f0b9c56-1c1c-4c3d-9f21-6b1d4a3b2c10&state=open"},
		// Filters the list cannot express exactly give no link.
		{dashboard.WidgetFilter{AgeBand: []string{"90+"}}, ""},
		{dashboard.WidgetFilter{SLAState: []string{"none"}}, ""},
		{dashboard.WidgetFilter{KEV: &no}, ""},
		{dashboard.WidgetFilter{PriorityClass: []string{"none"}}, ""},
		{dashboard.WidgetFilter{AssetGroupIDs: []string{"a", "b"}}, ""},
	} {
		if got := drillHref(tc.f); got != tc.want {
			t.Errorf("drill(%+v) = %q, want %q", tc.f, got, tc.want)
		}
	}
}

func TestHistoryCompatible(t *testing.T) {
	yes := true
	if !historyCompatible(dashboard.WidgetFilter{Severity: []string{"high"}}, []dashboard.Dimension{dashboard.DimPriorityClass}) {
		t.Error("severity filter by priority is traceable")
	}
	if historyCompatible(dashboard.WidgetFilter{KEV: &yes}, nil) {
		t.Error("the history has no KEV flag")
	}
	if historyCompatible(dashboard.WidgetFilter{}, []dashboard.Dimension{dashboard.DimSource}) {
		t.Error("the history has no source")
	}
}

func TestTargetMetAndOrder(t *testing.T) {
	if m := targetMet(&dashboard.WidgetTarget{Op: "<=", Value: 0}, 3); m == nil || *m {
		t.Error("3 open against a target of 0 is not met")
	}
	if m := targetMet(&dashboard.WidgetTarget{Op: ">=", Value: 95}, 96.5); m == nil || !*m {
		t.Error("96.5 % against 95 % is met")
	}
	if targetMet(nil, 1) != nil {
		t.Error("no target, no verdict")
	}
	keys := []string{"low", "critical", "info", "high"}
	sortKeys(keys, dashboard.DimSeverity)
	if keys[0] != "critical" || keys[3] != "info" {
		t.Errorf("severity order = %v", keys)
	}
}

func TestLimiter(t *testing.T) {
	l := newLimiter(1, 2, 3)
	r1, err := l.acquire("t1", "u1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.acquire("t1", "u1"); err == nil {
		t.Error("second read of the same user accepted")
	}
	r2, _ := l.acquire("t1", "u2")
	if _, err := l.acquire("t1", "u3"); err == nil {
		t.Error("tenant cap not applied")
	}
	r1()
	r1() // idempotent
	if _, err := l.acquire("t1", "u1"); err != nil {
		t.Errorf("released slot not reusable: %v", err)
	}
	r2()
}
