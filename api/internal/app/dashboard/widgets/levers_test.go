package widgets

import (
	"context"
	"strings"
	"testing"
	"time"

	dashboardapp "github.com/openctemio/openctem/api/internal/app/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// storyFacts answers open counts per filter shape, the seven-day flows and
// the top fix, and records every scope it was asked for.
type storyFacts struct {
	ctemFacts
	priorityOpen int64
	kevByClass   []dashboard.CountRow // keys: class, severity
	brByClass    []dashboard.CountRow
	due, past    int64
	kevOpen      int64
	days         []dashboard.DayRow
	fix          *dashboard.FixLever
	daysFrom     time.Time
}

func (f *storyFacts) CountOpen(_ context.Context, s dashboard.ReadScope, w dashboard.WidgetFilter, gb []dashboard.Dimension) ([]dashboard.CountRow, error) {
	f.scopes = append(f.scopes, s)
	byClass := len(gb) == 2
	switch {
	case w.KEV != nil && byClass:
		return f.kevByClass, nil
	case w.KEV != nil:
		return []dashboard.CountRow{{Count: f.kevOpen}}, nil
	case len(w.SLAState) == 1 && w.SLAState[0] == "breached" && byClass:
		return f.brByClass, nil
	case len(w.SLAState) == 1 && w.SLAState[0] == "breached":
		return []dashboard.CountRow{{Count: f.past}}, nil
	case len(w.SLAState) == 1 && w.SLAState[0] == "warning":
		return []dashboard.CountRow{{Count: f.due}}, nil
	case len(w.PriorityClass) == 2:
		return []dashboard.CountRow{{Count: f.priorityOpen}}, nil
	}
	return nil, nil
}

func (f *storyFacts) Days(_ context.Context, s dashboard.ReadScope, _ dashboard.WidgetFilter, _ dashboard.Dimension, from, _ time.Time) ([]dashboard.DayRow, error) {
	f.scopes = append(f.scopes, s)
	f.daysFrom = from
	return f.days, nil
}

func (f *storyFacts) TopFix(_ context.Context, s dashboard.ReadScope) (*dashboard.FixLever, error) {
	f.scopes = append(f.scopes, s)
	return f.fix, nil
}

func assertOneScope(t *testing.T, got []dashboard.ReadScope, want dashboard.ReadScope) {
	t.Helper()
	if len(got) == 0 {
		t.Fatal("no fact read")
	}
	for _, g := range got {
		if g.TenantID != want.TenantID || g.Assets != want.Assets || g.CampaignViewer != want.CampaignViewer {
			t.Fatalf("a read used another scope: %+v", g)
		}
	}
}

func richFacts() *storyFacts {
	return &storyFacts{
		ctemFacts:    ctemFacts{within: 60, slaDen: 100, disc: dashboard.DiscoveryCounts{Tracked: 200, Covered: 150}},
		priorityOpen: 31,
		// 9 KEV: 2 P0 critical, 3 P1 high, 4 P3 low -> P0-P1 5, points 16+12+4 = 32.
		kevByClass: []dashboard.CountRow{{Keys: []string{"P0", "critical"}, Count: 2}, {Keys: []string{"P1", "high"}, Count: 3}, {Keys: []string{"P3", "low"}, Count: 4}},
		// 10 breached P0-P1: 1 P0, 9 P1 -> points 8+36 = 44.
		brByClass: []dashboard.CountRow{{Keys: []string{"P0", "high"}, Count: 1}, {Keys: []string{"P1", "high"}, Count: 9}},
		fix:       &dashboard.FixLever{SuggestionID: shared.NewID(), Title: "Upgrade openssl to 3.0.15", Findings: 27, Assets: 14, PriorityOpen: 12, Points: 70},
		due:       4, past: 10, kevOpen: 9,
		days: []dashboard.DayRow{{Opened: 5, Fixed: 12}, {Opened: 3, Fixed: 1}},
	}
}

func TestLevers_RankedByPointsWithExactEffects(t *testing.T) {
	facts := richFacts()
	s := NewService(nil, nil, facts, nil)
	scope := restrictedScope()
	v := s.widget(context.Background(), 0, ctemWidget("exposure.levers", "levers", 0), true, scope)
	if v.State != StateReady || v.Shape != dashboard.ShapeLevers || v.Levers == nil {
		t.Fatalf("state %s shape %s levers %v", v.State, v.Shape, v.Levers)
	}
	assertOneScope(t, facts.scopes, scope)
	ls := v.Levers.Levers
	// Coverage 75 % is under target: two point levers, then the blind spot.
	if len(ls) != 3 || ls[0].Kind != LeverOneFix || ls[1].Kind != LeverSLABreached || ls[2].Kind != LeverBlindSpot {
		t.Fatalf("levers %+v", ls)
	}
	fix := ls[0]
	if fix.Count != 27 || *fix.Assets != 14 || fix.Effect.Before != 31 || fix.Effect.After != 19 || fix.Drill != drillSuggestions || fix.Title == "" {
		t.Errorf("one fix %+v", fix)
	}
	sla := ls[1]
	// Within SLA 60 / 100 -> 60 / (100 - 10).
	if sla.Count != 10 || sla.Points != 44 || sla.Effect.Before != 60 || sla.Effect.After != 66.7 {
		t.Errorf("sla lever %+v", sla)
	}
	if sla.Drill != drillHref(dashboard.WidgetFilter{SLAState: []string{"breached"}, PriorityClass: []string{"P0", "P1"}}) {
		t.Errorf("sla drill %s", sla.Drill)
	}
	blind := ls[2]
	if blind.Count != 50 || blind.Effect.Before != 75 || blind.Effect.After != 100 || blind.Drill != drillUncovered {
		t.Errorf("blind spot %+v", blind)
	}
}

func TestLevers_KEVEffectAndNoBlindSpotWhenCovered(t *testing.T) {
	facts := richFacts()
	facts.fix = nil
	facts.disc = dashboard.DiscoveryCounts{Tracked: 100, Covered: 95}
	s := NewService(nil, nil, facts, nil)
	lv, err := s.levers(context.Background(), restrictedScope())
	if err != nil {
		t.Fatal(err)
	}
	if len(lv.Levers) != 2 || lv.Levers[0].Kind != LeverSLABreached || lv.Levers[1].Kind != LeverKEVOpen {
		t.Fatalf("levers %+v", lv.Levers)
	}
	kev := lv.Levers[1]
	// Fixing the 9 KEV findings removes their 5 P0-P1: 31 -> 26.
	if kev.Count != 9 || kev.Points != 32 || kev.Effect.Metric != "exposure.priority_open" || kev.Effect.After != 26 || !strings.Contains(kev.Drill, "is_in_kev=true") {
		t.Errorf("kev lever %+v", kev)
	}
}

func TestLevers_NothingToDo(t *testing.T) {
	facts := &storyFacts{ctemFacts: ctemFacts{disc: dashboard.DiscoveryCounts{}}}
	s := NewService(nil, nil, facts, nil)
	lv, err := s.levers(context.Background(), orgScope(shared.NewID()))
	if err != nil {
		t.Fatal(err)
	}
	if len(lv.Levers) != 0 {
		t.Fatalf("levers %+v", lv.Levers)
	}
}

func TestBrief_DeterministicSentences(t *testing.T) {
	facts := richFacts()
	s := NewService(nil, nil, facts, nil)
	now := time.Date(2026, 10, 29, 10, 30, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	scope := restrictedScope()
	v := s.widget(context.Background(), 0, ctemWidget("brief.weekly", "brief", 0), true, scope)
	if v.State != StateReady || v.Brief == nil {
		t.Fatalf("state %s brief %v", v.State, v.Brief)
	}
	assertOneScope(t, facts.scopes, scope)
	if want := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC); !facts.daysFrom.Equal(want) || !v.Brief.Since.Equal(want) {
		t.Errorf("window from %s since %s", facts.daysFrom, v.Brief.Since)
	}
	items := v.Brief.Items
	if len(items) != 3 || items[0].Kind != BriefChange || items[1].Kind != BriefLever || items[2].Kind != BriefSLADue {
		t.Fatalf("items %+v", items)
	}
	if items[0].Variant != VariantDown || items[0].Chips[0].Value != 8 || items[0].Chips[1].Value != 13 {
		t.Errorf("change %+v", items[0])
	}
	for _, c := range items[0].Chips {
		if c.Drill != "" {
			t.Errorf("a flow chip links to %s", c.Drill)
		}
	}
	if items[1].Lever == nil || items[1].Lever.Kind != LeverOneFix || items[1].Chips[0].Drill != drillSuggestions {
		t.Errorf("lever %+v", items[1])
	}
	due := items[2].Chips
	if due[0].Value != 4 || due[0].Drill != drillHref(dashboard.WidgetFilter{SLAState: []string{"warning"}, PriorityClass: []string{"P0", "P1", "P2"}}) ||
		due[1].Value != 10 || due[1].Drill != drillHref(dashboard.WidgetFilter{SLAState: []string{"breached"}, PriorityClass: []string{"P0", "P1", "P2"}}) {
		t.Errorf("sla chips %+v", due)
	}
}

func TestBrief_QuietAndKEVFallback(t *testing.T) {
	facts := &storyFacts{}
	s := NewService(nil, nil, facts, nil)
	b, err := s.brief(context.Background(), orgScope(shared.NewID()))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Items) != 1 || b.Items[0].Kind != BriefQuiet {
		t.Fatalf("quiet %+v", b.Items)
	}
	facts.kevOpen = 3
	b, err = s.brief(context.Background(), orgScope(shared.NewID()))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Items) != 1 || b.Items[0].Kind != BriefKEV || b.Items[0].Chips[0].Value != 3 {
		t.Fatalf("kev %+v", b.Items)
	}
}

func TestKPIs_FiveTilesFromTheSinglePaths(t *testing.T) {
	facts := richFacts()
	s := NewService(nil, nil, facts, nil)
	scope := restrictedScope()
	w := ctemWidget("exposure.kpis", "kpi", 0)
	w.Config["data"].(map[string]any)["time"] = map[string]any{"range": "30d", "compare": "previous_period"}
	v := s.widget(context.Background(), 0, w, true, scope)
	if v.State != StateReady || v.KPIs == nil {
		t.Fatalf("state %s reason %s kpis %v", v.State, v.Reason, v.KPIs)
	}
	assertOneScope(t, facts.scopes, scope)
	ts := v.KPIs.Tiles
	keys := []string{KPIPriorityOpen, KPIKEVOpen, KPISLAWithin, KPITimeToFix, KPICoverage}
	if len(ts) != len(keys) {
		t.Fatalf("tiles %+v", ts)
	}
	for i, k := range keys {
		if ts[i].Key != k {
			t.Fatalf("tile %d is %s, want %s", i, ts[i].Key, k)
		}
	}
	if *ts[0].Value != 31 || ts[0].Drill != drillHref(dashboard.WidgetFilter{PriorityClass: []string{"P0", "P1"}}) {
		t.Errorf("priority tile %+v", ts[0])
	}
	if *ts[1].Value != 9 || ts[2].Value == nil || *ts[2].Value != 60 {
		t.Errorf("kev %+v sla %+v", ts[1], ts[2])
	}
	// No fixes in the window: not measured, never zero.
	if ts[3].State != StateNotMeasured || ts[3].Reason != ReasonTooFewFixed || ts[3].Value != nil {
		t.Errorf("time to fix %+v", ts[3])
	}
	if *ts[4].Value != 75 || ts[4].Drill != drillUncovered {
		t.Errorf("coverage %+v", ts[4])
	}
}

func TestKPIs_NotMeasuredWithoutDenominators(t *testing.T) {
	facts := &storyFacts{}
	s := NewService(nil, nil, facts, nil)
	k, err := s.kpis(context.Background(), orgScope(shared.NewID()), newWindow(time.Now(), dashboard.WidgetTime{}), false)
	if err != nil {
		t.Fatal(err)
	}
	if k.Tiles[2].State != StateNotMeasured || k.Tiles[2].Value != nil || k.Tiles[4].State != StateNotMeasured || k.Tiles[4].Value != nil {
		t.Errorf("tiles %+v", k.Tiles)
	}
}

func TestMask_AssetPartsNeedAssetsRead(t *testing.T) {
	facts := richFacts()
	s := NewService(nil, nil, facts, nil)
	scope := restrictedScope()
	d := &DashboardData{Widgets: []WidgetValue{
		s.widget(context.Background(), 0, ctemWidget("exposure.levers", "levers", 0), true, scope),
		s.widget(context.Background(), 1, ctemWidget("exposure.kpis", "kpi", 0), true, scope),
	}}
	findingsOnly := dashboardapp.Caller{Has: func(p string) bool { return p == permission.FindingsRead.String() }}
	maskForbidden(d, findingsOnly)
	for _, l := range d.Widgets[0].Levers.Levers {
		if l.Kind == LeverBlindSpot {
			t.Error("blind spot lever shown without assets:read")
		}
	}
	cov := d.Widgets[1].KPIs.Tiles[4]
	if cov.State != StateUnsupported || cov.Reason != ReasonForbidden || cov.Value != nil || cov.Drill != "" {
		t.Errorf("coverage tile %+v", cov)
	}
	if d.Widgets[1].KPIs.Tiles[0].Value == nil {
		t.Error("a findings tile was masked")
	}

	// Without findings:read the whole widget is masked.
	d2 := &DashboardData{Widgets: []WidgetValue{s.widget(context.Background(), 0, ctemWidget("brief.weekly", "brief", 0), true, scope)}}
	maskForbidden(d2, dashboardapp.Caller{Has: func(string) bool { return false }})
	if d2.Widgets[0].State != StateUnsupported || d2.Widgets[0].Brief != nil {
		t.Errorf("brief not masked %+v", d2.Widgets[0])
	}
}
