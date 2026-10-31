package widgets

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
)

// A scope that never held a finding: every findings figure is not measured
// (never a 0, an empty chart or a met target), asset figures are unaffected.
func TestNoFindings_FindingsFiguresAreNotMeasured(t *testing.T) {
	for _, tc := range []struct{ metric, viz string }{
		{"exposure.priority_open", "stat"},
		{"intel.kev_open", "stat"},
		{"findings.open", "stat"},
		{"sla.within", "progress"},
		{"fix.time_to_fix", "stat"},
		{"flow.new_vs_fixed", "diverging"},
		{"exposure.open_by_priority", "area"},
		{"fix.next", "table"},
		{"sla.at_risk", "list"},
		{"exceptions.expiring", "bar"},
		{"exposure.flow", "flow"},
	} {
		facts := &ctemFacts{noFindings: true}
		s := NewService(nil, nil, facts, nil)
		w := ctemWidget(tc.metric, tc.viz, 0)
		if tc.metric == "exposure.priority_open" {
			// A target on the figure must not be reported as met.
			w.Config["target"] = map[string]any{"op": "<=", "value": 0}
		}
		v := s.widget(context.Background(), 0, w, true, orgScope(restrictedScope().TenantID))
		if v.State != StateNotMeasured || v.Reason != ReasonNoFindings {
			t.Errorf("%s: state %s reason %s", tc.metric, v.State, v.Reason)
		}
		if v.TargetMet != nil || v.Scalar != nil || v.Series != nil || v.Items != nil || v.Flow != nil || v.Category != nil {
			t.Errorf("%s: a figure was drawn: %+v", tc.metric, v)
		}
	}
}

func TestNoFindings_AssetFiguresStillRead(t *testing.T) {
	facts := &ctemFacts{noFindings: true, disc: dashboard.DiscoveryCounts{Tracked: 4, Covered: 4}}
	s := NewService(nil, nil, facts, nil)
	v := s.widget(context.Background(), 0, ctemWidget("coverage.discovery", "progress", 0), true, restrictedScope())
	if v.State != StateReady || v.Ratio == nil || v.Ratio.Num != 4 {
		t.Fatalf("%+v", v)
	}
}

func TestNoFindings_ReadOncePerDashboard(t *testing.T) {
	facts := &ctemFacts{noFindings: true}
	s := NewService(nil, nil, facts, nil)
	scope := restrictedScope()
	ctx := withFindingsProbe(context.Background())
	for i, m := range []string{"exposure.priority_open", "intel.kev_open", "findings.open"} {
		_ = s.widget(ctx, i, ctemWidget(m, "stat", 0), true, scope)
	}
	if len(facts.scopes) != 1 {
		t.Fatalf("HasFindings read %d times, want once per dashboard read", len(facts.scopes))
	}
	if got := facts.scopes[0]; got.TenantID != scope.TenantID || got.Assets != scope.Assets || got.CampaignViewer != scope.CampaignViewer {
		t.Fatalf("probe read another scope: %+v", got)
	}
}

// With findings, a met target stays reported.
func TestPriorityExposure_TargetMetOnlyWhenMeasured(t *testing.T) {
	facts := &ctemFacts{}
	s := NewService(nil, nil, facts, nil)
	w := ctemWidget("exposure.priority_open", "stat", 0)
	w.Config["target"] = map[string]any{"op": "<=", "value": 0}
	v := s.widget(context.Background(), 0, w, true, restrictedScope())
	if v.State != StateReady || v.TargetMet == nil || !*v.TargetMet {
		t.Fatalf("state %s target_met %v", v.State, v.TargetMet)
	}
}

func TestKPIs_NoFindingsKeepsOnlyCoverage(t *testing.T) {
	facts := &ctemFacts{noFindings: true, disc: dashboard.DiscoveryCounts{Tracked: 2, Covered: 1}}
	s := NewService(nil, nil, facts, nil)
	v := s.widget(context.Background(), 0, ctemWidget("exposure.kpis", "kpi", 0), true, restrictedScope())
	if v.KPIs == nil {
		t.Fatalf("%+v", v)
	}
	for _, tile := range v.KPIs.Tiles {
		if tile.Key == KPICoverage {
			if tile.State != StateReady || tile.Value == nil {
				t.Errorf("coverage tile %+v", tile)
			}
			continue
		}
		if tile.State != StateNotMeasured || tile.Reason != ReasonNoFindings || tile.Value != nil {
			t.Errorf("tile %s: %+v", tile.Key, tile)
		}
	}
}

func TestKEV_ShowsItsPopulation(t *testing.T) {
	facts := &ctemFacts{kev: 3}
	s := NewService(nil, nil, &kevFacts{ctemFacts: facts, all: 40}, nil)
	scope := restrictedScope()
	v := s.widget(context.Background(), 0, ctemWidget("intel.kev_open", "stat", 0), true, scope)
	if v.State != StateReady || v.Scalar == nil || v.Scalar.Value != 3 {
		t.Fatalf("%+v", v)
	}
	if v.Scalar.Of == nil || *v.Scalar.Of != 40 {
		t.Fatalf("of %v", v.Scalar.Of)
	}
	if v.Scalar.OfDrill != drillHref(dashboard.WidgetFilter{}) {
		t.Errorf("of drill %s", v.Scalar.OfDrill)
	}
	sameScope(t, facts, scope)
}

// kevFacts answers the KEV count and, without the KEV filter, all open.
type kevFacts struct {
	*ctemFacts
	all int64
}

func (f *kevFacts) CountOpen(ctx context.Context, s dashboard.ReadScope, w dashboard.WidgetFilter, gb []dashboard.Dimension) ([]dashboard.CountRow, error) {
	if w.KEV == nil && len(gb) == 0 {
		f.scopes = append(f.scopes, s)
		return []dashboard.CountRow{{Count: f.all}}, nil
	}
	return f.ctemFacts.CountOpen(ctx, s, w, gb)
}

func TestCoverageCauses_RowsInPrecedenceOrderWithLists(t *testing.T) {
	facts := &ctemFacts{
		disc: dashboard.DiscoveryCounts{Tracked: 10, Covered: 4},
		causes: []dashboard.CauseRow{
			{Cause: "target_unreachable", Count: 2}, {Cause: "no_sensor", Count: 3}, {Cause: "overdue", Count: 1},
		},
	}
	s := NewService(nil, nil, facts, nil)
	scope := restrictedScope()
	v := s.widget(context.Background(), 0, ctemWidget("coverage.discovery", "progress", 0), true, scope)
	if v.Ratio == nil || len(v.Ratio.Causes) != 3 {
		t.Fatalf("%+v", v.Ratio)
	}
	want := []string{"no_sensor", "target_unreachable", "overdue"}
	for i, r := range v.Ratio.Causes {
		if r.Key != want[i] {
			t.Errorf("row %d key %s want %s", i, r.Key, want[i])
		}
		if r.Drill != "/assets?coverage=uncovered&coverage_cause="+r.Key+"&program_assets=exclude" {
			t.Errorf("drill %s", r.Drill)
		}
	}
	sameScope(t, facts, scope)
}

func TestCoverageCauses_FullyCoveredReadsNoCauses(t *testing.T) {
	facts := &ctemFacts{disc: dashboard.DiscoveryCounts{Tracked: 5, Covered: 5}, causes: []dashboard.CauseRow{{Cause: "overdue", Count: 9}}}
	s := NewService(nil, nil, facts, nil)
	v := s.widget(context.Background(), 0, ctemWidget("coverage.discovery", "progress", 0), true, restrictedScope())
	if v.Ratio == nil || v.Ratio.Causes != nil || len(facts.scopes) != 1 {
		t.Fatalf("causes %+v reads %d", v.Ratio, len(facts.scopes))
	}
}

// Levers, brief and KPI strip decide after computing: with no finding and
// nothing else to say they are not measured, never "nothing stands out".
func TestNoFindings_StoryWidgetsAreNotMeasured(t *testing.T) {
	for _, tc := range []struct{ metric, viz string }{
		{"exposure.levers", "levers"},
		{"brief.weekly", "brief"},
		{"exposure.kpis", "kpi"},
	} {
		facts := &ctemFacts{noFindings: true}
		s := NewService(nil, nil, facts, nil)
		v := s.widget(context.Background(), 0, ctemWidget(tc.metric, tc.viz, 0), true, restrictedScope())
		if v.State != StateNotMeasured || v.Reason != ReasonNoFindings || v.Levers != nil || v.Brief != nil || v.KPIs != nil {
			t.Errorf("%s: %s %s %+v", tc.metric, v.State, v.Reason, v)
		}
	}
}
