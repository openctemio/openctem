package widgets

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/attack"
	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ctemFacts is a FactReader for the CTEM metrics: open counts per filter,
// and the CTEM reads; it records the scopes it was asked for.
type ctemFacts struct {
	p0, kev, breached int64
	within, slaDen    int64
	cj                dashboard.CrownJewelCounts
	disc              dashboard.DiscoveryCounts
	val               dashboard.ValidationCounts
	visible           map[shared.ID]bool
	scopes            []dashboard.ReadScope
	priorities        [][]string
	// The exposure flow and intake reads.
	byClass, bySev []dashboard.CountRow
	outcomes       dashboard.OutcomeCounts
	intake         []dashboard.IntakeRow
	intakeTenants  []shared.ID
	since          time.Time
	// The attack surface and accepted-risk breakdowns.
	newAssets    []dashboard.NewAssetRow
	newFrom      [2]time.Time
	certs        dashboard.CertificateExpiryCounts
	accepted     dashboard.AcceptanceExpiryCounts
	breakdownNow time.Time
	// The coverage causes, and a scope with no finding at all.
	causes     []dashboard.CauseRow
	noFindings bool
	// The emerging-threats breakdown.
	threats dashboard.EmergingThreatCounts
}

func (f *ctemFacts) FactsBuiltAt(context.Context, shared.ID) (*time.Time, error) {
	t := time.Now()
	return &t, nil
}

func (f *ctemFacts) CountOpen(_ context.Context, s dashboard.ReadScope, w dashboard.WidgetFilter, gb []dashboard.Dimension) ([]dashboard.CountRow, error) {
	f.scopes = append(f.scopes, s)
	switch {
	case len(w.PriorityClass) == 1 && w.PriorityClass[0] == "P0":
		return []dashboard.CountRow{{Count: f.p0}}, nil
	case w.KEV != nil:
		return []dashboard.CountRow{{Count: f.kev}}, nil
	case len(w.SLAState) == 1:
		return []dashboard.CountRow{{Count: f.breached}}, nil
	case len(gb) == 1 && gb[0] == dashboard.DimPriorityClass:
		return f.byClass, nil
	case len(gb) == 1 && gb[0] == dashboard.DimSeverity:
		return f.bySev, nil
	}
	return nil, nil
}

func (f *ctemFacts) SLAWithin(_ context.Context, s dashboard.ReadScope, _ dashboard.WidgetFilter) (int64, int64, error) {
	f.scopes = append(f.scopes, s)
	return f.within, f.slaDen, nil
}

func (f *ctemFacts) Days(context.Context, dashboard.ReadScope, dashboard.WidgetFilter, dashboard.Dimension, time.Time, time.Time) ([]dashboard.DayRow, error) {
	return nil, nil
}

func (f *ctemFacts) FixHist(context.Context, dashboard.ReadScope, dashboard.WidgetFilter, dashboard.Dimension, time.Time, time.Time) ([]dashboard.FixHistRow, error) {
	return nil, nil
}

func (f *ctemFacts) Rank(context.Context, dashboard.ReadScope, dashboard.RankKind, dashboard.WidgetFilter, int) ([]dashboard.RankItem, error) {
	return nil, nil
}

func (f *ctemFacts) CampaignsOf(context.Context, shared.ID, shared.ID) ([]shared.ID, error) {
	return nil, nil
}

func (f *ctemFacts) CrownJewels(_ context.Context, s dashboard.ReadScope, pr []string) (dashboard.CrownJewelCounts, error) {
	f.scopes = append(f.scopes, s)
	f.priorities = append(f.priorities, pr)
	return f.cj, nil
}

func (f *ctemFacts) Discovery(_ context.Context, s dashboard.ReadScope, _ time.Time) (dashboard.DiscoveryCounts, error) {
	f.scopes = append(f.scopes, s)
	return f.disc, nil
}

func (f *ctemFacts) UncoveredCauses(_ context.Context, s dashboard.ReadScope, _ time.Time) ([]dashboard.CauseRow, error) {
	f.scopes = append(f.scopes, s)
	return f.causes, nil
}

func (f *ctemFacts) HasFindings(_ context.Context, s dashboard.ReadScope) (bool, error) {
	f.scopes = append(f.scopes, s)
	return !f.noFindings, nil
}

func (f *ctemFacts) Validation(_ context.Context, s dashboard.ReadScope, _ time.Time) (dashboard.ValidationCounts, error) {
	f.scopes = append(f.scopes, s)
	return f.val, nil
}

func (f *ctemFacts) VisibleAssets(_ context.Context, s dashboard.ReadScope, ids []shared.ID) (map[shared.ID]bool, error) {
	f.scopes = append(f.scopes, s)
	out := map[shared.ID]bool{}
	for _, id := range ids {
		if f.visible[id] {
			out[id] = true
		}
	}
	return out, nil
}

func (f *ctemFacts) Outcomes(_ context.Context, s dashboard.ReadScope, since time.Time) (dashboard.OutcomeCounts, error) {
	f.scopes = append(f.scopes, s)
	f.since = since
	return f.outcomes, nil
}

func (f *ctemFacts) OrgIntake(_ context.Context, tenantID shared.ID, since time.Time) ([]dashboard.IntakeRow, error) {
	f.intakeTenants = append(f.intakeTenants, tenantID)
	f.since = since
	return f.intake, nil
}

func (f *ctemFacts) TopFix(_ context.Context, s dashboard.ReadScope) (*dashboard.FixLever, error) {
	f.scopes = append(f.scopes, s)
	return nil, nil
}

func (f *ctemFacts) NewAssets(_ context.Context, s dashboard.ReadScope, from, prevFrom time.Time) ([]dashboard.NewAssetRow, error) {
	f.scopes = append(f.scopes, s)
	f.newFrom = [2]time.Time{from, prevFrom}
	return f.newAssets, nil
}

func (f *ctemFacts) CertificateExpiry(_ context.Context, s dashboard.ReadScope, now time.Time) (dashboard.CertificateExpiryCounts, error) {
	f.scopes = append(f.scopes, s)
	f.breakdownNow = now
	return f.certs, nil
}

func (f *ctemFacts) AcceptanceExpiry(_ context.Context, s dashboard.ReadScope, now time.Time) (dashboard.AcceptanceExpiryCounts, error) {
	f.scopes = append(f.scopes, s)
	f.breakdownNow = now
	return f.accepted, nil
}

func (f *ctemFacts) EmergingThreats(_ context.Context, s dashboard.ReadScope) (dashboard.EmergingThreatCounts, error) {
	f.scopes = append(f.scopes, s)
	return f.threats, nil
}

type fakePaths struct {
	rows    []attack.CrownJewelPath
	noGraph bool
}

func (p fakePaths) ReachableCrownJewels(context.Context, shared.ID) ([]attack.CrownJewelPath, bool, error) {
	return p.rows, !p.noGraph, nil
}

func ctemWidget(metric, viz string, limit int) dashboard.Widget {
	data := map[string]any{"kind": "metric", "metric": metric, "filter": map[string]any{}, "time": map[string]any{}}
	if limit > 0 {
		data["limit"] = limit
	}
	return dashboard.Widget{WidgetType: "metric", Config: map[string]any{
		"v": 2, "id": "w_t1", "data": data, "viz": map[string]any{"type": viz, "options": map[string]any{}},
	}}
}

func restrictedScope() dashboard.ReadScope {
	user := shared.NewID()
	return dashboard.ReadScope{TenantID: shared.NewID(), Assets: &shared.DataScope{UserID: user}, CampaignViewer: &user}
}

func TestCTEMLoop_StagesFromTheReadScope(t *testing.T) {
	facts := &ctemFacts{
		p0: 3, kev: 7, breached: 4, within: 60, slaDen: 100,
		cj:   dashboard.CrownJewelCounts{Designated: 9, Exposed: 2},
		disc: dashboard.DiscoveryCounts{Tracked: 200, Covered: 150},
		val:  dashboard.ValidationCounts{Open: 50, Validated: 0, RetestsRun: 0},
	}
	s := NewService(nil, nil, facts, nil)
	scope := restrictedScope()
	v := s.widget(context.Background(), 0, ctemWidget("ctem.loop", "loop", 0), true, scope)
	if v.State != StateReady || v.Shape != dashboard.ShapeStages || v.Stages == nil {
		t.Fatalf("state %s shape %s stages %v", v.State, v.Shape, v.Stages)
	}
	// Every read used exactly the scope the server built.
	for _, got := range facts.scopes {
		if got.TenantID != scope.TenantID || got.Assets != scope.Assets || got.CampaignViewer != scope.CampaignViewer {
			t.Fatalf("a stage read another scope: %+v", got)
		}
	}
	st := v.Stages.Stages
	keys := []string{StageScoping, StageDiscovery, StagePrioritize, StageValidate, StageMobilize}
	if len(st) != len(keys) {
		t.Fatalf("stages %d", len(st))
	}
	for i, k := range keys {
		if st[i].Key != k {
			t.Fatalf("stage %d is %s, want %s", i, st[i].Key, k)
		}
		// A percentage opens no list: no list's total equals it. The
		// validate and mobilize stages drill only through their counts.
		pct := k == StageValidate || k == StageMobilize
		if pct && st[i].Drill != "" {
			t.Errorf("stage %s percent links to %s", k, st[i].Drill)
		}
		if !pct && st[i].Drill == "" {
			t.Errorf("stage %s has no list", k)
		}
	}
	if *st[0].Value != 9 || st[0].Detail.Value != 2 || st[0].State != StageGood {
		t.Errorf("scoping %+v", st[0])
	}
	if !strings.Contains(st[0].Detail.Drill, "asset_crown_jewel=true") || !strings.Contains(st[0].Detail.Drill, "priority_class=P0,P1") {
		t.Errorf("exposed drill %s", st[0].Detail.Drill)
	}
	if *st[1].Value != 75 || st[1].Detail.Value != 50 || st[1].State != StageWarn || st[1].Drill != drillUncovered {
		t.Errorf("discovery %+v", st[1])
	}
	if *st[2].Value != 3 || st[2].Detail.Value != 7 || st[2].Flag != FlagExploitableNow || st[2].Drill != "/findings?priority_class=P0&state=open" {
		t.Errorf("prioritize %+v", st[2])
	}
	if *st[3].Value != 0 || st[3].Flag != FlagNoneRunYet || st[3].State != StageCrit {
		t.Errorf("validate %+v", st[3])
	}
	if *st[4].Value != 60 || st[4].Detail.Value != 4 || st[4].State != StageCrit {
		t.Errorf("mobilize %+v", st[4])
	}
	// The largest gap is the first off-track stage.
	if v.Stages.Focus == nil || *v.Stages.Focus != 3 {
		t.Errorf("focus %v", v.Stages.Focus)
	}
}

func TestCTEMLoop_NotMeasuredIsNeverZero(t *testing.T) {
	facts := &ctemFacts{} // nothing tracked, nothing open, no SLA, no crown jewel
	s := NewService(nil, nil, facts, nil)
	v := s.widget(context.Background(), 0, ctemWidget("ctem.loop", "loop", 0), true, restrictedScope())
	st := v.Stages.Stages
	for _, i := range []int{1, 3, 4} {
		if st[i].State != StageNotMeasured || st[i].Value != nil || st[i].Reason == "" {
			t.Errorf("stage %s: %+v, want not measured with a reason", st[i].Key, st[i])
		}
	}
	if st[0].Flag != FlagDesignate || st[0].State != StageWarn {
		t.Errorf("scoping without crown jewels: %+v", st[0])
	}
	if st[2].State != StageGood || *st[2].Value != 0 {
		t.Errorf("no P0 open is a measured 0: %+v", st[2])
	}
	if v.Stages.Focus == nil || *v.Stages.Focus != 0 {
		t.Errorf("focus %v", v.Stages.Focus)
	}
}

func TestCrownJewelsExposed_CountsAndOpensTheGroupedList(t *testing.T) {
	facts := &ctemFacts{cj: dashboard.CrownJewelCounts{Designated: 5, Exposed: 2}}
	s := NewService(nil, nil, facts, nil)
	v := s.widget(context.Background(), 0, ctemWidget("crown_jewels.exposed", "stat", 0), true, restrictedScope())
	if v.State != StateReady || v.Scalar == nil || v.Scalar.Value != 2 {
		t.Fatalf("%+v", v)
	}
	want := "/findings?asset_crown_jewel=true&group=asset_id&priority_class=P0,P1&state=open"
	if v.Drill != want {
		t.Errorf("drill %s, want %s", v.Drill, want)
	}
	if got := facts.priorities[0]; len(got) != 2 || got[0] != "P0" || got[1] != "P1" {
		t.Errorf("priorities %v", got)
	}
}

func TestAttackPaths_OnlyCrownJewelsInScope(t *testing.T) {
	in1, in2, out := shared.NewID(), shared.NewID(), shared.NewID()
	facts := &ctemFacts{cj: dashboard.CrownJewelCounts{Designated: 4}, visible: map[shared.ID]bool{in1: true, in2: true}}
	s := NewService(nil, nil, facts, nil)
	s.SetAttackPaths(fakePaths{rows: []attack.CrownJewelPath{
		{AssetID: out, Name: "secret-db", ReachableFrom: 9, PathScore: 99},
		{AssetID: in1, Name: "payroll", ReachableFrom: 2, PathScore: 40},
		{AssetID: in2, Name: "crm", ReachableFrom: 1, PathScore: 10},
	}})
	v := s.widget(context.Background(), 0, ctemWidget("attack_paths.to_crown_jewels", "paths", 1), true, restrictedScope())
	if v.State != StateReady || v.Paths == nil {
		t.Fatalf("%+v", v)
	}
	if v.Paths.Reachable != 2 || v.Paths.Designated != 4 {
		t.Errorf("reachable %d designated %d", v.Paths.Reachable, v.Paths.Designated)
	}
	if len(v.Paths.Rows) != 1 || v.Paths.Rows[0].Name != "payroll" {
		t.Errorf("rows %+v (limit 1, out-of-scope asset first in rank)", v.Paths.Rows)
	}
	for _, r := range v.Paths.Rows {
		if r.AssetID == out.String() || r.Name == "secret-db" {
			t.Fatal("an out-of-scope crown jewel reached the result")
		}
	}
	if v.Drill != drillAttackPaths {
		t.Errorf("drill %s", v.Drill)
	}
}

func TestAttackPaths_UnwiredIsNotMeasured(t *testing.T) {
	s := NewService(nil, nil, &ctemFacts{}, nil)
	v := s.widget(context.Background(), 0, ctemWidget("attack_paths.to_crown_jewels", "paths", 0), true, restrictedScope())
	if v.State != StateNotMeasured || v.Paths != nil {
		t.Fatalf("%+v", v)
	}
}

// No crown jewel designated in scope: "0 exposed" and "none reachable" are
// not measurements and must never render as a green 0.
func TestCrownJewelMetrics_NoneDesignatedIsNotMeasured(t *testing.T) {
	facts := &ctemFacts{cj: dashboard.CrownJewelCounts{Designated: 0, Exposed: 0}}
	s := NewService(nil, nil, facts, nil)
	s.SetAttackPaths(fakePaths{})
	w := ctemWidget("crown_jewels.exposed", "stat", 0)
	w.Config["target"] = map[string]any{"op": "<=", "value": 0}
	v := s.widget(context.Background(), 0, w, true, restrictedScope())
	if v.State != StateNotMeasured || v.Reason != ReasonNoCrownJewels || v.Scalar != nil || v.TargetMet != nil {
		t.Errorf("crown jewels exposed without crown jewels: %+v", v)
	}
	v = s.widget(context.Background(), 0, ctemWidget("attack_paths.to_crown_jewels", "paths", 0), true, restrictedScope())
	if v.State != StateNotMeasured || v.Reason != ReasonNoCrownJewels || v.Paths != nil {
		t.Errorf("attack paths without crown jewels: %+v", v)
	}
}

// No relationship data in the tenant: an empty reachable list is unknown.
func TestAttackPaths_NoRelationshipDataIsNotMeasured(t *testing.T) {
	facts := &ctemFacts{cj: dashboard.CrownJewelCounts{Designated: 3}}
	s := NewService(nil, nil, facts, nil)
	s.SetAttackPaths(fakePaths{noGraph: true})
	v := s.widget(context.Background(), 0, ctemWidget("attack_paths.to_crown_jewels", "paths", 0), true, restrictedScope())
	if v.State != StateNotMeasured || v.Reason != ReasonNoRelationshipData || v.Paths != nil {
		t.Errorf("attack paths without relationships: %+v", v)
	}
	// With a graph, an empty list is a measured 0.
	s.SetAttackPaths(fakePaths{})
	v = s.widget(context.Background(), 0, ctemWidget("attack_paths.to_crown_jewels", "paths", 0), true, restrictedScope())
	if v.State != StateReady || v.Paths == nil || v.Paths.Reachable != 0 {
		t.Errorf("attack paths with a graph: %+v", v)
	}
}

func TestDiscoveryCoverage_ShareOfTrackedAssetsInTheReadScope(t *testing.T) {
	facts := &ctemFacts{disc: dashboard.DiscoveryCounts{Tracked: 8, Covered: 6}}
	s := NewService(nil, nil, facts, nil)
	scope := restrictedScope()
	v := s.widget(context.Background(), 0, ctemWidget("coverage.discovery", "progress", 0), true, scope)
	if v.State != StateReady || v.Shape != dashboard.ShapeRatio || v.Ratio == nil {
		t.Fatalf("%+v", v)
	}
	if v.Ratio.Num != 6 || v.Ratio.Den != 8 || v.Ratio.ValuePct == nil || *v.Ratio.ValuePct != 75 {
		t.Errorf("ratio %+v", v.Ratio)
	}
	// The figure opens the uncovered assets.
	if v.Drill != drillUncovered {
		t.Errorf("drill %s", v.Drill)
	}
	// Read in exactly the scope the server built, never wider (the share
	// and its causes).
	if len(facts.scopes) != 2 {
		t.Fatalf("reads %d", len(facts.scopes))
	}
	for _, got := range facts.scopes {
		if got.TenantID != scope.TenantID || got.Assets != scope.Assets {
			t.Fatalf("coverage read another scope: %+v", got)
		}
	}
}

func TestDiscoveryCoverage_NothingTrackedIsNotMeasuredNeverZero(t *testing.T) {
	facts := &ctemFacts{}
	s := NewService(nil, nil, facts, nil)
	v := s.widget(context.Background(), 0, ctemWidget("coverage.discovery", "progress", 0), true, restrictedScope())
	if v.State != StateNotMeasured || v.Reason != ReasonNoTrackedAssets {
		t.Fatalf("state %s reason %s", v.State, v.Reason)
	}
	if v.Ratio == nil || v.Ratio.ValuePct != nil {
		t.Errorf("a not-measured share has no value: %+v", v.Ratio)
	}
}
