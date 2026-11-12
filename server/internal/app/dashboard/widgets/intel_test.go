package widgets

import (
	"context"
	"strings"
	"testing"

	dashboardapp "github.com/openctemio/openctem/api/internal/app/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// fakeModules turns modules off per organization.
type fakeModules struct {
	off   map[string]bool // tenant/module
	calls int
}

func (m *fakeModules) IsReadable(_ context.Context, tenantID, moduleID string) bool {
	m.calls++
	return !m.off[tenantID+"/"+moduleID]
}

func TestEmergingThreats_LevelsAndLists(t *testing.T) {
	facts := &ctemFacts{threats: dashboard.EmergingThreatCounts{Seen: 9, Open: 5, Immediate: 2, Digest: 0, Listed: 3}}
	s := NewService(nil, nil, facts, nil)
	scope := restrictedScope()
	v := s.widget(context.Background(), 0, surfaceWidget("intel.emerging_threats", "", ""), true, scope)
	if v.State != StateReady || v.Shape != dashboard.ShapeCategory || v.Category == nil {
		t.Fatalf("state %s reason %s", v.State, v.Reason)
	}
	sameScope(t, facts, scope)
	rows := v.Category.Rows
	if len(rows) != 3 || rows[0].Key != "immediate" || rows[1].Key != "digest" || rows[2].Key != "listed" {
		t.Fatalf("rows %+v", rows)
	}
	if v.Category.Total != 5 {
		t.Errorf("total %v", v.Category.Total)
	}
	// An empty level opens nothing; the others open the open alerts of that
	// level with the list's own parameters.
	if rows[1].Drill != "" {
		t.Errorf("empty level links %s", rows[1].Drill)
	}
	q := query(t, rows[0].Drill)
	if !strings.HasPrefix(rows[0].Drill, "/emerging-threats?") || q.Get("level") != "immediate" || q.Get("state") != "open" || len(q) != 2 {
		t.Errorf("immediate list %s", rows[0].Drill)
	}
	if q := query(t, v.Drill); q.Get("level") != "" || q.Get("state") != "open" {
		t.Errorf("widget list %s", v.Drill)
	}

	// Alerts seen, none open: a real empty figure, no link.
	facts.threats = dashboard.EmergingThreatCounts{Seen: 4}
	v = s.widget(context.Background(), 0, surfaceWidget("intel.emerging_threats", "", ""), true, scope)
	if v.State != StateReady || v.Category == nil || v.Category.Total != 0 || v.Drill != "" {
		t.Errorf("none open: %s %+v %s", v.State, v.Category, v.Drill)
	}

	// No alert ever in scope: not measured, never "0 threats".
	facts.threats = dashboard.EmergingThreatCounts{}
	v = s.widget(context.Background(), 0, surfaceWidget("intel.emerging_threats", "", ""), true, scope)
	if v.State != StateNotMeasured || v.Reason != ReasonNoThreatAlerts || v.Category != nil {
		t.Errorf("no alerts: %s %s %+v", v.State, v.Reason, v.Category)
	}

	// The spec refuses a time range: the alerts are counted as they are now.
	if _, err := dashboard.ParseWidgetSpec("metric", surfaceWidget("intel.emerging_threats", "30d", "").Config); err == nil {
		t.Error("a range on the emerging-threats breakdown was accepted")
	}
}

func TestEmergingThreats_Permission(t *testing.T) {
	facts := &ctemFacts{threats: dashboard.EmergingThreatCounts{Seen: 1, Open: 1, Immediate: 1}}
	s := NewService(nil, nil, facts, nil)
	scope := restrictedScope()
	read := func() *DashboardData {
		return &DashboardData{Widgets: []WidgetValue{s.widget(context.Background(), 0, surfaceWidget("intel.emerging_threats", "", ""), true, scope)}}
	}
	// findings:read is not enough: the alert list needs vulnerabilities:read.
	d := read()
	maskForbidden(d, dashboardapp.Caller{Has: func(p string) bool { return p == permission.FindingsRead.String() }})
	if w := d.Widgets[0]; w.State != StateUnsupported || w.Reason != ReasonForbidden || w.Category != nil {
		t.Errorf("not masked without vulnerabilities:read: %+v", w)
	}
	d = read()
	maskForbidden(d, dashboardapp.Caller{Has: func(p string) bool { return p == permission.VulnerabilitiesRead.String() }})
	if d.Widgets[0].Category == nil {
		t.Error("masked with vulnerabilities:read")
	}
}

// A widget of a module that is off reads module_off with no figure, is not
// computed, and a figure stored while the module was on is masked on the way
// out; other organizations and metrics without a module are not affected.
func TestModuleOff_ComputeMaskAndCatalog(t *testing.T) {
	facts := &ctemFacts{threats: dashboard.EmergingThreatCounts{Seen: 3, Open: 3, Immediate: 3}}
	s := NewService(nil, nil, facts, nil)
	scope := restrictedScope()
	mods := &fakeModules{off: map[string]bool{}}
	s.SetModules(mods)

	// Stored while the module was on.
	stored := &DashboardData{Widgets: []WidgetValue{
		s.widget(context.Background(), 0, surfaceWidget("intel.emerging_threats", "", ""), true, scope),
		s.widget(context.Background(), 1, surfaceWidget("exceptions.expiring", "", ""), true, scope),
	}}
	if stored.Widgets[0].Category == nil || stored.Widgets[0].Category.Total != 3 {
		t.Fatalf("module on: %+v", stored.Widgets[0])
	}
	if !s.MetricOffered(context.Background(), scope.TenantID, "intel.emerging_threats") {
		t.Error("catalog leaves out a metric whose module is on")
	}

	mods.off[scope.TenantID.String()+"/"+module.ModuleThreatIntel] = true
	facts.scopes = nil
	v := s.widget(context.Background(), 0, surfaceWidget("intel.emerging_threats", "", ""), true, scope)
	if v.State != StateUnsupported || v.Reason != ReasonModuleOff || v.Category != nil || v.Drill != "" {
		t.Errorf("module off computed: %+v", v)
	}
	if len(facts.scopes) != 0 {
		t.Error("a widget of a module that is off was read")
	}

	out, err := s.forViewer(context.Background(), stored, dashboardapp.Caller{TenantID: scope.TenantID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if w := out.Widgets[0]; w.State != StateUnsupported || w.Reason != ReasonModuleOff || w.Category != nil || w.Drill != "" || w.ID != "w_s1" {
		t.Errorf("stored figure not masked: %+v", w)
	}
	if out.Widgets[1].Category == nil {
		t.Error("a metric without a module was masked")
	}
	if s.MetricOffered(context.Background(), scope.TenantID, "intel.emerging_threats") {
		t.Error("catalog offers a metric whose module is off")
	}
	if !s.MetricOffered(context.Background(), scope.TenantID, "exceptions.expiring") || s.MetricOffered(context.Background(), scope.TenantID, "no.such") {
		t.Error("catalog of metrics without a module")
	}
	// A snapshot stored while the module was off is computed again once it
	// is back on (it holds no figure), not served until the next refresh.
	storedOff := &DashboardData{Widgets: []WidgetValue{v}}
	if s.moduleBackOn(context.Background(), storedOff, scope.TenantID) {
		t.Error("recompute while the module is still off")
	}
	mods.off[scope.TenantID.String()+"/"+module.ModuleThreatIntel] = false
	if !s.moduleBackOn(context.Background(), storedOff, scope.TenantID) {
		t.Error("a module turned back on keeps the stored module_off widget")
	}
	// (forViewer masked stored in place; its second widget has figures.)
	if s.moduleBackOn(context.Background(), &DashboardData{Widgets: stored.Widgets[1:]}, scope.TenantID) {
		t.Error("a snapshot with figures is recomputed")
	}
	mods.off[scope.TenantID.String()+"/"+module.ModuleThreatIntel] = true

	// Another organization still has the module.
	other := shared.NewID()
	if !s.MetricOffered(context.Background(), other, "intel.emerging_threats") {
		t.Error("module off leaks to another organization")
	}
}
