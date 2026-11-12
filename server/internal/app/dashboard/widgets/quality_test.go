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

func TestClosureQuality_RowsListsAndPrevious(t *testing.T) {
	facts := &ctemFacts{closure: dashboard.ClosureQualityCounts{
		Current:      dashboard.ClosureWindowCounts{ByPerson: 4, Automatic: 9, Reopened: 2},
		Previous:     dashboard.ClosureWindowCounts{ByPerson: 1, Automatic: 3, Reopened: 0},
		ReadyToClose: 5,
	}}
	s := NewService(nil, nil, facts, nil)
	now := fixedNow(s)
	scope := restrictedScope()
	v := s.widget(context.Background(), 0, surfaceWidget("findings.closure_quality", "7d", "previous_period"), true, scope)
	if v.State != StateReady || v.Shape != dashboard.ShapeCategory || v.Category == nil || v.Window == nil {
		t.Fatalf("state %s reason %s", v.State, v.Reason)
	}
	sameScope(t, facts, scope)
	from := time.Date(now.Year(), now.Month(), now.Day()-6, 0, 0, 0, 0, time.UTC)
	if !facts.newFrom[0].Equal(from) || !facts.newFrom[1].Equal(from.AddDate(0, 0, -7)) {
		t.Fatalf("window %v", facts.newFrom)
	}
	r := v.Category.Rows
	keys := []string{ClosureByPerson, ClosureAutomatic, ClosureReopened, ClosureReadyToClose}
	for i, k := range keys {
		if r[i].Key != k {
			t.Fatalf("row %d is %s", i, r[i].Key)
		}
	}
	if v.Category.Total != 20 || r[1].Value != 9 || r[3].Value != 5 {
		t.Errorf("figures %+v total %v", r, v.Category.Total)
	}
	if r[0].Previous == nil || *r[0].Previous != 1 || r[2].Previous == nil || *r[2].Previous != 0 || r[3].Previous != nil {
		t.Errorf("previous %+v", r)
	}
	since := from.Format(time.RFC3339)
	person, auto := query(t, r[0].Drill), query(t, r[1].Drill)
	if person.Get("status") != "resolved" || person.Get("resolved_at_gte") != since || person.Get("resolved_by_null") != "false" ||
		person.Get("informational") != "true" || auto.Get("resolved_by_null") != "true" {
		t.Errorf("fix lists %s %s", r[0].Drill, r[1].Drill)
	}
	re := query(t, r[2].Drill)
	if re.Get("state") != "all" || re.Get("last_reopened_at_gte") != since {
		t.Errorf("reopened list %s", r[2].Drill)
	}
	if r[3].Drill != "/findings/ready-to-close" {
		t.Errorf("ready to close %s", r[3].Drill)
	}

	// An empty row opens nothing.
	facts.closure.Current.Reopened = 0
	v = s.widget(context.Background(), 0, surfaceWidget("findings.closure_quality", "7d", ""), true, scope)
	if v.Category.Rows[2].Drill != "" || v.Category.Rows[0].Previous != nil {
		t.Errorf("empty row %+v", v.Category.Rows[2])
	}

	// Nothing at all: not measured, never a row of zeros.
	facts.closure = dashboard.ClosureQualityCounts{}
	v = s.widget(context.Background(), 0, surfaceWidget("findings.closure_quality", "", ""), true, scope)
	if v.State != StateNotMeasured || v.Reason != ReasonNoClosures || v.Category != nil {
		t.Errorf("nothing: %s %s %+v", v.State, v.Reason, v.Category)
	}
}

func TestCampaignProgress_LateFirstAndLinks(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	past, later := now.AddDate(0, 0, -3), now.AddDate(0, 0, 10)
	ids := []shared.ID{shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()}
	facts := &ctemFacts{campaigns: []dashboard.CampaignProgressRow{
		{ID: ids[0], Name: "On track", DueDate: &later, Tasks: 4, Done: 3},
		{ID: ids[1], Name: "Past due", DueDate: &past, Tasks: 2, Done: 1},
		{ID: ids[2], Name: "Overdue tasks", DueDate: &later, Tasks: 10, Done: 2, Overdue: 3},
		{ID: ids[3], Name: "Nothing visible", Tasks: 0},
	}}
	s := NewService(nil, nil, facts, nil)
	fixedNow(s)
	scope := restrictedScope()
	v := s.widget(context.Background(), 0, surfaceWidget("remediation.campaign_progress", "", ""), true, scope)
	if v.State != StateReady || v.Category == nil {
		t.Fatalf("state %s reason %s", v.State, v.Reason)
	}
	sameScope(t, facts, scope)
	r := v.Category.Rows
	if len(r) != 3 || r[0].Label != "Overdue tasks" || r[1].Label != "Past due" || r[2].Label != "On track" {
		t.Fatalf("order %+v", r)
	}
	if r[0].Value != 20 || r[1].Value != 50 || r[2].Value != 75 || r[0].N == nil || *r[0].N != 10 {
		t.Errorf("shares %+v", r)
	}
	if r[0].Key != ids[2].String() || r[0].Drill != "/remediation/campaigns/"+ids[2].String() {
		t.Errorf("link %+v", r[0])
	}
	// Total: 6 done of 16 visible tasks.
	if v.Category.Total != 37.5 {
		t.Errorf("total %v", v.Category.Total)
	}
	if _, err := dashboard.ParseWidgetSpec("metric", surfaceWidget("remediation.campaign_progress", "90d", "").Config); err == nil {
		t.Error("a range on campaign progress was accepted")
	}

	facts.campaigns = facts.campaigns[3:]
	v = s.widget(context.Background(), 0, surfaceWidget("remediation.campaign_progress", "", ""), true, scope)
	if v.State != StateNotMeasured || v.Reason != ReasonNoActiveCampaigns || v.Category != nil {
		t.Errorf("no campaign: %s %s", v.State, v.Reason)
	}
}

func TestFPRateByTool_OrganizationOnlyAndMinimum(t *testing.T) {
	facts := &ctemFacts{toolClosed: []dashboard.ToolClosedRow{
		{Tool: "nuclei", Closed: 40, FalsePositive: 10},
		{Tool: "semgrep", Closed: 20, FalsePositive: 0},
		{Tool: "tiny", Closed: 2, FalsePositive: 1},
		{Tool: "trivy", Closed: 50, FalsePositive: 25},
	}}
	s := NewService(nil, nil, facts, nil)
	now := fixedNow(s)

	// A personal read is not measured and reads nothing.
	v := s.widget(context.Background(), 0, surfaceWidget("detection.fp_rate_by_tool", "30d", ""), true, restrictedScope())
	if v.State != StateNotMeasured || v.Reason != ReasonOrganizationOnly || v.Category != nil || facts.qualityCalls != 0 {
		t.Fatalf("personal: %s %s calls %d", v.State, v.Reason, facts.qualityCalls)
	}

	scope := orgScope(shared.NewID())
	v = s.widget(context.Background(), 0, surfaceWidget("detection.fp_rate_by_tool", "30d", ""), true, scope)
	if v.State != StateReady || v.Category == nil {
		t.Fatalf("state %s reason %s", v.State, v.Reason)
	}
	sameScope(t, facts, scope)
	from := time.Date(now.Year(), now.Month(), now.Day()-29, 0, 0, 0, 0, time.UTC)
	if !facts.since.Equal(from) {
		t.Errorf("since %v", facts.since)
	}
	r := v.Category.Rows
	// Highest rate first; a tool under the minimum is left out, never "50 %".
	if len(r) != 3 || r[0].Key != "trivy" || r[1].Key != "nuclei" || r[2].Key != "semgrep" {
		t.Fatalf("rows %+v", r)
	}
	if r[0].Value != 50 || r[1].Value != 25 || r[2].Value != 0 || *r[0].N != 50 {
		t.Errorf("rates %+v", r)
	}
	// 35 of 110 closes.
	if v.Category.Total != 31.8 {
		t.Errorf("total %v", v.Category.Total)
	}
	q := query(t, r[0].Drill)
	if q.Get("status") != "false_positive" || q.Get("tool_name") != "trivy" || q.Get("resolved_at_gte") != from.Format(time.RFC3339) {
		t.Errorf("list %s", r[0].Drill)
	}
	if r[2].Drill != "" {
		t.Errorf("a tool with no false positive links %s", r[2].Drill)
	}
	// A crafted tool name stays one bound value of one parameter.
	if href := falsePositiveHref("x&status=open", "t"); query(t, href).Get("status") != "false_positive" || !strings.Contains(href, "x%26status%3Dopen") {
		t.Errorf("tool name not encoded: %s", href)
	}
	if _, err := dashboard.ParseWidgetSpec("metric", surfaceWidget("detection.fp_rate_by_tool", "30d", "previous_period").Config); err == nil {
		t.Error("a comparison on the false-positive rate was accepted")
	}

	facts.toolClosed = facts.toolClosed[2:3]
	v = s.widget(context.Background(), 0, surfaceWidget("detection.fp_rate_by_tool", "30d", ""), true, scope)
	if v.State != StateNotMeasured || v.Reason != ReasonTooFewClosed {
		t.Errorf("too few: %s %s", v.State, v.Reason)
	}
}

// A stored personal snapshot is masked on the way out by the permission of
// each metric: campaigns need findings:remediation:read, the others
// findings:read.
func TestQualityBreakdowns_Permissions(t *testing.T) {
	facts := &ctemFacts{
		closure:   dashboard.ClosureQualityCounts{ReadyToClose: 1},
		campaigns: []dashboard.CampaignProgressRow{{ID: shared.NewID(), Name: "secret campaign", Tasks: 1}},
	}
	s := NewService(nil, nil, facts, nil)
	scope := restrictedScope()
	build := func() *DashboardData {
		return &DashboardData{Widgets: []WidgetValue{
			s.widget(context.Background(), 0, surfaceWidget("findings.closure_quality", "", ""), true, scope),
			s.widget(context.Background(), 1, surfaceWidget("remediation.campaign_progress", "", ""), true, scope),
		}}
	}
	d := build()
	maskForbidden(d, dashboardapp.Caller{Has: func(p string) bool { return p == permission.FindingsRead.String() }})
	if w := d.Widgets[1]; w.State != StateUnsupported || w.Reason != ReasonForbidden || w.Category != nil {
		t.Errorf("campaigns not masked: %+v", w)
	}
	if d.Widgets[0].Category == nil {
		t.Error("closure quality masked with findings:read")
	}
	d = build()
	maskForbidden(d, dashboardapp.Caller{Has: func(p string) bool { return p == permission.RemediationRead.String() }})
	if d.Widgets[0].Category != nil || d.Widgets[1].Category == nil {
		t.Errorf("remediation:read alone: %+v", d.Widgets)
	}
}
