package routes

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	dashboardapp "github.com/openctemio/openctem/api/internal/app/dashboard"
	"github.com/openctemio/openctem/api/internal/app/dashboard/widgets"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// widgetEnv is the pentest data-scope fixture (two assets, a scoped member,
// a full-data member, a campaign tester, an owner, and another tenant whose
// pentest finding carries a marker) with the dashboard routes mounted and
// the facts built.
type widgetEnv struct {
	*ptEnv
}

func newWidgetEnv(t *testing.T) *widgetEnv {
	t.Helper()
	e := &widgetEnv{ptEnv: newPtEnv(t)}
	h := e.h
	db := &postgres.DB{DB: h.db}
	log := logger.NewNop()
	dash := dashboardapp.NewService(postgres.NewUserDashboardRepository(db), log)
	dash.SetAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log))
	dash.SetMembershipReader(postgres.NewTenantRepository(db))
	wsvc := widgets.NewService(dash, h.enforcer, postgres.NewDashboardWidgetRepository(db), log)
	registerUserDashboardRoutes(h.router, handler.NewUserDashboardHandler(dash, log).SetWidgetData(wsvc), Middleware(h.dsAuth), nil)

	facts := postgres.NewDashboardFactsRepository(db)
	for _, tid := range []shared.ID{h.tenant, e.otherTenant} {
		if _, err := facts.RebuildTenant(context.Background(), tid, 100); err != nil {
			t.Fatalf("build facts: %v", err)
		}
	}
	return e
}

// call sends a request as user with explicit permissions (nil: the member
// default of the harness).
func (e *widgetEnv) call(user shared.ID, admin bool, perms []string, method, path string, body any) (int, string) {
	e.h.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, e.h.srv.URL+path, rdr)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-User", user.String())
	auth := "Test " + user.String()
	if admin {
		req.Header.Set("X-Test-Admin", "1")
		auth += " admin"
	}
	req.Header.Set("Authorization", auth)
	if perms != nil {
		req.Header.Set("X-Test-Perms", strings.Join(perms, ","))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func metricWidget(id, metric string, extra map[string]any) map[string]any {
	data := map[string]any{"kind": "metric", "metric": metric}
	for k, v := range extra {
		data[k] = v
	}
	return map[string]any{"widget_type": "metric", "x": 0, "y": 0, "w": 3, "h": 2,
		"config": map[string]any{"v": 2, "id": id, "data": data, "viz": map[string]any{}}}
}

var widgetLayout = []any{
	metricWidget("w_open", "findings.open", nil),
	metricWidget("w_p0", "exposure.priority_open", map[string]any{"filter": map[string]any{"priority_class": []string{"P0"}}}),
	metricWidget("w_sev", "findings.open", map[string]any{"group_by": []string{"severity"}, "time": map[string]any{"compare": "previous_period"}}),
	metricWidget("w_sla", "sla.within", nil),
	metricWidget("w_next", "fix.next", nil),
	metricWidget("w_flow", "flow.new_vs_fixed", nil),
	metricWidget("w_trend", "exposure.open_by_priority", nil),
	metricWidget("w_ttf", "fix.time_to_fix", nil),
	map[string]any{"widget_type": "open_findings", "x": 0, "y": 0, "w": 1, "h": 1}, // legacy, answered from the facts
	map[string]any{"widget_type": "assets_total", "x": 0, "y": 0, "w": 1, "h": 1},  // legacy, not answerable
}

type dataResp struct {
	Scope      string                `json:"scope"`
	Restricted bool                  `json:"restricted"`
	Built      *string               `json:"facts_built_at"`
	Widgets    []widgets.WidgetValue `json:"widgets"`
}

func (e *widgetEnv) data(t *testing.T, user shared.ID, admin bool, perms []string, path string) dataResp {
	t.Helper()
	code, body := e.call(user, admin, perms, http.MethodGet, path, nil)
	if code != http.StatusOK {
		t.Fatalf("GET %s = %d %s", path, code, body)
	}
	for _, m := range []string{ptDraft, ptReview, ptOther} {
		if strings.Contains(body, m) {
			t.Errorf("widget data shows %q", m)
		}
	}
	var out dataResp
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func byID(t *testing.T, d dataResp, id string) widgets.WidgetValue {
	t.Helper()
	for _, w := range d.Widgets {
		if w.ID == id {
			return w
		}
	}
	t.Fatalf("no widget %s in %+v", id, d.Widgets)
	return widgets.WidgetValue{}
}

// listTotal is the findings list total for the same viewer and filter.
func (e *widgetEnv) listTotal(t *testing.T, user shared.ID, admin bool, query string) int {
	t.Helper()
	code, body := e.call(user, admin, nil, http.MethodGet, "/api/v1/findings?per_page=1&"+query, nil)
	if code != http.StatusOK {
		t.Fatalf("list %s = %d %s", query, code, body)
	}
	var out struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	return out.Total
}

// A personal dashboard computes every widget for its owner's own scope: the
// figures equal the findings list of the same viewer and filter (parity),
// pentest findings count only for campaign members, nothing of another
// tenant or of an unpublished finding shows, and a member with no scope row
// sees zeros.
func TestDashboardWidgetData_PersonalScopeParity_DB(t *testing.T) {
	e := newWidgetEnv(t)
	h := e.h
	for _, tc := range []struct {
		name          string
		user          shared.ID
		admin         bool
		open, p0      int64
		seesPub       bool
		restricted    bool
		fixNextTitles int
	}{
		{"scoped non-member", h.memberA, false, 2, 1, false, true, 1},
		{"campaign tester", e.tester, false, 3, 2, true, true, 2},
		{"full-data non-member", h.memberFull, false, 3, 1, false, false, 1},
		{"member without scope rows", h.memberFree, false, 0, 0, false, true, 0},
		{"administrator", h.owner, true, 4, 2, true, false, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := e.call(tc.user, tc.admin, nil, http.MethodPost, "/api/v1/me/dashboards", map[string]any{"name": "Mine", "layout": widgetLayout})
			if code != http.StatusCreated {
				t.Fatalf("create = %d %s", code, body)
			}
			var d struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal([]byte(body), &d)
			out := e.data(t, tc.user, tc.admin, nil, "/api/v1/me/dashboards/"+d.ID+"/data")
			if out.Scope != "personal" || out.Restricted != tc.restricted || out.Built == nil {
				t.Errorf("scope = %s restricted = %v built = %v", out.Scope, out.Restricted, out.Built)
			}

			open := byID(t, out, "w_open")
			if open.State != widgets.StateReady || open.Scalar == nil || open.Scalar.Value != tc.open {
				t.Fatalf("open findings = %+v, want %d", open, tc.open)
			}
			if got := e.listTotal(t, tc.user, tc.admin, "state=open"); int64(got) != tc.open {
				t.Errorf("parity: widget %d, findings list %d", tc.open, got)
			}
			if open.Drill != "/findings?state=open" {
				t.Errorf("drill = %q", open.Drill)
			}
			p0 := byID(t, out, "w_p0")
			if p0.Scalar == nil || p0.Scalar.Value != tc.p0 {
				t.Errorf("P0 open = %+v, want %d", p0.Scalar, tc.p0)
			}
			if got := e.listTotal(t, tc.user, tc.admin, "state=open&priority_class=P0"); int64(got) != tc.p0 {
				t.Errorf("parity P0: widget %d, findings list %d", tc.p0, got)
			}
			// The legacy "open findings" tile is answered from the facts too.
			if legacy := out.Widgets[8]; legacy.Scalar == nil || legacy.Scalar.Value != tc.open {
				t.Errorf("legacy open_findings = %+v", legacy)
			}
			if un := out.Widgets[9]; un.State != widgets.StateUnsupported || un.Reason != widgets.ReasonLegacyTile {
				t.Errorf("legacy assets_total = %+v", un)
			}
			// Severity rows add up to the open count, each opens its own list.
			sev := byID(t, out, "w_sev")
			var sum float64
			for _, r := range sev.Category.Rows {
				sum += r.Value
				if !strings.HasPrefix(r.Drill, "/findings?") || !strings.Contains(r.Drill, "severity="+r.Key) {
					t.Errorf("row %s drill %q", r.Key, r.Drill)
				}
				if r.Previous == nil {
					t.Errorf("row %s has no previous period", r.Key)
				}
			}
			if int64(sum) != tc.open {
				t.Errorf("severity rows sum %v, want %d", sum, tc.open)
			}
			// No open finding has an SLA: not measured, never 0 % or 100 %.
			if sla := byID(t, out, "w_sla"); sla.State != widgets.StateNotMeasured || sla.Ratio.ValuePct != nil {
				t.Errorf("sla within = %+v", sla)
			}
			if ttf := byID(t, out, "w_ttf"); ttf.State != widgets.StateNotMeasured {
				t.Errorf("time to fix with nothing fixed = %+v", ttf)
			}
			next := byID(t, out, "w_next")
			if len(next.Items.Rows) != tc.fixNextTitles {
				t.Errorf("fix next rows = %d, want %d", len(next.Items.Rows), tc.fixNextTitles)
			}
			sawPub := false
			for _, r := range next.Items.Rows {
				if r.Title == ptPub {
					sawPub = true
				}
			}
			if sawPub != tc.seesPub {
				t.Errorf("fix next shows the campaign finding = %v, want %v", sawPub, tc.seesPub)
			}
			if tc.seesPub && len(next.Items.Rows) > 0 && next.Items.Rows[0].Title != ptPub {
				t.Errorf("fix next order: critical P0 first, got %s", next.Items.Rows[0].Title)
			}
			flow := byID(t, out, "w_flow")
			if flow.Series == nil || flow.Series.Totals["opened"] != tc.open {
				t.Errorf("opened in 30 days = %+v, want %d", flow.Series, tc.open)
			}
			trend := byID(t, out, "w_trend")
			for _, line := range trend.Series.Series {
				if line.Key == "P0" {
					if last := line.Points[len(line.Points)-1].V; int64(last) != tc.p0 {
						t.Errorf("P0 trend ends at %v, want the live %d", last, tc.p0)
					}
				}
			}
		})
	}
}

// An organization dashboard reads the whole organization for a viewer with
// dashboards:org:view; list rows still follow the viewer's campaign
// membership; without the permission it is 403, outside the audience 404,
// and nobody reads another person's personal dashboard data.
func TestDashboardWidgetData_OrganizationAndAuthz_DB(t *testing.T) {
	e := newWidgetEnv(t)
	h := e.h
	view := append(append([]string{}, dsMemberPerms...), permission.DashboardsOrgView.String())
	code, body := e.call(h.owner, true, nil, http.MethodPost, "/api/v1/organization/dashboards", map[string]any{"name": "Org", "layout": widgetLayout})
	if code != http.StatusCreated {
		t.Fatalf("create org = %d %s", code, body)
	}
	var org struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(body), &org)
	path := "/api/v1/organization/dashboards/" + org.ID + "/data"

	// A scoped member with org view sees organization-wide aggregates
	// (pentest included), but not the campaign finding's title.
	out := e.data(t, h.memberA, false, view, path)
	if out.Scope != "organization" || out.Restricted {
		t.Errorf("scope = %s restricted = %v", out.Scope, out.Restricted)
	}
	if v := byID(t, out, "w_open").Scalar.Value; v != 4 {
		t.Errorf("organization open = %d, want 4", v)
	}
	for _, r := range byID(t, out, "w_next").Items.Rows {
		if r.Title == ptPub {
			t.Error("organization list shows a campaign finding to a non-member")
		}
	}
	// The tester sees it in the same list.
	saw := false
	for _, r := range byID(t, e.data(t, e.tester, false, view, path), "w_next").Items.Rows {
		saw = saw || r.Title == ptPub
	}
	if !saw {
		t.Error("campaign member does not see the campaign finding")
	}

	if code, _ := e.call(h.memberA, false, dsMemberPerms, http.MethodGet, path, nil); code != http.StatusForbidden {
		t.Errorf("without dashboards:org:view = %d, want 403", code)
	}
	// Narrow the audience to a role memberA does not hold: 404.
	role := shared.NewID()
	h.exec(`INSERT INTO roles (id, tenant_id, slug, name, hierarchy_level) VALUES ($1, $2, $3, 'aud', 20)`, role.String(), h.tenant.String(), "aud-"+role.String()[:8])
	if code, b := e.call(h.owner, true, nil, http.MethodPut, "/api/v1/organization/dashboards/"+org.ID+"/audience",
		map[string]any{"audience": []any{map[string]any{"type": "role", "id": role.String()}}}); code != http.StatusOK {
		t.Fatalf("audience = %d %s", code, b)
	}
	if code, _ := e.call(h.memberA, false, view, http.MethodGet, path, nil); code != http.StatusNotFound {
		t.Errorf("outside the audience = %d, want 404", code)
	}

	// Another person's personal dashboard: 404, data included.
	code, body = e.call(e.tester, false, nil, http.MethodPost, "/api/v1/me/dashboards", map[string]any{"name": "T", "layout": widgetLayout})
	if code != http.StatusCreated {
		t.Fatalf("create = %d", code)
	}
	var mine struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(body), &mine)
	for _, u := range []shared.ID{h.memberA, h.owner} {
		if code, _ := e.call(u, u == h.owner, nil, http.MethodGet, "/api/v1/me/dashboards/"+mine.ID+"/data", nil); code != http.StatusNotFound {
			t.Errorf("another person's dashboard data = %d, want 404", code)
		}
	}
}

// A preview computes one spec for the caller's own scope and refuses a spec
// the server would not save.
func TestDashboardWidgetData_Preview_DB(t *testing.T) {
	e := newWidgetEnv(t)
	h := e.h
	w := metricWidget("w_pre", "findings.open", map[string]any{"filter": map[string]any{"severity": []string{"high"}}})
	code, body := e.call(h.memberA, false, nil, http.MethodPost, "/api/v1/me/dashboards/widget-preview", w)
	if code != http.StatusOK {
		t.Fatalf("preview = %d %s", code, body)
	}
	var v widgets.WidgetValue
	_ = json.Unmarshal([]byte(body), &v)
	if v.Scalar == nil || v.Scalar.Value != 1 { // findingA only; findingB is outside the scope
		t.Errorf("preview high = %+v, want 1", v.Scalar)
	}
	bad := metricWidget("w_bad", "findings.open", map[string]any{"filter": map[string]any{"tenant_id": []string{e.otherTenant.String()}}})
	if code, _ := e.call(h.memberA, false, nil, http.MethodPost, "/api/v1/me/dashboards/widget-preview", bad); code != http.StatusBadRequest {
		t.Errorf("preview with a smuggled field = %d, want 400", code)
	}
	legacy := map[string]any{"widget_type": "open_findings", "config": map[string]any{}}
	if code, _ := e.call(h.memberA, false, nil, http.MethodPost, "/api/v1/me/dashboards/widget-preview", legacy); code != http.StatusBadRequest {
		t.Errorf("preview of a legacy tile = %d, want 400", code)
	}
}

// Measured SLA and time-to-fix figures come from the facts with the same
// scope rules: the SLA share counts open findings with an SLA, and the time
// to fix is a bucketed median once five fixes exist in the window.
func TestDashboardWidgetData_SLAAndTimeToFix_DB(t *testing.T) {
	e := newWidgetEnv(t)
	h := e.h
	ten := h.tenant.String()
	h.exec(`UPDATE findings SET sla_status = 'overdue' WHERE id = $1`, h.findingA.String())
	h.exec(`UPDATE findings SET sla_status = 'on_track' WHERE id = $1`, h.findingB.String())
	h.exec(`UPDATE findings SET sla_status = 'warning' WHERE tenant_id = $1 AND title = $2`, ten, ptSca)
	for i := 0; i < 5; i++ {
		id := shared.NewID()
		h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, priority_class, first_detected_at, resolved_at)
			VALUES ($1::uuid, $2, $3, 'sast', 'ttf', 'fixed one', 'high', $1::text, 'resolved', 'P1', now() - interval '2 days' - interval '10 hours', now() - interval '2 days')`,
			id.String(), ten, h.assetA.String())
	}
	if _, err := postgres.NewDashboardFactsRepository(&postgres.DB{DB: h.db}).RebuildTenant(context.Background(), h.tenant, 100); err != nil {
		t.Fatal(err)
	}
	layout := []any{metricWidget("w_sla", "sla.within", nil), metricWidget("w_ttf", "fix.time_to_fix", nil),
		metricWidget("w_ttfp", "fix.time_to_fix", map[string]any{"group_by": []string{"priority_class"}})}
	for _, tc := range []struct {
		name  string
		user  shared.ID
		admin bool
		pct   float64
		fixed int64
	}{
		{"administrator", h.owner, true, 66.7, 5},
		{"scoped member", h.memberA, false, 50, 5},
		{"member without scope rows", h.memberFree, false, -1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, body := e.call(tc.user, tc.admin, nil, http.MethodPost, "/api/v1/me/dashboards", map[string]any{"name": "S", "layout": layout})
			var d struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal([]byte(body), &d)
			out := e.data(t, tc.user, tc.admin, nil, "/api/v1/me/dashboards/"+d.ID+"/data")
			sla := byID(t, out, "w_sla")
			if tc.pct < 0 {
				if sla.State != widgets.StateNotMeasured {
					t.Errorf("no SLA in scope = %+v", sla)
				}
			} else if sla.Ratio.ValuePct == nil || *sla.Ratio.ValuePct != tc.pct {
				t.Errorf("within SLA = %+v, want %v", sla.Ratio, tc.pct)
			}
			if !strings.Contains(sla.Drill, "sla_status=overdue,exceeded") {
				t.Errorf("SLA drill = %q", sla.Drill)
			}
			ttf := byID(t, out, "w_ttf")
			if tc.fixed == 0 {
				if ttf.State != widgets.StateNotMeasured {
					t.Errorf("time to fix with no fixes in scope = %+v", ttf)
				}
				return
			}
			if ttf.Duration == nil || ttf.Duration.N != tc.fixed || ttf.Duration.MedianHours == nil ||
				*ttf.Duration.MedianHours < 8 || *ttf.Duration.MedianHours >= 16 {
				t.Errorf("time to fix = %+v, want 5 fixes with a median in 8-16 h", ttf.Duration)
			}
			byPrio := byID(t, out, "w_ttfp")
			if byPrio.Category == nil || len(byPrio.Category.Rows) != 1 || byPrio.Category.Rows[0].Key != "P1" {
				t.Errorf("time to fix by priority = %+v", byPrio.Category)
			}
		})
	}
}
