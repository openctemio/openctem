package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/dashboard/widgets"
	threatalertapp "github.com/openctemio/openctem/api/internal/app/threatalert"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// switchableModules turns modules off per organization for the module gate.
type switchableModules struct {
	mu  sync.Mutex
	off map[string]bool // tenant/module
}

func (m *switchableModules) TenantDisabledModules(_ context.Context, tenantID string) map[string]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]bool{}
	for k, v := range m.off {
		if t, mod, ok := strings.Cut(k, "/"); ok && t == tenantID && v {
			out[mod] = true
		}
	}
	return out
}

func (m *switchableModules) set(tenantID shared.ID, moduleID string, off bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.off[tenantID.String()+"/"+moduleID] = off
}

const intelMarkerOther = "CVE-2099-0001"

type intelEnv struct {
	*widgetEnv
	modules *switchableModules
	gate    *middleware.ModuleGate
}

// newIntelEnv extends the widget fixture with the emerging-threat list
// mounted behind the module gate and four alerts of the tenant: an open
// immediate alert on A1 (in memberA's scope), a resolved listed alert on A1
// (seen, not open), an open digest and an open immediate alert on B1 (outside
// memberA's scope). Another tenant has an open immediate alert.
func newIntelEnv(t *testing.T) *intelEnv {
	t.Helper()
	e := &intelEnv{widgetEnv: newWidgetEnv(t), modules: &switchableModules{off: map[string]bool{}}}
	h := e.h
	db := &postgres.DB{DB: h.db}
	log := logger.NewNop()
	e.gate = middleware.NewModuleGate(e.modules, time.Minute)
	e.svc.SetModules(e.gate)
	et := handler.NewEmergingThreatHandler(threatalertapp.NewService(postgres.NewThreatAlertRepository(db), nil, log), h.enforcer, log)
	registerEmergingThreatRoutes(h.router, et, Middleware(h.dsAuth), nil, e.gate.RequireModule(module.ModuleThreatIntel))

	ten := h.tenant.String()
	alert := func(tenant, asset, vuln, level, state string) {
		id := shared.NewID().String()
		h.exec(`INSERT INTO threat_alerts (id, tenant_id, vuln_id, level, tier, ets, state) VALUES ($1, $2, $3, $4, 'confirmed', 70, $5)`,
			id, tenant, vuln, level, state)
		h.exec(`INSERT INTO threat_alert_assets (tenant_id, alert_id, asset_id, match_kind) VALUES ($1, $2, $3, 'confirmed')`, tenant, id, asset)
	}
	alert(ten, h.assetA.String(), "CVE-2026-0001", "immediate", "new")
	alert(ten, h.assetA.String(), "CVE-2026-0002", "listed", "resolved")
	alert(ten, h.assetB.String(), "CVE-2026-0003", "digest", "acknowledged")
	alert(ten, h.assetB.String(), "CVE-2026-0004", "immediate", "remediating")
	otherAsset := shared.NewID().String()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, 'intel other', 'host', 'public', 'high')`,
		otherAsset, e.otherTenant.String())
	alert(e.otherTenant.String(), otherAsset, intelMarkerOther, "immediate", "new")
	return e
}

// intelPerms is the member default, which holds the alert list's
// permission; noVulnPerms is it without vulnerabilities:read.
func intelPerms() []string { return dsMemberPerms }

func noVulnPerms() []string {
	out := make([]string, 0, len(dsMemberPerms))
	for _, p := range dsMemberPerms {
		if p != permission.VulnerabilitiesRead.String() {
			out = append(out, p)
		}
	}
	return out
}

// alertTotal is the emerging-threat list total for the viewer and query.
func (e *intelEnv) alertTotal(t *testing.T, user shared.ID, admin bool, query string) int {
	t.Helper()
	code, body := e.call(user, admin, intelPerms(), http.MethodGet, "/api/v1/emerging-threats/?per_page=1&"+query, nil)
	if code != http.StatusOK {
		t.Fatalf("alert list %s = %d %s", query, code, body)
	}
	var out struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	return out.Total
}

var intelLayout = []any{metricWidget("w_et", "intel.emerging_threats", nil)}

// The emerging-threats widget counts the open alerts affecting each viewer's
// own scope by level: alerts whose assets are all outside the scope and
// another tenant's alerts never count or show, a member with no scope row is
// not measured, and each level equals the alert list it opens.
func TestDashboardIntelWidget_ScopeAndParity_DB(t *testing.T) {
	e := newIntelEnv(t)
	h := e.h
	for _, tc := range []struct {
		name                      string
		user                      shared.ID
		admin                     bool
		measured                  bool
		immediate, digest, listed float64
	}{
		{"scoped member", h.memberA, false, true, 1, 0, 0},
		{"member without scope rows", h.memberFree, false, false, 0, 0, 0},
		{"administrator", h.owner, true, true, 2, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := e.createPersonal(t, tc.user, tc.admin, intelLayout)
			code, raw := e.call(tc.user, tc.admin, intelPerms(), http.MethodGet, "/api/v1/me/dashboards/"+id+"/data", nil)
			if code != http.StatusOK {
				t.Fatalf("data = %d %s", code, raw)
			}
			if strings.Contains(raw, intelMarkerOther) {
				t.Errorf("the widget shows another tenant's alert")
			}
			w := byID(t, e.data(t, tc.user, tc.admin, intelPerms(), "/api/v1/me/dashboards/"+id+"/data"), "w_et")
			if !tc.measured {
				if w.State != widgets.StateNotMeasured || w.Reason != widgets.ReasonNoThreatAlerts || w.Category != nil {
					t.Fatalf("no alerts in scope = %+v", w)
				}
				return
			}
			rows := category(t, w)
			if rows["immediate"].Value != tc.immediate || rows["digest"].Value != tc.digest || rows["listed"].Value != tc.listed {
				t.Errorf("levels %+v", rows)
			}
			for k, r := range rows {
				if r.Value == 0 {
					if r.Drill != "" {
						t.Errorf("empty level %s links %s", k, r.Drill)
					}
					continue
				}
				u, err := url.Parse(r.Drill)
				if err != nil || u.Path != "/emerging-threats" {
					t.Fatalf("level %s opens %s", k, r.Drill)
				}
				if got := e.alertTotal(t, tc.user, tc.admin, u.RawQuery); float64(got) != r.Value {
					t.Errorf("parity %s: widget %v, alert list %d (%s)", k, r.Value, got, r.Drill)
				}
			}
		})
	}
}

// While the module is off the widget reads module_off with no figure (also
// the snapshot stored while it was on), the catalog leaves it out, and the
// alert list itself is refused; another tenant keeps the module. Without
// vulnerabilities:read the widget is forbidden.
func TestDashboardIntelWidget_ModuleOffAndPermission_DB(t *testing.T) {
	e := newIntelEnv(t)
	h := e.h
	id := e.createPersonal(t, h.memberA, false, intelLayout)
	path := "/api/v1/me/dashboards/" + id + "/data"
	if w := byID(t, e.data(t, h.memberA, false, intelPerms(), path), "w_et"); w.Category == nil {
		t.Fatalf("module on = %+v", w)
	}
	catalogHas := func(user shared.ID) bool {
		code, body := e.call(user, false, intelPerms(), http.MethodGet, "/api/v1/me/dashboards/widget-catalog", nil)
		if code != http.StatusOK {
			t.Fatalf("catalog = %d %s", code, body)
		}
		return strings.Contains(body, `"intel.emerging_threats"`)
	}
	if !catalogHas(h.memberA) {
		t.Error("catalog leaves out the widget while the module is on")
	}

	// Without the alert list's permission: forbidden, no figure.
	if w := byID(t, e.data(t, h.memberA, false, noVulnPerms(), path), "w_et"); w.State != widgets.StateUnsupported ||
		w.Reason != widgets.ReasonForbidden || w.Category != nil {
		t.Errorf("without vulnerabilities:read = %+v", w)
	}

	e.modules.set(h.tenant, module.ModuleThreatIntel, true)
	e.gate.Invalidate(h.tenant.String())
	code, raw := e.call(h.memberA, false, intelPerms(), http.MethodGet, path, nil)
	if code != http.StatusOK {
		t.Fatalf("data = %d %s", code, raw)
	}
	if strings.Contains(raw, "/emerging-threats") {
		t.Errorf("a stored figure leaks while the module is off: %s", raw)
	}
	if w := byID(t, e.data(t, h.memberA, false, intelPerms(), path), "w_et"); w.State != widgets.StateUnsupported ||
		w.Reason != widgets.ReasonModuleOff || w.Category != nil {
		t.Errorf("module off = %+v", w)
	}
	code, _ = e.call(h.memberA, false, intelPerms(), http.MethodPost, "/api/v1/me/dashboards/"+id+"/refresh", nil)
	if code != http.StatusOK && code != http.StatusTooManyRequests {
		t.Fatalf("refresh = %d", code)
	}
	if w := byID(t, e.data(t, h.memberA, false, intelPerms(), path), "w_et"); w.Reason != widgets.ReasonModuleOff || w.Category != nil {
		t.Errorf("module off after refresh = %+v", w)
	}
	if catalogHas(h.memberA) {
		t.Error("catalog offers the widget while the module is off")
	}
	if code, _ := e.call(h.memberA, false, intelPerms(), http.MethodGet, "/api/v1/emerging-threats/", nil); code != http.StatusForbidden {
		t.Errorf("alert list with the module off = %d", code)
	}

	// Turned back on: the figure returns at once, although the stored
	// snapshot (refreshed while it was off) has none.
	e.modules.set(h.tenant, module.ModuleThreatIntel, false)
	e.gate.Invalidate(h.tenant.String())
	if w := byID(t, e.data(t, h.memberA, false, intelPerms(), path), "w_et"); w.Category == nil {
		t.Errorf("module back on = %+v", w)
	}
}
