package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/dashboard/widgets"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const flowMarkerOther = "flow-other-tenant-tool"

var flowLayout = []any{
	metricWidget("w_flow", "exposure.flow", nil),
	metricWidget("w_intake", "ingest.intake", nil),
}

// newFlowEnv extends the widget fixture with outcomes (in progress on A1,
// fixed on A1 two days ago, false positive on B1 yesterday, accepted on A1
// 40 days ago, outside the window), receipts of three sources of the tenant
// and a source of another tenant, and the receipt list routes.
func newFlowEnv(t *testing.T) *widgetEnv {
	t.Helper()
	e := newWidgetEnv(t)
	h := e.h
	ten := h.tenant.String()
	seed := func(tenant, asset shared.ID, status, sev, prio, resolvedAgo string) {
		id := shared.NewID()
		var resolved any
		if resolvedAgo != "" {
			resolved = resolvedAgo
		}
		h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, priority_class, resolved_at)
			VALUES ($1::uuid, $2, $3, 'sast', 'x', 'flow', $4, $1::text, $5, $6, now() - $7::interval)`,
			id.String(), tenant.String(), asset.String(), sev, status, prio, resolved)
	}
	seed(h.tenant, h.assetA, "in_progress", "high", "P1", "")
	seed(h.tenant, h.assetA, "resolved", "high", "P1", "2 days")
	seed(h.tenant, h.assetB, "false_positive", "medium", "P2", "1 day")
	seed(h.tenant, h.assetA, "accepted", "low", "P3", "40 days")

	receipt := func(tenant, kind, tool, status string, received, created, still, reopened, skipped, failed, suppressed int, ago string) {
		id := shared.NewID().String()
		h.exec(`INSERT INTO ingest_receipts (id, tenant_id, source_kind, source_ref, tool_name, status, reports, findings_received,
			findings_created, findings_updated, findings_reopened, skipped, findings_failed, findings_suppressed, created_at, updated_at)
			VALUES ($1::uuid, $2, $3, $1::text, NULLIF($4, ''), $5, 1, $6, $7, $8, $9, $10, $11, $12, now() - $13::interval, now() - $13::interval)`,
			id, tenant, kind, tool, status, received, created, still, reopened, skipped, failed, suppressed, ago)
		// What the writer records with every receipt: the counts of the tool
		// that reported, which the intake reads instead of the receipt's own.
		h.exec(`INSERT INTO ingest_receipt_tools (tenant_id, receipt_id, tool, reports, received, created, still_detected, reopened,
			skipped, failed, suppressed, first_at, last_at)
			VALUES ($1, $2::uuid, COALESCE(NULLIF($3, ''), 'unknown'), 1, $4, $5, $6, $7, $8, $9, $10, now() - $11::interval, now() - $11::interval)`,
			tenant, id, tool, received, created, still, reopened, skipped, failed, suppressed, ago)
	}
	// nuclei on sensors: three runs a day apart, the latest an hour ago.
	receipt(ten, "scan_run", "nuclei", "completed", 100, 20, 70, 2, 3, 0, 4, "1 hour")
	receipt(ten, "command", "nuclei", "completed", 50, 5, 40, 0, 0, 0, 0, "25 hours")
	receipt(ten, "scan_run", "nuclei", "completed", 40, 2, 38, 0, 0, 0, 0, "49 hours")
	// A CI upload without a tool whose latest run failed.
	receipt(ten, "ci_run", "", "failed", 10, 0, 0, 0, 0, 10, 0, "2 hours")
	// An import 60 days ago: outside the 30-day window.
	receipt(ten, "connector", "cloud", "completed", 500, 500, 0, 0, 0, 0, 0, "60 days")
	// Another organization's source never counts.
	receipt(e.otherTenant.String(), "scan_run", flowMarkerOther, "completed", 999, 999, 0, 0, 0, 0, 0, "1 hour")

	db := &postgres.DB{DB: h.db}
	pass := Middleware(func(next http.Handler) http.Handler { return next })
	registerFindingImportRoutes(h.router, nil, handler.NewIngestReceiptHandler(postgres.NewIngestReceiptRepository(db), h.enforcer, logger.NewNop()),
		Middleware(h.dsAuth), pass)

	facts := postgres.NewDashboardFactsRepository(db)
	for _, tid := range []shared.ID{h.tenant, e.otherTenant} {
		if _, err := facts.RebuildTenant(context.Background(), tid, 100); err != nil {
			t.Fatalf("build facts: %v", err)
		}
	}
	return e
}

type receiptTotals struct {
	Total  int `json:"total"`
	Totals struct {
		Receipts   int64 `json:"receipts"`
		Received   int64 `json:"received"`
		Created    int64 `json:"created"`
		Updated    int64 `json:"updated"`
		Reopened   int64 `json:"reactivated"`
		Skipped    int64 `json:"skipped"`
		Failed     int64 `json:"failed"`
		Suppressed int64 `json:"suppressed"`
	} `json:"totals"`
}

func (e *widgetEnv) receipts(t *testing.T, user shared.ID, perms []string, drill string) receiptTotals {
	t.Helper()
	path := "/api/v1" + drill
	if strings.Contains(path, "?") {
		path += "&per_page=1"
	} else {
		path += "?per_page=1"
	}
	code, body := e.call(user, false, perms, http.MethodGet, path, nil)
	if code != http.StatusOK {
		t.Fatalf("receipts %s = %d %s", path, code, body)
	}
	var out receiptTotals
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// The organization exposure flow: findings figures are organization-wide
// and equal their lists for an unrestricted viewer; every source figure
// equals the receipt list it opens (its totals), another tenant's receipts
// and receipts outside the window never count, and source health follows
// the latest receipt and the usual interval.
func TestDashboardFlowWidgets_Organization_DB(t *testing.T) {
	e := newFlowEnv(t)
	h := e.h
	view := append(append([]string{}, dsMemberPerms...), permission.DashboardsOrgView.String())
	code, body := e.call(h.owner, true, nil, http.MethodPost, "/api/v1/organization/dashboards", map[string]any{"name": "Flow", "layout": flowLayout})
	if code != http.StatusCreated {
		t.Fatalf("create org = %d %s", code, body)
	}
	var org struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(body), &org)
	code, raw := e.call(h.memberA, false, view, http.MethodGet, "/api/v1/organization/dashboards/"+org.ID+"/data", nil)
	if code != http.StatusOK {
		t.Fatalf("data = %d %s", code, raw)
	}
	if strings.Contains(raw, flowMarkerOther) {
		t.Errorf("the flow shows another tenant's source")
	}
	var out dataResp
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	flow := byID(t, out, "w_flow")
	if flow.State != widgets.StateReady || flow.Flow == nil {
		t.Fatalf("flow = %+v", flow)
	}
	f := flow.Flow
	in := f.Intake
	if in == nil {
		t.Fatalf("organization flow without intake (%s)", f.IntakeReason)
	}
	// nuclei (3 receipts in the window) and the CI source; never the
	// 60-day-old import or the other tenant's source.
	if len(in.Sources) != 2 {
		t.Fatalf("sources %+v", in.Sources)
	}
	byTool := map[string]widgets.IntakeSource{}
	for _, s := range in.Sources {
		byTool[s.Tool] = s
	}
	nuc, ci := byTool["nuclei"], byTool["unknown"]
	if nuc.Origin != "sensor" || nuc.Receipts != 3 || nuc.Received != 190 || nuc.Health != widgets.HealthOK || nuc.ExpectedEverySeconds == nil {
		t.Errorf("nuclei = %+v", nuc)
	}
	if ci.Origin != "ci" || ci.Health != widgets.HealthFailed || ci.NotStored != 10 || ci.LastStatus != "failed" {
		t.Errorf("ci = %+v", ci)
	}
	if in.Failing != 1 || in.Totals.Received != 200 || in.Totals.Receipts != 4 {
		t.Errorf("failing %d totals %+v", in.Failing, in.Totals)
	}
	n := in.Noise
	if n.New+n.Merged+n.NotStored != n.Received || n.Suppressed != 4 || n.New != 27+2 {
		t.Errorf("noise %+v", n)
	}

	// Each source figure is the receipt list's totals for the same viewer.
	for _, s := range append(in.Sources, in.Totals) {
		got := e.receipts(t, h.memberA, view, s.Drill)
		if got.Totals.Received != s.Received || got.Totals.Receipts != s.Receipts || int64(got.Total) != s.Receipts ||
			got.Totals.Suppressed != s.Suppressed || got.Totals.Skipped+got.Totals.Failed != s.NotStored {
			t.Errorf("parity %s: widget %+v, list %+v", s.Drill, s, got)
		}
	}

	// Findings figures: organization-wide, each its list for the owner.
	for name, fig := range map[string]widgets.FlowFigure{"open": f.Open, "actionable": f.Actionable, "in progress": f.InProgress,
		"fixed": f.Fixed, "accepted": f.Accepted, "false positive": f.FalsePositive, "past sla": f.PastSLA} {
		if got := e.listTotal(t, h.owner, true, strings.TrimPrefix(fig.Drill, "/findings?")); int64(got) != fig.Value {
			t.Errorf("parity %s: widget %d, list %d (%s)", name, fig.Value, got, fig.Drill)
		}
	}
	if f.InProgress.Value != 1 || f.Fixed.Value != 1 || f.FalsePositive.Value != 1 || f.Accepted.Value != 0 {
		t.Errorf("outcomes %+v %+v %+v %+v", f.InProgress, f.Fixed, f.FalsePositive, f.Accepted)
	}
	var arcs int64
	for _, c := range f.Classes {
		arcs += c.Value
		if got := e.listTotal(t, h.owner, true, strings.TrimPrefix(c.Drill, "/findings?")); int64(got) != c.Value {
			t.Errorf("parity class %s: widget %d, list %d", c.Key, c.Value, got)
		}
	}
	if arcs != f.Actionable.Value {
		t.Errorf("arcs %d, actionable %d", arcs, f.Actionable.Value)
	}
	if in.FalsePositive.Value != f.FalsePositive.Value {
		t.Errorf("intake false positive %d, flow %d", in.FalsePositive.Value, f.FalsePositive.Value)
	}

	intake := byID(t, out, "w_intake")
	if intake.State != widgets.StateReady || intake.Intake == nil || intake.Intake.Totals.Received != 200 {
		t.Errorf("intake widget = %+v", intake)
	}
}

// A personal flow counts the viewer's own scope and carries receipts only
// for a reader the receipt list shows every receipt to (no data scope: the
// owner): the out-of-scope false positive on B1 never counts for memberA,
// each figure equals the list the viewer opens, and for a scoped reader the
// intake widget is not measured (organization only) instead of showing
// organization volumes.
func TestDashboardFlowWidgets_PersonalScope_DB(t *testing.T) {
	e := newFlowEnv(t)
	h := e.h
	for _, tc := range []struct {
		name          string
		user          shared.ID
		admin         bool
		falsePositive int64
		receipts      bool
	}{
		{"scoped member", h.memberA, false, 0, false},
		{"member without scope rows", h.memberFree, false, 0, false},
		{"owner", h.owner, true, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := e.call(tc.user, tc.admin, nil, http.MethodPost, "/api/v1/me/dashboards", map[string]any{"name": "Flow", "layout": flowLayout})
			if code != http.StatusCreated {
				t.Fatalf("create = %d %s", code, body)
			}
			var d struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal([]byte(body), &d)
			code, raw := e.call(tc.user, tc.admin, nil, http.MethodGet, "/api/v1/me/dashboards/"+d.ID+"/data", nil)
			if code != http.StatusOK {
				t.Fatalf("data = %d %s", code, raw)
			}
			if strings.Contains(raw, flowMarkerOther) || strings.Contains(raw, "nuclei") != tc.receipts {
				t.Errorf("receipts shown = %v, want %v", strings.Contains(raw, "nuclei"), tc.receipts)
			}
			var out dataResp
			if err := json.Unmarshal([]byte(raw), &out); err != nil {
				t.Fatal(err)
			}
			flow := byID(t, out, "w_flow")
			if tc.user == h.memberFree {
				// Nothing in scope and no organization intake: not measured,
				// never a diagram of zeros.
				if flow.State != widgets.StateNotMeasured || flow.Reason != widgets.ReasonNoFindings || flow.Flow != nil {
					t.Fatalf("empty flow = %+v", flow)
				}
				return
			}
			if flow.State != widgets.StateReady || flow.Flow == nil {
				t.Fatalf("flow = %+v", flow)
			}
			f := flow.Flow
			if tc.receipts {
				if f.Intake == nil || f.Intake.Totals.Received != 200 {
					t.Errorf("owner intake %+v (%s)", f.Intake, f.IntakeReason)
				}
			} else if f.Intake != nil || f.IntakeReason != widgets.ReasonOrganizationOnly {
				t.Errorf("personal intake %v (%s)", f.Intake, f.IntakeReason)
			}
			if f.FalsePositive.Value != tc.falsePositive {
				t.Errorf("false positive %d, want %d", f.FalsePositive.Value, tc.falsePositive)
			}
			for name, fig := range map[string]widgets.FlowFigure{"open": f.Open, "actionable": f.Actionable, "in progress": f.InProgress,
				"fixed": f.Fixed, "false positive": f.FalsePositive} {
				if got := e.listTotal(t, tc.user, tc.admin, strings.TrimPrefix(fig.Drill, "/findings?")); int64(got) != fig.Value {
					t.Errorf("parity %s: widget %d, list %d (%s)", name, fig.Value, got, fig.Drill)
				}
			}
			intake := byID(t, out, "w_intake")
			if tc.receipts {
				if intake.State != widgets.StateReady || intake.Intake == nil {
					t.Errorf("owner intake widget = %+v", intake)
				}
			} else if intake.State != widgets.StateNotMeasured || intake.Reason != widgets.ReasonOrganizationOnly || intake.Intake != nil {
				t.Errorf("personal intake widget = %+v", intake)
			}
		})
	}
}

// The receipt list filters refuse malformed values (never a wider list),
// and a reader without the organization view gets totals over their own
// uploads only.
func TestReceiptListFilters_DB(t *testing.T) {
	e := newFlowEnv(t)
	h := e.h
	for _, q := range []string{"origin=upload", "since=yesterday", "tool=" + strings.Repeat("x", 101)} {
		code, body := e.call(h.memberA, false, nil, http.MethodGet, "/api/v1/findings/imports?"+q, nil)
		if code != http.StatusBadRequest || !strings.Contains(body, "INVALID_FILTER") {
			t.Errorf("%s = %d %s", q, code, body)
		}
	}
	got := e.receipts(t, h.memberA, nil, "/findings/imports?origin=sensor&tool=nuclei&since="+url.QueryEscape("2000-01-01T00:00:00Z"))
	if got.Total != 0 || got.Totals.Received != 0 {
		t.Errorf("a member without the organization view sees run receipts: %+v", got)
	}
	view := append(append([]string{}, dsMemberPerms...), permission.DashboardsOrgView.String())
	got = e.receipts(t, h.memberA, view, "/findings/imports?origin=sensor&tool=nuclei")
	if got.Total != 3 || got.Totals.Received != 190 || got.Totals.Created != 27 || got.Totals.Updated != 148 || got.Totals.Reopened != 2 {
		t.Errorf("nuclei receipts %+v", got)
	}
}
