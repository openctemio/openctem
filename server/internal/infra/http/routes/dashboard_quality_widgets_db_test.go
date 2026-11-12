package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/dashboard/widgets"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const (
	qualityMarkerOther    = "quality-other-tenant-campaign"
	qualityMarkerDraft    = "quality-draft-campaign"
	qualityMarkerHiddenCo = "quality-campaign-b"
)

var qualityLayout = []any{
	metricWidget("w_close", "findings.closure_quality", map[string]any{"time": map[string]any{"range": "7d", "compare": "previous_period"}}),
	metricWidget("w_camp", "remediation.campaign_progress", nil),
	metricWidget("w_fp", "detection.fp_rate_by_tool", map[string]any{"time": map[string]any{"range": "30d"}}),
}

// qualityFinding inserts a finding of the tenant on the asset with the
// given status and extra columns (resolved_at, resolved_by,
// last_reopened_at as SQL expressions).
func qualityFinding(h *dsHarness, tenant, asset shared.ID, tool, status, resolvedAt, resolvedBy, reopenedAt string) shared.ID {
	id := shared.NewID()
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, resolved_at, resolved_by, last_reopened_at)
		VALUES ($1::uuid, $2, $3, 'sast', $4, 'quality', 'high', $1::text, $5,
			now() - NULLIF($6, '')::interval, NULLIF($7, '')::uuid, now() - NULLIF($8, '')::interval)`,
		id.String(), tenant.String(), asset.String(), tool, status, resolvedAt, resolvedBy, reopenedAt)
	return id
}

// newQualityEnv extends the widget fixture with closes, reopens, Ready to
// close proposals and remediation campaigns, in memberA's scope (A1), out
// of it (B1) and in another tenant.
func newQualityEnv(t *testing.T) *widgetEnv {
	t.Helper()
	e := newWidgetEnv(t)
	h := e.h
	ten := h.tenant
	owner := h.owner.String()

	// Closes in the window: A1 one by a person and one automatic; B1 one
	// automatic. One fixed finding on A1 came back. One close before the
	// window (previous period) on A1.
	qualityFinding(h, ten, h.assetA, "cq", "resolved", "1 day", owner, "")
	qualityFinding(h, ten, h.assetA, "cq", "resolved", "2 days", "", "")
	qualityFinding(h, ten, h.assetB, "cq", "resolved", "2 days", "", "")
	qualityFinding(h, ten, h.assetA, "cq", "confirmed", "", "", "1 day")
	qualityFinding(h, ten, h.assetA, "cq", "resolved", "9 days", owner, "")

	// Ready to close: a pending proposal on each harness finding.
	for _, f := range []shared.ID{h.findingA, h.findingB} {
		h.exec(`INSERT INTO finding_closure_proposals (tenant_id, finding_id, method, evidence_at) VALUES ($1, $2, 'covered_scan', now() + interval '1 day')`,
			ten.String(), f.String())
	}

	// Another tenant: an automatic close, a proposal and an active campaign.
	otherAsset := shared.NewID()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'quality-other', 'domain')`, otherAsset.String(), e.otherTenant.String())
	of := qualityFinding(h, e.otherTenant, otherAsset, "cq", "resolved", "1 day", "", "")
	open := qualityFinding(h, e.otherTenant, otherAsset, "cq", "confirmed", "", "", "")
	h.exec(`INSERT INTO finding_closure_proposals (tenant_id, finding_id, method, evidence_at) VALUES ($1, $2, 'covered_scan', now() + interval '1 day')`,
		e.otherTenant.String(), open.String())
	_ = of

	// Campaigns. C1 (active): a done task on A1 and an overdue open task on
	// B1. C2 (active, owned by memberA): an open task on B1. C3 is a draft.
	task := func(tenant, campaign shared.ID, state, deadline string, finding shared.ID) {
		id := shared.NewID().String()
		h.exec(`INSERT INTO remediation_actions (id, tenant_id, action_key, kind, title, origin)
			VALUES ($1::uuid, $2, 'manual:'||$1::text, 'manual', 'quality task', 'manual')`, id, tenant.String())
		h.exec(`INSERT INTO remediation_tasks (id, tenant_id, action_id, campaign_id, title, member_count, open_count)
			VALUES ($1, $2, $1, $3, 'quality task', 1, 1)`, id, tenant.String(), campaign.String())
		h.exec(`INSERT INTO remediation_task_members (tenant_id, task_id, finding_id, role, join_source)
			VALUES ($1, $2, $3, 'primary', 'manual')`, tenant.String(), id, finding.String())
		h.exec(`UPDATE remediation_tasks SET state = $3, deadline = now() - NULLIF($4, '')::interval,
			deadline_source = CASE WHEN $4 = '' THEN deadline_source ELSE 'manual' END WHERE tenant_id = $1 AND id = $2`,
			tenant.String(), id, state, deadline)
	}
	campaign := func(tenant shared.ID, name, status string, assignee any) shared.ID {
		id := shared.NewID()
		h.exec(`INSERT INTO remediation_campaigns (id, tenant_id, name, status, assigned_to) VALUES ($1, $2, $3, $4, $5)`,
			id.String(), tenant.String(), name, status, assignee)
		return id
	}
	c1 := campaign(ten, "quality-campaign-a", "active", nil)
	task(ten, c1, "done", "", qualityFinding(h, ten, h.assetA, "cq", "confirmed", "", "", ""))
	task(ten, c1, "open", "2 days", qualityFinding(h, ten, h.assetB, "cq", "confirmed", "", "", ""))
	c2 := campaign(ten, qualityMarkerHiddenCo, "active", h.memberA.String())
	task(ten, c2, "open", "", qualityFinding(h, ten, h.assetB, "cq", "confirmed", "", "", ""))
	c3 := campaign(ten, qualityMarkerDraft, "draft", nil)
	task(ten, c3, "open", "", qualityFinding(h, ten, h.assetA, "cq", "confirmed", "", "", ""))
	oc := campaign(e.otherTenant, qualityMarkerOther, "active", nil)
	task(e.otherTenant, oc, "open", "", qualityFinding(h, e.otherTenant, otherAsset, "cq", "confirmed", "", "", ""))
	return e
}

func campaignRows(t *testing.T, w widgets.WidgetValue) []widgets.CategoryRow {
	t.Helper()
	if w.State != widgets.StateReady || w.Category == nil {
		t.Fatalf("%s = %s %s", w.ID, w.State, w.Reason)
	}
	return w.Category.Rows
}

// Closure quality and campaign progress count each viewer's own scope: the
// fixes and reopens equal the findings list each row opens, Ready to close
// equals the Ready to close count for the same scope, campaigns follow the
// campaign list's visibility, and another tenant never counts or shows.
func TestDashboardQualityWidgets_ScopeAndParity_DB(t *testing.T) {
	e := newQualityEnv(t)
	h := e.h
	findings := postgres.NewFindingRepository(&postgres.DB{DB: h.db})
	perms := append(append([]string{}, dsMemberPerms...), permission.RemediationRead.String())
	for _, tc := range []struct {
		name                        string
		user                        shared.ID
		admin                       bool
		scope                       *shared.DataScope
		measured                    bool
		person, auto, reopen, ready float64
		prevPerson                  float64
		campaigns                   []string
		shares                      []float64
	}{
		{"scoped member", h.memberA, false, &shared.DataScope{TenantID: h.tenant, UserID: h.memberA}, true, 1, 1, 1, 1, 1,
			// C2 is memberA's own campaign: counted whole (0 of 1 done);
			// of C1 only the task on A1 is visible (done).
			[]string{qualityMarkerHiddenCo, "quality-campaign-a"}, []float64{0, 100}},
		{"member without scope rows", h.memberFree, false, &shared.DataScope{TenantID: h.tenant, UserID: h.memberFree}, false, 0, 0, 0, 0, 0, nil, nil},
		// The owner: C1 has the overdue task, so it comes first (1 of 2 done).
		{"administrator", h.owner, true, nil, true, 1, 2, 1, 2, 1,
			[]string{"quality-campaign-a", qualityMarkerHiddenCo}, []float64{50, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := e.createPersonal(t, tc.user, tc.admin, qualityLayout)
			code, raw := e.call(tc.user, tc.admin, perms, http.MethodGet, "/api/v1/me/dashboards/"+id+"/data", nil)
			if code != http.StatusOK {
				t.Fatalf("data = %d %s", code, raw)
			}
			for _, m := range []string{qualityMarkerOther, qualityMarkerDraft} {
				if strings.Contains(raw, m) {
					t.Errorf("quality widgets show %q", m)
				}
			}
			out := e.data(t, tc.user, tc.admin, perms, "/api/v1/me/dashboards/"+id+"/data")

			// The false-positive rate is an organization figure: a member's
			// personal read is not measured. The owner's data scope is the
			// whole organization, so it is read (no tool reaches the minimum
			// here).
			want := widgets.ReasonOrganizationOnly
			if tc.admin {
				want = widgets.ReasonTooFewClosed
			}
			if fp := byID(t, out, "w_fp"); fp.State != widgets.StateNotMeasured || fp.Reason != want || fp.Category != nil {
				t.Errorf("personal false-positive rate = %s %s", fp.State, fp.Reason)
			}

			cl := byID(t, out, "w_close")
			if !tc.measured {
				if cl.State != widgets.StateNotMeasured || cl.Reason != widgets.ReasonNoClosures {
					t.Errorf("nothing in scope = %+v", cl)
				}
			} else {
				rows := category(t, cl)
				if rows[widgets.ClosureByPerson].Value != tc.person || rows[widgets.ClosureAutomatic].Value != tc.auto ||
					rows[widgets.ClosureReopened].Value != tc.reopen || rows[widgets.ClosureReadyToClose].Value != tc.ready {
					t.Errorf("closure rows %+v", rows)
				}
				if p := rows[widgets.ClosureByPerson].Previous; p == nil || *p != tc.prevPerson {
					t.Errorf("previous by person %v", p)
				}
				for _, k := range []string{widgets.ClosureByPerson, widgets.ClosureAutomatic, widgets.ClosureReopened} {
					r := rows[k]
					if got := e.listTotal(t, tc.user, tc.admin, strings.TrimPrefix(r.Drill, "/findings?")); float64(got) != r.Value {
						t.Errorf("parity %s: widget %v, findings list %d (%s)", k, r.Value, got, r.Drill)
					}
				}
				n, err := findings.CountClosureProposals(context.Background(), h.tenant, tc.scope)
				if err != nil {
					t.Fatal(err)
				}
				if float64(n) != rows[widgets.ClosureReadyToClose].Value {
					t.Errorf("ready to close: widget %v, list %d", rows[widgets.ClosureReadyToClose].Value, n)
				}
			}

			camp := byID(t, out, "w_camp")
			if tc.campaigns == nil {
				if camp.State != widgets.StateNotMeasured || camp.Reason != widgets.ReasonNoActiveCampaigns {
					t.Errorf("no campaign = %+v", camp)
				}
				return
			}
			rows := campaignRows(t, camp)
			if len(rows) != len(tc.campaigns) {
				t.Fatalf("campaign rows %+v", rows)
			}
			for i, r := range rows {
				if r.Label != tc.campaigns[i] || r.Value != tc.shares[i] || r.Drill != "/remediation/campaigns/"+r.Key {
					t.Errorf("campaign %d = %+v", i, r)
				}
			}

			// Losing findings:remediation:read masks the stored campaign
			// figures; the closure figures stay.
			again := e.data(t, tc.user, tc.admin, dsMemberPerms, "/api/v1/me/dashboards/"+id+"/data")
			if !tc.admin {
				if w := byID(t, again, "w_camp"); w.State != widgets.StateUnsupported || w.Reason != widgets.ReasonForbidden || w.Category != nil {
					t.Errorf("campaigns after losing the permission = %+v", w)
				}
				if w := byID(t, again, "w_close"); w.Category == nil {
					t.Errorf("closure masked with findings:read: %+v", w)
				}
			}
		})
	}
}

// The false-positive rate by tool reads the whole organization on an
// organization dashboard (the same figures for every viewer), leaves out a
// tool under the minimum, never counts another tenant, and each rate is the
// false-positive list over the closed list of that tool.
func TestDashboardQualityWidgets_FalsePositiveRate_DB(t *testing.T) {
	e := newWidgetEnv(t)
	h := e.h
	for i := 0; i < 20; i++ {
		status := "resolved"
		if i < 5 {
			status = "false_positive"
		}
		asset := h.assetA
		if i%2 == 1 {
			asset = h.assetB
		}
		qualityFinding(h, h.tenant, asset, "fp-tool", status, "3 days", "", "")
	}
	for i := 0; i < 3; i++ {
		qualityFinding(h, h.tenant, h.assetA, "tiny-tool", "false_positive", "3 days", "", "")
	}
	otherAsset := shared.NewID()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'fp-other', 'domain')`, otherAsset.String(), e.otherTenant.String())
	for i := 0; i < 25; i++ {
		qualityFinding(h, e.otherTenant, otherAsset, "fp-tool", "false_positive", "3 days", "", "")
	}

	code, body := e.call(h.owner, true, nil, http.MethodPost, "/api/v1/organization/dashboards", map[string]any{"name": "Quality", "layout": qualityLayout})
	if code != http.StatusCreated {
		t.Fatalf("create org = %d %s", code, body)
	}
	var org struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(body), &org)
	path := "/api/v1/organization/dashboards/" + org.ID + "/data"
	view := append(append([]string{}, dsMemberPerms...), permission.DashboardsOrgView.String())
	for _, viewer := range []struct {
		user  shared.ID
		admin bool
	}{{h.owner, true}, {h.memberA, false}} {
		fp := byID(t, e.data(t, viewer.user, viewer.admin, view, path), "w_fp")
		if fp.State != widgets.StateReady || fp.Category == nil || len(fp.Category.Rows) != 1 {
			t.Fatalf("false-positive rate = %+v", fp)
		}
		r := fp.Category.Rows[0]
		if r.Key != "fp-tool" || r.Value != 25 || r.N == nil || *r.N != 20 {
			t.Errorf("fp-tool row %+v", r)
		}
	}
	// Parity, read as the owner (who sees the whole organization's list).
	fp := byID(t, e.data(t, h.owner, true, view, path), "w_fp")
	r := fp.Category.Rows[0]
	fps := e.listTotal(t, h.owner, true, strings.TrimPrefix(r.Drill, "/findings?"))
	closed := e.listTotal(t, h.owner, true, strings.Replace(strings.TrimPrefix(r.Drill, "/findings?"), "status=false_positive", "state=closed", 1))
	if fps != 5 || closed != 20 || float64(fps)*100/float64(closed) != r.Value {
		t.Errorf("parity: widget %v, false positives %d of %d closed (%s)", r.Value, fps, closed, r.Drill)
	}
}
