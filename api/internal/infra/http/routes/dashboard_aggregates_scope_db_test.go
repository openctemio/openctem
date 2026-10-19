package routes

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// Every dashboard figure follows the viewer (owner decision D6), not only
// /dashboard/stats: weekly velocity, the executive summary totals and the data
// quality scorecard count a restricted member's own scope; the figures kept
// for the whole organization (risk trend history, program metrics) are not
// shown to them without dashboards:org:view. memberA is restricted to asset
// A1; the organization has two assets and two findings.
func TestDashboardAggregates_FollowTheViewer_DB(t *testing.T) {
	h := newDSHarness(t)
	h.exec(`INSERT INTO risk_snapshots (tenant_id, snapshot_date, risk_score_avg, findings_open) VALUES ($1, CURRENT_DATE, 42, 2)`, h.tenant.String())
	t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM risk_snapshots WHERE tenant_id = $1`, h.tenant.String()) })
	aggPerms := append(append([]string{}, dsMemberPerms...), permission.DashboardsOrgView.String())

	get := func(who string, path string) (int, string) {
		switch who {
		case "member":
			return h.do(h.memberA, false, http.MethodGet, path, nil)
		case "aggregate":
			return h.doWithPerms(h.memberA, aggPerms, http.MethodGet, path, nil)
		default: // the owner
			return h.do(h.owner, true, http.MethodGet, path, nil)
		}
	}
	decode := func(path, who string, into any) {
		t.Helper()
		status, body := get(who, path)
		if status != http.StatusOK {
			t.Fatalf("%s as %s = %d %.200s", path, who, status, body)
		}
		if err := json.Unmarshal([]byte(body), into); err != nil {
			t.Fatalf("%s: %v (%.200s)", path, err, body)
		}
	}
	want := map[string]int{"member": 1, "aggregate": 2, "owner": 2}

	for who, n := range want {
		var pts []struct {
			NewCount int `json:"new_count"`
		}
		decode("/api/v1/dashboard/velocity?weeks=1", who, &pts)
		sum := 0
		for _, p := range pts {
			sum += p.NewCount
		}
		if sum != n {
			t.Errorf("velocity new_count as %s = %d, want %d", who, sum, n)
		}

		var ex struct {
			Total int `json:"findings_total"`
			New   int `json:"findings_new_period"`
		}
		decode("/api/v1/dashboard/executive-summary?days=30", who, &ex)
		if ex.Total != n || ex.New != n {
			t.Errorf("executive summary as %s = %+v, want %d findings", who, ex, n)
		}

		var dq struct {
			Assets   int `json:"total_assets"`
			Findings int `json:"total_findings"`
		}
		decode("/api/v1/dashboard/data-quality", who, &dq)
		if dq.Assets != n || dq.Findings != n {
			t.Errorf("data quality as %s = %+v, want %d assets and findings", who, dq, n)
		}

		var trend []struct {
			Open int `json:"findings_open"`
		}
		decode("/api/v1/dashboard/risk-trend?days=7", who, &trend)
		if (who == "member") != (len(trend) == 0) {
			t.Errorf("risk trend as %s has %d points: organization history must reach only unrestricted or aggregate viewers", who, len(trend))
		}

		status, body := get(who, "/api/v1/dashboard/program-metrics")
		if wantStatus := map[bool]int{true: http.StatusForbidden, false: http.StatusOK}[who == "member"]; status != wantStatus {
			t.Errorf("program metrics as %s = %d %.200s, want %d", who, status, body, wantStatus)
		}
		// The refusal names the grant, so the web shows "no access" with who
		// can grant it rather than "module not enabled" or a raw error.
		if who == "member" && (!strings.Contains(body, `"any_of"`) || !strings.Contains(body, "dashboards:org:view")) {
			t.Errorf("program metrics refusal does not name the grant: %.300s", body)
		}
		if status, body := get(who, "/api/v1/dashboard/process-metrics"); status != http.StatusOK {
			t.Errorf("process metrics as %s = %d %.200s", who, status, body)
		}
	}

	// The executive summary's top risks hold only in-scope findings, the
	// export renders the same numbers.
	var ex struct {
		Top []struct {
			AssetID string `json:"asset_id"`
		} `json:"top_risks"`
	}
	decode("/api/v1/dashboard/executive-summary?days=30", "member", &ex)
	for _, r := range ex.Top {
		if r.AssetID != h.assetA.String() {
			t.Errorf("a top risk on an asset outside the member's scope: %s", r.AssetID)
		}
	}
}
