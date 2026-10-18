package routes

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The dashboard's threat intel, validation, scan coverage, CTEM cycle and
// attack-path figures follow the viewer (owner decision D6) like the rest of
// the dashboard: a restricted member counts their own scope, a viewer holding
// dashboard:aggregate gets organization totals, an owner is unchanged, and
// another tenant's rows are never counted.
//
// memberA is restricted to asset A1. The organization has two findings
// (A on A1, B on B1) that share a known-exploited CVE with a high EPSS score,
// validation evidence for B only, two hosts (one in scope), an internal crown
// jewel C reachable from the public asset B1, and a second tenant holding one
// of everything.
func TestDashboardSummaries_FollowTheViewer_DB(t *testing.T) {
	h := newDSHarness(t)
	tenant, other := h.tenant.String(), shared.NewID().String()
	cve := "CVE-2099-" + h.tenant.String()[:8]
	hostA, hostB, jewel := shared.NewID().String(), shared.NewID().String(), shared.NewID().String()

	h.exec(`INSERT INTO kev_catalog (cve_id, vulnerability_name, date_added, due_date) VALUES ($1, 'wp4', CURRENT_DATE - 60, CURRENT_DATE - 30)`, cve)
	h.exec(`INSERT INTO epss_scores (cve_id, epss_score, score_date) VALUES ($1, 0.9, CURRENT_DATE)`, cve)
	t.Cleanup(func() {
		_, _ = h.db.Exec(`DELETE FROM kev_catalog WHERE cve_id = $1`, cve)
		_, _ = h.db.Exec(`DELETE FROM epss_scores WHERE cve_id = $1`, cve)
	})
	h.exec(`UPDATE findings SET cve_id = $1 WHERE tenant_id = $2`, cve, tenant)
	h.exec(`INSERT INTO validation_evidence (tenant_id, finding_id, executor_kind, outcome) VALUES ($1, $2, 'manual', 'detected')`, tenant, h.findingB.String())
	for id, name := range map[string]string{hostA: "wp4-host-a", hostB: "wp4-host-b"} {
		h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'host', 'private', 'critical')`, id, tenant, name)
	}
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`, h.memberA.String(), tenant, hostA)
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality, is_crown_jewel) VALUES ($1, $2, 'wp4-jewel', 'database', 'private', 'critical', TRUE)`, jewel, tenant)
	h.exec(`INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type) VALUES ($1, $2, $3, 'exposes')`, tenant, h.assetB.String(), jewel)

	// Another tenant: the same shapes, never counted for this one.
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other, "ds-other-"+other)
	t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM tenants WHERE id = $1`, other) })
	otherAsset, otherFinding := shared.NewID().String(), shared.NewID().String()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality, is_crown_jewel) VALUES ($1, $2, 'other-host', 'host', 'public', 'critical', TRUE)`, otherAsset, other)
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, cve_id)
		VALUES ($1::uuid, $2, $3, 'sast', 'ds-tool', 'other tenant', 'high', $1::text, 'confirmed', $4)`, otherFinding, other, otherAsset, cve)
	h.exec(`INSERT INTO validation_evidence (tenant_id, finding_id, executor_kind, outcome) VALUES ($1, $2, 'manual', 'detected')`, other, otherFinding)

	aggPerms := append(append([]string{}, dsMemberPerms...), permission.DashboardAggregate.String())
	get := func(who, path string) (int, string) {
		switch who {
		case "member":
			return h.do(h.memberA, false, http.MethodGet, path, nil)
		case "aggregate":
			return h.doWithPerms(h.memberA, aggPerms, http.MethodGet, path, nil)
		default:
			return h.do(h.owner, true, http.MethodGet, path, nil)
		}
	}
	decode := func(who, path string, into any) {
		t.Helper()
		status, body := get(who, path)
		if status != http.StatusOK {
			t.Fatalf("%s as %s = %d %.200s", path, who, status, body)
		}
		if err := json.Unmarshal([]byte(body), into); err != nil {
			t.Fatalf("%s: %v (%.200s)", path, err, body)
		}
	}
	// What each viewer may count: the member their own scope, the others the
	// organization (two findings, two hosts, two entry points, one jewel).
	for who, org := range map[string]bool{"member": false, "aggregate": true, "owner": true} {
		n := map[bool]int{false: 1, true: 2}[org]

		var ti struct {
			EPSS struct {
				High     int `json:"high_risk_count"`
				Critical int `json:"critical_risk_count"`
			} `json:"epss"`
			KEV struct {
				PastDue int `json:"past_due_count"`
			} `json:"kev"`
		}
		decode(who, "/api/v1/threat-intel/stats", &ti)
		if ti.EPSS.High != n || ti.EPSS.Critical != n || ti.KEV.PastDue != n {
			t.Errorf("threat intel as %s = %+v, want %d open findings", who, ti, n)
		}

		var val struct {
			Total     int `json:"total"`
			Validated int `json:"validated"`
			Downgrade int `json:"downgrade_validated"`
		}
		decode(who, "/api/v1/validation/coverage", &val)
		if wantVal := map[bool]int{false: 0, true: 1}[org]; val.Total != n || val.Validated != wantVal || val.Downgrade != wantVal {
			t.Errorf("validation coverage as %s = %+v, want total %d validated %d", who, val, n, wantVal)
		}

		var sc struct {
			Total int `json:"total_scannable"`
		}
		decode(who, "/api/v1/scans/coverage", &sc)
		if sc.Total != n {
			t.Errorf("scan coverage as %s = %+v, want %d hosts", who, sc, n)
		}

		var ap struct {
			Summary struct {
				Entry     int  `json:"entry_points"`
				Reachable int  `json:"reachable_assets"`
				Jewels    int  `json:"crown_jewels_at_risk"`
				Critical  int  `json:"critical_reachable"`
				Paths     int  `json:"total_paths"`
				HasRel    bool `json:"has_relationship_data"`
			} `json:"summary"`
			Top []struct {
				AssetID string `json:"asset_id"`
			} `json:"top_assets"`
		}
		decode(who, "/api/v1/attack-surface/attack-paths", &ap)
		wantJewel := map[bool]int{false: 0, true: 1}[org]
		if ap.Summary.Entry != n || ap.Summary.Reachable != wantJewel || ap.Summary.Jewels != wantJewel ||
			ap.Summary.Critical != wantJewel || ap.Summary.Paths != wantJewel || ap.Summary.HasRel != org {
			t.Errorf("attack path summary as %s = %+v, want %d entry points, %d reachable", who, ap.Summary, n, wantJewel)
		}
		for _, a := range ap.Top {
			if !org && a.AssetID != h.assetA.String() && a.AssetID != hostA {
				t.Errorf("attack paths as %s list an asset outside their scope: %s", who, a.AssetID)
			}
		}

		// Cycle metrics are organization-wide: refused for a member.
		status, body := get(who, "/api/v1/ctem-cycles/metrics/trend")
		if want := map[bool]int{false: http.StatusForbidden, true: http.StatusOK}[org]; status != want {
			t.Errorf("ctem cycle metrics trend as %s = %d %.200s, want %d", who, status, body, want)
		}
		// The per-cycle metrics are the same organization-wide figures: the
		// same refusal, before the cycle is even looked up (an unknown cycle
		// is a 404 only for a caller who may read them).
		status, body = get(who, "/api/v1/ctem-cycles/"+shared.NewID().String()+"/metrics")
		if want := map[bool]int{false: http.StatusForbidden, true: http.StatusNotFound}[org]; status != want {
			t.Errorf("ctem cycle metrics as %s = %d %.200s, want %d", who, status, body, want)
		}
	}
}
