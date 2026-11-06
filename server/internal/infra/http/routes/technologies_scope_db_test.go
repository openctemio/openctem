package routes

// GET /attack-surface/technologies: a technology version counts only the
// assets the caller may see. Another tenant's technologies, technologies only
// on assets outside the caller's data scope or on deleted assets never
// appear, in the list, the counts, a search or the alert figures; a member
// with no scope row sees nothing. The CVE figures come from the software
// version the technology was matched to.

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type techRow struct {
	Key          string   `json:"key"`
	Version      string   `json:"version"`
	VersionKnown bool     `json:"version_known"`
	Vendor       string   `json:"vendor"`
	AssetCount   int      `json:"asset_count"`
	CVECount     int      `json:"cve_count"`
	TopCVE       string   `json:"top_cve"`
	TopCVSS      *float64 `json:"top_cvss"`
	KEV          bool     `json:"kev"`
	ActiveAlerts int      `json:"active_alerts"`
}

func techList(t *testing.T, body string) (int, []techRow) {
	t.Helper()
	var r struct {
		Total int       `json:"total"`
		Data  []techRow `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	return r.Total, r.Data
}

// seedTechnologies: nginx 1.18.0 on asset A (memberA's scope) and asset B
// (not), matched to a version with one known-exploited CVE whose open alert
// is on B only; "secrettech" only on B; nginx on a deleted asset and on
// another tenant's asset.
func (h *dsHarness) seedTechnologies() (cve string) {
	h.t.Helper()
	tn := h.tenant.String()
	a, b, gone := shared.NewID(), shared.NewID(), shared.NewID()
	ins := `INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'host', 'public', 'low')`
	h.exec(ins, a.String(), tn, "tech-a.dsa.example")
	h.exec(ins, b.String(), tn, "tech-b.dsb.example")
	h.exec(ins, gone.String(), tn, "tech-gone.dsa.example")
	h.exec(`UPDATE assets SET deleted_at = now() WHERE id = $1`, gone.String())
	for _, id := range []shared.ID{a, gone} {
		h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
			h.memberA.String(), tn, id.String())
	}
	now := time.Now().UTC()
	tech := `INSERT INTO asset_technologies (tenant_id, asset_id, name_key, name, version, category, source, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, 'web_server', 'httpx', $6, $6)`
	h.exec(tech, tn, a.String(), "nginx", "nginx", "1.18.0", now)
	h.exec(tech, tn, b.String(), "nginx", "nginx", "1.18.0", now)
	h.exec(tech, tn, b.String(), "secrettech", "SecretTech", "", now)
	h.exec(tech, tn, gone.String(), "nginx", "nginx", "1.18.0", now)

	// A tenant-private product and version, linked to A and B.
	var pid, vid string
	if err := h.db.QueryRow(`INSERT INTO software_products (tenant_id, part, vendor, name, source)
		VALUES ($1, 'a', 'F5', 'nginx', 'observed') RETURNING id`, tn).Scan(&pid); err != nil {
		h.t.Fatalf("product: %v", err)
	}
	if err := h.db.QueryRow(`INSERT INTO software_versions (product_id, tenant_id, raw) VALUES ($1, $2, '1.18.0') RETURNING id`,
		pid, tn).Scan(&vid); err != nil {
		h.t.Fatalf("version: %v", err)
	}
	link := `INSERT INTO asset_software (tenant_id, asset_id, product_id, software_version_id, source, confidence)
		VALUES ($1, $2, $3, $4, 'technology', 65)`
	h.exec(link, tn, a.String(), pid, vid)
	h.exec(link, tn, b.String(), pid, vid)

	cve = fmt.Sprintf("CVE-2099-%07d", rand.IntN(10_000_000)) //nolint:gosec // test id
	h.exec(`INSERT INTO cve_records (cve_id, cvss_score, severity) VALUES ($1, 9.8, 'critical')`, cve)
	h.t.Cleanup(func() {
		_, _ = h.db.Exec(`DELETE FROM kev_catalog WHERE cve_id = $1`, cve)
		_, _ = h.db.Exec(`DELETE FROM cve_records WHERE cve_id = $1`, cve)
	})
	h.exec(`INSERT INTO kev_catalog (cve_id, vulnerability_name, date_added) VALUES ($1, 'test', now())`, cve)
	h.exec(`INSERT INTO software_version_vulns (software_version_id, cve_id) VALUES ($1, $2)`, vid, cve)
	var alert string
	if err := h.db.QueryRow(`INSERT INTO threat_alerts (tenant_id, vuln_id, level, tier, ets)
		VALUES ($1, $2, 'immediate', 'confirmed', 90) RETURNING id`, tn, cve).Scan(&alert); err != nil {
		h.t.Fatalf("alert: %v", err)
	}
	h.exec(`INSERT INTO threat_alert_assets (tenant_id, alert_id, asset_id, match_kind) VALUES ($1, $2, $3, 'confirmed')`,
		tn, alert, b.String())

	other := shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "tech-other-"+other.String())
	h.t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM tenants WHERE id = $1`, other.String()) })
	oa := shared.NewID()
	h.exec(ins, oa.String(), other.String(), "tech-other.example")
	h.exec(tech, other.String(), oa.String(), "othertenanttech", "OtherTenantTech", "2.0", now)
	h.exec(tech, other.String(), oa.String(), "nginx", "nginx", "1.18.0", now)
	return cve
}

func TestTechnologies_DataScopeAndTenant_DB(t *testing.T) {
	h := newDSHarness(t)
	cve := h.seedTechnologies()
	const list = "/api/v1/attack-surface/technologies"

	// The scoped member sees nginx on its one visible asset, with the CVE
	// figures of the matched version, but not the alert, which is on an
	// asset outside its scope; never SecretTech nor another tenant's names.
	st, body := h.do(h.memberA, false, http.MethodGet, list, nil)
	total, rows := techList(t, body)
	if st != http.StatusOK || total != 1 || len(rows) != 1 || strings.Contains(body, "ecret") || strings.Contains(body, "OtherTenant") {
		t.Fatalf("memberA list = %d %s", st, body)
	}
	r := rows[0]
	if r.Key != "nginx" || r.Version != "1.18.0" || !r.VersionKnown || r.AssetCount != 1 || r.CVECount != 1 || r.TopCVE != cve ||
		r.TopCVSS == nil || *r.TopCVSS != 9.8 || !r.KEV || r.Vendor != "F5" || r.ActiveAlerts != 0 {
		t.Fatalf("memberA nginx row = %+v", r)
	}
	st, body = h.do(h.memberA, false, http.MethodGet, list+"/stats", nil)
	if st != http.StatusOK || !strings.Contains(body, `"total":1`) || !strings.Contains(body, `"with_cves":1`) ||
		!strings.Contains(body, `"with_alerts":0`) || !strings.Contains(body, `"unknown_version":0`) {
		t.Fatalf("memberA stats = %d %s", st, body)
	}
	for _, q := range []string{"?q=Secret", "?name=secrettech", "?name_contains=secret", "?version_known=false"} {
		if st, body := h.do(h.memberA, false, http.MethodGet, list+q, nil); st != http.StatusOK || strings.Contains(body, "ecret") {
			t.Errorf("memberA %s = %d %s", q, st, body)
		} else if n, _ := techList(t, body); n != 0 {
			t.Errorf("memberA %s total = %d, want 0", q, n)
		}
	}
	// A member with no scope row sees nothing.
	if st, body := h.do(h.memberStrict, false, http.MethodGet, list, nil); st != http.StatusOK {
		t.Errorf("member without scope list = %d %s", st, body)
	} else if n, _ := techList(t, body); n != 0 {
		t.Errorf("member without scope total = %d", n)
	}
	if st, body := h.do(h.memberStrict, false, http.MethodGet, list+"/stats", nil); st != http.StatusOK || !strings.Contains(body, `"total":0`) {
		t.Errorf("member without scope stats = %d %s", st, body)
	}

	// The owner sees both of the tenant's technologies, nginx on two live
	// assets with its alert, never the deleted asset or the other tenant.
	st, body = h.do(h.owner, true, http.MethodGet, list, nil)
	total, rows = techList(t, body)
	if st != http.StatusOK || total != 2 || strings.Contains(body, "OtherTenant") || rows[0].Key != "nginx" ||
		rows[0].AssetCount != 2 || rows[0].ActiveAlerts != 1 {
		t.Fatalf("owner list = %d %s", st, body)
	}
	if st, body := h.do(h.owner, true, http.MethodGet, list+"/stats", nil); st != http.StatusOK ||
		!strings.Contains(body, `"total":2`) || !strings.Contains(body, `"with_cves":1`) || !strings.Contains(body, `"kev":1`) ||
		!strings.Contains(body, `"unknown_version":1`) || !strings.Contains(body, `"with_alerts":1`) {
		t.Errorf("owner stats = %d %s", st, body)
	}
	for q, want := range map[string]int{
		"?version_known=false": 1, "?has_cves=true": 1, "?has_cves=false": 1, "?kev=true": 1,
		"?category=web_server": 2, "?vendor=F5": 1, "?source=httpx": 2, "?sort=-cve_count": 2, "?sort=top_cvss,name": 2,
	} {
		st, body := h.do(h.owner, true, http.MethodGet, list+q, nil)
		if n, _ := techList(t, body); st != http.StatusOK || n != want {
			t.Errorf("owner %s = %d total %d, want %d (%s)", q, st, n, want, body)
		}
	}
	if st, _ := h.do(h.owner, true, http.MethodGet, list+"?nonsense=1", nil); st != http.StatusBadRequest {
		t.Errorf("unknown param = %d, want 400", st)
	}
	if st, _ := h.do(h.owner, true, http.MethodGet, list+"?asset_count=3", nil); st != http.StatusBadRequest {
		t.Errorf("filter on a sort-only key = %d, want 400", st)
	}

	// A row drills down to the assets that run that exact version (an
	// empty version is the unknown one), within the caller's data scope.
	for _, c := range []struct {
		user  shared.ID
		admin bool
		query string
		want  int
	}{
		{h.owner, true, "technology=nginx&technology_version=1.18.0", 2},
		{h.owner, true, "technology=nginx&technology_version=9.9", 0},
		{h.owner, true, "technology=secrettech&technology_version=", 1},
		{h.owner, true, "technology=nginx&technology_version=", 0},
		{h.memberA, false, "technology=nginx&technology_version=1.18.0", 1},
		{h.memberA, false, "technology=secrettech&technology_version=", 0},
	} {
		st, body := h.do(c.user, c.admin, http.MethodGet, "/api/v1/assets?"+c.query, nil)
		if n, _ := techList(t, body); st != http.StatusOK || n != c.want {
			t.Errorf("assets?%s = %d total %d, want %d", c.query, st, n, c.want)
		}
	}
}
