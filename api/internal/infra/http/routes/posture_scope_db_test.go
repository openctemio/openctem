package routes

// GET /attack-surface/posture: the score sums only the surface assets the
// caller may see. Another tenant's issues, issues on deleted or rejected
// assets and, for a scoped member, issues on assets outside the scope and
// issues without an asset never count; a member with no scope row has no
// grade. Recalculate now rebuilds the facts once per five minutes.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type postureBody struct {
	State struct {
		Building     bool   `json:"building"`
		RefreshEvery string `json:"refresh_every"`
	} `json:"state"`
	Scoped bool `json:"scoped"`
	Score  struct {
		Measured   bool   `json:"measured"`
		Score      int    `json:"score"`
		Grade      string `json:"grade"`
		Assets     int64  `json:"assets"`
		Categories []struct {
			Category string `json:"category"`
			Issues   int64  `json:"issues"`
		} `json:"categories"`
	} `json:"score"`
	PreviousScore *int `json:"previous_score"`
	Plan          struct {
		Steps []struct {
			AssetName string `json:"asset_name"`
		} `json:"steps"`
	} `json:"plan"`
	Reductions []struct {
		Criticality string `json:"criticality"`
		Issues      int64  `json:"issues"`
	} `json:"reductions"`
	Roots []struct {
		RootDomain string `json:"root_domain"`
		Assets     int64  `json:"assets"`
	} `json:"roots"`
}

func decodePosture(t *testing.T, body string) postureBody {
	t.Helper()
	var p postureBody
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	return p
}

func (p postureBody) issues(cat string) int64 {
	for _, c := range p.Score.Categories {
		if c.Category == cat {
			return c.Issues
		}
	}
	return -1
}

func (p postureBody) roots() map[string]int64 {
	out := map[string]int64{}
	for _, r := range p.Roots {
		out[r.RootDomain] = r.Assets
	}
	return out
}

// seedPosture adds, besides the harness's two domains (each with a high
// finding and an open port; A in memberA's scope):
//   - www.example.org (critical, in memberA's scope) with a confirmed takeover;
//   - api.example.net (medium, out of scope) with a public bucket;
//   - a leaked credential with no asset;
//   - a deleted and a rejected asset with issues, and another tenant's.
func (h *dsHarness) seedPosture() {
	h.t.Helper()
	tn := h.tenant.String()
	pa, pb, gone, rej := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	ins := `INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'subdomain', 'public', $4)`
	h.exec(ins, pa.String(), tn, "www.example.org", "critical")
	h.exec(ins, pb.String(), tn, "api.example.net", "medium")
	h.exec(ins, gone.String(), tn, "gone.example.org", "high")
	h.exec(ins, rej.String(), tn, "notours.example.org", "high")
	h.exec(`UPDATE assets SET deleted_at = now() WHERE id = $1`, gone.String())
	h.exec(`INSERT INTO asset_attributions (tenant_id, asset_id, state, confidence, reason) VALUES ($1, $2, 'rejected', 0, 'manual')`,
		tn, rej.String())
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		h.memberA.String(), tn, pa.String())
	ev := `INSERT INTO exposure_events (tenant_id, asset_id, event_type, title, fingerprint, source, severity, state)
		VALUES ($1, $2, $3, 'posture test', gen_random_uuid()::text, 'posture-test', $4, 'active')`
	h.exec(ev, tn, pa.String(), "subdomain_takeover", "critical")
	h.exec(ev, tn, pa.String(), "dangling_cname", "high") // same asset: one hijackable issue
	h.exec(ev, tn, pb.String(), "bucket_public", "high")
	h.exec(ev, tn, nil, "credential_leaked", "high")
	h.exec(ev, tn, gone.String(), "bucket_public", "critical")
	h.exec(ev, tn, rej.String(), "bucket_public", "critical")
	// A projection of a finding never counts twice.
	h.exec(`INSERT INTO exposure_events (tenant_id, asset_id, event_type, title, fingerprint, source, severity, state)
		VALUES ($1, $2, 'credential_leaked', 'bridged', gen_random_uuid()::text, 'secret_scan', 'critical', 'active')`, tn, h.assetA.String())
	for _, a := range []shared.ID{h.assetA, h.assetB} {
		h.exec(`SELECT dash_recompute_asset($1, $2)`, tn, a.String())
	}

	other := shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "posture-other-"+other.String())
	h.t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM tenants WHERE id = $1`, other.String()) })
	oa := shared.NewID()
	h.exec(ins, oa.String(), other.String(), "other.example.edu", "critical")
	h.exec(ev, other.String(), oa.String(), "bucket_public", "critical")
}

func TestPosture_DataScopeAndTenant_DB(t *testing.T) {
	h := newDSHarness(t)
	h.seedPosture()
	const path = "/api/v1/attack-surface/posture"

	// Before the first computation the state says it is building.
	st, body := h.do(h.owner, true, http.MethodGet, path, nil)
	if p := decodePosture(t, body); st != http.StatusOK || !p.State.Building || p.Score.Measured || p.State.RefreshEvery != "6h" {
		t.Fatalf("owner before compute = %d %s", st, body)
	}
	if st, body := h.do(h.owner, true, http.MethodPost, path+"/refresh", nil); st != http.StatusOK {
		t.Fatalf("recalculate = %d %s", st, body)
	}
	if st, _ := h.do(h.owner, true, http.MethodPost, path+"/refresh", nil); st != http.StatusTooManyRequests {
		t.Fatalf("second recalculate = %d, want 429", st)
	}

	// The owner: four live surface assets, every category of this tenant,
	// the issue without an asset, never the deleted, rejected or other
	// tenant's assets.
	st, body = h.do(h.owner, true, http.MethodGet, path, nil)
	p := decodePosture(t, body)
	if st != http.StatusOK || p.Scoped || !p.Score.Measured || p.Score.Assets != 4 {
		t.Fatalf("owner = %d %s", st, body)
	}
	for cat, want := range map[string]int64{"vulnerabilities": 2, "exposed_services": 2, "hijackable_subdomains": 1,
		"cloud_storage": 1, "suspicious_activity": 1, "misconfiguration": 0} {
		if got := p.issues(cat); got != want {
			t.Errorf("owner %s issues = %d, want %d (%s)", cat, got, want, body)
		}
	}
	if r := p.roots(); len(r) != 3 || r["example.com"] != 2 || r["example.org"] != 1 || r["example.net"] != 1 {
		t.Errorf("owner roots = %v", r)
	}
	if strings.Contains(body, "other.example.edu") || strings.Contains(body, "gone.example.org") || strings.Contains(body, "notours") {
		t.Errorf("owner body names a foreign, deleted or rejected asset: %s", body)
	}
	if p.Score.Grade == "" || p.Score.Score >= 100 || len(p.Plan.Steps) == 0 {
		t.Errorf("owner score/plan = %+v", p.Score)
	}

	// memberA: assets A and www.example.org only; no bucket, no issue
	// without an asset, no organization trend.
	st, body = h.do(h.memberA, false, http.MethodGet, path, nil)
	p = decodePosture(t, body)
	if st != http.StatusOK || !p.Scoped || p.Score.Assets != 2 || p.PreviousScore != nil {
		t.Fatalf("memberA = %d %s", st, body)
	}
	for cat, want := range map[string]int64{"vulnerabilities": 1, "exposed_services": 1, "hijackable_subdomains": 1,
		"cloud_storage": 0, "suspicious_activity": 0} {
		if got := p.issues(cat); got != want {
			t.Errorf("memberA %s issues = %d, want %d", cat, got, want)
		}
	}
	if r := p.roots(); len(r) != 2 || r["example.net"] != 0 || r["example.com"] != 1 {
		t.Errorf("memberA roots = %v", r)
	}
	if strings.Contains(body, "api.example.net") || strings.Contains(body, dsMarkerAssetB) {
		t.Errorf("memberA sees an out-of-scope asset: %s", body)
	}
	// A filter on a root domain the member cannot see gives nothing.
	if st, body := h.do(h.memberA, false, http.MethodGet, path+"?root_domain=example.net", nil); st != http.StatusOK || decodePosture(t, body).Score.Measured {
		t.Errorf("memberA root filter = %d %s", st, body)
	}
	if st, _ := h.do(h.memberA, false, http.MethodGet, path+"?nonsense=1", nil); st != http.StatusBadRequest {
		t.Errorf("unknown param = %d, want 400", st)
	}

	// A member with no scope row has no grade.
	st, body = h.do(h.memberStrict, false, http.MethodGet, path, nil)
	if p := decodePosture(t, body); st != http.StatusOK || p.Score.Measured || p.Score.Assets != 0 || len(p.Roots) != 0 {
		t.Errorf("member without scope = %d %s", st, body)
	}

	// The schedule is validated.
	if st, _ := h.do(h.owner, true, http.MethodPut, path+"/schedule", map[string]string{"refresh_every": "5m"}); st != http.StatusBadRequest {
		t.Errorf("bad schedule = %d, want 400", st)
	}
	if st, body := h.do(h.owner, true, http.MethodPut, path+"/schedule", map[string]string{"refresh_every": "manual"}); st != http.StatusOK ||
		!strings.Contains(body, `"refresh_every":"manual"`) || strings.Contains(body, "next_refresh_at") {
		t.Errorf("manual schedule = %d %s", st, body)
	}
}
