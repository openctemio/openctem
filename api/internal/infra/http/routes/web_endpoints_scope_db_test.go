package routes

// /web-endpoints and /assets/{id}/web-endpoints (RFC-056): an endpoint is
// visible exactly when its origin asset is. Out-of-scope and other-tenant
// ids answer 404, lists and counts include only in-scope origins, and a
// member with no scope row sees nothing.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const (
	weMarkerA = "/dsa-endpoint/{int}"
	weMarkerB = "/dsB-SECRET-endpoint/{int}"
)

type weSeed struct{ epA, epB, epOther shared.ID }

func (h *dsHarness) seedWebEndpoints() weSeed {
	h.t.Helper()
	s := weSeed{epA: shared.NewID(), epB: shared.NewID(), epOther: shared.NewID()}
	t := h.tenant.String()
	ins := `INSERT INTO web_endpoints (id, tenant_id, origin_asset_id, method, path_template, template_hash, path_hash, in_scope)
		VALUES ($1, $2, $3, 'GET', $4::text, md5($4::text) || md5($4::text), md5($4::text) || md5($4::text), $5)`
	h.exec(ins, s.epA.String(), t, h.assetA.String(), weMarkerA, true)
	h.exec(ins, s.epB.String(), t, h.assetB.String(), weMarkerB, false)
	h.exec(`INSERT INTO web_endpoint_params (tenant_id, endpoint_id, location, name) VALUES ($1, $2, 'query', 'b_secret_param')`, t, s.epB.String())
	h.exec(`INSERT INTO web_endpoint_params (tenant_id, endpoint_id, location, name, risk_hints) VALUES ($1, $2, 'query', 'redirect_uri', '{ssrf_candidate}')`, t, s.epA.String())

	// Another tenant's endpoint.
	other, otherAsset := shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "we-other-"+other.String())
	h.t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM tenants WHERE id = $1`, other.String()) })
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, 'we-other.test', 'domain', 'public', 'low')`,
		otherAsset.String(), other.String())
	h.exec(ins, s.epOther.String(), other.String(), otherAsset.String(), "/other-tenant", true)
	return s
}

func weTotal(t *testing.T, body string) int {
	t.Helper()
	var r struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	return r.Total
}

func TestWebEndpoints_DataScopeAndTenant_DB(t *testing.T) {
	h := newDSHarness(t)
	s := h.seedWebEndpoints()

	// The scoped member lists only the endpoint of the origin in scope.
	st, body := h.do(h.memberA, false, http.MethodGet, "/api/v1/web-endpoints", nil)
	if st != http.StatusOK || weTotal(t, body) != 1 || !strings.Contains(body, weMarkerA) || strings.Contains(body, weMarkerB) {
		t.Fatalf("memberA list = %d %s", st, body)
	}
	st, body = h.do(h.memberA, false, http.MethodGet, "/api/v1/web-endpoints/stats", nil)
	if st != http.StatusOK || !strings.Contains(body, `"total":1`) || !strings.Contains(body, `"excluded_untested":0`) {
		t.Fatalf("memberA stats = %d %s", st, body)
	}
	// By id, out of scope: 404 on every route, never the data.
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/web-endpoints/" + s.epB.String()},
		{http.MethodGet, "/api/v1/web-endpoints/" + s.epB.String() + "/parameters"},
		{http.MethodPatch, "/api/v1/web-endpoints/" + s.epB.String()},
		{http.MethodGet, "/api/v1/assets/" + h.assetB.String() + "/web-endpoints"},
	} {
		var b any
		if c.method == http.MethodPatch {
			b = map[string]any{"state": "ignored"}
		}
		st, body := h.do(h.memberA, false, c.method, c.path, b)
		if st != http.StatusNotFound || strings.Contains(body, "SECRET") || strings.Contains(body, "b_secret_param") {
			t.Errorf("memberA %s %s = %d %s, want 404 without data", c.method, c.path, st, body)
		}
	}
	// In scope: detail, parameters (names and hints, no value), per-origin list.
	if st, body := h.do(h.memberA, false, http.MethodGet, "/api/v1/web-endpoints/"+s.epA.String()+"/parameters", nil); st != http.StatusOK ||
		!strings.Contains(body, `"name":"redirect_uri"`) || !strings.Contains(body, "ssrf_candidate") || strings.Contains(body, `"value"`) {
		t.Errorf("memberA params = %d %s", st, body)
	}
	if st, body := h.do(h.memberA, false, http.MethodGet, "/api/v1/assets/"+h.assetA.String()+"/web-endpoints", nil); st != http.StatusOK || weTotal(t, body) != 1 {
		t.Errorf("memberA per-asset list = %d %s", st, body)
	}

	// A member with no scope row sees nothing.
	if st, body := h.do(h.memberStrict, false, http.MethodGet, "/api/v1/web-endpoints", nil); st != http.StatusOK || weTotal(t, body) != 0 {
		t.Errorf("member without scope list = %d %s", st, body)
	}

	// The owner sees the tenant's two endpoints, one excluded-untested, and
	// never another tenant's.
	st, body = h.do(h.owner, true, http.MethodGet, "/api/v1/web-endpoints", nil)
	if st != http.StatusOK || weTotal(t, body) != 2 || strings.Contains(body, "/other-tenant") {
		t.Fatalf("owner list = %d %s", st, body)
	}
	if st, body := h.do(h.owner, true, http.MethodGet, "/api/v1/web-endpoints/stats?in_scope=false", nil); st != http.StatusOK ||
		!strings.Contains(body, `"total":1`) || !strings.Contains(body, `"excluded_untested":1`) {
		t.Errorf("owner excluded-untested stats = %d %s", st, body)
	}
	for _, p := range []string{"/api/v1/web-endpoints/" + s.epOther.String(), "/api/v1/web-endpoints/" + s.epOther.String() + "/parameters"} {
		if st, _ := h.do(h.owner, true, http.MethodGet, p, nil); st != http.StatusNotFound {
			t.Errorf("owner GET another tenant's %s = %d, want 404", p, st)
		}
	}
	if st, _ := h.do(h.owner, true, http.MethodPatch, "/api/v1/web-endpoints/"+s.epOther.String(), map[string]any{"state": "ignored"}); st != http.StatusNotFound {
		t.Errorf("owner PATCH another tenant's endpoint = %d, want 404", st)
	}
	var otherState string
	if err := h.db.QueryRow(`SELECT state FROM web_endpoints WHERE id = $1`, s.epOther.String()).Scan(&otherState); err != nil || otherState != "active" {
		t.Errorf("another tenant's endpoint changed: %q %v", otherState, err)
	}
}

func TestWebEndpoints_UpdateAndFilters_DB(t *testing.T) {
	h := newDSHarness(t)
	s := h.seedWebEndpoints()
	path := "/api/v1/web-endpoints/" + s.epA.String()

	for _, b := range []map[string]any{
		{"state": "gone"},              // the platform's call, not a person's
		{"labels": []string{"a b"}},    // invalid characters
		{},                             // nothing to change
		{"state": "ignored", "x": "y"}, // unknown member
	} {
		if st, body := h.do(h.memberA, false, http.MethodPatch, path, b); st != http.StatusBadRequest {
			t.Errorf("PATCH %v = %d %s, want 400", b, st, body)
		}
	}
	st, body := h.do(h.memberA, false, http.MethodPatch, path, map[string]any{"state": "ignored", "labels": []string{"Admin", "admin", "pii"}})
	if st != http.StatusOK || !strings.Contains(body, `"state":"ignored"`) || !strings.Contains(body, `"labels":["admin","pii"]`) {
		t.Fatalf("PATCH = %d %s", st, body)
	}

	// The list filters by the contract; an unknown param is refused.
	if st, body := h.do(h.owner, true, http.MethodGet, "/api/v1/web-endpoints?state=ignored&label=pii", nil); st != http.StatusOK || weTotal(t, body) != 1 {
		t.Errorf("filtered list = %d %s", st, body)
	}
	if st, _ := h.do(h.owner, true, http.MethodGet, "/api/v1/web-endpoints?nonsense=1", nil); st != http.StatusBadRequest {
		t.Errorf("unknown param = %d, want 400", st)
	}
	if st, body := h.do(h.owner, true, http.MethodGet, "/api/v1/web-endpoints?q=SECRET-endpoint", nil); st != http.StatusOK || weTotal(t, body) != 1 {
		t.Errorf("search = %d %s", st, body)
	}
}
