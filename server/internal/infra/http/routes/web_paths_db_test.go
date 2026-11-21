package routes

// GET /assets/{id}/web-paths (docs/architecture/web-surface.md, "Path
// tree"): one level of an origin's path tree. The origin's tenant and the
// caller's data scope are checked first: another tenant's origin and one
// outside the member's scope answer 404 without data. Findings map onto
// endpoints by path template; a resolved finding is not counted.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

type wpSeed struct{ origin, outOrigin, otherOrigin shared.ID }

func (h *dsHarness) seedWebPaths() wpSeed {
	h.t.Helper()
	s := wpSeed{origin: shared.NewID(), outOrigin: shared.NewID(), otherOrigin: shared.NewID()}
	t := h.tenant.String()
	asset := `INSERT INTO assets (id, tenant_id, name, asset_type, sub_type, exposure, criticality) VALUES ($1, $2, $3, 'service', 'http', 'public', 'high')`
	h.exec(asset, s.origin.String(), t, "https://paths.web.test")
	h.exec(asset, s.outOrigin.String(), t, "https://wpB-SECRET.web.test")
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		h.memberA.String(), t, s.origin.String())

	other := shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "wp-other-"+other.String())
	h.t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, other.String())
	})
	h.exec(asset, s.otherOrigin.String(), other.String(), "https://wp-other.web.test")

	ep := `INSERT INTO web_endpoints (id, tenant_id, origin_asset_id, method, path_template, template_hash, path_hash, last_status, content_type, in_scope, state)
		VALUES (gen_random_uuid(), $1, $2, $3::text, $4::text, md5($4::text) || md5($3::text), md5($4::text) || md5($4::text), $5, $6, $7, $8)`
	for _, e := range []struct {
		origin       shared.ID
		tenant, m, p string
		status       int
		ct           string
		inScope      bool
		state        string
	}{
		{s.origin, t, "GET", "/api/users", 200, "application/json", true, "active"},
		{s.origin, t, "GET", "/api/users/{int}", 200, "application/json", true, "active"},
		{s.origin, t, "DELETE", "/api/users/{int}", 204, "", true, "active"},
		{s.origin, t, "GET", "/admin/console", 403, "text/html", false, "active"},
		{s.origin, t, "GET", "/assets/site.css", 200, "text/css", true, "active"},
		{s.origin, t, "GET", "/old", 404, "text/html", true, "gone"},
		{s.outOrigin, t, "GET", "/wpB-SECRET-path", 200, "", true, "active"},
		{s.otherOrigin, other.String(), "GET", "/other-tenant-path", 200, "", true, "active"},
	} {
		h.exec(ep, e.tenant, e.origin.String(), e.m, e.p, e.status, e.ct, e.inScope, e.state)
	}
	f := `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, location_key)
		VALUES ($1::uuid, $2, $3, 'dast', 'wp-tool', 'wp finding', $4, $1::text, $5, $6)`
	for _, x := range []struct{ sev, status, key string }{
		{"high", "confirmed", "url:https://paths.web.test/api/users/42"},
		{"critical", "confirmed", "url:https://paths.web.test/.env"},     // a path no endpoint records
		{"medium", "confirmed", "net:443/tcp"},                           // on the origin, no path
		{"critical", "resolved", "url:https://paths.web.test/api/users"}, // closed: not counted
	} {
		h.exec(f, shared.NewID().String(), t, s.origin.String(), x.sev, x.status, x.key)
	}
	return s
}

type wpResp struct {
	Path   string `json:"path"`
	Totals struct {
		Recorded       int    `json:"recorded"`
		Endpoints      int    `json:"endpoints"`
		Hidden         int    `json:"hidden"`
		OutOfScope     int    `json:"out_of_scope"`
		Findings       int    `json:"findings"`
		Unrecorded     int    `json:"unrecorded_findings"`
		OriginFindings int    `json:"origin_findings"`
		TopSeverity    string `json:"top_severity"`
	} `json:"totals"`
	Folders []struct {
		Name, Path  string
		Endpoints   int
		OutOfScope  int `json:"out_of_scope"`
		Findings    int
		TopSeverity string `json:"top_severity"`
		HasFolders  bool   `json:"has_folders"`
		Param       bool
	} `json:"folders"`
	Endpoints []struct {
		Method       string
		PathTemplate string `json:"path_template"`
		FindingCount int    `json:"finding_count"`
		TopSeverity  string `json:"top_severity"`
	} `json:"endpoints"`
	EndpointTotal int `json:"endpoint_total"`
}

func decodeWP(t *testing.T, body string) wpResp {
	t.Helper()
	var r wpResp
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	return r
}

func TestWebPaths_TenantAndDataScope_DB(t *testing.T) {
	h := newDSHarness(t)
	s := h.seedWebPaths()
	url := func(id shared.ID, q string) string { return "/api/v1/assets/" + id.String() + "/web-paths" + q }

	// Another tenant's origin: 404 for the owner, never its paths.
	if st, body := h.do(h.owner, true, http.MethodGet, url(s.otherOrigin, ""), nil); st != http.StatusNotFound || strings.Contains(body, "other-tenant") {
		t.Errorf("owner, other tenant's origin = %d %s", st, body)
	}
	// Out of the member's data scope: 404 without data, on every level.
	for _, q := range []string{"", "?path=/wpB-SECRET-path", "?here=true"} {
		if st, body := h.do(h.memberA, false, http.MethodGet, url(s.outOrigin, q), nil); st != http.StatusNotFound || strings.Contains(body, "SECRET") {
			t.Errorf("memberA out-of-scope origin %q = %d %s", q, st, body)
		}
	}
	// A member with no scope row sees nothing.
	if st, _ := h.do(h.memberStrict, false, http.MethodGet, url(s.origin, ""), nil); st != http.StatusNotFound {
		t.Errorf("member without scope = %d, want 404", st)
	}
	// An unknown asset id and a malformed one answer the same 404.
	for _, p := range []string{url(shared.NewID(), ""), "/api/v1/assets/not-an-id/web-paths"} {
		if st, _ := h.do(h.owner, true, http.MethodGet, p, nil); st != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", p, st)
		}
	}
	// In scope: the tree of the member's origin.
	st, body := h.do(h.memberA, false, http.MethodGet, url(s.origin, ""), nil)
	if st != http.StatusOK {
		t.Fatalf("memberA tree = %d %s", st, body)
	}
	if strings.Contains(body, "SECRET") || strings.Contains(body, "other-tenant") {
		t.Fatalf("tree leaked another origin's paths: %s", body)
	}
	r := decodeWP(t, body)
	if r.Totals.Recorded != 6 || r.Totals.Endpoints != 5 || r.Totals.Hidden != 1 || r.Totals.OutOfScope != 1 {
		t.Errorf("totals = %+v", r.Totals)
	}
	// The resolved finding is not counted; .env stays visible as a folder of its own.
	if r.Totals.Findings != 2 || r.Totals.Unrecorded != 1 || r.Totals.OriginFindings != 1 || r.Totals.TopSeverity != "critical" {
		t.Errorf("finding totals = %+v", r.Totals)
	}
	names := map[string]int{}
	for i, f := range r.Folders {
		names[f.Name] = i
	}
	for _, n := range []string{"api", "admin", "assets", ".env"} {
		if _, ok := names[n]; !ok {
			t.Errorf("folder %q missing: %+v", n, r.Folders)
		}
	}
	if a := r.Folders[names["admin"]]; a.OutOfScope != 1 {
		t.Errorf("out-of-scope folder = %+v", a)
	}
	if a := r.Folders[names["api"]]; a.Endpoints != 3 || a.Findings != 1 || a.TopSeverity != "high" || !a.HasFolders {
		t.Errorf("api folder = %+v", a)
	}
}

func TestWebPaths_LevelsFiltersAndQuery_DB(t *testing.T) {
	h := newDSHarness(t)
	s := h.seedWebPaths()
	url := func(q string) string { return "/api/v1/assets/" + s.origin.String() + "/web-paths" + q }

	// A level: the node's own template with "here", its param child.
	st, body := h.do(h.memberA, false, http.MethodGet, url("?path=/api/users&here=true"), nil)
	r := decodeWP(t, body)
	if st != http.StatusOK || r.Path != "/api/users" || r.EndpointTotal != 1 || len(r.Folders) != 1 || !r.Folders[0].Param {
		t.Fatalf("level /api/users = %d %s", st, body)
	}
	// Both methods of /api/users/{int} carry the finding at /api/users/42.
	_, body = h.do(h.memberA, false, http.MethodGet, url("?path=/api/users/%7Bint%7D"), nil)
	r = decodeWP(t, body)
	if r.EndpointTotal != 2 || r.Endpoints[0].FindingCount != 1 || r.Endpoints[1].FindingCount != 1 {
		t.Errorf("method-blind finding count = %s", body)
	}
	// Filters: static and 4xx hidden, gone shown, scope, methods, search.
	for q, want := range map[string]int{
		"?hide_static=true":         4,
		"?hide_4xx=true":            4,
		"?include_gone=true":        6,
		"?scope=out":                1,
		"?method=DELETE":            1,
		"?with_findings=true":       2,
		"?q=USERS":                  3,
		"?hide_static=1&hide_4xx=1": 3,
		"?per_page=0":               5,
	} {
		st, body := h.do(h.memberA, false, http.MethodGet, url(q), nil)
		if r := decodeWP(t, body); st != http.StatusOK || r.Totals.Endpoints != want {
			t.Errorf("%s = %d, %d endpoints, want %d (%s)", q, st, r.Totals.Endpoints, want, body)
		}
	}
	// The findings at the node's own template, with their masked path.
	st, body = h.do(h.memberA, false, http.MethodGet, url("?path=/api/users/%7Bint%7D&here=true&findings=true&per_page=0"), nil)
	var nf struct {
		NodeFindings []struct{ Title, Severity, Path string } `json:"node_findings"`
		Total        int                                      `json:"node_finding_total"`
	}
	if err := json.Unmarshal([]byte(body), &nf); st != http.StatusOK || err != nil || nf.Total != 1 ||
		nf.NodeFindings[0].Severity != "high" || nf.NodeFindings[0].Path != "/api/users/42" {
		t.Errorf("node findings = %d %s", st, body)
	}
	// A malformed query is refused, never guessed at.
	for _, q := range []string{"?path=api", "?path=/api/", "?nonsense=1", "?hide_4xx=maybe", "?per_page=500",
		"?scope=all", "?method=GET%20X", "?page=x", "?path=/a&path=/b", "?findings=true"} {
		if st, _ := h.do(h.memberA, false, http.MethodGet, url(q), nil); st != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", q, st)
		}
	}
}

// A full origin (5,000 active endpoints, the cap) answers one level quickly
// and in a small payload: the tree never ships the whole endpoint list.
func TestWebPaths_FullOriginTiming_DB(t *testing.T) {
	h := newDSHarness(t)
	s := h.seedWebPaths()
	h.exec(`INSERT INTO web_endpoints (id, tenant_id, origin_asset_id, method, path_template, template_hash, path_hash, last_status, in_scope)
		SELECT gen_random_uuid(), $1, $2, (ARRAY['GET','POST','PUT','DELETE'])[1 + i % 4],
			format('/area%s/section%s/item%s/{int}', i % 20, (i / 20) % 25, i / 500),
			md5(i::text) || md5('t'), md5(i::text) || md5('p'), 200, true
		FROM generate_series(1, 5000) AS i`, h.tenant.String(), s.origin.String())
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, location_key)
		SELECT g, $1, $2, 'dast', 'wp-tool', 'bulk', 'medium', g::text, 'confirmed',
			format('url:https://paths.web.test/area%s/section%s/item%s/7', i % 20, (i / 20) % 25, i / 500)
		FROM (SELECT gen_random_uuid() AS g, i FROM generate_series(1, 500) AS i) x`, h.tenant.String(), s.origin.String())
	for _, q := range []string{"", "?path=/area3", "?path=/area3/section4&per_page=100"} {
		start := time.Now()
		st, body := h.do(h.owner, true, http.MethodGet, "/api/v1/assets/"+s.origin.String()+"/web-paths"+q, nil)
		took := time.Since(start)
		t.Logf("web-paths%s: %d, %d bytes, %s", q, st, len(body), took)
		if st != http.StatusOK || took > 2*time.Second || len(body) > 256<<10 {
			t.Errorf("web-paths%s = %d, %d bytes, %s", q, st, len(body), took)
		}
	}
}
