package routes

// API descriptions of web origins and their drift (RFC-056 WS13): upload is
// gated on assets:write and on an origin the caller may see; another
// tenant's or an out-of-scope description answers 404; the document is
// never stored, only its parsed operations; drift compares with what scans
// observed.

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	apispecapp "github.com/openctemio/openctem/api/internal/app/apispec"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const specSecret = "SPEC-EXAMPLE-SECRET"

const specDoc = `openapi: 3.0.0
info: {title: Shop API, version: "1"}
paths:
  /products/{productId}:
    get:
      parameters: [{name: productId, in: path}]
  /legacy/export:
    get: {deprecated: true}
  /orders:
    post:
      requestBody:
        content:
          application/json:
            schema:
              properties:
                sku: {type: string, example: ` + specSecret + `}
`

type specHarness struct {
	t                                *testing.T
	db                               *sql.DB
	srv                              *httptest.Server
	tenant, other                    shared.ID
	owner, member                    shared.ID
	origin, domainAsset, otherOrigin shared.ID
}

func newSpecHarness(t *testing.T) *specHarness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	h := &specHarness{t: t, db: sqldb, tenant: shared.NewID(), other: shared.NewID(), owner: shared.NewID(), member: shared.NewID(),
		origin: shared.NewID(), domainAsset: shared.NewID(), otherOrigin: shared.NewID()}
	for _, tn := range []shared.ID{h.tenant, h.other} {
		h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tn.String(), "spec-"+tn.String())
		tid := tn
		t.Cleanup(func() { _, _ = sqldb.Exec(`DELETE FROM tenants WHERE id = $1`, tid.String()) })
	}
	for _, u := range []shared.ID{h.owner, h.member} {
		h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, $3)`, u.String(), u.String()+"@spec.test", "u")
		uid := u
		t.Cleanup(func() { _, _ = sqldb.Exec(`DELETE FROM users WHERE id = $1`, uid.String()) })
		h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, u.String(), h.tenant.String())
	}
	ins := `INSERT INTO assets (id, tenant_id, name, asset_type, sub_type, exposure, criticality) VALUES ($1, $2, $3, $4, $5, 'public', 'high')`
	h.exec(ins, h.origin.String(), h.tenant.String(), "https://spec.web.test", "service", "http")
	h.exec(ins, h.domainAsset.String(), h.tenant.String(), "spec.web.test", "domain", nil)
	h.exec(ins, h.otherOrigin.String(), h.other.String(), "https://other.web.test", "service", "http")
	// Observed endpoints: one declared, one shadow, the deprecated one alive.
	ep := `INSERT INTO web_endpoints (id, tenant_id, origin_asset_id, method, path_template, template_hash, path_hash, last_status, sources)
		VALUES (gen_random_uuid(), $1, $2, $3::text, $4::text, md5($4::text) || md5($3::text), md5($4::text) || md5($4::text), 200, '{crawl}')`
	h.exec(ep, h.tenant.String(), h.origin.String(), "GET", "/products/{int}")
	h.exec(ep, h.tenant.String(), h.origin.String(), "GET", "/admin/debug")
	h.exec(ep, h.tenant.String(), h.origin.String(), "GET", "/legacy/export")

	db := &postgres.DB{DB: sqldb}
	enforcer := datascope.New(postgres.NewDataScopeRepository(db), func(ctx context.Context) datascope.Caller {
		return datascope.Caller{UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx)}
	}, logger.NewNop())
	svc := apispecapp.NewService(postgres.NewAPISpecRepository(db), postgres.NewAssetRepository(db), enforcer)
	router := infrahttp.NewChiRouter()
	auth := Middleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), middleware.UserIDKey, r.Header.Get("X-Test-User"))
			ctx = context.WithValue(ctx, middleware.TenantIDKey, h.tenant.String())
			ctx = context.WithValue(ctx, middleware.IsAdminKey, r.Header.Get("X-Test-Admin") == "1")
			ctx = context.WithValue(ctx, middleware.PermissionsKey, strings.Split(r.Header.Get("X-Test-Perms"), ","))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	registerAPISpecRoutes(router, handler.NewAPISpecHandler(svc, nil, logger.NewNop()), auth, nil)
	h.srv = httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(h.srv.Close)
	return h
}

func (h *specHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.Exec(q, args...); err != nil {
		h.t.Fatalf("%s: %v", q, err)
	}
}

func (h *specHarness) req(method, path string, user shared.ID, admin bool, perms []string, body io.Reader, ct string) (int, string) {
	h.t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, body)
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	req.Header.Set("X-Test-User", user.String())
	if admin {
		req.Header.Set("X-Test-Admin", "1")
	}
	req.Header.Set("X-Test-Perms", strings.Join(perms, ","))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func multipartSpec(t *testing.T, content string) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "shop.yaml")
	_, _ = fw.Write([]byte(content))
	_ = mw.WriteField("name", "Shop")
	_ = mw.Close()
	return &buf, mw.FormDataContentType()
}

func TestAPISpecs_UploadDriftAndIsolation_DB(t *testing.T) {
	h := newSpecHarness(t)
	write := []string{permission.AssetsRead.String(), permission.AssetsWrite.String()}

	body, ct := multipartSpec(t, specDoc)
	st, out := h.req(http.MethodPost, "/api/v1/assets/"+h.origin.String()+"/api-specs", h.owner, true, write, body, ct)
	if st != http.StatusCreated || !strings.Contains(out, `"operation_count":3`) || !strings.Contains(out, `"format":"openapi3"`) {
		t.Fatalf("upload = %d %s", st, out)
	}
	id := between(out, `"id":"`, `"`)

	// The document is never stored: no example value anywhere.
	var n int
	if err := h.db.QueryRow(`SELECT count(*) FROM api_spec_operations o WHERE o.tenant_id = $1 AND row_to_json(o)::text LIKE '%' || $2 || '%'`,
		h.tenant.String(), specSecret).Scan(&n); err != nil || n != 0 {
		t.Fatalf("an example value was stored (%d, %v)", n, err)
	}

	st, out = h.req(http.MethodGet, "/api/v1/api-specs/"+id+"/drift", h.owner, true, write, nil, "")
	if st != http.StatusOK {
		t.Fatalf("drift = %d %s", st, out)
	}
	for _, want := range []string{`"shadow":[{"method":"GET","path":"/admin/debug"`, `"orphan":[{"method":"POST","path":"/orders"}]`,
		`"zombie":[{"method":"GET","path":"/legacy/export"`} {
		if !strings.Contains(out, want) {
			t.Errorf("drift lacks %s: %s", want, out)
		}
	}

	// Isolation and gates.
	cases := []struct {
		name   string
		method string
		path   string
		user   shared.ID
		admin  bool
		perms  []string
		want   int
	}{
		{"member without scope reads the spec", http.MethodGet, "/api/v1/api-specs/" + id, h.member, false, write, http.StatusNotFound},
		{"member without scope reads the drift", http.MethodGet, "/api/v1/api-specs/" + id + "/drift", h.member, false, write, http.StatusNotFound},
		{"member without scope deletes", http.MethodDelete, "/api/v1/api-specs/" + id, h.member, false, write, http.StatusNotFound},
		{"read-only member uploads", http.MethodPost, "/api/v1/assets/" + h.origin.String() + "/api-specs", h.member, false,
			[]string{permission.AssetsRead.String()}, http.StatusForbidden},
		{"upload to another tenant's origin", http.MethodPost, "/api/v1/assets/" + h.otherOrigin.String() + "/api-specs", h.owner, true, write, http.StatusNotFound},
		{"upload to a domain asset", http.MethodPost, "/api/v1/assets/" + h.domainAsset.String() + "/api-specs", h.owner, true, write, http.StatusBadRequest},
	}
	for _, c := range cases {
		var b io.Reader
		ct := ""
		if c.method == http.MethodPost {
			buf, typ := multipartSpec(t, specDoc)
			b, ct = buf, typ
		}
		if st, out := h.req(c.method, c.path, c.user, c.admin, c.perms, b, ct); st != c.want {
			t.Errorf("%s = %d %s, want %d", c.name, st, out, c.want)
		}
	}
	// Another tenant's description is not found.
	var otherSpec string
	if err := h.db.QueryRow(`INSERT INTO api_specs (tenant_id, origin_asset_id, name, format, digest, size_bytes)
		VALUES ($1, $2, 'x', 'har', repeat('a', 64), 1) RETURNING id`, h.other.String(), h.otherOrigin.String()).Scan(&otherSpec); err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{http.MethodGet, http.MethodDelete} {
		if st, _ := h.req(m, "/api/v1/api-specs/"+otherSpec, h.owner, true, write, nil, ""); st != http.StatusNotFound {
			t.Errorf("%s another tenant's spec = %d, want 404", m, st)
		}
	}
	// A hostile or unknown document is refused.
	bad, ct := multipartSpec(t, `{"hello":"world"}`)
	if st, _ := h.req(http.MethodPost, "/api/v1/assets/"+h.origin.String()+"/api-specs", h.owner, true, write, bad, ct); st != http.StatusBadRequest {
		t.Errorf("unknown document = %d, want 400", st)
	}
	// The owner deletes it.
	if st, _ := h.req(http.MethodDelete, "/api/v1/api-specs/"+id, h.owner, true, write, nil, ""); st != http.StatusNoContent {
		t.Errorf("delete = %d", st)
	}
}

func between(s, a, b string) string {
	i := strings.Index(s, a)
	if i < 0 {
		return ""
	}
	s = s[i+len(a):]
	if j := strings.Index(s, b); j >= 0 {
		return s[:j]
	}
	return s
}
