package routes

// The proxy pool management API (/api/v1/proxy-pools) over the real routes,
// services and a migrated database, across two tenants: credentials are
// write-only (never in a response, the audit log or the stored row in
// clear), every id of another tenant behaves as unknown, the permission
// gates hold, and a pool in use cannot be deleted. Requires DATABASE_URL.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/audit"
	proxypoolapp "github.com/openctemio/openctem/api/internal/app/proxypool"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const ppSecret = "pp-Very-Secret-pw"

type ppHarness struct {
	t                *testing.T
	db               *sql.DB
	srv              *httptest.Server
	tenantA, tenantB shared.ID
	sensorA, sensorB shared.ID
	sharedSensor     shared.ID
	admin            shared.ID
}

// ppCaller is who calls: a tenant and, for a member, its permissions
// (nil: an administrator).
type ppCaller struct {
	Tenant shared.ID
	Perms  []permission.Permission
}

func newPPHarness(t *testing.T) *ppHarness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set to a test database; skipping proxy pool DB test")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := sqldb.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	h := &ppHarness{t: t, db: sqldb, tenantA: shared.NewID(), tenantB: shared.NewID(), sensorA: shared.NewID(),
		sensorB: shared.NewID(), sharedSensor: shared.NewID(), admin: shared.NewID()}
	h.seed()

	db := &postgres.DB{DB: sqldb}
	log := logger.NewNop()
	enc, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	svc := proxypoolapp.NewService(postgres.NewProxyPoolRepository(db), enc, audit.NewAuditService(postgres.NewAuditRepository(db), log), log)
	router := infrahttp.NewChiRouter()
	auth := Middleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var c ppCaller
			_ = json.Unmarshal([]byte(r.Header.Get("X-Test-Caller")), &c)
			ctx := context.WithValue(r.Context(), middleware.UserIDKey, h.admin.String())
			ctx = context.WithValue(ctx, middleware.TenantIDKey, c.Tenant.String())
			ctx = context.WithValue(ctx, middleware.IsAdminKey, c.Perms == nil)
			perms := make([]string, 0, len(c.Perms))
			for _, p := range c.Perms {
				perms = append(perms, p.String())
			}
			ctx = context.WithValue(ctx, middleware.PermissionsKey, perms)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	registerProxyPoolRoutes(router, handler.NewProxyPoolHandler(svc, log), auth, nil)
	h.srv = httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(h.srv.Close)
	return h
}

func (h *ppHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("seed %q: %v", q, err)
	}
}

func (h *ppHarness) seed() {
	for _, tn := range []shared.ID{h.tenantA, h.tenantB} {
		h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tn.String(), "pp-"+tn.String())
	}
	h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'pp')`, h.admin.String(), h.admin.String()+"@pp.test")
	h.t.Cleanup(func() {
		ctx := context.Background()
		_, _ = h.db.ExecContext(ctx, `DELETE FROM sensors WHERE id = $1`, h.sharedSensor.String())
		for _, tn := range []shared.ID{h.tenantA, h.tenantB} {
			_, _ = h.db.ExecContext(ctx, `DELETE FROM audit_logs WHERE tenant_id = $1`, tn.String())
			_, _ = h.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tn.String())
		}
		_, _ = h.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, h.admin.String())
	})
	for id, tn := range map[shared.ID]shared.ID{h.sensorA: h.tenantA, h.sensorB: h.tenantB} {
		h.exec(`INSERT INTO sensors (id, tenant_id, name, type, status, health, execution_mode, api_key_hash, api_key_prefix, scope)
			VALUES ($1, $2, $3, 'worker', 'active', 'unknown', 'daemon', $4, 'octs_pp', 'organization')`,
			id.String(), tn.String(), "pp-"+id.String(), "pp-hash-"+id.String())
	}
	h.exec(`INSERT INTO sensors (id, tenant_id, name, type, status, health, execution_mode, api_key_hash, api_key_prefix, scope)
		VALUES ($1, NULL, $2, 'worker', 'active', 'unknown', 'daemon', $3, 'octs_pp', 'instance')`,
		h.sharedSensor.String(), "pp-shared-"+h.sharedSensor.String(), "pp-hash-"+h.sharedSensor.String())
}

func (h *ppHarness) do(c ppCaller, method, path string, body any) (int, string) {
	h.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, rdr)
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	cb, _ := json.Marshal(c)
	req.Header.Set("X-Test-Caller", string(cb))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

type ppPool struct {
	ID            string `json:"id"`
	Revision      int    `json:"revision"`
	EndpointsText string `json:"endpoints_text"`
	Endpoints     []struct {
		ID             string `json:"id"`
		Host           string `json:"host"`
		HasCredentials bool   `json:"has_credentials"`
		Health         struct {
			State string `json:"state"`
		} `json:"health"`
	} `json:"endpoints"`
}

func decodePool(t *testing.T, body string) ppPool {
	t.Helper()
	var p ppPool
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return p
}

func (h *ppHarness) noSecret(where, s string) {
	h.t.Helper()
	if strings.Contains(s, ppSecret) || strings.Contains(s, "pp-user") {
		h.t.Fatalf("%s carries a credential: %.300s", where, s)
	}
}

func TestProxyPools_CredentialsWriteOnly(t *testing.T) {
	h := newPPHarness(t)
	a := ppCaller{Tenant: h.tenantA}
	list := "socks5://pp-user:" + ppSecret + "@10.0.0.5:1080#dc1\nhttp://proxy.corp.example:3128"
	status, body := h.do(a, http.MethodPost, "/api/v1/proxy-pools/", map[string]any{"name": "corp", "is_default": true, "endpoints_text": list})
	if status != http.StatusCreated {
		t.Fatalf("create = %d %s", status, body)
	}
	h.noSecret("create response", body)
	p := decodePool(t, body)
	if len(p.Endpoints) != 2 || !p.Endpoints[0].HasCredentials || p.Endpoints[1].HasCredentials ||
		p.EndpointsText != "socks5://••••@10.0.0.5:1080#dc1\nhttp://proxy.corp.example:3128" {
		t.Fatalf("pool = %+v", p)
	}
	var stored string
	if err := h.db.QueryRow(`SELECT credentials_encrypted FROM proxy_endpoints WHERE id = $1`, p.Endpoints[0].ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	h.noSecret("stored row", stored)

	// Re-pasting the masked list keeps the credentials, the ids and health.
	status, body = h.do(a, http.MethodPut, "/api/v1/proxy-pools/"+p.ID+"/endpoints", map[string]any{"text": p.EndpointsText})
	if status != http.StatusOK {
		t.Fatalf("re-paste = %d %s", status, body)
	}
	again := decodePool(t, body)
	if again.Endpoints[0].ID != p.Endpoints[0].ID || !again.Endpoints[0].HasCredentials || again.Revision != p.Revision {
		t.Fatalf("re-paste changed the pool: %+v", again)
	}
	// A line without user information drops them.
	status, body = h.do(a, http.MethodPut, "/api/v1/proxy-pools/"+p.ID+"/endpoints", map[string]any{"text": "socks5://10.0.0.5:1080"})
	if status != http.StatusOK || decodePool(t, body).Endpoints[0].HasCredentials {
		t.Fatalf("drop credentials = %d %s", status, body)
	}
	// An invalid line names its number, never its content.
	status, body = h.do(a, http.MethodPut, "/api/v1/proxy-pools/"+p.ID+"/endpoints",
		map[string]any{"text": "http://10.0.0.7:3128\nhttp://pp-user:" + ppSecret + "@169.254.169.254:80"})
	if status != http.StatusBadRequest || !strings.Contains(body, "INVALID_PROXY_ENDPOINT") || !strings.Contains(body, "line 2") {
		t.Fatalf("metadata endpoint = %d %s", status, body)
	}
	h.noSecret("validation error", body)

	var audits string
	if err := h.db.QueryRow(`SELECT COALESCE(string_agg(row_to_json(a)::text, ' '), '') FROM audit_logs a WHERE tenant_id = $1`, h.tenantA.String()).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(audits, "proxy_pool.credentials_changed") || !strings.Contains(audits, "proxy_pool.created") {
		t.Fatalf("audit trail missing: %.500s", audits)
	}
	h.noSecret("audit log", audits)
}

func TestProxyPools_CrossTenantAndShared(t *testing.T) {
	h := newPPHarness(t)
	a, b := ppCaller{Tenant: h.tenantA}, ppCaller{Tenant: h.tenantB}
	status, body := h.do(b, http.MethodPost, "/api/v1/proxy-pools/", map[string]any{"name": "b-pool",
		"endpoints_text": "http://pp-user:" + ppSecret + "@10.1.0.5:3128"})
	if status != http.StatusCreated {
		t.Fatalf("create = %d %s", status, body)
	}
	bp := decodePool(t, body)
	bPath := "/api/v1/proxy-pools/" + bp.ID

	for name, req := range map[string][3]any{
		"get":       {http.MethodGet, bPath, nil},
		"patch":     {http.MethodPatch, bPath, map[string]any{"name": "taken"}},
		"endpoints": {http.MethodPut, bPath + "/endpoints", map[string]any{"text": "http://10.9.9.9:3128"}},
		"endpoint":  {http.MethodPatch, bPath + "/endpoints/" + bp.Endpoints[0].ID, map[string]any{"enabled": false}},
		"delete":    {http.MethodDelete, bPath, nil},
		"assign":    {http.MethodPut, "/api/v1/proxy-pools/assignments/" + h.sensorA.String(), map[string]any{"mode": "pool", "pool_id": bp.ID}},
	} {
		status, body := h.do(a, req[0].(string), req[1].(string), req[2])
		if status != http.StatusNotFound {
			t.Errorf("%s on tenant B's pool = %d, want 404 (%.200s)", name, status, body)
		}
		h.noSecret(name, body)
	}
	status, body = h.do(a, http.MethodGet, "/api/v1/proxy-pools/", nil)
	if status != http.StatusOK || strings.Contains(body, bp.ID) {
		t.Fatalf("list leaks tenant B: %d %s", status, body)
	}
	// Tenant B's sensor and a shared sensor cannot be given a path by A.
	for _, sid := range []shared.ID{h.sensorB, h.sharedSensor} {
		status, body := h.do(a, http.MethodPut, "/api/v1/proxy-pools/assignments/"+sid.String(), map[string]any{"mode": "direct"})
		if status != http.StatusNotFound {
			t.Errorf("assign %s = %d %s, want 404", sid, status, body)
		}
	}
	var n int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM proxy_sensor_assignments WHERE sensor_id = ANY($1::uuid[])`,
		"{"+h.sensorB.String()+","+h.sharedSensor.String()+"}").Scan(&n); err != nil || n != 0 {
		t.Fatalf("foreign assignments written: %d %v", n, err)
	}
	// B's pool is untouched.
	var name string
	if err := h.db.QueryRow(`SELECT name FROM proxy_pools WHERE id = $1`, bp.ID).Scan(&name); err != nil || name != "b-pool" {
		t.Fatalf("tenant B's pool changed: %q %v", name, err)
	}
}

func TestProxyPools_PermissionsAndInUse(t *testing.T) {
	h := newPPHarness(t)
	admin := ppCaller{Tenant: h.tenantA}
	none := ppCaller{Tenant: h.tenantA, Perms: []permission.Permission{permission.SensorsRead}}
	reader := ppCaller{Tenant: h.tenantA, Perms: []permission.Permission{permission.SensorEgressRead}}

	if status, _ := h.do(none, http.MethodGet, "/api/v1/proxy-pools/", nil); status != http.StatusForbidden {
		t.Fatalf("list without sensors:egress:read = %d", status)
	}
	if status, _ := h.do(reader, http.MethodGet, "/api/v1/proxy-pools/assignments", nil); status != http.StatusOK {
		t.Fatalf("assignments with read = %d", status)
	}
	if status, _ := h.do(reader, http.MethodPost, "/api/v1/proxy-pools/", map[string]any{"name": "x"}); status != http.StatusForbidden {
		t.Fatalf("create with read only = %d", status)
	}
	if status, _ := h.do(reader, http.MethodPut, "/api/v1/proxy-pools/assignments/"+h.sensorA.String(), map[string]any{"mode": "direct"}); status != http.StatusForbidden {
		t.Fatalf("assign with read only = %d", status)
	}

	status, body := h.do(admin, http.MethodPost, "/api/v1/proxy-pools/", map[string]any{"name": "seg", "endpoints_text": "socks5://10.9.0.1:1080"})
	if status != http.StatusCreated {
		t.Fatalf("create = %d %s", status, body)
	}
	p := decodePool(t, body)
	if status, body := h.do(admin, http.MethodPut, "/api/v1/proxy-pools/assignments/"+h.sensorA.String(),
		map[string]any{"mode": "pool", "pool_id": p.ID}); status != http.StatusOK {
		t.Fatalf("assign = %d %s", status, body)
	}
	if status, body := h.do(reader, http.MethodDelete, "/api/v1/proxy-pools/"+p.ID, nil); status != http.StatusForbidden {
		t.Fatalf("delete with read only = %d %s", status, body)
	}
	if status, body := h.do(admin, http.MethodDelete, "/api/v1/proxy-pools/"+p.ID, nil); status != http.StatusConflict || !strings.Contains(body, "PROXY_POOL_IN_USE") {
		t.Fatalf("delete in use = %d %s", status, body)
	}
	if status, body := h.do(admin, http.MethodPut, "/api/v1/proxy-pools/assignments/"+h.sensorA.String(), map[string]any{"mode": "inherit"}); status != http.StatusOK {
		t.Fatalf("inherit = %d %s", status, body)
	}
	if status, body := h.do(admin, http.MethodDelete, "/api/v1/proxy-pools/"+p.ID, nil); status != http.StatusNoContent {
		t.Fatalf("delete = %d %s", status, body)
	}
	// An enabled pool needs a proxy: scans fail closed without one.
	if status, body := h.do(admin, http.MethodPost, "/api/v1/proxy-pools/", map[string]any{"name": "empty"}); status != http.StatusBadRequest ||
		!strings.Contains(body, "PROXY_POOL_NEEDS_ENDPOINT") {
		t.Fatalf("enabled pool without a proxy = %d %s", status, body)
	}
	// One default per organization.
	if status, _ := h.do(admin, http.MethodPost, "/api/v1/proxy-pools/", map[string]any{"name": "d1", "is_default": true, "enabled": false}); status != http.StatusCreated {
		t.Fatalf("first default = %d", status)
	}
	if status, body := h.do(admin, http.MethodPost, "/api/v1/proxy-pools/", map[string]any{"name": "d2", "is_default": true, "enabled": false}); status != http.StatusConflict ||
		!strings.Contains(body, "PROXY_POOL_DEFAULT_EXISTS") {
		t.Fatalf("second default = %d %s", status, body)
	}
}
