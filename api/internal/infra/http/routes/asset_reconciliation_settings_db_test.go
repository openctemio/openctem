package routes

// Asset source precedence settings (RFC-069) over the real routes and a
// migrated database: only an owner or administrator changes them, an invalid
// policy is refused, and one organization's save never touches another's.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

type arsHarness struct {
	t                *testing.T
	db               *sql.DB
	srv              *httptest.Server
	tenantA, tenantB shared.ID
}

func newARSHarness(t *testing.T) *arsHarness {
	t.Helper()
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set to a test database; skipping settings DB test")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	h := &arsHarness{t: t, db: db, tenantA: shared.NewID(), tenantB: shared.NewID()}
	for _, id := range []shared.ID{h.tenantA, h.tenantB} {
		if _, err := db.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, id.String(), "ars-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM tenants WHERE id = ANY($1::uuid[])`, "{"+h.tenantA.String()+","+h.tenantB.String()+"}")
	})
	pg := &postgres.DB{DB: db}
	log := logger.NewNop()
	router := infrahttp.NewChiRouter()
	tenantSvc := tenantapp.NewTenantService(postgres.NewTenantRepository(pg), log)
	registerAssetReconciliationSettingsRoutes(router, handler.NewTenantHandler(tenantSvc, validator.New(), log), Middleware(h.auth), nil)
	h.srv = httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(h.srv.Close)
	return h
}

func (h *arsHarness) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, middleware.UserIDKey, shared.NewID().String())
		ctx = context.WithValue(ctx, middleware.TenantIDKey, h.tenantA.String())
		ctx = context.WithValue(ctx, middleware.IsAdminKey, r.Header.Get("X-Test-Admin") == "1")
		ctx = context.WithValue(ctx, middleware.PermissionsKey, []string{"settings:read", "settings:write"})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *arsHarness) do(admin bool, method string, body any) (int, string) {
	h.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, h.srv.URL+"/api/v1/organization/settings/asset-reconciliation", &buf)
	req.Header.Set("Content-Type", "application/json")
	if admin {
		req.Header.Set("X-Test-Admin", "1")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out bytes.Buffer
	_, _ = out.ReadFrom(resp.Body)
	return resp.StatusCode, out.String()
}

func (h *arsHarness) stored(id shared.ID) string {
	h.t.Helper()
	var s sql.NullString
	if err := h.db.QueryRow(`SELECT settings->'asset_reconciliation' FROM tenants WHERE id = $1`, id.String()).Scan(&s); err != nil {
		h.t.Fatal(err)
	}
	return s.String
}

func TestAssetReconciliationSettings_AdminSavesValidPolicy(t *testing.T) {
	h := newARSHarness(t)
	status, body := h.do(true, http.MethodGet, nil)
	if status != http.StatusOK || !strings.Contains(body, `"defaults"`) {
		t.Fatalf("get = %d %.300s", status, body)
	}
	status, body = h.do(true, http.MethodPut, map[string]any{
		"precedence": map[string][]string{"criticality": {"import", "integration"}},
		"ttl_days":   map[string]int{"scan": 7},
	})
	if status != http.StatusOK {
		t.Fatalf("put = %d %.300s", status, body)
	}
	var got struct {
		Effective struct {
			Precedence map[string][]string `json:"precedence"`
			TTLDays    map[string]int      `json:"ttl_days"`
		} `json:"effective"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if p := got.Effective.Precedence["criticality"]; len(p) != 3 || p[0] != "manual" || p[1] != "import" {
		t.Errorf("effective criticality precedence = %v", p)
	}
	if got.Effective.TTLDays["scan"] != 7 || got.Effective.TTLDays["integration"] != 30 {
		t.Errorf("effective ttl = %v", got.Effective.TTLDays)
	}
	if !strings.Contains(h.stored(h.tenantA), "import") {
		t.Errorf("not stored: %s", h.stored(h.tenantA))
	}
	if s := h.stored(h.tenantB); s != "" && s != "null" {
		t.Errorf("another organization's settings changed: %s", s)
	}
}

func TestAssetReconciliationSettings_RefusesInvalidAndNonAdmin(t *testing.T) {
	h := newARSHarness(t)
	for _, body := range []map[string]any{
		{"precedence": map[string][]string{"criticality": {"manual"}}},
		{"precedence": map[string][]string{"hostname": {"scan"}}},
		{"ttl_days": map[string]int{"scan": -1}},
		{"precedence": map[string][]string{}, "extra": true},
	} {
		if status, resp := h.do(true, http.MethodPut, body); status != http.StatusBadRequest {
			t.Errorf("%v = %d, want 400 (%.200s)", body, status, resp)
		}
	}
	if status, resp := h.do(false, http.MethodPut, map[string]any{"ttl_days": map[string]int{"scan": 1}}); status != http.StatusForbidden {
		t.Errorf("member put = %d, want 403 (%.200s)", status, resp)
	}
	if s := h.stored(h.tenantA); s != "" && s != "null" {
		t.Errorf("a refused save was stored: %s", s)
	}
}
