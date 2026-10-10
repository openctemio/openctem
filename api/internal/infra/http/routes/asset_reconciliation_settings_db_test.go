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
	"time"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
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
	tenantRepo := postgres.NewTenantRepository(pg)
	tenantSvc := tenantapp.NewTenantService(tenantRepo, log)
	tenantSvc.SetStepUpGate(arsStepUp{})
	assetSvc := assetapp.NewAssetService(postgres.NewAssetRepository(pg), log)
	assetSvc.SetAttributeSources(postgres.NewAssetAttributeSourceRepository(pg), tenantRepo)
	changes := postgres.NewAssetChangeEventRepository(pg)
	assetSvc.SetChangeTimeline(changes)
	assetSvc.SetAttributeSourceLister(changes)
	tenantSvc.SetAssetPolicyListener(assetSvc)
	th := handler.NewTenantHandler(tenantSvc, validator.New(), log)
	th.SetAssetService(assetSvc)
	registerAssetReconciliationSettingsRoutes(router, th, Middleware(h.auth), nil)
	h.srv = httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(h.srv.Close)
	return h
}

// arsStepUp passes only a request marked as recently re-authenticated.
type arsStepUp struct{}

type arsRecentKey struct{}

func (arsStepUp) RequireRecentAuth(ctx context.Context, _ string) error {
	if ctx.Value(arsRecentKey{}) == true {
		return nil
	}
	return middleware.ErrStepUpRequired
}

func (h *arsHarness) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, middleware.UserIDKey, shared.NewID().String())
		ctx = context.WithValue(ctx, middleware.TenantIDKey, h.tenantA.String())
		ctx = context.WithValue(ctx, middleware.IsAdminKey, r.Header.Get("X-Test-Admin") == "1")
		ctx = context.WithValue(ctx, middleware.PermissionsKey, []string{"settings:read", "settings:write"})
		ctx = context.WithValue(ctx, arsRecentKey{}, r.Header.Get("X-Test-Recent") == "1")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *arsHarness) do(admin bool, method string, body any) (int, string) {
	return h.doAt(admin, false, method, "", body)
}

func (h *arsHarness) doAt(admin, recent bool, method, sub string, body any) (int, string) {
	h.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, h.srv.URL+"/api/v1/organization/settings/asset-reconciliation"+sub, &buf)
	req.Header.Set("Content-Type", "application/json")
	if admin {
		req.Header.Set("X-Test-Admin", "1")
	}
	if recent {
		req.Header.Set("X-Test-Recent", "1")
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

func rules(rs ...map[string]any) []map[string]any { return rs }

func row(src string, ttl int, trusted bool) map[string]any {
	return map[string]any{"source": src, "ttl_days": ttl, "trusted": trusted}
}

// seedAsset creates an asset of tenant with criticality crit and the given
// observations (kind, name, value, minutes ago).
func (h *arsHarness) seedAsset(tenant shared.ID, crit string, obs ...[4]string) string {
	h.t.Helper()
	id := shared.NewID().String()
	if _, err := h.db.Exec(`INSERT INTO assets (id, tenant_id, name, asset_type, criticality) VALUES ($1, $2, $3, 'domain', $4)`,
		id, tenant.String(), "ars-"+id+".example.com", crit); err != nil {
		h.t.Fatal(err)
	}
	for _, o := range obs {
		if _, err := h.db.Exec(`INSERT INTO asset_attribute_sources (tenant_id, asset_id, attribute, source_kind, source_name, value, observed_at, ingested_at)
			VALUES ($1, $2, 'criticality', $3, $4, $5, now() - ($6 || ' minutes')::interval, now())`,
			tenant.String(), id, o[0], o[1], o[2], o[3]); err != nil {
			h.t.Fatal(err)
		}
	}
	return id
}

func (h *arsHarness) criticality(id string) string {
	h.t.Helper()
	var c string
	if err := h.db.QueryRow(`SELECT criticality FROM assets WHERE id = $1`, id).Scan(&c); err != nil {
		h.t.Fatal(err)
	}
	return c
}

func TestAssetReconciliationSettings_AdminSavesValidPolicy(t *testing.T) {
	h := newARSHarness(t)
	h.seedAsset(h.tenantA, "high", [4]string{"scan", "nmap", "low", "5"})
	status, body := h.do(true, http.MethodGet, nil)
	if status != http.StatusOK || !strings.Contains(body, `"defaults"`) || !strings.Contains(body, `"name":"nmap"`) {
		t.Fatalf("get = %d %.400s", status, body)
	}
	var got struct {
		Classes []struct {
			Class      string   `json:"class"`
			Attributes []string `json:"attributes"`
		} `json:"classes"`
	}
	_ = json.Unmarshal([]byte(body), &got)
	if len(got.Classes) != 6 {
		t.Fatalf("classes = %+v", got.Classes)
	}

	// No connector demoted (it stays first): saved without step-up.
	status, body = h.do(true, http.MethodPut, map[string]any{
		"default": rules(row("integration", 30, true), row("scan:nmap", 7, true), row("scan", 30, true)),
		"classes": map[string]any{"ownership": rules(row("integration", 30, true), row("import", 90, true))},
	})
	if status != http.StatusOK {
		t.Fatalf("put = %d %.300s", status, body)
	}
	var saved struct {
		Effective struct {
			Default []struct {
				Source  string `json:"source"`
				TTLDays int    `json:"ttl_days"`
			} `json:"default"`
			Classes map[string]json.RawMessage `json:"classes"`
		} `json:"effective"`
	}
	_ = json.Unmarshal([]byte(body), &saved)
	if len(saved.Effective.Default) != 3 || saved.Effective.Default[1].Source != "scan:nmap" || saved.Effective.Default[1].TTLDays != 7 {
		t.Errorf("effective default = %+v", saved.Effective.Default)
	}
	if _, ok := saved.Effective.Classes["ownership"]; !ok {
		t.Errorf("ownership override missing: %v", saved.Effective.Classes)
	}
	if !strings.Contains(h.stored(h.tenantA), "scan:nmap") {
		t.Errorf("not stored: %s", h.stored(h.tenantA))
	}
	if s := h.stored(h.tenantB); s != "" && s != "null" {
		t.Errorf("another organization's settings changed: %s", s)
	}
}

func TestAssetReconciliationSettings_DemotingAConnectorNeedsStepUp(t *testing.T) {
	h := newARSHarness(t)
	importFirst := map[string]any{
		"default": rules(row("import", 90, true), row("integration", 30, true), row("scan", 30, true)),
		"classes": map[string]any{"ownership": rules(row("import", 90, true), row("integration", 30, true))},
	}
	status, body := h.doAt(true, false, http.MethodPut, "", importFirst)
	if status != http.StatusForbidden || !strings.Contains(body, "STEP_UP_REQUIRED") {
		t.Fatalf("demotion without step-up = %d %.300s", status, body)
	}
	if s := h.stored(h.tenantA); s != "" && s != "null" {
		t.Fatalf("a refused demotion was stored: %s", s)
	}
	if status, body = h.doAt(true, true, http.MethodPut, "", importFirst); status != http.StatusOK {
		t.Fatalf("demotion after step-up = %d %.300s", status, body)
	}
}

func TestAssetReconciliationSettings_PreviewAndBackgroundReResolve(t *testing.T) {
	h := newARSHarness(t)
	// The connector says high (an hour ago), an import says low (now).
	a := h.seedAsset(h.tenantA, "high", [4]string{"integration", "cmdb", "high", "60"}, [4]string{"import", "csv", "low", "1"})
	h.seedAsset(h.tenantB, "high", [4]string{"integration", "cmdb", "high", "60"}, [4]string{"import", "csv", "low", "1"})
	// Resolve once so the connector is flagged as deciding.
	importFirst := map[string]any{
		"default": rules(row("import", 90, true), row("integration", 30, true)),
		"classes": map[string]any{"ownership": rules(row("import", 90, true), row("integration", 30, true))},
	}

	status, body := h.doAt(true, false, http.MethodPost, "/preview", importFirst)
	if status != http.StatusOK {
		t.Fatalf("preview = %d %.300s", status, body)
	}
	var pv struct {
		ScannedAssets int `json:"scanned_assets"`
		ChangedAssets int `json:"changed_assets"`
		Samples       []struct {
			AssetID, Current, Next, NextSource string
		} `json:"samples"`
	}
	_ = json.Unmarshal([]byte(body), &pv)
	if pv.ScannedAssets != 1 || pv.ChangedAssets != 1 || len(pv.Samples) != 1 || pv.Samples[0].Next != "low" {
		t.Fatalf("preview (only this organization's asset) = %.400s", body)
	}
	if h.criticality(a) != "high" {
		t.Fatal("a preview changed the asset")
	}
	// One asset, and another organization's asset is not found.
	if status, body = h.doAt(true, false, http.MethodPost, "/preview", map[string]any{"default": importFirst["default"], "classes": importFirst["classes"], "asset_id": a}); status != http.StatusOK || !strings.Contains(body, `"changed_values":1`) {
		t.Fatalf("one-asset preview = %d %.300s", status, body)
	}
	if status, _ = h.doAt(true, false, http.MethodPost, "/preview", map[string]any{"asset_id": shared.NewID().String()}); status != http.StatusNotFound {
		t.Fatalf("unknown asset preview = %d, want 404", status)
	}
	if status, _ = h.doAt(false, false, http.MethodPost, "/preview", importFirst); status != http.StatusForbidden {
		t.Fatalf("member preview = %d, want 403", status)
	}

	// Saving re-resolves in the background: the asset follows the import and
	// the timeline says why.
	if status, body = h.doAt(true, true, http.MethodPut, "", importFirst); status != http.StatusOK {
		t.Fatalf("save = %d %.300s", status, body)
	}
	deadline := time.Now().Add(10 * time.Second)
	for h.criticality(a) != "low" {
		if time.Now().After(deadline) {
			t.Fatal("the asset was not re-resolved after the save")
		}
		time.Sleep(50 * time.Millisecond)
	}
	var reason string
	if err := h.db.QueryRow(`SELECT reason FROM asset_change_events WHERE tenant_id = $1 AND asset_id = $2 ORDER BY at DESC LIMIT 1`,
		h.tenantA.String(), a).Scan(&reason); err != nil || reason != "policy_change" {
		t.Fatalf("timeline reason = %q (%v), want policy_change", reason, err)
	}
	var otherCrit string
	_ = h.db.QueryRow(`SELECT criticality FROM assets WHERE tenant_id = $1`, h.tenantB.String()).Scan(&otherCrit)
	if otherCrit != "high" {
		t.Fatalf("another organization's asset was re-resolved: %s", otherCrit)
	}
}

func TestAssetReconciliationSettings_RefusesInvalidAndNonAdmin(t *testing.T) {
	h := newARSHarness(t)
	for _, body := range []map[string]any{
		{"default": rules(row("manual", 0, true))},
		{"classes": map[string]any{"hostname": rules(row("scan", 1, true))}},
		{"default": rules(row("scan", -1, true))},
		{"default": rules(row("scan", 1, true), row("scan", 2, true))},
		{"default": rules(), "extra": true},
	} {
		if status, resp := h.doAt(true, true, http.MethodPut, "", body); status != http.StatusBadRequest {
			t.Errorf("%v = %d, want 400 (%.200s)", body, status, resp)
		}
	}
	if status, resp := h.do(false, http.MethodPut, map[string]any{"default": rules(row("scan", 1, true))}); status != http.StatusForbidden {
		t.Errorf("member put = %d, want 403 (%.200s)", status, resp)
	}
	if s := h.stored(h.tenantA); s != "" && s != "null" {
		t.Errorf("a refused save was stored: %s", s)
	}
}
