package handler

// POST /exposures and POST /exposures/ingest against real Postgres: an
// exposure's asset_id must be a live asset of the caller's tenant that the
// caller may see. exposure_events.asset_id references assets(id) without the
// tenant, so before the check a member of tenant A could point an exposure at
// tenant B's asset (and probe which ids exist through the FK error).
// Research doc 21b, C3.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/exposure"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

func TestExposureCreateIngest_AssetTenantAndScope_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed handler test")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer raw.Close()
	ctx := context.Background()
	if err := raw.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := raw.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}

	tenantA, tenantB := shared.NewID().String(), shared.NewID().String()
	admin, scoped := shared.NewID().String(), shared.NewID().String()
	inScope, outScope, deleted, foreign := shared.NewID().String(), shared.NewID().String(), shared.NewID().String(), shared.NewID().String()
	for _, tn := range []string{tenantA, tenantB} {
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'exa', $2)`, tn, "exa-"+tn)
	}
	t.Cleanup(func() {
		bg := context.Background()
		for _, tn := range []string{tenantA, tenantB} {
			_, _ = raw.ExecContext(bg, `DELETE FROM exposure_events WHERE tenant_id = $1`, tn)
			_, _ = raw.ExecContext(bg, `DELETE FROM tenants WHERE id = $1`, tn)
		}
		for _, u := range []string{admin, scoped} {
			_, _ = raw.ExecContext(bg, `DELETE FROM users WHERE id = $1`, u)
		}
	})
	for _, u := range []string{admin, scoped} {
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'exa')`, u, u+"@exa.test")
	}
	for id, tn := range map[string]string{inScope: tenantA, outScope: tenantA, deleted: tenantA, foreign: tenantB} {
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'domain', 'public', 'high')`,
			id, tn, "exa-"+id+".example.com")
	}
	exec(`UPDATE assets SET deleted_at = now() WHERE id = $1`, deleted)
	exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		scoped, tenantA, inScope)

	db := &postgres.DB{DB: raw}
	enforcer := datascope.New(postgres.NewDataScopeRepository(db),
		func(ctx context.Context) datascope.Caller {
			return datascope.Caller{UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx)}
		}, logger.NewNop())
	svc := exposure.NewExposureService(postgres.NewExposureRepository(db), postgres.NewExposureStateHistoryRepository(db), logger.NewNop())
	svc.SetDataScope(enforcer)
	h := NewExposureHandler(svc, nil, validator.New(), logger.NewNop())

	n := 0
	body := func(assetID string) map[string]any {
		n++
		return map[string]any{
			"asset_id": assetID, "event_type": "port_open", "severity": "high", "source": "exa",
			"title": "exa exposure " + string(rune('a'+n)),
		}
	}
	as := func(user string, isAdmin bool, payload any) *http.Request {
		b, _ := json.Marshal(payload)
		r := pentestDBRequest(http.MethodPost, "/", tenantA, string(b), nil)
		c := context.WithValue(r.Context(), middleware.UserIDKey, user)
		c = context.WithValue(c, middleware.IsAdminKey, isAdmin)
		return r.WithContext(c)
	}
	create := func(user string, isAdmin bool, assetID string) (int, string) {
		t.Helper()
		w := httptest.NewRecorder()
		h.Create(w, as(user, isAdmin, body(assetID)))
		return w.Code, w.Body.String()
	}
	type ingestResult struct {
		Ingested int `json:"ingested"`
		Failed   int `json:"failed"`
		Errors   []struct {
			Index  int    `json:"index"`
			Reason string `json:"reason"`
		} `json:"errors"`
	}
	ingest := func(user string, isAdmin bool, assetIDs ...string) ingestResult {
		t.Helper()
		items := make([]any, 0, len(assetIDs))
		for _, a := range assetIDs {
			items = append(items, body(a))
		}
		w := httptest.NewRecorder()
		h.BulkIngest(w, as(user, isAdmin, map[string]any{"exposures": items}))
		if w.Code != http.StatusCreated {
			t.Fatalf("ingest = %d (%s)", w.Code, w.Body.String())
		}
		var res ingestResult
		_ = json.Unmarshal(w.Body.Bytes(), &res)
		return res
	}

	// Create: cross-tenant refused for an admin too, identical to unknown.
	fStatus, fBody := create(admin, true, foreign)
	if fStatus != http.StatusNotFound {
		t.Errorf("create on a tenant B asset = %d, want 404 (%s)", fStatus, fBody)
	}
	uStatus, uBody := create(admin, true, shared.NewID().String())
	if uStatus != fStatus || uBody != fBody {
		t.Errorf("foreign id answered %d %q, unknown id %d %q: must be identical", fStatus, fBody, uStatus, uBody)
	}
	if status, _ := create(admin, true, deleted); status != http.StatusNotFound {
		t.Errorf("create on a deleted asset = %d, want 404", status)
	}
	if status, body := create(scoped, false, outScope); status != http.StatusNotFound {
		t.Errorf("scoped member, out-of-scope asset = %d, want 404 (%s)", status, body)
	}
	if status, body := create(scoped, false, inScope); status != http.StatusCreated {
		t.Errorf("scoped member, in-scope asset = %d, want 201 (%s)", status, body)
	}
	if status, body := create(admin, true, outScope); status != http.StatusCreated {
		t.Errorf("admin, own-tenant asset = %d, want 201 (%s)", status, body)
	}

	// Ingest: refused items are dropped with one generic reason.
	res := ingest(admin, true, inScope, foreign, shared.NewID().String(), deleted)
	if res.Ingested != 1 || res.Failed != 3 {
		t.Errorf("admin ingest = %d ingested / %d failed, want 1 / 3 (%+v)", res.Ingested, res.Failed, res.Errors)
	}
	for _, e := range res.Errors {
		if e.Reason != "asset not found" {
			t.Errorf("ingest error %d reason %q, want the generic one", e.Index, e.Reason)
		}
	}
	res = ingest(scoped, false, inScope, outScope)
	if res.Ingested != 1 || res.Failed != 1 || len(res.Errors) != 1 || res.Errors[0].Index != 1 {
		t.Errorf("scoped ingest = %+v, want only the out-of-scope item (index 1) refused", res)
	}

	var stray int
	if err := raw.QueryRowContext(ctx, `SELECT COUNT(*) FROM exposure_events WHERE asset_id = ANY($1::uuid[])`,
		"{"+foreign+","+deleted+"}").Scan(&stray); err != nil {
		t.Fatal(err)
	}
	if stray != 0 {
		t.Errorf("%d exposure(s) stored on a foreign or deleted asset", stray)
	}
	var outScopeByScoped int
	if err := raw.QueryRowContext(ctx, `SELECT COUNT(*) FROM exposure_events WHERE tenant_id = $1 AND asset_id = $2`,
		tenantA, outScope).Scan(&outScopeByScoped); err != nil {
		t.Fatal(err)
	}
	if outScopeByScoped != 1 { // the admin's create only
		t.Errorf("%d exposure(s) on the out-of-scope asset, want 1 (the admin's)", outScopeByScoped)
	}

	// H1 (RFC-050 W1): an asset-less exposure is full-data only (D11). The
	// administrator records a critical one; a restricted member can neither
	// create one nor downgrade it by ingesting the same fingerprint.
	assetless := func(severity string) map[string]any {
		return map[string]any{"event_type": "port_open", "severity": severity, "source": "exa", "title": "exa assetless"}
	}
	w := httptest.NewRecorder()
	h.Create(w, as(admin, true, assetless("critical")))
	if w.Code != http.StatusCreated {
		t.Fatalf("admin asset-less create = %d (%s), want 201", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.Create(w, as(scoped, false, assetless("info")))
	if w.Code != http.StatusBadRequest {
		t.Errorf("scoped member asset-less create = %d (%s), want 400", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.BulkIngest(w, as(scoped, false, map[string]any{"exposures": []any{assetless("info"), body(inScope)}}))
	var bulk ingestResult
	_ = json.Unmarshal(w.Body.Bytes(), &bulk)
	if w.Code != http.StatusCreated || bulk.Ingested != 1 || bulk.Failed != 1 || len(bulk.Errors) != 1 ||
		bulk.Errors[0].Index != 0 || bulk.Errors[0].Reason != "asset_id is required" {
		t.Errorf("scoped bulk with an asset-less item = %d %+v, want the asset-less item refused", w.Code, bulk)
	}
	var sev string
	if err := raw.QueryRowContext(ctx, `SELECT severity FROM exposure_events
		WHERE tenant_id = $1 AND asset_id IS NULL AND title = 'exa assetless'`, tenantA).Scan(&sev); err != nil {
		t.Fatal(err)
	}
	if sev != "critical" {
		t.Errorf("asset-less exposure severity = %q after a restricted ingest, want critical (not downgraded)", sev)
	}
}
