package handler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// TestPriorityRuleHandler_MutationsEnqueueReclassify proves rule create, a
// decision change and delete each record a tenant scoring change and queue
// the assets of the tenant's open findings (the rules trigger), while a
// rename records nothing and closed findings and other tenants are never
// queued.
//
// DB-gated: needs DATABASE_URL pointing at app_test (never the live DB).
func TestPriorityRuleHandler_MutationsEnqueueReclassify(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	ctx := context.Background()

	// Seed a tenant + user to satisfy FK / uuid columns.
	tenantID := shared.NewID()
	userID := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		tenantID.String(), "reclassify-test", "reclassify-test-"+tenantID.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM findings WHERE tenant_id = $1`, tenantID.String())
		_, _ = db.ExecContext(ctx, `DELETE FROM assets WHERE tenant_id = $1`, tenantID.String())
		_, _ = db.ExecContext(ctx, `DELETE FROM priority_override_rules WHERE tenant_id = $1`, tenantID.String())
		_, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID.String())
	})
	// One asset with an open finding, one with only a closed finding.
	openAsset, closedAsset := shared.NewID(), shared.NewID()
	for _, a := range []shared.ID{openAsset, closedAsset} {
		if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, criticality) VALUES ($1, $2, $3, 'domain', 'medium')`,
			a.String(), tenantID.String(), "rule-it-"+a.String()); err != nil {
			t.Fatalf("seed asset: %v", err)
		}
	}
	for _, f := range []struct {
		asset  shared.ID
		status string
	}{{openAsset, "new"}, {closedAsset, "resolved"}} {
		if _, err := db.ExecContext(ctx, `INSERT INTO findings (tenant_id, asset_id, source, tool_name, severity, message, fingerprint, status)
			VALUES ($1, $2, 'manual', 'it', 'high', 'rule it', $3, $4)`,
			tenantID.String(), f.asset.String(), "rule-it-"+f.asset.String(), f.status); err != nil {
			t.Fatalf("seed finding: %v", err)
		}
	}
	queued := func() map[string]bool {
		rows, err := db.QueryContext(ctx, `SELECT asset_id FROM finding_priority_queue WHERE tenant_id = $1 AND reason = 'scoring_change' AND scoring_change_id IS NOT NULL`, tenantID.String())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		out := map[string]bool{}
		for rows.Next() {
			var id string
			_ = rows.Scan(&id)
			out[id] = true
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	clearQueue := func() {
		if _, err := db.ExecContext(ctx, `DELETE FROM finding_priority_queue WHERE tenant_id = $1`, tenantID.String()); err != nil {
			t.Fatal(err)
		}
	}
	changes := func() int {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scoring_changes WHERE tenant_id = $1 AND kind = 'finding_priority' AND source = 'priority_rules'`, tenantID.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	expect := func(step string, wantChanges int) {
		t.Helper()
		if got := changes(); got != wantChanges {
			t.Fatalf("%s: scoring changes = %d, want %d", step, got, wantChanges)
		}
		q := queued()
		if wantChanges > 0 && !q[openAsset.String()] {
			t.Fatalf("%s: the asset with an open finding was not queued", step)
		}
		if q[closedAsset.String()] {
			t.Fatalf("%s: an asset with only closed findings was queued", step)
		}
		clearQueue()
	}
	clearQueue()

	h := NewPriorityRuleHandler(db, logger.NewNop())

	withCtx := func(r *http.Request) *http.Request {
		c := context.WithValue(r.Context(), middleware.TenantIDKey, tenantID.String())
		c = context.WithValue(c, middleware.UserIDKey, userID.String())
		return r.WithContext(c)
	}

	// --- Create ---
	body, _ := json.Marshal(map[string]any{
		"name": "esc P0", "priority_class": "P0", "is_active": true, "conditions": json.RawMessage(`[{"field":"is_in_kev","operator":"eq","value":true}]`),
	})
	rec := httptest.NewRecorder()
	h.Create(rec, withCtx(httptest.NewRequest(http.MethodPost, "/priority-rules", bytes.NewReader(body))))
	if rec.Code != http.StatusCreated {
		t.Fatalf("Create status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("decode create response: %v (%s)", err, rec.Body.String())
	}
	expect("create", 1)

	// A rename changes no decision: nothing is recorded or queued.
	nameBody, _ := json.Marshal(map[string]any{"name": "renamed"})
	rec = httptest.NewRecorder()
	nreq := withURLParam(withCtx(httptest.NewRequest(http.MethodPut, "/priority-rules/"+created.ID, bytes.NewReader(nameBody))), "id", created.ID)
	h.Update(rec, nreq)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("rename status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if got := changes(); got != 1 {
		t.Fatalf("rename recorded a scoring change (total %d)", got)
	}
	if len(queued()) != 0 {
		t.Fatal("rename queued findings")
	}

	// --- Update ---
	upBody, _ := json.Marshal(map[string]any{"priority_class": "P1"})
	rec = httptest.NewRecorder()
	req := withCtx(httptest.NewRequest(http.MethodPut, "/priority-rules/"+created.ID, bytes.NewReader(upBody)))
	req = withURLParam(req, "id", created.ID)
	h.Update(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("Update status = %d, body=%s", rec.Code, rec.Body.String())
	}
	expect("update", 2)

	// --- Delete ---
	rec = httptest.NewRecorder()
	req = withCtx(httptest.NewRequest(http.MethodDelete, "/priority-rules/"+created.ID, nil))
	req = withURLParam(req, "id", created.ID)
	h.Delete(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("Delete status = %d, body=%s", rec.Code, rec.Body.String())
	}
	expect("delete", 3)

	// Another tenant saw nothing.
	var foreign int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM finding_priority_queue q JOIN assets a ON a.id = q.asset_id WHERE a.tenant_id = $1 AND q.tenant_id <> $1`, tenantID.String()).Scan(&foreign); err != nil {
		t.Fatal(err)
	}
	if foreign != 0 {
		t.Fatalf("%d queue rows point across tenants", foreign)
	}
}

// withURLParam injects a chi URL param into the request's route context.
func withURLParam(r *http.Request, key, val string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, val)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}
