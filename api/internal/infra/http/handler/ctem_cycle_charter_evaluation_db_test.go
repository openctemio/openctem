package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/ctemcycle"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// cycleRequest builds a request carrying the tenant/user context and the
// {id} route param, the way the router would.
func cycleRequest(method, path, tenantID, cycleID string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", cycleID)
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenantID)
	ctx = context.WithValue(ctx, middleware.UserIDKey, shared.NewID().String())
	ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	return req.WithContext(ctx)
}

func seedHandlerTenant(ctx context.Context, t *testing.T, db *sql.DB) string {
	t.Helper()
	id := shared.NewID().String()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO tenants (id, name, slug) VALUES ($1,'ctem-charter-eval',$2)`,
		id, "ctemev-"+id); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id=$1`, id) })
	return id
}

// TestCTEMCycleHandler_CloseEvaluatesCharter drives Close end-to-end: each
// charter criterion is judged against the cycle's metrics, the verdicts are
// returned and persisted, the completion rate lands in the cycle metrics,
// and another tenant can neither read nor close the cycle.
func TestCTEMCycleHandler_CloseEvaluatesCharter(t *testing.T) {
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

	tenantID := seedHandlerTenant(ctx, t, raw)
	otherTenant := seedHandlerTenant(ctx, t, raw)

	assetID := shared.NewID().String()
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1,$2,'a','host')`,
		assetID, tenantID); err != nil {
		t.Fatalf("seed asset: %v", err)
	}

	charter := `{"success_criteria":[
		{"name":"Resolve P0s","metric":"P0 resolved","target":">= 1"},
		{"name":"Fast fixes","metric":"MTTR","target":"<= 1 day"},
		{"name":"KEV","metric":"open KEV findings","target":"0"}]}`
	base := time.Now().UTC().Truncate(time.Second)
	var cycleID string
	if err := raw.QueryRowContext(ctx,
		`INSERT INTO ctem_cycles (tenant_id, name, status, created_by, activated_at, charter)
		 VALUES ($1,'close cycle','review',$2,$3,$4::jsonb) RETURNING id`,
		tenantID, shared.NewID().String(), base.Add(-10*24*time.Hour), charter,
	).Scan(&cycleID); err != nil {
		t.Fatalf("seed cycle: %v", err)
	}
	// One P0 finding resolved 72h after creation: P0 resolved = 1 (met),
	// MTTR = 72h > 24h (unmet).
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO findings
		   (tenant_id, asset_id, source, tool_name, message, severity, status,
		    fingerprint, created_at, resolved_at, priority_class)
		 VALUES ($1,$2,'sast','tool','msg','critical','resolved',$3,$4,$5,'P0')`,
		tenantID, assetID, "fp-"+cycleID,
		base.Add(-6*24*time.Hour), base.Add(-3*24*time.Hour)); err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	repo := postgres.NewCTEMCycleMetricsRepository(&postgres.DB{DB: raw})
	h := NewCTEMCycleHandler(raw, repo, logger.NewNop())

	// --- another tenant cannot close it ---
	w := httptest.NewRecorder()
	h.Close(w, cycleRequest(http.MethodPost, "/api/v1/ctem-cycles/"+cycleID+"/close", otherTenant, cycleID))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("foreign close status = %d, want 400; body=%s", w.Code, w.Body.String())
	}

	// --- owner closes ---
	w = httptest.NewRecorder()
	h.Close(w, cycleRequest(http.MethodPost, "/api/v1/ctem-cycles/"+cycleID+"/close", tenantID, cycleID))
	if w.Code != http.StatusOK {
		t.Fatalf("close status = %d; body=%s", w.Code, w.Body.String())
	}
	var closed CTEMCycleResponse
	if err := json.Unmarshal(w.Body.Bytes(), &closed); err != nil {
		t.Fatalf("decode close: %v", err)
	}
	ev := closed.CharterEvaluation
	if ev == nil {
		t.Fatalf("close response has no charter_evaluation: %s", w.Body.String())
	}
	if ev.Met != 1 || ev.Unmet != 1 || ev.NotMeasurable != 1 {
		t.Fatalf("counts met=%d unmet=%d nm=%d; %+v", ev.Met, ev.Unmet, ev.NotMeasurable, ev.Criteria)
	}
	if ev.CompletionRate == nil || *ev.CompletionRate != 50 {
		t.Fatalf("completion rate = %v, want 50", ev.CompletionRate)
	}
	if c := ev.Criteria[1]; c.Outcome != ctemcycle.CriterionUnmet || c.Actual == nil || *c.Actual != 72 || *c.Threshold != 24 {
		t.Fatalf("MTTR criterion = %+v", c)
	}
	if c := ev.Criteria[2]; c.Outcome != ctemcycle.CriterionNotMeasurable || c.Reason == "" {
		t.Fatalf("KEV criterion = %+v", c)
	}

	// --- persisted: Get returns it ---
	w = httptest.NewRecorder()
	h.Get(w, cycleRequest(http.MethodGet, "/api/v1/ctem-cycles/"+cycleID, tenantID, cycleID))
	if w.Code != http.StatusOK {
		t.Fatalf("get status = %d", w.Code)
	}
	var got CTEMCycleResponse
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.CharterEvaluation == nil || got.CharterEvaluation.Met != 1 {
		t.Fatalf("get did not return the persisted evaluation: %s", w.Body.String())
	}

	// --- completion rate is a cycle metric ---
	w = httptest.NewRecorder()
	h.GetMetrics(w, cycleRequest(http.MethodGet, "/api/v1/ctem-cycles/"+cycleID+"/metrics", tenantID, cycleID))
	var metrics struct {
		Values map[string]float64 `json:"values"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &metrics)
	if v, ok := metrics.Values[ctemcycle.MetricCharterCompletionRate]; !ok || v != 50 {
		t.Fatalf("charter_completion_rate = %v (present=%v); values=%v", v, ok, metrics.Values)
	}

	// --- another tenant cannot read the cycle or its metrics ---
	w = httptest.NewRecorder()
	h.Get(w, cycleRequest(http.MethodGet, "/api/v1/ctem-cycles/"+cycleID, otherTenant, cycleID))
	if w.Code != http.StatusNotFound {
		t.Fatalf("foreign get status = %d, want 404", w.Code)
	}
	w = httptest.NewRecorder()
	h.GetMetrics(w, cycleRequest(http.MethodGet, "/api/v1/ctem-cycles/"+cycleID+"/metrics", otherTenant, cycleID))
	if w.Code != http.StatusNotFound {
		t.Fatalf("foreign metrics status = %d, want 404", w.Code)
	}

	// --- list carries the evaluation too ---
	lreq := httptest.NewRequest(http.MethodGet, "/api/v1/ctem-cycles", nil)
	lreq = lreq.WithContext(context.WithValue(lreq.Context(), middleware.TenantIDKey, tenantID))
	w = httptest.NewRecorder()
	h.List(w, lreq)
	var list struct {
		Data []CTEMCycleResponse `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if len(list.Data) != 1 || list.Data[0].CharterEvaluation == nil {
		t.Fatalf("list = %s", w.Body.String())
	}
}

// TestCTEMCycleHandler_LazyEvaluation: a cycle closed before charter
// evaluation existed already has metrics stored, but no verdicts. Reading its
// metrics evaluates the charter once.
func TestCTEMCycleHandler_LazyEvaluation(t *testing.T) {
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
	tenantID := seedHandlerTenant(ctx, t, raw)

	base := time.Now().UTC().Truncate(time.Second)
	var cycleID string
	if err := raw.QueryRowContext(ctx,
		`INSERT INTO ctem_cycles (tenant_id, name, status, created_by, activated_at, closed_at, charter)
		 VALUES ($1,'old cycle','closed',$2,$3,$4,
		         '{"success_criteria":[{"name":"Nothing new","metric":"findings opened","target":"0"}]}'::jsonb)
		 RETURNING id`,
		tenantID, shared.NewID().String(), base.Add(-10*24*time.Hour), base,
	).Scan(&cycleID); err != nil {
		t.Fatalf("seed cycle: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO ctem_cycle_metrics (cycle_id, metric_type, value) VALUES ($1,'mttr_hours',0)`,
		cycleID); err != nil {
		t.Fatalf("seed old metric: %v", err)
	}

	repo := postgres.NewCTEMCycleMetricsRepository(&postgres.DB{DB: raw})
	h := NewCTEMCycleHandler(raw, repo, logger.NewNop())

	w := httptest.NewRecorder()
	h.GetMetrics(w, cycleRequest(http.MethodGet, "/api/v1/ctem-cycles/"+cycleID+"/metrics", tenantID, cycleID))
	if w.Code != http.StatusOK {
		t.Fatalf("metrics status = %d; body=%s", w.Code, w.Body.String())
	}

	var stored sql.NullString
	if err := raw.QueryRowContext(ctx,
		`SELECT charter_evaluation::text FROM ctem_cycles WHERE id=$1`, cycleID,
	).Scan(&stored); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !stored.Valid {
		t.Fatal("lazy path did not evaluate the charter")
	}
	var ev ctemcycle.CharterEvaluation
	_ = json.Unmarshal([]byte(stored.String), &ev)
	if ev.Met != 1 || len(ev.Criteria) != 1 {
		t.Fatalf("lazy evaluation = %+v", ev)
	}
}
