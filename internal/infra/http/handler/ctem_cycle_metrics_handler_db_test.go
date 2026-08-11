package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	_ "github.com/lib/pq"

	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// TestCTEMCycleMetricsHandler_LazyAndTrend drives the two read endpoints
// end-to-end against app_test: lazy compute-on-read for a closed cycle
// with no stored metrics, and the trend/maturity response shape. Skipped
// unless DATABASE_URL is set.
func TestCTEMCycleMetricsHandler_LazyAndTrend(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
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

	tenantID := shared.NewID()
	slug := "ctemx-" + tenantID.String()[:8]
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO tenants (id, name, slug) VALUES ($1,'ctem-metrics-http',$2)`,
		tenantID.String(), slug); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	defer func() { _, _ = raw.ExecContext(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID.String()) }()

	assetID := shared.NewID()
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1,$2,'a','host')`,
		assetID.String(), tenantID.String()); err != nil {
		t.Fatalf("seed asset: %v", err)
	}

	base := time.Now().UTC().Truncate(time.Second)
	var cycleID string
	if err := raw.QueryRowContext(ctx,
		`INSERT INTO ctem_cycles (tenant_id, name, status, created_by, activated_at, closed_at)
		 VALUES ($1,'http cycle','closed',$2,$3,$4) RETURNING id`,
		tenantID.String(), shared.NewID().String(),
		base.Add(-10*24*time.Hour), base,
	).Scan(&cycleID); err != nil {
		t.Fatalf("seed cycle: %v", err)
	}
	// One finding opened AND resolved within the window so metrics are non-zero.
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO findings
		   (tenant_id, asset_id, source, tool_name, message, severity, status, fingerprint, created_at, resolved_at)
		 VALUES ($1,$2,'sast','tool','msg','high','resolved',$3,$4,$5)`,
		tenantID.String(), assetID.String(), "fp-"+cycleID[:8],
		base.Add(-5*24*time.Hour), base.Add(-2*24*time.Hour)); err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	repo := postgres.NewCTEMCycleMetricsRepository(&postgres.DB{DB: raw})
	h := NewCTEMCycleHandler(raw, repo, logger.NewNop())

	// --- lazy compute-on-read: no metrics stored yet ---
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ctem-cycles/"+cycleID+"/metrics", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", cycleID)
	reqCtx := context.WithValue(req.Context(), middleware.TenantIDKey, tenantID.String())
	reqCtx = context.WithValue(reqCtx, chi.RouteCtxKey, rctx)
	req = req.WithContext(reqCtx)

	w := httptest.NewRecorder()
	h.GetMetrics(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GetMetrics status = %d, body=%s", w.Code, w.Body.String())
	}
	var metricsResp struct {
		ComputedLazily bool               `json:"computed_lazily"`
		Values         map[string]float64 `json:"values"`
		Metrics        []struct {
			MetricType string `json:"metric_type"`
		} `json:"metrics"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &metricsResp); err != nil {
		t.Fatalf("decode metrics: %v (body=%s)", err, w.Body.String())
	}
	if !metricsResp.ComputedLazily {
		t.Errorf("expected computed_lazily=true on first read of a closed cycle")
	}
	if len(metricsResp.Metrics) != 6 {
		t.Errorf("want 6 metric rows, got %d", len(metricsResp.Metrics))
	}
	if metricsResp.Values["findings_opened"] != 1 || metricsResp.Values["findings_resolved"] != 1 {
		t.Errorf("unexpected values: %#v", metricsResp.Values)
	}

	// --- trend endpoint shape ---
	treq := httptest.NewRequest(http.MethodGet, "/api/v1/ctem-cycles/metrics/trend", nil)
	treq = treq.WithContext(context.WithValue(treq.Context(), middleware.TenantIDKey, tenantID.String()))
	tw := httptest.NewRecorder()
	h.MetricsTrend(tw, treq)
	if tw.Code != http.StatusOK {
		t.Fatalf("MetricsTrend status = %d, body=%s", tw.Code, tw.Body.String())
	}
	var trend struct {
		CyclesAnalyzed int              `json:"cycles_analyzed"`
		Series         map[string][]any `json:"series"`
		Maturity       struct {
			Score      float64          `json:"score"`
			Components []map[string]any `json:"components"`
			Stage      struct {
				CoveredCount int `json:"covered_count"`
			} `json:"ctem_stage_coverage"`
		} `json:"maturity"`
	}
	if err := json.Unmarshal(tw.Body.Bytes(), &trend); err != nil {
		t.Fatalf("decode trend: %v (body=%s)", err, tw.Body.String())
	}
	if trend.CyclesAnalyzed < 1 {
		t.Errorf("cycles_analyzed = %d, want >=1", trend.CyclesAnalyzed)
	}
	for _, key := range []string{
		"mttr_hours", "findings_opened", "findings_resolved",
		"p_class_churn", "validation_coverage", "scope_drift_size",
	} {
		if _, ok := trend.Series[key]; !ok {
			t.Errorf("series missing metric %q", key)
		}
	}
	if len(trend.Maturity.Components) != 5 {
		t.Errorf("maturity components = %d, want 5", len(trend.Maturity.Components))
	}
}
