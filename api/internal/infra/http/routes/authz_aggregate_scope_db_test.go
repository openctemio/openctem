package routes

// Research 170 (assets authz audit, fork 2): proofs over the dsHarness.
// Each test states the secure behavior; a FAIL demonstrates the bug.

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// /scoping/summary must count only what the caller may see (L-18).
func TestAuthz170F2_ScopingSummary_TenantWideCounts(t *testing.T) {
	h := newDSHarness(t)
	registerScopingRoutes(h.router, handler.NewScopingHandler(postgres.NewScopingSummaryRepository(&postgres.DB{DB: h.db}), logger.NewNop()).WithDataScope(h.enforcer), Middleware(h.dsAuth), nil)
	h.exec(`UPDATE assets SET is_crown_jewel = TRUE WHERE id = $1`, h.assetB.String())
	status, body := h.do(h.memberA, false, http.MethodGet, "/api/v1/scoping/summary", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /scoping/summary = %d %.200s", status, body)
	}
	var s struct {
		CrownJewels struct{ Total int } `json:"crown_jewels"`
		Assets      struct{ Total int } `json:"assets"`
	}
	_ = json.Unmarshal([]byte(body), &s)
	if s.Assets.Total != 1 || s.CrownJewels.Total != 0 {
		t.Errorf("scoped member (1 asset in scope, 0 crown jewels) sees assets.total=%d crown_jewels.total=%d", s.Assets.Total, s.CrownJewels.Total)
	}
}

// /attack-surface/stats asset_breakdown and risk_score must follow the scope
// like total_assets does (L-18).
func TestAuthz170F2_AttackSurfaceStats_BreakdownTenantWide(t *testing.T) {
	h := newDSHarness(t)
	status, body := h.do(h.memberA, false, http.MethodGet, "/api/v1/attack-surface/stats", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /attack-surface/stats = %d %.200s", status, body)
	}
	var s struct {
		TotalAssets    int `json:"total_assets"`
		AssetBreakdown []struct {
			Type  string `json:"type"`
			Total int    `json:"total"`
		} `json:"asset_breakdown"`
	}
	_ = json.Unmarshal([]byte(body), &s)
	sum := 0
	for _, b := range s.AssetBreakdown {
		sum += b.Total
	}
	if sum != s.TotalAssets {
		t.Errorf("scoped member: total_assets=%d but asset_breakdown sums to %d (tenant-wide)", s.TotalAssets, sum)
	}
}
