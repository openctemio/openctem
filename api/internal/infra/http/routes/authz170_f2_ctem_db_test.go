package routes

// Research 170 (assets authz audit, fork 2): proofs over the dsHarness.
// Each test states the secure behaviour; a FAIL demonstrates the bug.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func authz170Mount(t *testing.T, h *dsHarness) {
	t.Helper()
	log := logger.NewNop()
	auth := Middleware(h.dsAuth)
	registerCompensatingControlRoutes(h.router, handler.NewCompensatingControlHandler(h.db, log), auth, nil, passthrough)
	registerBusinessServiceRoutes(h.router, handler.NewBusinessServiceHandler(h.db, log).WithDataScope(h.enforcer), auth, nil, passthrough)
	registerScopingRoutes(h.router, handler.NewScopingHandler(postgres.NewScopingSummaryRepository(&postgres.DB{DB: h.db}), log), auth, nil)
}

func authz170Do(t *testing.T, h *dsHarness, user shared.ID, admin bool, perms []string, method, path string, body any) (int, string) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, rdr)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-User", user.String())
	if admin {
		req.Header.Set("X-Test-Admin", "1")
	}
	req.Header.Set("X-Test-Perms", strings.Join(perms, ","))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

// A scoped member (member role holds compensating_controls:write) must not be
// able to attach a compensating control to an asset or finding outside their
// data scope: the link lowers the priority of findings they cannot see.
func TestAuthz170F2_CompensatingControlLink_OutOfScope(t *testing.T) {
	h := newDSHarness(t)
	authz170Mount(t, h)
	ctrl := shared.NewID()
	h.exec(`INSERT INTO compensating_controls (id, tenant_id, name, control_type, status, reduction_factor)
		VALUES ($1, $2, 'ctl', 'segmentation', 'active', 0.9)`, ctrl.String(), h.tenant.String())
	perms := []string{permission.CompensatingControlsWrite.String(), permission.CompensatingControlsRead.String()}
	base := "/api/v1/compensating-controls/" + ctrl.String()

	status, body := authz170Do(t, h, h.memberA, false, perms, http.MethodPost, base+"/assets",
		map[string]any{"asset_ids": []string{h.assetB.String()}})
	var n int
	_ = h.db.QueryRow(`SELECT count(*) FROM compensating_control_assets WHERE control_id=$1 AND asset_id=$2`, ctrl.String(), h.assetB.String()).Scan(&n)
	if n != 0 {
		t.Errorf("scoped member linked out-of-scope asset B1 to a control (status %d, body %.200s)", status, body)
	}

	status, body = authz170Do(t, h, h.memberA, false, perms, http.MethodPost, base+"/findings",
		map[string]any{"finding_ids": []string{h.findingB.String()}})
	_ = h.db.QueryRow(`SELECT count(*) FROM compensating_control_findings WHERE control_id=$1 AND finding_id=$2`, ctrl.String(), h.findingB.String()).Scan(&n)
	if n != 0 {
		t.Errorf("scoped member linked out-of-scope finding FB to a control (status %d, body %.200s)", status, body)
	}
}

// A scoped member must not change the criticality of a business service
// that links an asset outside their scope (owner decision A8): business
// service criticality raises the effective criticality of every linked asset.
// The list's asset_count must also not count out-of-scope links.
func TestAuthz170F2_BusinessService_OutOfScopeWriteAndCount(t *testing.T) {
	h := newDSHarness(t)
	authz170Mount(t, h)
	svc := shared.NewID()
	h.exec(`INSERT INTO business_services (id, tenant_id, name, criticality) VALUES ($1, $2, 'payments', 'low')`, svc.String(), h.tenant.String())
	h.exec(`INSERT INTO business_service_assets (tenant_id, service_id, asset_id) VALUES ($1, $2, $3)`, h.tenant.String(), svc.String(), h.assetB.String())
	perms := []string{permission.BusinessServicesRead.String(), permission.BusinessServicesWrite.String()}

	status, body := authz170Do(t, h, h.memberA, false, perms, http.MethodGet, "/api/v1/business-services/", nil)
	if status == http.StatusOK && strings.Contains(body, `"asset_count":1`) {
		t.Errorf("scoped member sees asset_count=1 for a service whose only asset is out of scope: %.300s", body)
	}

	status, body = authz170Do(t, h, h.memberA, false, perms, http.MethodPut, "/api/v1/business-services/"+svc.String(),
		map[string]any{"name": "payments", "criticality": "critical"})
	var crit string
	_ = h.db.QueryRow(`SELECT criticality FROM business_services WHERE id=$1`, svc.String()).Scan(&crit)
	if crit == "critical" {
		t.Errorf("scoped member raised criticality of a service linking out-of-scope asset B1 (status %d, body %.200s)", status, body)
	}
}

// /scoping/summary must count only what the caller may see (L-18).
func TestAuthz170F2_ScopingSummary_TenantWideCounts(t *testing.T) {
	h := newDSHarness(t)
	authz170Mount(t, h)
	h.exec(`UPDATE assets SET is_crown_jewel = TRUE WHERE id = $1`, h.assetB.String())
	status, body := authz170Do(t, h, h.memberA, false, []string{permission.AssetsRead.String()}, http.MethodGet, "/api/v1/scoping/summary", nil)
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
