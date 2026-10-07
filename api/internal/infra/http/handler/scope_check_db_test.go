package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/app/scopeauth"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

type fakeDryRun struct{ results []scansvc.DryRunResult }

func (f fakeDryRun) DryRunTargets(context.Context, scansvc.DryRunInput) ([]scansvc.DryRunResult, error) {
	return f.results, nil
}

type fakeCoverage struct{}

func (fakeCoverage) CoverOf(_ context.Context, _ shared.ID, targets []string) (map[string]scopeauth.Via, error) {
	out := map[string]scopeauth.Via{}
	for _, t := range targets {
		if strings.HasSuffix(t, "ok.example") {
			out[t] = scopeauth.Via{Kind: scopeauth.KindScopeTarget, ID: "t1", Pattern: "*.ok.example", Proof: scopeauth.ProofAsserted}
		}
	}
	return out, nil
}

// POST /scope/check names the caller's own entry behind a refusal and keeps
// only the fixes the caller may take (RFC-054 §6.4).
func TestScopeCheck_DryRunResponse_DB(t *testing.T) {
	db, ctx := openScopingTestDB(t)
	tenantID := seedHandlerTenant(ctx, t, db)
	other := seedHandlerTenant(ctx, t, db)
	mustExec(ctx, t, db, `INSERT INTO scope_targets (tenant_id, target_type, pattern, status, approvals_required) VALUES ($1,'domain','pend.example','pending',1)`, tenantID)
	// Another tenant's pending entry for the same name explains nothing here.
	mustExec(ctx, t, db, `INSERT INTO scope_targets (tenant_id, target_type, pattern, status, approvals_required) VALUES ($1,'domain','*.b.example','pending',1)`, other)

	pg := &postgres.DB{DB: db}
	svc := scopeapp.NewService(postgres.NewScopeTargetRepository(pg), postgres.NewScopeExclusionRepository(pg), postgres.NewAssetRepository(pg), logger.NewNop())
	h := NewScopeHandler(svc, validator.New(), logger.NewNop())
	h.SetDryRun(fakeDryRun{results: []scansvc.DryRunResult{
		{Target: "app.ok.example", Allowed: true},
		{Target: "pend.example", Code: scopedom.RefusalNoEntry},
		{Target: "x.b.example", Code: scopedom.RefusalNoEntry},
		{Target: "portal.gov.vn", Code: scopedom.RefusalDenyList},
	}}, fakeCoverage{})

	call := func(admin bool, perms []string) CheckScopeResponse {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/scope/check", strings.NewReader(`{"targets":["app.ok.example","pend.example","x.b.example","portal.gov.vn"]}`))
		c := context.WithValue(req.Context(), middleware.TenantIDKey, tenantID)
		c = context.WithValue(c, middleware.IsAdminKey, admin)
		c = context.WithValue(c, middleware.FetchedPermissionsKey, perms)
		rec := httptest.NewRecorder()
		h.CheckScope(rec, req.WithContext(c))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		var out CheckScopeResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	by := func(out CheckScopeResponse) map[string]ScopeCheckResult {
		m := map[string]ScopeCheckResult{}
		for _, r := range out.Results {
			m[r.Target] = r
		}
		return m
	}

	adm := by(call(true, nil))
	if r := adm["app.ok.example"]; !r.Allowed || r.Via == nil || r.Via.Pattern != "*.ok.example" {
		t.Errorf("allowed: %+v", r)
	}
	if r := adm["pend.example"]; r.Code != scopedom.RefusalEntryPending || r.Rule == nil || r.Rule.Pattern != "pend.example" {
		t.Errorf("pending entry: %+v", r)
	}
	if r := adm["x.b.example"]; r.Code != scopedom.RefusalNoEntry || r.Rule != nil {
		t.Errorf("another tenant's entry leaked into the explanation: %+v", r)
	}
	if r := adm["portal.gov.vn"]; r.Code != scopedom.RefusalDenyList || r.Rule == nil || r.Rule.Kind != scopedom.RulePlatformPolicy || r.Rule.Pattern != "" {
		t.Errorf("deny list: %+v", r)
	}
	hasAction := func(r ScopeCheckResult, a string) bool {
		for _, f := range r.Fixes {
			if f.Action == a {
				return true
			}
		}
		return false
	}
	if !hasAction(adm["x.b.example"], scopedom.FixAllowTemporarily) || hasAction(adm["x.b.example"], scopedom.FixRequestAccess) {
		t.Errorf("admin fixes: %+v", adm["x.b.example"].Fixes)
	}
	mem := by(call(false, []string{"attack_surface:scope:read", "attack_surface:scope:write"}))
	if hasAction(mem["x.b.example"], scopedom.FixAllowTemporarily) || !hasAction(mem["x.b.example"], scopedom.FixRequestAccess) {
		t.Errorf("member fixes: %+v", mem["x.b.example"].Fixes)
	}
	if hasAction(mem["pend.example"], scopedom.FixApproveEntry) {
		t.Errorf("a member was offered to approve: %+v", mem["pend.example"].Fixes)
	}
}

// tier_exceeds names the caller's entry with the highest ceiling and offers
// raising it to approvers only; another tenant's higher entry is never named
// (RFC-054 §6.5).
func TestScopeCheck_TierExceeds_DB(t *testing.T) {
	db, ctx := openScopingTestDB(t)
	tenantID := seedHandlerTenant(ctx, t, db)
	other := seedHandlerTenant(ctx, t, db)
	mustExec(ctx, t, db, `INSERT INTO scope_targets (tenant_id, target_type, pattern, status, max_tier) VALUES ($1,'domain','*.low.example','active',0)`, tenantID)
	mustExec(ctx, t, db, `INSERT INTO scope_targets (tenant_id, target_type, pattern, status, max_tier, expires_at, reason, approvals_required)
		VALUES ($1,'domain','*.low.example','active',2, now() + interval '3 days', 'pentest', 1)`, other)

	pg := &postgres.DB{DB: db}
	svc := scopeapp.NewService(postgres.NewScopeTargetRepository(pg), postgres.NewScopeExclusionRepository(pg), postgres.NewAssetRepository(pg), logger.NewNop())
	h := NewScopeHandler(svc, validator.New(), logger.NewNop())
	h.SetDryRun(fakeDryRun{results: []scansvc.DryRunResult{{Target: "app.low.example", Code: scopedom.RefusalTierExceeds}}}, fakeCoverage{})

	call := func(admin bool, perms []string) ScopeCheckResult {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/scope/check", strings.NewReader(`{"targets":["app.low.example"],"tier":1}`))
		c := context.WithValue(req.Context(), middleware.TenantIDKey, tenantID)
		c = context.WithValue(c, middleware.IsAdminKey, admin)
		c = context.WithValue(c, middleware.FetchedPermissionsKey, perms)
		rec := httptest.NewRecorder()
		h.CheckScope(rec, req.WithContext(c))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		var out CheckScopeResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Results[0]
	}
	adm := call(true, nil)
	if adm.Code != scopedom.RefusalTierExceeds || adm.Rule == nil || adm.Rule.Pattern != "*.low.example" {
		t.Fatalf("admin: %+v", adm)
	}
	var mine string
	if err := db.QueryRowContext(ctx, `SELECT id FROM scope_targets WHERE tenant_id = $1`, tenantID).Scan(&mine); err != nil {
		t.Fatal(err)
	}
	if adm.Rule.ID != mine {
		t.Fatalf("the rule names %s, not the caller's entry %s", adm.Rule.ID, mine)
	}
	if len(adm.Fixes) != 1 || adm.Fixes[0].Action != scopedom.FixRaiseTier || adm.Fixes[0].ID != mine || adm.Fixes[0].Tier != "t1" {
		t.Fatalf("admin fixes: %+v", adm.Fixes)
	}
	mem := call(false, []string{"attack_surface:scope:read", "attack_surface:scope:write"})
	if mem.Code != scopedom.RefusalTierExceeds || len(mem.Fixes) != 0 {
		t.Fatalf("member: %+v (raising a tier is for approvers)", mem)
	}
}

type recordingDryRun struct {
	got     []scansvc.DryRunInput
	results []scansvc.DryRunResult
}

func (f *recordingDryRun) DryRunTargets(_ context.Context, in scansvc.DryRunInput) ([]scansvc.DryRunResult, error) {
	f.got = append(f.got, in)
	return f.results, nil
}

// asset_ids reach the dry run as ids; an asset the caller may not see comes
// back by its id only, with no fixes, and the request is bounded
// (RFC-054 §6.4).
func TestScopeCheck_AssetIDs_DB(t *testing.T) {
	db, ctx := openScopingTestDB(t)
	tenantID := seedHandlerTenant(ctx, t, db)
	pg := &postgres.DB{DB: db}
	svc := scopeapp.NewService(postgres.NewScopeTargetRepository(pg), postgres.NewScopeExclusionRepository(pg), postgres.NewAssetRepository(pg), logger.NewNop())
	h := NewScopeHandler(svc, validator.New(), logger.NewNop())
	mine, hidden := shared.NewID().String(), shared.NewID().String()
	dry := &recordingDryRun{results: []scansvc.DryRunResult{
		{Target: "app.ok.example", AssetID: mine, Allowed: true},
		{Target: hidden, AssetID: hidden, Code: scopedom.RefusalOutOfDataScope, Reason: "outside"},
	}}
	h.SetDryRun(dry, fakeCoverage{})

	call := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/scope/check", strings.NewReader(body))
		c := context.WithValue(req.Context(), middleware.TenantIDKey, tenantID)
		c = context.WithValue(c, middleware.IsAdminKey, true)
		rec := httptest.NewRecorder()
		h.CheckScope(rec, req.WithContext(c))
		return rec
	}

	rec := call(`{"asset_ids":["` + mine + `","` + hidden + `"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if len(dry.got) != 1 || len(dry.got[0].AssetIDs) != 2 || len(dry.got[0].Targets) != 0 || dry.got[0].Tier != 1 {
		t.Fatalf("dry-run input = %+v", dry.got)
	}
	var out CheckScopeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if r := out.Results[0]; !r.Allowed || r.AssetID != mine || r.Via == nil {
		t.Fatalf("own asset = %+v", r)
	}
	if r := out.Results[1]; r.Allowed || r.Target != hidden || r.AssetID != hidden || r.Code != scopedom.RefusalOutOfDataScope || len(r.Fixes) != 0 || r.Rule != nil {
		t.Fatalf("hidden asset = %+v", r)
	}

	many := make([]string, 0, 201)
	for range 201 {
		many = append(many, `"`+shared.NewID().String()+`"`)
	}
	for name, body := range map[string]string{
		"empty":             `{}`,
		"not a uuid":        `{"asset_ids":["nope"]}`,
		"too many assets":   `{"asset_ids":[` + strings.Join(many, ",") + `]}`,
		"too many together": `{"targets":["a.example"],"asset_ids":[` + strings.Join(many[:200], ",") + `]}`,
	} {
		// 400 for the size rule, 422 for a field validation error.
		if rec := call(body); rec.Code != http.StatusBadRequest && rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: status %d, want 400 or 422", name, rec.Code)
		}
	}
	if len(dry.got) != 1 {
		t.Fatalf("a refused request reached the dry run: %d calls", len(dry.got))
	}
}
